"""Picking the event that explains the drift, or admitting we can't.

CloudTrail will happily return thirty events mentioning a security group.
Most of them are not the change we are looking at. Ranking is how we pick,
and the floor is how we decline.

The score is three signals, and they are weighted by how much they actually
tell you:

**Resource match — 0.5.** The event's own `Resources` list names the
resource that drifted. The strongest evidence there is, and it matters for
calls that touch several resources at once: a `ModifySecurityGroupRules`
naming three groups is only an exact match for the one we asked about.

**Expected event name — 0.3.** The event is one the mapping associates with
the attribute that changed. `ModifyVolume` on a changed `size` is a much
better story than `CreateTags` on the same volume.

**Recency — 0.2.** Later events are likelier to be the current state's
cause. The weakest signal by far, and treated as such: a scan that runs a
week after the change inverts the intuition entirely, which is why recency
alone cannot clear the floor.

Confidence is then **not** a threshold on the score, which would let a pile
of weak signals add up to a confident wrong answer. It is a statement about
which evidence is present:

- `high` — exact resource match **and** an expected event name. Both.
- `medium` — exact resource match, but the event name is not one we associate
  with the attribute that changed. Probably the right resource, possibly the
  wrong event.
- `low` — it cleared the floor on something else. Worth showing with the
  event ID attached; not worth repeating in a meeting.
- `unknown` — no events, below the floor, lookup failed, or the resource type
  is not in the mapping. **Names nobody.**

That last line is the one that matters. `Attribution.unknown()` is the only
way to construct an attribution without an event, and it sets `actor` to
`None`, so there is no code path that produces a name without the evidence
for it. Being told "we don't know" is annoying; being told the wrong
colleague's name is a problem that outlives the report.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from crosswind.core.attribution.lookup import (
    Lookup,
    LookupFailed,
    resolve_region,
    within_retention,
)
from crosswind.core.attribution.mapping import Mapping
from crosswind.core.findings import Attribution, Confidence, Event
from crosswind.core.plan import DriftedResource

#: Signal weights. They sum to 1.0 so a score reads as a fraction.
WEIGHT_RESOURCE_MATCH = 0.5
WEIGHT_EVENT_NAME = 0.3
WEIGHT_RECENCY = 0.2

#: Below this, we say nothing. Deliberately above `WEIGHT_RECENCY` alone:
#: "this event is recent" is not evidence that it caused anything.
SCORE_FLOOR = 0.45

#: Events from these principals are AWS doing its job, not a person making a
#: change. Attributing drift to `AWSService` is technically true and useless;
#: ranked last so a human actor always wins, but still reported if it is all
#: there is, because "an AWS service did this" is a real answer.
SERVICE_PRINCIPALS = frozenset({"AWSService", "AWSAccount", "Root"})


def attribute(
    resource: DriftedResource,
    *,
    lookup: Lookup,
    mapping: Mapping,
    window_hours: int,
    region: str | None = None,
    session_region: str | None = None,
) -> Attribution:
    """Who changed this resource, on the evidence available.

    Returns an `unknown` attribution rather than raising, for every reason a
    lookup can fail. Attribution is a bonus on top of a drift report that has
    already succeeded.
    """
    mapped = mapping.for_type(resource.resource_type)
    if mapped is None:
        return Attribution.unknown("unmapped_resource_type")

    value = mapped.lookup_value(resource.raw_before or resource.raw_after)
    if not value:
        # The prior state has none of the attributes CloudTrail would know
        # this resource by. Looking up a guessed value would produce
        # confident nonsense.
        return Attribution.unknown("no_lookup_value")

    search_region = resolve_region(
        is_global=mapped.is_global,
        resource_region=region,
        session_region=session_region,
    )

    try:
        events = lookup.events_for(value=value, region=search_region, window_hours=window_hours)
    except LookupFailed as exc:
        return Attribution.unknown(exc.reason)

    if not events:
        return Attribution.unknown("no_matching_events")

    expected = mapped.events_for(resource.changed_paths)
    ranked = rank_candidates(
        events,
        lookup_value=value,
        expected_events=expected,
        window_hours=window_hours,
    )
    if not ranked:
        return Attribution.unknown("no_matching_events")

    best, score = ranked[0]
    if score < SCORE_FLOOR:
        return Attribution.unknown("below_confidence_floor")
    if not within_retention(best.event_time):
        return Attribution.unknown("outside_cloudtrail_retention")

    return Attribution(
        confidence=_confidence_for(best, value, expected),
        actor=_actor(best),
        event=best,
        score=score,
    )


def rank_candidates(
    events: Sequence[Event],
    *,
    lookup_value: str,
    expected_events: frozenset[str],
    window_hours: int,
) -> list[tuple[Event, float]]:
    """Candidate events, best first, with their scores.

    Ties break towards the more recent event, then the event ID, so two runs
    over an unchanged account rank identically and the reports diff clean.
    """
    scored = [
        (
            event,
            _score(
                event,
                lookup_value=lookup_value,
                expected_events=expected_events,
                window_hours=window_hours,
            ),
        )
        for event in events
    ]
    scored.sort(key=lambda pair: (-pair[1], -pair[0].event_time.timestamp(), pair[0].event_id))
    return scored


def _score(
    event: Event,
    *,
    lookup_value: str,
    expected_events: frozenset[str],
    window_hours: int,
) -> float:
    score = 0.0
    if _matches_resource(event, lookup_value):
        score += WEIGHT_RESOURCE_MATCH
    if event.event_name in expected_events:
        score += WEIGHT_EVENT_NAME
    score += WEIGHT_RECENCY * _recency(event.event_time, window_hours)

    # An AWS service acting on its own behalf is a worse explanation for
    # drift than a person, so it loses the tie it would otherwise win on
    # recency. Not zeroed: sometimes a service really is the answer.
    if event.username in SERVICE_PRINCIPALS or (
        event.principal_type and event.principal_type in SERVICE_PRINCIPALS
    ):
        score *= 0.8
    return round(score, 4)


def _matches_resource(event: Event, lookup_value: str) -> bool:
    """Does the event's own resource list name the resource that drifted?

    `LookupEvents` returns a `Resources` list of `(ResourceType,
    ResourceName)` per event, so this is a real check against what CloudTrail
    recorded rather than an assumption about why the event came back. It
    matters for the events that touch several resources at once: a
    `ModifySecurityGroupRules` call naming three groups should only count as
    an exact match for the group we are actually asking about.

    When CloudTrail returned no resource list at all — which happens for some
    event sources — we fall back to trusting the query. The alternative is
    scoring every such event below the floor and attributing nothing, which
    would be worse than a `medium`.
    """
    if not lookup_value:
        return False
    if not event.resources:
        return True
    return event.mentions(lookup_value)


def _recency(when: datetime, window_hours: int) -> float:
    """1.0 for just now, falling linearly to 0.0 at the window's edge.

    The weakest of the three signals and treated as such. A scan that runs a
    week after the change inverts the intuition entirely — which is why
    recency alone cannot clear the floor.
    """
    age_hours = (datetime.now(UTC) - when).total_seconds() / 3600.0
    if age_hours <= 0:
        return 1.0
    if age_hours >= window_hours:
        return 0.0
    return 1.0 - (age_hours / window_hours)


def _confidence_for(event: Event, lookup_value: str, expected: frozenset[str]) -> Confidence:
    """Confidence from which evidence is present, not from the score total.

    A score threshold would let three weak signals add up to `high`, which is
    exactly the kind of confident wrong answer this feature cannot afford.
    """
    resource_match = _matches_resource(event, lookup_value)
    name_match = event.event_name in expected
    if resource_match and name_match:
        return Confidence.HIGH
    if resource_match:
        return Confidence.MEDIUM
    return Confidence.LOW


def _actor(event: Event) -> str:
    """How to name whoever did this, without inventing anything.

    Falls back to the principal type and then to a plain statement, so the
    field is never empty and never a guess. `Username` is CloudTrail's own
    text: an IAM user, a role session name, or `AWSService`.
    """
    if event.username:
        return event.username
    if event.principal_type:
        return f"unnamed {event.principal_type}"
    return "an identity CloudTrail did not name"
