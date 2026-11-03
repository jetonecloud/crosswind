"""What Crosswind found, and everything a reader needs to judge it.

Three rules shaped these types:

- **A finding carries its own evidence.** The severity names the rule that
  set it; the attribution names the CloudTrail event it came from; the cost
  estimate carries the arithmetic. A report should never be the only place a
  claim exists — a reader has to be able to go and check.
- **"We don't know" is a value, not an absence.** `Attribution` has an
  `UNKNOWN` confidence with a `reason`, because "CloudTrail has no record of
  this" and "we didn't look" are different facts and a reader deserves to be
  told which one applies.
- **A stack that failed is not a stack with no findings.** `StackResult`
  distinguishes them, and the report counts them separately. This is the one
  bug that would make the tool actively harmful.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(Enum):
    """How much attention a drifted resource deserves."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Sort key: 0 is the most severe."""
        return _SEVERITY_ORDER[self]

    @property
    def label(self) -> str:
        return self.value

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            allowed = ", ".join(level.value for level in cls)
            raise ValueError(f"Unknown severity {value!r}. Use one of: {allowed}.") from exc

    def at_least(self, floor: Severity) -> bool:
        """Is this severity at or above `floor`?"""
        return self.rank <= floor.rank


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class Confidence(Enum):
    """How sure we are that a named person made this change.

    `UNKNOWN` is not a low score — it is the absence of a claim, and it is
    what every finding gets until CloudTrail evidence earns it something
    better. Guessing a person is the worst thing this tool could do.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    @property
    def label(self) -> str:
        return self.value


class DriftKind(Enum):
    """What kind of disagreement this is."""

    #: Attributes differ between state and reality.
    CHANGED = "changed"
    #: The resource is gone. Terraform's refresh dropped it from state.
    DELETED = "deleted"
    #: The provider reports it as needing replacement to reconcile.
    REPLACED = "replaced"

    @property
    def label(self) -> str:
        return self.value


class Recommendation(Enum):
    """What we think the team should do. We never do it."""

    #: The change looks wrong or dangerous. Put it back the way the code says.
    REVERT = "revert"
    #: The change looks intentional. Write it into the code so it stops drifting.
    UPDATE_CODE = "update_code"
    #: We can't tell from here. A human has to look.
    INVESTIGATE = "investigate"

    @property
    def label(self) -> str:
        return self.value.replace("_", " ")


@dataclass(frozen=True)
class AttributeChange:
    """One attribute that disagrees, already redacted.

    `before` is what Terraform's state said; `after` is what the provider
    found when it refreshed. Both have been through `redact.scrub`, so this
    object is safe to render anywhere. `redacted` records that we changed the
    value, so a report can say "(sensitive value)" and mean it rather than
    leaving a reader to wonder whether the value really was that string.
    """

    path: str
    before: Any
    after: Any
    redacted: bool = False
    #: True when the provider itself marked this attribute sensitive, as
    #: opposed to our name matching catching it. Worth distinguishing: the
    #: first is a promise from the provider author, the second is our guess.
    provider_sensitive: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "before": self.before,
            "after": self.after,
            "redacted": self.redacted,
            "provider_sensitive": self.provider_sensitive,
        }


@dataclass(frozen=True)
class Event:
    """A CloudTrail event, as CloudTrail recorded it.

    Copied through rather than interpreted, so a reader can paste the event
    ID into the console and see the same thing we saw.

    The field set follows what `LookupEvents` actually returns, which is
    narrower than the full CloudTrail record: `EventId`, `EventName`,
    `ReadOnly`, `AccessKeyId`, `EventTime`, `EventSource`, `Username`,
    `Resources` and the `CloudTrailEvent` JSON blob. Notably there is **no**
    region field in the summary — the region lives inside the blob — which is
    the kind of thing you only find out by asking the service model.
    """

    event_id: str
    event_name: str
    event_time: datetime
    #: Whatever CloudTrail put in `Username` — an IAM user, a role session
    #: name, `AWSService`, or an assumed-role ARN fragment. Not normalised,
    #: because normalising it would be inventing precision we don't have.
    username: str | None
    event_source: str
    region: str
    #: Present when the caller was a service or an assumed role and
    #: CloudTrail could tell us more than `Username` carries.
    principal_type: str | None = None
    #: `(ResourceType, ResourceName)` pairs CloudTrail associated with the
    #: event. This is what makes the resource-match signal real rather than
    #: an assumption about why the event came back.
    resources: tuple[tuple[str, str], ...] = ()
    #: CloudTrail's own flag. A read-only call cannot have caused drift, so
    #: these are dropped before ranking.
    read_only: bool | None = None

    def mentions(self, value: str) -> bool:
        """Does this event name `value` in its resource list?"""
        if not value:
            return False
        needle = value.strip().lower()
        for _kind, name in self.resources:
            if not name:
                continue
            haystack = name.strip().lower()
            # An ARN contains the name or ID, so match either direction:
            # we may have looked up `my-role` and CloudTrail may have
            # recorded the full ARN, or the other way round.
            if needle == haystack or needle in haystack or haystack in needle:
                return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_name": self.event_name,
            "event_time": self.event_time.isoformat(),
            "username": self.username,
            "event_source": self.event_source,
            "region": self.region,
            "principal_type": self.principal_type,
            "resources": [{"type": kind, "name": name} for kind, name in self.resources],
            "read_only": self.read_only,
        }


@dataclass(frozen=True)
class Attribution:
    """Who changed it, or an honest account of why we don't know.

    `confidence == UNKNOWN` always comes with a `reason`, and `actor` is
    `None`. There is no code path that produces a name without an event.
    """

    confidence: Confidence
    actor: str | None = None
    event: Event | None = None
    #: Why we don't know, when we don't. One of a small set of strings so a
    #: consumer can branch on it: `no_matching_events`, `lookup_failed`,
    #: `outside_cloudtrail_retention`, `unmapped_resource_type`,
    #: `attribution_disabled`, `below_confidence_floor`.
    reason: str | None = None
    #: How the score was reached, for the curious and for debugging.
    score: float | None = None

    @classmethod
    def unknown(cls, reason: str) -> Attribution:
        return cls(confidence=Confidence.UNKNOWN, reason=reason)

    @property
    def known(self) -> bool:
        return self.confidence is not Confidence.UNKNOWN and self.actor is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence": self.confidence.value,
            "actor": self.actor,
            "reason": self.reason,
            "score": round(self.score, 3) if self.score is not None else None,
            "event": self.event.to_dict() if self.event else None,
        }


@dataclass(frozen=True)
class CostEstimate:
    """A dollar figure and the arithmetic behind it.

    `basis` is printed directly under the number. If you cannot write the
    sentence, you do not understand the estimate well enough to show it to
    someone — and in that case the estimate should be `None` instead.
    """

    monthly_usd: float
    basis: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "monthly_usd": round(self.monthly_usd, 2),
            "annual_usd": round(self.monthly_usd * 12, 2),
            "basis": self.basis,
        }


@dataclass(frozen=True)
class Finding:
    """One drifted resource, scored and attributed.

    `id` is stable across runs for the same resource in the same stack, so
    two reports can be diffed to see what was actually dealt with.
    """

    stack: str
    address: str
    resource_type: str
    kind: DriftKind
    changes: Sequence[AttributeChange]
    severity: Severity
    #: The id of the rule in `severity.yml` that set `severity`. Shown in
    #: every format. A severity with no traceable rule is a severity nobody
    #: will act on.
    severity_rule: str
    severity_reason: str
    recommendation: Recommendation
    recommendation_reason: str
    attribution: Attribution
    provider: str | None = None
    region: str | None = None
    cost: CostEstimate | None = None

    @property
    def id(self) -> str:
        return f"{self.stack}::{self.address}"

    @property
    def changed_paths(self) -> tuple[str, ...]:
        return tuple(change.path for change in self.changes)

    @property
    def sort_key(self) -> tuple[Any, ...]:
        """Most severe first, then by address so an unchanged account diffs clean."""
        return (self.severity.rank, self.stack, self.address)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "stack": self.stack,
            "address": self.address,
            "resource_type": self.resource_type,
            "provider": self.provider,
            "region": self.region,
            "drift_kind": self.kind.value,
            "severity": self.severity.value,
            "severity_rule": self.severity_rule,
            "severity_reason": self.severity_reason,
            "recommendation": self.recommendation.value,
            "recommendation_reason": self.recommendation_reason,
            "changes": [change.to_dict() for change in self.changes],
            "attribution": self.attribution.to_dict(),
            "cost": self.cost.to_dict() if self.cost else None,
        }


class StackStatus(Enum):
    """How a stack's scan turned out."""

    #: Scanned, no drift at all.
    CLEAN = "clean"
    #: Scanned, drift found.
    DRIFTED = "drifted"
    #: Could not be scanned. Never reported as clean — this is the whole point.
    FAILED = "failed"

    @property
    def label(self) -> str:
        return self.value


@dataclass(frozen=True)
class StackResult:
    """What happened to one stack.

    A `FAILED` result carries the error and no findings. It is counted
    separately everywhere and forces exit code 2, because a stack we could
    not check is the one thing a drift report must never present as a stack
    with nothing wrong.
    """

    path: str
    status: StackStatus
    findings: Sequence[Finding] = field(default_factory=tuple)
    #: Set when `status is FAILED`. Already scrubbed.
    error: str | None = None
    #: Which Terraform/OpenTofu produced this, for the report header.
    binary: str | None = None
    #: How many findings an ignore rule suppressed. Shown as a total, so a
    #: user can tell the difference between "clean" and "quiet".
    ignored: int = 0
    duration_seconds: float | None = None

    @property
    def ok(self) -> bool:
        return self.status is not StackStatus.FAILED

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status.value,
            "error": self.error,
            "binary": self.binary,
            "ignored": self.ignored,
            "duration_seconds": (
                round(self.duration_seconds, 2) if self.duration_seconds is not None else None
            ),
            "findings": [finding.to_dict() for finding in self.findings],
        }


def rank(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    """Findings in the order a reader should work through them."""
    return tuple(sorted(findings, key=lambda finding: finding.sort_key))


def count_by_severity(findings: Sequence[Finding]) -> dict[str, int]:
    """Findings per severity, always with all four keys so a chart doesn't gap."""
    counts = {level.value: 0 for level in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def stack_label(path: Path | str, root: Path | None = None) -> str:
    """How a stack is named in a report: relative to the scan root if we can.

    An absolute path in a shared report leaks the layout of someone's laptop
    and is harder to read than `infra/prod/network`.
    """
    candidate = Path(path)
    if root is not None:
        try:
            return candidate.resolve().relative_to(root.resolve()).as_posix() or "."
        except ValueError:
            pass
    return candidate.as_posix()
