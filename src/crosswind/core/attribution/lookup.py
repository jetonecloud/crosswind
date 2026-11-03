"""Talking to CloudTrail `LookupEvents`, which does not like being talked to.

`LookupEvents` has a documented quota of roughly **two requests per second
per account per region**, and it is enforced per account rather than per
caller — so a scan competing with someone else's tooling gets throttled even
when it is behaving. A drift scan over fifty resources is fifty lookups, and
a naive loop will spend most of its time being refused.

What this module does about that:

- **A token bucket**, shared across the scan's threads, holding the request
  rate below the quota rather than discovering it by being refused.
- **Exponential backoff with full jitter** on `ThrottlingException`. Jitter
  rather than a fixed sequence, because every thread retrying in lockstep is
  how a throttle becomes a thundering herd.
- **A cache** keyed on `(region, attribute, value, window)`. Several drifted
  attributes on one resource is one lookup, and two stacks sharing a security
  group is also one lookup.
- **A budget.** Past a fixed number of failures the lookup stops trying and
  every remaining finding attributes to `unknown` with the reason recorded.
  Spending ten minutes being throttled is worse than saying "we could not
  check" — the drift report is the product and it is already finished.

And the limits that are not ours to fix, each of which is surfaced in the
report rather than hidden:

- **Management events only.** Data events (an S3 object write, a Lambda
  invoke) are not recorded unless the account opted in and paid for it.
- **90 days.** `LookupEvents` serves the event history, not a trail's S3
  bucket. Older drift is `outside_cloudtrail_retention`.
- **Regional.** Events are returned by the region they happened in. Global
  services (IAM, Route 53, CloudFront) log to `us-east-1` wherever the
  resource lives, which the mapping file records per resource type.
- **Eventual consistency.** An event can take around 15 minutes to appear.
  Drift created moments ago may legitimately attribute to `unknown`.
"""

from __future__ import annotations

import json
import random
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from crosswind.core.findings import Event

#: CloudTrail's event history. Asking for more just returns nothing.
RETENTION_DAYS = 90

#: Requests per second. The documented quota is about 2/s; we sit under it,
#: because the quota is per account and we are not the only caller.
DEFAULT_RATE = 1.5

#: How many times to retry one throttled lookup before giving up on it.
MAX_ATTEMPTS = 5

#: Total lookup failures across a scan before we stop trying entirely. The
#: drift report is already complete at this point; attribution is the bonus.
DEFAULT_FAILURE_BUDGET = 10

#: Most events we will read for one resource. Ranking only needs the
#: plausible candidates, and a chatty resource can have thousands.
MAX_EVENTS_PER_LOOKUP = 50

#: Errors that mean "slow down" rather than "stop".
THROTTLE_CODES = frozenset(
    {"ThrottlingException", "Throttling", "RequestLimitExceeded", "TooManyRequestsException"}
)

#: Errors that mean the credentials cannot do this at all. Retrying is futile
#: and the reason is worth reporting precisely.
DENIAL_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "InvalidClientTokenId",
        "ExpiredToken",
        "ExpiredTokenException",
        "UnrecognizedClientException",
    }
)


class LookupFailed(RuntimeError):
    """CloudTrail could not be read. Carries a machine-readable reason.

    Never fatal to a scan: callers turn this into an `unknown` attribution
    and carry on. Drift reporting must work without CloudTrail.
    """

    def __init__(self, message: str, *, reason: str = "lookup_failed") -> None:
        super().__init__(message)
        self.reason = reason


class Lookup(Protocol):
    """What `rank.attribute` needs from a CloudTrail source."""

    def events_for(self, *, value: str, region: str, window_hours: int) -> tuple[Event, ...]: ...

    @property
    def failed(self) -> bool: ...


class NullLookup:
    """A lookup that never looks anything up.

    Used by `--no-attribution` and by `demo`, so the attribution code path is
    the same one in every mode rather than a branch that only runs in
    production.
    """

    reason = "attribution_disabled"

    def events_for(self, *, value: str, region: str, window_hours: int) -> tuple[Event, ...]:
        return ()

    @property
    def failed(self) -> bool:
        return False


@dataclass
class _Bucket:
    """A token bucket, shared across threads.

    Simple on purpose: one lock, one timestamp. The contention here is
    nothing next to the network call it is pacing.
    """

    rate: float
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _next_at: float = 0.0

    def take(self) -> None:
        """Block until this caller is allowed to make a request."""
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_at - now)
            self._next_at = max(now, self._next_at) + 1.0 / self.rate
        if wait > 0:
            time.sleep(wait)


class CloudTrailLookup:
    """Reads `LookupEvents`, carefully.

    One instance per scan. It holds the cache and the rate limiter, so
    sharing it across stacks is what makes the budget and the pacing mean
    anything.
    """

    def __init__(
        self,
        session: Any,
        *,
        rate: float = DEFAULT_RATE,
        failure_budget: int = DEFAULT_FAILURE_BUDGET,
        sleeper: Any = time.sleep,
    ) -> None:
        self._session = session
        self._bucket = _Bucket(rate=rate)
        self._cache: dict[tuple[str, str, int], tuple[Event, ...]] = {}
        self._clients: dict[str, Any] = {}
        self._lock = threading.Lock()
        self._failures = 0
        self._failure_budget = failure_budget
        self._sleep = sleeper
        #: The reason attribution stopped working, if it did. Reported once
        #: rather than repeated on every finding.
        self.failure_reason: str | None = None

    @property
    def failed(self) -> bool:
        """Has attribution given up for this scan?"""
        return self._failures >= self._failure_budget

    def events_for(self, *, value: str, region: str, window_hours: int) -> tuple[Event, ...]:
        """Events mentioning `value` in `region` within the window.

        Raises `LookupFailed` on anything the caller should report as a
        reason. Returns an empty tuple when CloudTrail simply has no record,
        which is a different fact and becomes `no_matching_events`.
        """
        window_hours = self._clamp_window(window_hours)
        key = (region, value, window_hours)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
            if self.failed:
                raise LookupFailed(
                    "Gave up on CloudTrail after repeated failures.",
                    reason=self.failure_reason or "lookup_failed",
                )

        events = self._lookup(value=value, region=region, window_hours=window_hours)
        with self._lock:
            self._cache[key] = events
        return events

    def _clamp_window(self, window_hours: int) -> int:
        """CloudTrail serves 90 days. Asking for more is a slower way to get
        the same answer."""
        return max(1, min(window_hours, RETENTION_DAYS * 24))

    def _client(self, region: str) -> Any:
        with self._lock:
            client = self._clients.get(region)
            if client is None:
                client = self._session.client("cloudtrail", region_name=region)
                self._clients[region] = client
            return client

    def _lookup(self, *, value: str, region: str, window_hours: int) -> tuple[Event, ...]:
        end = datetime.now(UTC)
        start = end - timedelta(hours=window_hours)
        client = self._client(region)

        last_error: Exception | None = None
        for attempt in range(MAX_ATTEMPTS):
            self._bucket.take()
            try:
                return self._page(client, value, start, end, region)
            except Exception as exc:  # noqa: BLE001 - classified immediately below
                code = _error_code(exc)
                if code in DENIAL_CODES:
                    self._record_failure(_reason_for(code))
                    raise LookupFailed(
                        f"CloudTrail lookup in {region} was denied ({code}).",
                        reason=_reason_for(code),
                    ) from exc
                if code not in THROTTLE_CODES:
                    self._record_failure("lookup_failed")
                    raise LookupFailed(
                        f"CloudTrail lookup in {region} failed ({code or type(exc).__name__}).",
                        reason="lookup_failed",
                    ) from exc
                last_error = exc
                # Full jitter: every thread picking the same delay is how a
                # throttle turns into a thundering herd.
                backoff = min(2.0**attempt, 30.0)
                self._sleep(random.uniform(0.0, backoff))  # noqa: S311 - not cryptographic

        self._record_failure("throttled")
        raise LookupFailed(
            f"CloudTrail in {region} throttled {MAX_ATTEMPTS} attempts.",
            reason="throttled",
        ) from last_error

    def _page(
        self,
        client: Any,
        value: str,
        start: datetime,
        end: datetime,
        region: str,
    ) -> tuple[Event, ...]:
        """One lookup, following pages up to the event cap.

        Two things about the request that come from reading botocore's
        service model rather than the prose documentation:

        - **`EventCategory` is not how you ask for management events.** Its
          only permitted value is `insight`. `LookupEvents` returns
          management events by default, and passing `"Management"` is a
          parameter validation error. Data events are not available through
          this API at all, which is the limitation the report states.
        - **`MaxResults` exists**, so the page size is asked for rather than
          discovered. CloudTrail returns 50 per page by default anyway, but
          saying so keeps the request honest about what we want.
        """
        events: list[Event] = []
        token: str | None = None
        while True:
            request: dict[str, Any] = {
                "LookupAttributes": [{"AttributeKey": "ResourceName", "AttributeValue": value}],
                "StartTime": start,
                "EndTime": end,
                "MaxResults": min(MAX_EVENTS_PER_LOOKUP, 50),
            }
            if token:
                request["NextToken"] = token
            response = client.lookup_events(**request)
            for raw in response.get("Events", ()):
                parsed = _parse_event(raw, region)
                if parsed is None:
                    continue
                # A read-only call cannot have caused drift. Dropping these
                # here rather than in ranking keeps the candidate list
                # honest and the cache smaller.
                if parsed.read_only:
                    continue
                events.append(parsed)
            token = response.get("NextToken")
            if not token or len(events) >= MAX_EVENTS_PER_LOOKUP:
                break
            self._bucket.take()
        return tuple(events[:MAX_EVENTS_PER_LOOKUP])

    def _record_failure(self, reason: str) -> None:
        with self._lock:
            self._failures += 1
            if self.failure_reason is None:
                self.failure_reason = reason


def _error_code(exc: Exception) -> str:
    """The AWS error code from a botocore exception, if there is one."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict):
            return str(error.get("Code") or "")
    # botocore's own client-side errors (no credentials, bad region) carry
    # their class name and nothing else useful.
    return type(exc).__name__


def _reason_for(code: str) -> str:
    if code in {"ExpiredToken", "ExpiredTokenException"}:
        return "credentials_expired"
    if code in {"InvalidClientTokenId", "UnrecognizedClientException"}:
        return "credentials_invalid"
    return "lookup_denied"


def _parse_event(raw: Any, region: str) -> Event | None:
    """One CloudTrail event, copied through rather than interpreted.

    `Username` is taken exactly as CloudTrail recorded it. Normalising it
    into "a person" would be inventing precision we do not have: the field
    holds IAM user names, role session names, `AWSService`, and sometimes
    nothing at all.

    The region is **not** a field of the `LookupEvents` event summary — only
    `EventId`, `EventName`, `ReadOnly`, `AccessKeyId`, `EventTime`,
    `EventSource`, `Username`, `Resources` and `CloudTrailEvent` are. It is
    read out of the embedded JSON blob, falling back to the region we
    queried.
    """
    if not isinstance(raw, dict):
        return None
    event_id = raw.get("EventId")
    event_name = raw.get("EventName")
    event_time = raw.get("EventTime")
    if not event_id or not event_name:
        return None
    if isinstance(event_time, datetime):
        when = event_time if event_time.tzinfo else event_time.replace(tzinfo=UTC)
    else:
        return None

    detail = _detail(raw)
    resources = tuple(
        (str(item.get("ResourceType") or ""), str(item.get("ResourceName") or ""))
        for item in raw.get("Resources", ())
        if isinstance(item, dict)
    )

    return Event(
        event_id=str(event_id),
        event_name=str(event_name),
        event_time=when,
        username=str(raw["Username"]) if raw.get("Username") else None,
        event_source=str(raw.get("EventSource") or ""),
        region=str(detail.get("awsRegion") or region),
        principal_type=_principal_type(detail),
        resources=resources,
        read_only=_read_only(raw, detail),
    )


def _detail(raw: dict[str, Any]) -> dict[str, Any]:
    """The `CloudTrailEvent` JSON blob, or an empty mapping.

    Everything read out of here is best-effort: a reader who needs certainty
    has the event ID and can look it up themselves.
    """
    blob = raw.get("CloudTrailEvent")
    if not isinstance(blob, str):
        return {}
    try:
        payload = json.loads(blob)
    except (json.JSONDecodeError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _principal_type(detail: dict[str, Any]) -> str | None:
    """`IAMUser`, `AssumedRole`, `AWSService` — whatever CloudTrail said."""
    identity = detail.get("userIdentity")
    if isinstance(identity, dict):
        kind = identity.get("type")
        return str(kind) if kind else None
    return None


def _read_only(raw: dict[str, Any], detail: dict[str, Any]) -> bool | None:
    """Whether CloudTrail considers this a read.

    `ReadOnly` is a string in the summary (`"true"`/`"false"`) and a real
    boolean inside the blob, so both spellings are handled. `None` means
    CloudTrail did not say, which is treated as "might have written" — the
    safe direction, since the alternative is discarding the event that
    explains the drift.
    """
    summary = raw.get("ReadOnly")
    if isinstance(summary, bool):
        return summary
    if isinstance(summary, str) and summary.strip():
        return summary.strip().lower() == "true"
    nested = detail.get("readOnly")
    if isinstance(nested, bool):
        return nested
    return None


def resolve_region(
    *, is_global: bool, resource_region: str | None, session_region: str | None
) -> str:
    """Which region's trail to search.

    Global services log to `us-east-1` no matter where the resource is. This
    is the single most common reason a real change attributes to "unknown":
    looking for an IAM event in eu-west-1, where it was never written.
    """
    if is_global:
        return "us-east-1"
    return resource_region or session_region or "us-east-1"


def within_retention(when: datetime) -> bool:
    """Is this timestamp inside CloudTrail's 90-day event history?"""
    return (datetime.now(UTC) - when).days <= RETENTION_DAYS


def candidate_window(window_hours: int) -> Sequence[datetime]:
    """The window's bounds, for reporting what was searched."""
    end = datetime.now(UTC)
    return (end - timedelta(hours=window_hours), end)
