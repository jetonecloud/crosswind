"""Wording shared by every renderer.

The machine-readable reason codes (`no_matching_events`, `lookup_denied`)
are the JSON contract and must not change casually. The sentences people read
are here, in one place, so the terminal, the Markdown and the HTML cannot
drift apart and describe the same situation three different ways.
"""

from __future__ import annotations

#: Attribution reason codes in words. The code is what a consumer branches
#: on; this is what a person reads.
REASONS: dict[str, str] = {
    "no_matching_events": "CloudTrail has no matching event",
    "unmapped_resource_type": "no CloudTrail mapping for this resource type yet",
    "no_lookup_value": "the state has no identifier CloudTrail would know",
    "outside_cloudtrail_retention": "older than CloudTrail's 90-day history",
    "below_confidence_floor": "no candidate event was convincing enough",
    "attribution_disabled": "attribution was not run",
    "not_attempted": "attribution was not run",
    "lookup_denied": "no permission for cloudtrail:LookupEvents",
    "credentials_expired": "AWS credentials expired",
    "credentials_invalid": "AWS credentials were rejected",
    "credentials_denied": "AWS denied these credentials",
    "credentials_unavailable": "no usable AWS credentials",
    "throttled": "CloudTrail throttled the lookup",
    "lookup_failed": "the CloudTrail lookup failed",
}

#: Said in every format. The product's central claim, in one sentence.
READ_ONLY_NOTE = (
    "Crosswind is read-only: it ran `plan -refresh-only` and changed nothing. "
    "Recommendations are for a human to carry out."
)

#: What a "could not check" stack means, in case the phrase is not enough.
FAILED_NOTE = "These were not scanned. They are not known to be clean."


def reason(code: str | None) -> str:
    """A reason code as a sentence fragment.

    An unrecognised code is passed through rather than hidden: a new code
    reaching a report is a gap in this table, and showing it is how anyone
    finds out.
    """
    if code is None:
        return "no evidence"
    return REASONS.get(code, code)
