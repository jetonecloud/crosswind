"""Who changed it, when the evidence supports an answer.

Three modules:

- `mapping.py` reads `data/cloudtrail.yml`: which CloudTrail records
  correspond to which Terraform resource type, and how to derive a lookup
  value from the drifted resource's prior state.
- `lookup.py` talks to CloudTrail, with the retry, rate limiting and caching
  that `LookupEvents` requires of anyone who uses it seriously.
- `rank.py` turns candidate events into an `Attribution`, or into an honest
  `unknown`.

The rule that governs all three: **never name a person without an event.**
Attribution is the feature most likely to be quoted in a meeting, and a
confident wrong name is worse than no name at all. Every path that produces
an actor also produces the event ID it came from.
"""

from __future__ import annotations

from crosswind.core.attribution.lookup import (
    CloudTrailLookup,
    LookupFailed,
    NullLookup,
)
from crosswind.core.attribution.mapping import Mapping, load_mapping
from crosswind.core.attribution.rank import attribute, rank_candidates

__all__ = [
    "CloudTrailLookup",
    "LookupFailed",
    "Mapping",
    "NullLookup",
    "attribute",
    "load_mapping",
    "rank_candidates",
]
