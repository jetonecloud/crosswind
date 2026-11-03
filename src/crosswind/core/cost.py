"""What a drifted attribute costs, when we can actually say.

The rule this module exists to enforce: **no number we cannot defend.** A
drift report often ends up in front of someone deciding whether to spend
engineering time on it, and a figure that turns out to be wrong costs more
credibility than the figure was ever worth.

So an estimate is produced only when all three of these hold:

1. The attribute has an unambiguous price attached to it — an instance size,
   a storage size. Not a NAT gateway, whose cost is mostly data processing,
   and not a Lambda memory change, whose cost is memory times invocations and
   we do not know the invocations.
2. Both the before and after values are in the static price table. An
   unlisted instance type produces no estimate, never an interpolation.
3. The delta is non-zero.

Every estimate carries a `basis` sentence with the arithmetic in it, and
every estimate says it is an upper bound — because the table is on-demand
list price, and Savings Plans, Reserved Instances and Spot only ever make the
real figure smaller.

`estimate()` returning `None` is the normal case and not a failure.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from typing import Any

import yaml

from crosswind.core.findings import CostEstimate
from crosswind.core.plan import DriftedResource

DATA_FILE = "cost.yml"

#: Attribute paths that name an instance size, by resource family.
EC2_SIZE_PATHS = frozenset({"instance_type"})
RDS_SIZE_PATHS = frozenset({"instance_class"})

#: Attribute paths that name a storage size in GB.
EBS_SIZE_PATHS = frozenset(
    {"size", "root_block_device.0.volume_size", "ebs_block_device.0.volume_size"}
)
RDS_STORAGE_PATHS = frozenset({"allocated_storage"})

#: Below this, the arithmetic is right and the finding is noise. A report
#: claiming someone can save forty cents a month invites the reader to stop
#: trusting the other figures.
MIN_REPORTABLE_USD = 1.0


@lru_cache(maxsize=1)
def _prices() -> dict[str, Any]:
    raw = yaml.safe_load(
        resources.files("crosswind.data").joinpath(DATA_FILE).read_text(encoding="utf-8")
    )
    if not isinstance(raw, dict):
        raise ValueError(f"{DATA_FILE} should contain a mapping.")
    return raw


def estimate(resource: DriftedResource) -> CostEstimate | None:
    """The monthly cost difference this drift represents, or `None`.

    `None` whenever we cannot show the arithmetic, which is most of the time.
    """
    for change in resource.changes:
        for guess in (
            _compute_size,
            _storage_size,
        ):
            result = guess(resource, change.path, change.before, change.after)
            if result is not None:
                return result
    return None


def _compute_size(
    resource: DriftedResource, path: str, before: Any, after: Any
) -> CostEstimate | None:
    """An instance that is now a different size than the code says."""
    prices = _prices()
    hours = float(prices.get("hours_per_month", 730))

    if path in EC2_SIZE_PATHS:
        table, label = prices.get("ec2", {}), "EC2 on-demand"
    elif path in RDS_SIZE_PATHS:
        table, label = prices.get("rds", {}), "RDS on-demand, single-AZ"
    else:
        return None

    old_rate = table.get(_as_text(before))
    new_rate = table.get(_as_text(after))
    if old_rate is None or new_rate is None:
        # One of the sizes isn't in the table. Interpolating from a family
        # name would be a guess dressed as a calculation.
        return None

    delta_hourly = float(new_rate) - float(old_rate)
    delta_monthly = delta_hourly * hours
    if abs(delta_monthly) < MIN_REPORTABLE_USD:
        return None

    direction = "more" if delta_monthly > 0 else "less"
    multi_az = (
        " A Multi-AZ instance costs roughly double these rates." if path in RDS_SIZE_PATHS else ""
    )
    return CostEstimate(
        monthly_usd=abs(delta_monthly),
        basis=(
            f"{_as_text(after)} at ${new_rate:.4f}/hour versus {_as_text(before)} at "
            f"${old_rate:.4f}/hour, over {hours:.0f} hours: "
            f"${abs(delta_monthly):,.2f}/month {direction} than the code describes. "
            f"{label} list price in {prices.get('region', 'us-east-1')}, "
            f"checked {prices.get('checked', 'unknown')}. This is an upper bound — "
            f"Savings Plans, Reserved Instances and Spot all make it lower."
            f"{multi_az}"
        ),
    )


def _storage_size(
    resource: DriftedResource, path: str, before: Any, after: Any
) -> CostEstimate | None:
    """A volume or allocated storage that grew or shrank outside the code."""
    prices = _prices()

    if path in EBS_SIZE_PATHS:
        table = prices.get("ebs", {})
        volume_type = _volume_type(resource, default="gp3")
        label = f"EBS {volume_type}"
    elif path in RDS_STORAGE_PATHS:
        table = prices.get("rds_storage", {})
        volume_type = _volume_type(resource, default="gp3")
        label = f"RDS {volume_type} storage"
    else:
        return None

    rate = table.get(volume_type)
    if rate is None:
        return None

    old_gb, new_gb = _as_number(before), _as_number(after)
    if old_gb is None or new_gb is None:
        return None

    delta_gb = new_gb - old_gb
    delta_monthly = delta_gb * float(rate)
    if abs(delta_monthly) < MIN_REPORTABLE_USD:
        return None

    direction = "more" if delta_monthly > 0 else "less"
    return CostEstimate(
        monthly_usd=abs(delta_monthly),
        basis=(
            f"{new_gb:,.0f} GB versus {old_gb:,.0f} GB in the code, a difference of "
            f"{abs(delta_gb):,.0f} GB at ${rate:.3f}/GB-month: "
            f"${abs(delta_monthly):,.2f}/month {direction}. "
            f"{label} list price in {prices.get('region', 'us-east-1')}, "
            f"checked {prices.get('checked', 'unknown')}. "
            f"Storage usually cannot be shrunk, so reverting this may not be possible."
        ),
    )


def _volume_type(resource: DriftedResource, *, default: str) -> str:
    """The volume type from the prior state, if it says.

    Defaults to `gp3` — the cheapest of the common types, so an unknown type
    produces the smallest defensible figure rather than the largest.
    """
    state = resource.raw_before or {}
    for key in ("type", "volume_type", "storage_type"):
        value = state.get(key)
        if isinstance(value, str) and value:
            return value
    return default


def _as_text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    try:
        return float(_as_text(value))
    except ValueError:
        return None
