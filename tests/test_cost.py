"""Cost estimates, and the much more common case of declining to make one."""

from __future__ import annotations

from typing import Any

from crosswind.core.cost import MIN_REPORTABLE_USD, estimate
from crosswind.core.findings import AttributeChange, DriftKind
from crosswind.core.plan import DriftedResource


def drifted(
    resource_type: str,
    path: str,
    before: Any,
    after: Any,
    raw_before: dict[str, Any] | None = None,
) -> DriftedResource:
    return DriftedResource(
        address=f"{resource_type}.thing",
        resource_type=resource_type,
        name="thing",
        kind=DriftKind.CHANGED,
        changes=(AttributeChange(path=path, before=before, after=after),),
        raw_before=raw_before,
    )


# --- estimates we will make --------------------------------------------


def test_instance_upsize_is_priced() -> None:
    result = estimate(drifted("aws_instance", "instance_type", "t3.micro", "t3.large"))
    assert result is not None
    # (0.0832 - 0.0104) * 730 = 53.144
    assert round(result.monthly_usd, 2) == 53.14


def test_the_basis_contains_checkable_arithmetic() -> None:
    """A reader must be able to redo the sum with the pricing page open."""
    result = estimate(drifted("aws_instance", "instance_type", "t3.micro", "t3.large"))
    assert result is not None
    for fragment in ("t3.large", "t3.micro", "/hour", "730", "us-east-1"):
        assert fragment in result.basis


def test_the_basis_says_it_is_an_upper_bound() -> None:
    """List price ignores Savings Plans and RIs, which only reduce the figure.

    Saying so is the difference between a number someone can defend and a
    number someone will be contradicted on.
    """
    result = estimate(drifted("aws_instance", "instance_type", "t3.micro", "t3.2xlarge"))
    assert result is not None
    assert "upper bound" in result.basis
    assert "Savings Plans" in result.basis


def test_a_downsize_is_reported_as_a_positive_figure_with_direction_in_words() -> None:
    result = estimate(drifted("aws_instance", "instance_type", "m5.4xlarge", "m5.large"))
    assert result is not None
    assert result.monthly_usd > 0
    assert "less than the code describes" in result.basis


def test_rds_instance_class_is_priced_and_flags_multi_az() -> None:
    result = estimate(drifted("aws_db_instance", "instance_class", "db.t3.micro", "db.m5.large"))
    assert result is not None
    assert "Multi-AZ" in result.basis


def test_ebs_volume_growth_is_priced() -> None:
    result = estimate(drifted("aws_ebs_volume", "size", 100, 500, raw_before={"type": "gp3"}))
    assert result is not None
    # 400 GB * 0.08 = 32.00
    assert round(result.monthly_usd, 2) == 32.00
    assert "gp3" in result.basis


def test_storage_basis_warns_that_a_revert_may_be_impossible() -> None:
    """Shrinking storage usually is not possible, so the recommendation
    "revert" would be bad advice without this."""
    result = estimate(drifted("aws_ebs_volume", "size", 100, 500, raw_before={"type": "gp3"}))
    assert result is not None
    assert "cannot be shrunk" in result.basis


def test_unknown_volume_type_uses_the_cheapest_defensible_rate() -> None:
    """An unknown type should produce the smallest figure we can defend,
    not the largest."""
    cheap = estimate(drifted("aws_ebs_volume", "size", 0, 1000, raw_before={}))
    io = estimate(drifted("aws_ebs_volume", "size", 0, 1000, raw_before={"type": "io1"}))
    assert cheap is not None and io is not None
    assert cheap.monthly_usd < io.monthly_usd


# --- estimates we will not make ----------------------------------------


def test_an_unlisted_instance_type_produces_no_estimate() -> None:
    """Interpolating from a family name would be a guess dressed as a sum."""
    assert estimate(drifted("aws_instance", "instance_type", "t3.micro", "x9.enormous")) is None


def test_an_unpriceable_attribute_produces_no_estimate() -> None:
    """Most drift has no unambiguous price, and that is the normal case."""
    assert estimate(drifted("aws_security_group", "ingress.0.cidr_blocks.0", "a", "b")) is None
    assert estimate(drifted("aws_instance", "tags.Owner", "alice", "bob")) is None


def test_lambda_memory_is_deliberately_not_priced() -> None:
    """Cost is memory times invocations, and we do not know the invocations."""
    assert estimate(drifted("aws_lambda_function", "memory_size", 128, 1024)) is None


def test_nat_gateway_is_deliberately_not_priced() -> None:
    """Mostly data processing, which we cannot see."""
    assert estimate(drifted("aws_nat_gateway", "subnet_id", "subnet-a", "subnet-b")) is None


def test_a_change_with_no_size_delta_produces_no_estimate() -> None:
    assert estimate(drifted("aws_instance", "instance_type", "t3.large", "t3.large")) is None


def test_trivial_differences_are_not_reported() -> None:
    """A report claiming someone can save 40 cents a month invites the reader
    to stop trusting the other figures."""
    result = estimate(drifted("aws_instance", "instance_type", "t3.nano", "t3.micro"))
    # (0.0104 - 0.0052) * 730 = 3.80, which is above the floor.
    assert result is not None and result.monthly_usd >= MIN_REPORTABLE_USD

    tiny = estimate(drifted("aws_ebs_volume", "size", 100, 101, raw_before={"type": "gp3"}))
    assert tiny is None


def test_a_redacted_value_produces_no_estimate() -> None:
    """Scrubbed values must never be parsed into arithmetic."""
    assert (
        estimate(drifted("aws_instance", "instance_type", "(sensitive value)", "t3.large")) is None
    )


def test_non_numeric_storage_produces_no_estimate() -> None:
    assert estimate(drifted("aws_ebs_volume", "size", "(3 items)", "lots")) is None


def test_a_deleted_resource_produces_no_estimate() -> None:
    """The synthetic `(resource)` change has no price attached."""
    resource = DriftedResource(
        address="aws_instance.gone",
        resource_type="aws_instance",
        name="gone",
        kind=DriftKind.DELETED,
        changes=(AttributeChange(path="(resource)", before="present", after="absent"),),
    )
    assert estimate(resource) is None
