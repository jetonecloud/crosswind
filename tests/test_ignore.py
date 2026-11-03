"""Ignore rules, and the promise that nothing vanishes without a count."""

from __future__ import annotations

from pathlib import Path

from crosswind.core.findings import AttributeChange, DriftKind
from crosswind.core.ignore import (
    DEFAULT_SUGGESTIONS,
    IGNORE_FILENAME,
    filter_all,
    load,
    parse,
)
from crosswind.core.plan import DriftedResource


def drifted(address: str, paths: list[str]) -> DriftedResource:
    return DriftedResource(
        address=address,
        resource_type=address.split(".")[0],
        name="thing",
        kind=DriftKind.CHANGED,
        changes=tuple(AttributeChange(path=path, before="a", after="b") for path in paths),
    )


# --- parsing -----------------------------------------------------------


def test_parses_address_and_attribute() -> None:
    ignores = parse("aws_autoscaling_group.web   desired_capacity\n")
    assert len(ignores.patterns) == 1
    pattern = ignores.patterns[0]
    assert pattern.address == "aws_autoscaling_group.web"
    assert pattern.attribute == "desired_capacity"


def test_comments_and_blank_lines_are_skipped() -> None:
    text = """
    # a comment

    aws_instance.a              # trailing comment
    """
    ignores = parse(text)
    assert [pattern.address for pattern in ignores.patterns] == ["aws_instance.a"]
    assert ignores.patterns[0].attribute is None


def test_line_numbers_are_recorded_so_a_user_can_find_the_line() -> None:
    ignores = parse("# header\n\naws_instance.a size\n")
    assert ignores.patterns[0].line_number == 3


def test_an_empty_file_is_inactive() -> None:
    assert not parse("# nothing but comments\n").active


# --- applying ----------------------------------------------------------


def test_address_only_pattern_suppresses_the_whole_resource() -> None:
    ignores = parse("module.legacy.*\n")
    decision = ignores.apply(drifted("module.legacy.aws_instance.old", ["instance_type"]))
    assert decision.suppressed_entirely
    assert decision.matched[0].address == "module.legacy.*"


def test_attribute_pattern_leaves_other_drift_reported() -> None:
    """The important case: an ignored attribute must not hide its neighbours.

    If `desired_capacity` is ignored and the same ASG also had its `min_size`
    changed, the `min_size` finding still has to appear.
    """
    ignores = parse("aws_autoscaling_group.*  desired_capacity\n")
    decision = ignores.apply(drifted("aws_autoscaling_group.web", ["desired_capacity", "min_size"]))
    assert not decision.suppressed_entirely
    assert decision.resource is not None
    assert [change.path for change in decision.resource.changes] == ["min_size"]


def test_resource_disappears_when_every_attribute_is_ignored() -> None:
    """Nothing left to show, so nothing is shown — but it is still counted."""
    ignores = parse("aws_ecs_service.*  desired_count\n")
    decision = ignores.apply(drifted("aws_ecs_service.api", ["desired_count"]))
    assert decision.suppressed_entirely
    assert decision.matched


def test_non_matching_pattern_changes_nothing() -> None:
    ignores = parse("aws_s3_bucket.*  acl\n")
    resource = drifted("aws_instance.web", ["instance_type"])
    decision = ignores.apply(resource)
    assert decision.resource is resource
    assert decision.matched == ()


def test_globs_work_on_both_fields() -> None:
    ignores = parse("*  tags.*\n")
    decision = ignores.apply(drifted("aws_instance.web", ["tags.Owner", "instance_type"]))
    assert decision.resource is not None
    assert [change.path for change in decision.resource.changes] == ["instance_type"]


# --- counting ----------------------------------------------------------


def test_filter_all_returns_the_suppressed_count() -> None:
    """A reader must be able to tell "clean" from "quiet"."""
    ignores = parse("aws_ecs_service.*  desired_count\n")
    resources = [
        drifted("aws_ecs_service.a", ["desired_count"]),
        drifted("aws_ecs_service.b", ["desired_count"]),
        drifted("aws_instance.c", ["instance_type"]),
    ]
    kept, suppressed = filter_all(resources, ignores)
    assert [resource.address for resource in kept] == ["aws_instance.c"]
    assert suppressed == 2


def test_filter_all_with_no_patterns_keeps_everything() -> None:
    resources = [drifted("aws_instance.a", ["instance_type"])]
    kept, suppressed = filter_all(resources, parse(""))
    assert len(kept) == 1
    assert suppressed == 0


# --- loading from disk -------------------------------------------------


def test_load_reads_the_stack_directory(tmp_path: Path) -> None:
    (tmp_path / IGNORE_FILENAME).write_text("aws_instance.*  tags.*\n")
    ignores = load(tmp_path)
    assert ignores.active
    assert ignores.patterns[0].attribute == "tags.*"


def test_load_combines_a_root_file_with_a_stack_file(tmp_path: Path) -> None:
    """A monorepo keeps one file at the top; a stack can add its own."""
    root = tmp_path
    stack = tmp_path / "infra" / "prod"
    stack.mkdir(parents=True)
    (root / IGNORE_FILENAME).write_text("*  tags.*\n")
    (stack / IGNORE_FILENAME).write_text("aws_ecs_service.*  desired_count\n")

    ignores = load(stack, extra_roots=[root])
    attributes = {pattern.attribute for pattern in ignores.patterns}
    assert attributes == {"tags.*", "desired_count"}


def test_load_does_not_read_the_same_file_twice(tmp_path: Path) -> None:
    """Scanning the root itself must not double every pattern."""
    (tmp_path / IGNORE_FILENAME).write_text("*  tags.*\n")
    ignores = load(tmp_path, extra_roots=[tmp_path])
    assert len(ignores.patterns) == 1


def test_missing_file_is_not_an_error(tmp_path: Path) -> None:
    assert not load(tmp_path).active


def test_a_malformed_line_does_not_stop_the_scan() -> None:
    """Failing the scan over a typo means nobody sees any findings.

    A junk line is read as an address pattern that matches nothing, which
    errs towards showing a finding rather than hiding one.
    """
    ignores = parse("!!! not a pattern !!!\naws_instance.a  size\n")
    assert ignores.active
    decision = ignores.apply(drifted("aws_instance.a", ["size"]))
    assert decision.suppressed_entirely


# --- the shipped suggestions -------------------------------------------


def test_default_suggestions_parse() -> None:
    """They are printed for people to paste, so they had better be valid."""
    ignores = parse(DEFAULT_SUGGESTIONS)
    assert len(ignores.patterns) >= 5


def test_default_suggestions_cover_the_expected_drift_the_brief_names() -> None:
    attributes = {pattern.attribute for pattern in parse(DEFAULT_SUGGESTIONS).patterns}
    assert "desired_capacity" in attributes
    assert "desired_count" in attributes


def test_default_suggestions_are_not_applied_automatically(tmp_path: Path) -> None:
    """Crosswind writes nothing, and hides nothing a user did not ask it to.

    Silently applying a built-in ignore list is the same failure as reporting
    a broken stack as clean: a reader believing they have seen everything.
    """
    ignores = load(tmp_path)
    assert not ignores.active
    resource = drifted("aws_autoscaling_group.web", ["desired_capacity"])
    kept, suppressed = filter_all([resource], ignores)
    assert len(kept) == 1
    assert suppressed == 0
