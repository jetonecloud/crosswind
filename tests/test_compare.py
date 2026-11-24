"""Comparing two reports.

Most of these tests are about the one mistake a comparison must not make:
calling a finding resolved when the later run simply did not look at it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from crosswind.core.compare import (
    CompareError,
    Delta,
    compare,
    load_report,
    parse_report,
)
from crosswind.core.findings import Severity
from crosswind.core.scan import EXIT_CLEAN, EXIT_DRIFT, EXIT_ERROR
from crosswind.demo import demo_report


def finding(
    address: str = "aws_security_group.web",
    *,
    stack: str = "infra/prod",
    severity: str = "critical",
    changes: list[tuple[str, Any, Any]] | None = None,
    kind: str = "changed",
) -> dict[str, Any]:
    pairs = changes if changes is not None else [("ingress.0.cidr_blocks.0", "10/8", "0/0")]
    return {
        "id": f"{stack}::{address}",
        "stack": stack,
        "address": address,
        "severity": severity,
        "drift_kind": kind,
        "changes": [{"path": path, "before": old, "after": new} for path, old, new in pairs],
        "attribution": {"confidence": "unknown", "actor": None},
    }


def stack(path: str = "infra/prod", *, status: str = "drifted", ignored: int = 0) -> dict[str, Any]:
    return {"path": path, "status": status, "ignored": ignored, "error": None}


def report(
    findings: list[dict[str, Any]],
    stacks: list[dict[str, Any]] | None = None,
    *,
    generated_at: str = "2026-11-03T09:00:00+00:00",
    min_severity: str = "low",
    account: str | None = "111111111111",
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "tool": "crosswind",
        "generated_at": generated_at,
        "min_severity": min_severity,
        "account": account,
        "summary": {"stacks_failed": sum(1 for s in stacks or [] if s["status"] == "failed")},
        "stacks": stacks if stacks is not None else [stack()],
        "findings": findings,
    }


LATER = "2026-11-07T09:00:00+00:00"


def run(before: dict[str, Any], after: dict[str, Any], **kwargs: Any) -> Any:
    return compare(parse_report(before), parse_report(after), **kwargs)


def deltas(result: Any) -> dict[str, str]:
    return {entry.id: entry.delta.value for entry in result.entries}


# --- the basic sets -------------------------------------------------------


def test_identical_reports_are_all_persisting() -> None:
    data = report([finding()])
    result = run(data, report([finding()], generated_at=LATER))
    assert deltas(result) == {"infra/prod::aws_security_group.web": "persisting"}
    assert result.exit_code == EXIT_CLEAN


def test_new_finding_fails_the_comparison() -> None:
    result = run(report([]), report([finding()], generated_at=LATER))
    assert [entry.delta for entry in result.entries] == [Delta.NEW]
    assert result.exit_code == EXIT_DRIFT


def test_finding_gone_from_a_checked_stack_is_resolved() -> None:
    result = run(report([finding()]), report([], [stack(status="clean")], generated_at=LATER))
    assert [entry.delta for entry in result.entries] == [Delta.RESOLVED]
    assert result.exit_code == EXIT_CLEAN


# --- what must never be called resolved -----------------------------------


def test_finding_in_a_failed_stack_is_unverified_not_resolved() -> None:
    after = report([], [stack(status="failed")], generated_at=LATER)
    result = run(report([finding()]), after)
    (entry,) = result.entries
    assert entry.delta is Delta.UNVERIFIED
    assert entry.reason == "stack_failed"
    assert result.resolved == ()
    assert result.failed_stacks == ("infra/prod",)
    # A hole in the later report beats everything else.
    assert result.exit_code == EXIT_ERROR


def test_finding_in_an_unscanned_stack_is_unverified() -> None:
    after = report([], [stack("infra/staging", status="clean")], generated_at=LATER)
    result = run(report([finding()]), after)
    (entry,) = [e for e in result.entries]
    assert (entry.delta, entry.reason) == (Delta.UNVERIFIED, "stack_not_scanned")
    assert result.missing_stacks == ("infra/prod",)
    assert result.added_stacks == ("infra/staging",)


def test_finding_below_the_later_threshold_is_unverified() -> None:
    before = report([finding(severity="low")])
    after = report([], [stack(status="clean")], generated_at=LATER, min_severity="high")
    (entry,) = run(before, after).entries
    assert (entry.delta, entry.reason) == (Delta.UNVERIFIED, "below_threshold")


def test_finding_possibly_suppressed_by_a_new_ignore_rule_is_unverified() -> None:
    before = report([finding()], [stack(ignored=1)])
    after = report([], [stack(status="clean", ignored=2)], generated_at=LATER)
    (entry,) = run(before, after).entries
    assert (entry.delta, entry.reason) == (Delta.UNVERIFIED, "may_be_ignored")


def test_same_ignore_count_does_not_block_resolution() -> None:
    before = report([finding()], [stack(ignored=3)])
    after = report([], [stack(status="clean", ignored=3)], generated_at=LATER)
    (entry,) = run(before, after).entries
    assert entry.delta is Delta.RESOLVED


# --- changes to a finding present in both ---------------------------------


def test_severity_increase_is_worsened_and_fails() -> None:
    before = report([finding(severity="medium")])
    after = report([finding(severity="critical")], generated_at=LATER)
    result = run(before, after)
    (entry,) = result.entries
    assert entry.delta is Delta.CHANGED
    assert entry.worsened
    assert entry.differences == ("severity medium -> critical",)
    assert result.exit_code == EXIT_DRIFT


def test_severity_decrease_is_changed_but_passes() -> None:
    before = report([finding(severity="critical")])
    after = report([finding(severity="low")], generated_at=LATER)
    result = run(before, after)
    (entry,) = result.entries
    assert entry.delta is Delta.CHANGED
    assert not entry.worsened
    assert result.exit_code == EXIT_CLEAN


def test_attribute_differences_are_described() -> None:
    before = report([finding(changes=[("a", 1, 2), ("b", 1, 2)])])
    after = report([finding(changes=[("a", 1, 3), ("c", 1, 2)])], generated_at=LATER)
    (entry,) = run(before, after).entries
    assert entry.differences == (
        "now also differs: c",
        "no longer differs: b",
        "different value now: a",
    )


def test_attribution_changes_alone_are_not_a_change() -> None:
    old = finding()
    new = finding()
    new["attribution"] = {"confidence": "high", "actor": "dmitri"}
    result = run(report([old]), report([new], generated_at=LATER))
    assert [entry.delta for entry in result.entries] == [Delta.PERSISTING]


# --- exit code threshold --------------------------------------------------


def test_fail_threshold_ignores_minor_new_findings() -> None:
    result = run(
        report([]),
        report([finding(severity="low")], generated_at=LATER),
        fail_threshold=Severity.HIGH,
    )
    assert len(result.new) == 1
    assert result.regressions == ()
    assert result.exit_code == EXIT_CLEAN


# --- stacks ---------------------------------------------------------------


def test_recovered_stacks_are_listed() -> None:
    before = report([], [stack(status="failed")])
    after = report([], [stack(status="clean")], generated_at=LATER)
    assert run(before, after).recovered_stacks == ("infra/prod",)


# --- notes ----------------------------------------------------------------


def test_swapped_arguments_are_noticed() -> None:
    result = run(report([], generated_at=LATER), report([]))
    assert any("wrong way round" in note for note in result.notes)


def test_different_accounts_are_noticed() -> None:
    result = run(report([]), report([], account="222222222222", generated_at=LATER))
    assert any("different AWS accounts" in note for note in result.notes)


def test_lower_later_threshold_is_noticed() -> None:
    result = run(report([], min_severity="high"), report([], generated_at=LATER))
    assert any("lower --min-severity" in note for note in result.notes)


# --- ordering and serialisation -------------------------------------------


def test_entries_are_ordered_by_what_needs_attention() -> None:
    before = report(
        [
            finding("aws_s3_bucket.old", severity="high"),
            finding("aws_instance.same", severity="medium"),
        ]
    )
    after = report(
        [
            finding("aws_instance.same", severity="medium"),
            finding("aws_iam_role.low", severity="low"),
            finding("aws_iam_policy.crit", severity="critical"),
        ],
        [stack(status="drifted")],
        generated_at=LATER,
    )
    order = [(entry.delta.value, entry.address) for entry in run(before, after).entries]
    assert order == [
        ("new", "aws_iam_policy.crit"),
        ("new", "aws_iam_role.low"),
        ("persisting", "aws_instance.same"),
        ("resolved", "aws_s3_bucket.old"),
    ]


def test_to_dict_round_trips_through_json() -> None:
    result = run(report([finding()]), report([], [stack(status="failed")], generated_at=LATER))
    data = json.loads(json.dumps(result.to_dict()))
    assert data["kind"] == "comparison"
    assert data["summary"]["unverified"] == 1
    assert data["summary"]["resolved"] == 0
    assert data["summary"]["exit_code"] == EXIT_ERROR
    assert data["stacks"]["failed"] == ["infra/prod"]
    assert data["entries"][0]["reason"] == "stack_failed"


def test_compares_a_real_report_against_itself() -> None:
    data = json.loads(json.dumps(demo_report().to_dict(), default=str))
    result = run(data, data)
    assert result.entries
    assert {entry.delta for entry in result.entries} == {Delta.PERSISTING}


# --- loading --------------------------------------------------------------


def test_load_report_reads_a_file(tmp_path: Path) -> None:
    path = tmp_path / "r.json"
    path.write_text(json.dumps(report([finding()])), encoding="utf-8")
    assert list(load_report(path).findings) == ["infra/prod::aws_security_group.web"]


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not json", "is not JSON"),
        (json.dumps({"tool": "terraform"}), "is not a Crosswind report"),
        (json.dumps({**report([]), "schema_version": "2.0"}), "schema_version '2.0'"),
        (json.dumps({**report([]), "findings": None}), "missing its findings"),
        (json.dumps({**report([]), "findings": [{"stack": "x"}]}), "without an id"),
    ],
)
def test_load_report_rejects_what_it_cannot_read(
    tmp_path: Path, content: str, message: str
) -> None:
    path = tmp_path / "r.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(CompareError, match=message):
        load_report(path)


def test_load_report_missing_file(tmp_path: Path) -> None:
    with pytest.raises(CompareError, match="could not read"):
        load_report(tmp_path / "nope.json")
