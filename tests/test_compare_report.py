"""Rendering a comparison.

As with the scan report, the tests that matter are parametrised across every
format: a stack the later run could not check, and a finding we refuse to
call resolved, must be visible in all of them.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from crosswind.core.compare import Comparison, compare, parse_report
from crosswind.core.findings import Severity
from crosswind.core.report import compare as compare_report
from crosswind.core.report.compare import (
    COMPARE_FORMATS,
    COMPARE_RENDERERS,
    render_compare_json,
    render_compare_markdown,
    render_compare_terminal,
)


def finding(address: str, *, stack: str = "infra/prod", severity: str = "high") -> dict[str, Any]:
    return {
        "id": f"{stack}::{address}",
        "stack": stack,
        "address": address,
        "severity": severity,
        "drift_kind": "changed",
        "changes": [{"path": "description", "before": "a|b", "after": "<c>"}],
    }


def report(
    findings: list[dict[str, Any]], stacks: list[dict[str, Any]], when: str
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "tool": "crosswind",
        "generated_at": when,
        "min_severity": "low",
        "account": "111111111111",
        "summary": {},
        "stacks": stacks,
        "findings": findings,
    }


def sample() -> Comparison:
    before = report(
        [
            finding("aws_s3_bucket.fixed"),
            finding("aws_iam_role.hidden", stack="infra/broken"),
            finding("aws_instance.grew", severity="medium"),
        ],
        [
            {"path": "infra/prod", "status": "drifted", "ignored": 0},
            {"path": "infra/broken", "status": "drifted", "ignored": 0},
        ],
        "2026-11-03T09:00:00+00:00",
    )
    after = report(
        [
            finding("aws_instance.grew", severity="critical"),
            finding("aws_security_group.opened", severity="critical"),
        ],
        [
            {"path": "infra/prod", "status": "drifted", "ignored": 0},
            {"path": "infra/broken", "status": "failed", "ignored": 0},
        ],
        "2026-11-07T09:00:00+00:00",
    )
    return compare(
        parse_report(before, source="monday.json"), parse_report(after, source="friday.json")
    )


@pytest.mark.parametrize("fmt", COMPARE_FORMATS)
def test_every_format_shows_the_failed_stack(fmt: str) -> None:
    assert "infra/broken" in COMPARE_RENDERERS[fmt](sample())


@pytest.mark.parametrize("fmt", COMPARE_FORMATS)
def test_every_format_shows_what_is_new_and_unverified(fmt: str) -> None:
    text = COMPARE_RENDERERS[fmt](sample())
    assert "aws_security_group.opened" in text
    assert "aws_iam_role.hidden" in text
    assert "aws_s3_bucket.fixed" in text


@pytest.mark.parametrize(
    ("fmt", "phrase"),
    [
        ("terminal", "its stack could not be checked in the later run"),
        ("markdown", "its stack could not be checked in the later run"),
        ("json", '"reason": "stack_failed"'),
    ],
)
def test_every_format_says_why_a_finding_is_unverified(fmt: str, phrase: str) -> None:
    assert phrase in COMPARE_RENDERERS[fmt](sample())


def test_terminal_puts_failed_stacks_and_new_drift_first() -> None:
    text = render_compare_terminal(sample())
    assert text.index("COULD NOT CHECK") < text.index("NEW (1)")
    assert text.index("NEW (1)") < text.index("CHANGED (1)")
    assert text.index("CHANGED (1)") < text.index("NOT VERIFIED (1)")
    assert text.index("NOT VERIFIED (1)") < text.index("RESOLVED (1)")
    assert "[MEDIUM -> CRITICAL] aws_instance.grew" in text
    assert "Exit 2" in text


def test_terminal_is_plain_ascii() -> None:
    render_compare_terminal(sample()).encode("ascii")


def test_terminal_caps_long_sections(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compare_report, "TERMINAL_LIMIT", 1)
    many = [finding(f"aws_s3_bucket.b{i}") for i in range(4)]
    stacks = [{"path": "infra/prod", "status": "drifted", "ignored": 0}]
    result = compare(
        parse_report(report([], stacks, "2026-11-03T09:00:00+00:00")),
        parse_report(report(many, stacks, "2026-11-04T09:00:00+00:00")),
    )
    assert "... and 3 more" in render_compare_terminal(result)


def test_markdown_escapes_table_breaking_characters() -> None:
    before = report([], [], "2026-11-03T09:00:00+00:00")
    after = report(
        [finding("aws_s3_bucket.a|b<script>")],
        [{"path": "infra/prod", "status": "drifted", "ignored": 0}],
        "2026-11-04T09:00:00+00:00",
    )
    text = render_compare_markdown(compare(parse_report(before), parse_report(after)))
    assert "<script>" not in text
    assert "a\\|b" in text


def test_markdown_collapses_the_good_news() -> None:
    text = render_compare_markdown(sample())
    assert "<details><summary>Resolved (1)</summary>" in text
    assert "### New (1)" in text
    assert "**medium → critical**" in text


def test_markdown_stays_under_the_job_summary_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compare_report, "MAX_CHARS", 2_000)
    many = [finding(f"aws_s3_bucket.bucket_number_{i}") for i in range(200)]
    stacks = [{"path": "infra/prod", "status": "drifted", "ignored": 0}]
    result = compare(
        parse_report(report([], stacks, "2026-11-03T09:00:00+00:00")),
        parse_report(report(many, stacks, "2026-11-04T09:00:00+00:00")),
    )
    text = render_compare_markdown(result)
    assert len(text) < 2_200
    assert "Truncated" in text


def test_json_is_sorted_and_versioned() -> None:
    text = render_compare_json(sample())
    data = json.loads(text)
    assert data["schema_version"] == "1.0"
    assert data["kind"] == "comparison"
    assert data["summary"]["worsened"] == 1
    assert text.endswith("\n")
    assert text == json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def test_no_change_reads_as_such() -> None:
    stacks = [{"path": "infra/prod", "status": "clean", "ignored": 0}]
    same = report([], stacks, "2026-11-03T09:00:00+00:00")
    result = compare(parse_report(same), parse_report(same), fail_threshold=Severity.HIGH)
    text = render_compare_terminal(result)
    assert "no change in drift" in text
    assert "Exit 0: nothing new or worse at or above high." in text
