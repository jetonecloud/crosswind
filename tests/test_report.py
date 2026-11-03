"""The four output formats, and what every one of them must do.

The important tests here are the ones parametrised across all four formats:
a fact that matters must not be true in one renderer and missing from
another. Chief among them is that a failed stack is visible everywhere.
"""

from __future__ import annotations

import html as html_module
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from crosswind.core.findings import (
    AttributeChange,
    Attribution,
    Confidence,
    CostEstimate,
    DriftKind,
    Event,
    Finding,
    Recommendation,
    Severity,
    StackResult,
    StackStatus,
)
from crosswind.core.report import EXTENSIONS, FORMATS, RENDERERS, render
from crosswind.core.scan import Report

NOW = datetime(2026, 11, 3, 14, 30, tzinfo=UTC)


def finding(
    *,
    address: str = "aws_security_group.web",
    severity: Severity = Severity.CRITICAL,
    stack: str = "infra/prod",
    changes: tuple[AttributeChange, ...] = (),
    attribution: Attribution | None = None,
    cost: CostEstimate | None = None,
) -> Finding:
    return Finding(
        stack=stack,
        address=address,
        resource_type="aws_security_group",
        kind=DriftKind.CHANGED,
        changes=changes
        or (
            AttributeChange(path="ingress.0.cidr_blocks.0", before="10.0.0.0/8", after="0.0.0.0/0"),
        ),
        severity=severity,
        severity_rule="sg-ingress-public",
        severity_reason="An inbound rule now accepts traffic from the whole internet.",
        recommendation=Recommendation.REVERT,
        recommendation_reason="Revert unless this was deliberate and reviewed.",
        attribution=attribution or Attribution.unknown("no_matching_events"),
        provider="hashicorp/aws",
        region="eu-west-1",
        cost=cost,
    )


def attributed(actor: str = "alice") -> Attribution:
    return Attribution(
        confidence=Confidence.HIGH,
        actor=actor,
        score=0.92,
        event=Event(
            event_id="e-abc123",
            event_name="AuthorizeSecurityGroupIngress",
            event_time=NOW - timedelta(hours=3),
            username=actor,
            event_source="ec2.amazonaws.com",
            region="eu-west-1",
            principal_type="IAMUser",
        ),
    )


def report(
    *,
    stacks: tuple[StackResult, ...] | None = None,
    min_severity: Severity = Severity.LOW,
    **kwargs: Any,
) -> Report:
    if stacks is None:
        stacks = (
            StackResult(path="infra/prod", status=StackStatus.DRIFTED, findings=(finding(),)),
        )
    return Report(
        stacks=stacks,
        started_at=NOW - timedelta(seconds=12),
        finished_at=NOW,
        min_severity=min_severity,
        binary="terraform v1.15.8",
        account="123456789012",
        **kwargs,
    )


def rendered(fmt: str, report_obj: Report) -> str:
    return render(report_obj, fmt)


# --- the registry -------------------------------------------------------


def test_all_four_formats_are_registered() -> None:
    assert set(FORMATS) == {"terminal", "json", "markdown", "html"}
    assert set(RENDERERS) == set(FORMATS)


def test_terminal_has_no_file_extension() -> None:
    """It goes to stdout and is never written to a file."""
    assert "terminal" not in EXTENSIONS
    assert set(EXTENSIONS) == {"json", "markdown", "html"}


def test_unknown_format_is_a_clear_error() -> None:
    with pytest.raises(ValueError, match="Unknown format"):
        render(report(), "pdf")


# --- things every format must do ---------------------------------------


@pytest.mark.parametrize("fmt", FORMATS)
def test_every_format_renders_a_non_empty_string(fmt: str) -> None:
    output = rendered(fmt, report())
    assert isinstance(output, str)
    assert output.strip()


@pytest.mark.parametrize("fmt", FORMATS)
def test_every_format_shows_a_failed_stack(fmt: str) -> None:
    """The invariant, enforced at the presentation layer too.

    A stack we could not check has to be visible in whichever format the
    reader happens to open, not just the one we tested by hand.
    """
    failed = report(
        stacks=(
            StackResult(
                path="infra/broken",
                status=StackStatus.FAILED,
                error="Error: no valid credential sources found",
            ),
        )
    )
    output = rendered(fmt, failed)
    assert "infra/broken" in output
    if fmt == "json":
        assert json.loads(output)["summary"]["stacks_failed"] == 1
    else:
        assert re.search(r"could not (be )?check", output, re.IGNORECASE)


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_failed_stack_is_never_described_as_clean(fmt: str) -> None:
    failed = report(
        stacks=(StackResult(path="infra/broken", status=StackStatus.FAILED, error="boom"),)
    )
    output = rendered(fmt, failed).lower()
    assert "all clean" not in output
    assert "no drift found" not in output


@pytest.mark.parametrize("fmt", FORMATS)
def test_every_format_names_the_severity_rule(fmt: str) -> None:
    """A severity nobody can trace to a rule is one nobody will act on."""
    assert "sg-ingress-public" in rendered(fmt, report())


@pytest.mark.parametrize("fmt", FORMATS)
def test_every_format_shows_the_before_and_after(fmt: str) -> None:
    output = rendered(fmt, report())
    assert "10.0.0.0/8" in output
    assert "0.0.0.0/0" in output


@pytest.mark.parametrize("fmt", FORMATS)
def test_every_format_carries_attribution_with_its_event(fmt: str) -> None:
    """A name is never shown without the evidence beside it."""
    output = rendered(fmt, report(stacks=_with(finding(attribution=attributed()))))
    assert "alice" in output
    assert "AuthorizeSecurityGroupIngress" in output
    assert "e-abc123" in output


@pytest.mark.parametrize("fmt", FORMATS)
def test_every_format_says_unknown_rather_than_leaving_it_blank(fmt: str) -> None:
    output = rendered(fmt, report()).lower()
    assert "unknown" in output


@pytest.mark.parametrize("fmt", FORMATS)
def test_every_format_states_the_read_only_promise(fmt: str) -> None:
    output = rendered(fmt, report()).lower()
    if fmt == "json":
        # The JSON is a data contract; the promise belongs in the docs and
        # the human formats, not as a prose field a consumer would parse.
        return
    assert "read-only" in output


@pytest.mark.parametrize("fmt", FORMATS)
def test_every_format_includes_the_recommendation(fmt: str) -> None:
    output = rendered(fmt, report())
    assert "revert" in output.lower()


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_clean_report_renders_without_findings(fmt: str) -> None:
    clean = report(stacks=(StackResult(path="infra/prod", status=StackStatus.CLEAN),))
    output = rendered(fmt, clean)
    assert output.strip()
    if fmt == "json":
        assert json.loads(output)["summary"]["findings_reported"] == 0
    else:
        assert "no drift" in output.lower()


@pytest.mark.parametrize("fmt", FORMATS)
def test_an_empty_report_does_not_crash(fmt: str) -> None:
    assert rendered(fmt, report(stacks=())).strip()


@pytest.mark.parametrize("fmt", FORMATS)
def test_cost_estimates_carry_their_basis(fmt: str) -> None:
    """The number is only usable if the arithmetic travels with it."""
    priced = finding(
        cost=CostEstimate(monthly_usd=53.14, basis="t3.large at $0.0832/hour versus t3.micro.")
    )
    output = rendered(fmt, report(stacks=_with(priced)))
    assert "53.14" in output
    assert "0.0832" in output


def _with(item: Finding) -> tuple[StackResult, ...]:
    return (StackResult(path=item.stack, status=StackStatus.DRIFTED, findings=(item,)),)


# --- JSON ---------------------------------------------------------------


def test_json_is_valid_and_versioned() -> None:
    payload = json.loads(rendered("json", report()))
    assert payload["schema_version"]
    assert payload["tool"] == "crosswind"
    assert payload["summary"]["findings_reported"] == 1


def test_json_keys_are_sorted_so_reports_diff_cleanly() -> None:
    text = rendered("json", report())
    top_level = list(json.loads(text).keys())
    assert top_level == sorted(top_level)


def test_json_ends_with_a_newline() -> None:
    assert rendered("json", report()).endswith("\n")


def test_json_uses_null_rather_than_omitting_unknowns() -> None:
    """A missing key and a null key should not be different questions."""
    payload = json.loads(rendered("json", report()))
    attribution = payload["findings"][0]["attribution"]
    assert "actor" in attribution
    assert attribution["actor"] is None
    assert attribution["confidence"] == "unknown"
    assert payload["findings"][0]["cost"] is None


def test_json_includes_every_documented_finding_field() -> None:
    payload = json.loads(rendered("json", report()))
    expected = {
        "id",
        "stack",
        "address",
        "resource_type",
        "provider",
        "region",
        "drift_kind",
        "severity",
        "severity_rule",
        "severity_reason",
        "recommendation",
        "recommendation_reason",
        "changes",
        "attribution",
        "cost",
    }
    assert set(payload["findings"][0]) == expected


def test_json_exit_code_matches_the_report() -> None:
    payload = json.loads(rendered("json", report()))
    assert payload["summary"]["exit_code"] == 1


def test_json_handles_non_ascii_resource_names() -> None:
    """Tags and names are user-chosen; escaping them makes the export unreadable."""
    item = finding(address="aws_s3_bucket.données")
    text = rendered("json", report(stacks=_with(item)))
    assert "données" in text
    assert json.loads(text)["findings"][0]["address"] == "aws_s3_bucket.données"


# --- terminal -----------------------------------------------------------


def test_terminal_puts_failures_above_the_findings() -> None:
    """Ordering is the whole point: "no critical drift" below "we could not
    check prod" reads very differently from the other way round."""
    mixed = report(
        stacks=(
            StackResult(path="infra/broken", status=StackStatus.FAILED, error="boom"),
            StackResult(path="infra/prod", status=StackStatus.DRIFTED, findings=(finding(),)),
        )
    )
    output = rendered("terminal", mixed)
    assert output.index("COULD NOT CHECK") < output.index("sg-ingress-public")


def test_terminal_is_plain_ascii() -> None:
    """It gets piped into CI logs and read over SSH."""
    output = rendered("terminal", report(stacks=_with(finding(attribution=attributed()))))
    assert output.isascii(), [char for char in output if not char.isascii()][:5]


def test_terminal_has_no_ansi_escapes() -> None:
    assert "\x1b[" not in rendered("terminal", report())


def test_terminal_caps_the_detail_and_says_so() -> None:
    """A terminal report that scrolls is one nobody reads."""
    many = tuple(finding(address=f"aws_security_group.sg{index}") for index in range(30))
    output = rendered(
        "terminal",
        report(stacks=(StackResult(path="infra/prod", status=StackStatus.DRIFTED, findings=many),)),
    )
    assert "and 20 more" in output


def test_terminal_counts_unattributed_findings() -> None:
    output = rendered("terminal", report())
    assert "never guesses" in output


def test_terminal_reports_suppressed_findings() -> None:
    """A reader must be able to tell "clean" from "quiet"."""
    quiet = report(stacks=(StackResult(path="infra/prod", status=StackStatus.CLEAN, ignored=4),))
    assert "4 findings suppressed" in rendered("terminal", quiet)


# --- markdown -----------------------------------------------------------


def test_markdown_escapes_pipes_so_tables_survive() -> None:
    """Attribute values genuinely contain pipes - a policy, a description."""
    item = finding(changes=(AttributeChange(path="description", before="a|b", after="c|d"),))
    output = rendered("markdown", report(stacks=_with(item)))
    table_lines = [line for line in output.splitlines() if line.startswith("| `description")]
    assert table_lines
    assert "\\|" in table_lines[0]


def test_markdown_escapes_angle_brackets() -> None:
    """A comment body renders HTML, so a tag value must not become markup."""
    item = finding(
        changes=(AttributeChange(path="tags.Name", before="ok", after="<script>x</script>"),)
    )
    output = rendered("markdown", report(stacks=_with(item)))
    assert "<script>" not in output
    assert "&lt;script&gt;" in output


def test_markdown_collapses_the_long_tail() -> None:
    many = tuple(finding(address=f"aws_security_group.sg{index}") for index in range(40))
    output = rendered(
        "markdown",
        report(stacks=(StackResult(path="infra/prod", status=StackStatus.DRIFTED, findings=many),)),
    )
    assert "<details>" in output
    assert "20 more findings" in output


def test_markdown_heading_leads_with_the_failure_count() -> None:
    mixed = report(
        stacks=(
            StackResult(path="infra/broken", status=StackStatus.FAILED, error="boom"),
            StackResult(path="infra/prod", status=StackStatus.DRIFTED, findings=(finding(),)),
        )
    )
    heading = rendered("markdown", mixed).splitlines()[0]
    assert "could not be checked" in heading


def test_markdown_stays_under_the_job_summary_limit() -> None:
    """GitHub truncates a job summary past 1 MiB without saying so."""
    many = tuple(
        finding(
            address=f"aws_security_group.sg{index}",
            changes=tuple(
                AttributeChange(path=f"attr{i}", before="x" * 60, after="y" * 60) for i in range(10)
            ),
        )
        for index in range(4000)
    )
    output = rendered(
        "markdown",
        report(stacks=(StackResult(path="infra/prod", status=StackStatus.DRIFTED, findings=many),)),
    )
    assert len(output) < 1_048_576


def test_markdown_has_no_ansi_or_box_drawing() -> None:
    output = rendered("markdown", report())
    assert "\x1b[" not in output
    assert "─" not in output


# --- HTML ---------------------------------------------------------------


def test_html_is_a_complete_document() -> None:
    output = rendered("html", report())
    assert output.startswith("<!DOCTYPE html>")
    assert "</html>" in output
    assert "<title>" in output


def test_html_has_no_external_references() -> None:
    """Self-contained: a report that phones home leaks who read it and when."""
    output = rendered("html", report(stacks=_with(finding(attribution=attributed()))))
    for pattern in (
        r'src\s*=\s*["\']https?:',
        r"<link\b",
        r"@import",
        r'url\(\s*["\']?https?:',
        r"<script\b",
        r"fetch\(",
        r"XMLHttpRequest",
    ):
        assert not re.search(pattern, output, re.IGNORECASE), pattern


def test_html_contains_no_javascript_at_all() -> None:
    """Collapsing comes from <details>; the rest is not worth the surface."""
    output = rendered("html", report())
    assert "<script" not in output.lower()
    assert "javascript:" not in output.lower()
    assert not re.search(r"\son[a-z]+\s*=", output, re.IGNORECASE)


def test_html_escapes_hostile_values() -> None:
    """A resource can be tagged `<script>`. A person can do that.

    The property that matters is that no value can start a tag or close an
    attribute — not that a dangerous-looking substring is absent. `onerror=`
    as escaped *text content* is inert, and asserting on the substring would
    be testing the wrong thing.
    """
    hostile_tag = '"><img src=x onerror=alert(1)>'
    item = finding(
        address='aws_s3_bucket."<script>alert(1)</script>"',
        changes=(AttributeChange(path="tags.Name", before="fine", after=hostile_tag),),
    )
    output = rendered("html", report(stacks=_with(item)))

    # Nothing from the value survives as markup.
    assert "<script>alert(1)</script>" not in output
    assert "<img" not in output
    # It is present, escaped, so the reader still sees what changed.
    assert "&lt;script&gt;" in output
    assert html_module.escape(hostile_tag, quote=True) in output


def test_html_escapes_a_hostile_stack_error() -> None:
    """Terraform error text is the one string in a report we did not build."""
    failed = report(
        stacks=(
            StackResult(
                path="infra/x",
                status=StackStatus.FAILED,
                error="<script>alert('xss')</script>",
            ),
        )
    )
    output = rendered("html", failed)
    assert "<script>alert" not in output
    assert html_module.escape("<script>alert('xss')</script>", quote=True) in output


def test_html_includes_print_styles() -> None:
    """People print these for meetings."""
    assert "@media print" in rendered("html", report())


def test_html_states_the_limitations_a_manager_needs() -> None:
    """The reader here will not go and find docs/."""
    output = rendered("html", report())
    assert "Terraform already manages" in output
    assert "90 days" in output
    assert "no evidence" in output


def test_html_links_to_jet1() -> None:
    assert "jetonecloud.com" in rendered("html", report())


def test_html_severity_colours_are_distinct() -> None:
    from crosswind.core.report.html import SEVERITY_COLOURS

    assert len(set(SEVERITY_COLOURS.values())) == len(Severity)
