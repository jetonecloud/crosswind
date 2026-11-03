"""The demo fixture, and that it demonstrates the honest cases too.

A demo that only shows the happy path teaches people to expect one. So
these tests assert the fixture contains an unattributed finding, a stack
that could not be checked, and a provider-marked secret that is not printed.
"""

from __future__ import annotations

import json
import re

import pytest

from crosswind.core.findings import Confidence, Severity, StackStatus
from crosswind.core.report import FORMATS, render
from crosswind.demo import DEMO_ACCOUNT, demo_report


@pytest.fixture(scope="module")
def report():
    return demo_report()


def test_the_demo_builds_a_report_with_no_io(report) -> None:
    assert report.stacks
    assert report.findings


def test_the_demo_covers_all_three_stack_statuses(report) -> None:
    """Clean, drifted, and could-not-check all need to be on the page."""
    statuses = {stack.status for stack in report.stacks}
    assert statuses == set(StackStatus)


def test_the_demo_includes_a_stack_that_could_not_be_checked(report) -> None:
    """The case the whole design is built around.

    A demo without it would be advertising a guarantee the tool makes a
    point of not making.
    """
    assert len(report.failed_stacks) == 1
    assert report.failed_stacks[0].error


def test_the_demo_exit_code_reflects_the_failed_stack(report) -> None:
    assert report.exit_code == 2


def test_the_demo_includes_unattributed_findings(report) -> None:
    """ "We don't know" has to be visible, or the demo oversells attribution."""
    unknown = [
        finding
        for finding in report.findings
        if finding.attribution.confidence is Confidence.UNKNOWN
    ]
    assert unknown
    assert all(finding.attribution.actor is None for finding in unknown)
    reasons = {finding.attribution.reason for finding in unknown}
    assert "no_matching_events" in reasons
    assert "outside_cloudtrail_retention" in reasons


def test_the_demo_includes_attributed_findings_with_their_events(report) -> None:
    known = [finding for finding in report.findings if finding.attribution.known]
    assert known
    for finding in known:
        assert finding.attribution.event is not None
        assert finding.attribution.event.event_id
        assert finding.attribution.event.event_name


def test_the_demo_shows_a_global_service_logged_in_us_east_1(report) -> None:
    """IAM logs to us-east-1 wherever the role is. It is the thing people
    get wrong, so the demo shows it."""
    iam = [f for f in report.findings if f.resource_type == "aws_iam_role"]
    assert iam
    assert iam[0].attribution.event is not None
    assert iam[0].attribution.event.region == "us-east-1"


def test_the_demo_covers_several_severities(report) -> None:
    levels = {finding.severity for finding in report.findings}
    assert Severity.CRITICAL in levels
    assert len(levels) >= 3


def test_the_demo_includes_a_cost_estimate_with_its_basis(report) -> None:
    priced = [finding for finding in report.findings if finding.cost]
    assert priced
    for finding in priced:
        assert finding.cost is not None
        assert "/hour" in finding.cost.basis or "/GB-month" in finding.cost.basis
        assert "upper bound" in finding.cost.basis


def test_the_demo_shows_suppressed_findings(report) -> None:
    """So the difference between "clean" and "quiet" is on the page."""
    assert report.ignored_total > 0


def test_every_demo_finding_names_its_rule(report) -> None:
    for finding in report.findings:
        assert finding.severity_rule
        assert finding.severity_reason
        assert finding.recommendation_reason


def test_demo_rules_are_real_rules(report) -> None:
    """A demo citing a rule that does not exist would be a lie about the
    rule set."""
    from crosswind.core.severity import load_rules

    real = {rule.id for rule in load_rules().rules}
    for finding in report.findings:
        assert finding.severity_rule in real, finding.severity_rule


@pytest.mark.parametrize("fmt", FORMATS)
def test_the_demo_renders_in_every_format(fmt: str, report) -> None:
    output = render(report, fmt)
    assert output.strip()
    if fmt == "json":
        json.loads(output)


def test_demo_uses_an_obviously_fake_account(report) -> None:
    assert DEMO_ACCOUNT == "000000000000"
    assert report.account == DEMO_ACCOUNT


def test_demo_says_it_is_a_demo(report) -> None:
    """Nobody should mistake a sample report for a real one."""
    assert any("sample report" in note for note in report.notes)


# --- the demo fixture must contain nothing that looks like a credential ---


#: Shapes that would be alarming in a committed fixture. Checked against the
#: rendered output of every format, because that is what actually ships and
#: what people paste into issues.
CREDENTIAL_SHAPES = (
    # An AWS access key ID.
    re.compile(r"\b(AKIA|ASIA|AIDA|AROA)[0-9A-Z]{12,}\b"),
    # A 40-character base64-ish secret access key assigned to something.
    re.compile(r"(?i)secret[_-]?access[_-]?key\W{1,4}[A-Za-z0-9/+=]{40}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    # A real-looking 12-digit account ID that is not the demo's zeros. The
    # lookarounds exclude digits that are part of a longer token: a UUID
    # event ID can legitimately end in twelve digits, and `\b` alone treats
    # the `-` before it as a boundary.
    re.compile(r"(?<![-\w])(?!000000000000)\d{12}(?![-\w])"),
)


@pytest.mark.parametrize("fmt", FORMATS)
def test_the_demo_output_contains_nothing_credential_shaped(fmt: str, report) -> None:
    output = render(report, fmt)
    for pattern in CREDENTIAL_SHAPES:
        match = pattern.search(output)
        assert match is None, f"{fmt}: {pattern.pattern} matched {match.group(0)!r}"


@pytest.mark.parametrize("fmt", FORMATS)
def test_the_demo_never_prints_a_provider_marked_secret(fmt: str, report) -> None:
    """The fixture carries a sensitive `password` attribute deliberately.

    It must show as the placeholder in every format, so a reader can see
    that redaction happens rather than having to trust that it does.
    """
    output = render(report, fmt)
    assert "(sensitive value)" in output
