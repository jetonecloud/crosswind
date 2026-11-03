"""The terminal report: ten seconds to decide whether to care.

Short on purpose. Someone running this in the morning wants three things in
the first few lines — did anything fail, is anything critical, how much is
there — and then the detail for the worst handful. Everything else is what
the HTML and JSON are for.

Rendered to a string rather than printed, so it is testable and so the CLI
owns all the I/O. Plain ASCII box characters and no emoji: this gets piped
into CI logs, pasted into tickets, and read over SSH on terminals that will
mangle anything cleverer.

The failed stacks go **first**, above the findings, because "we could not
check three of your stacks" changes how you read everything below it.
"""

from __future__ import annotations

from crosswind.core.findings import Confidence, Finding, Severity
from crosswind.core.report.words import FAILED_NOTE, reason
from crosswind.core.scan import Report

#: How many findings get the full treatment. The rest are one line each:
#: a terminal report that scrolls is a terminal report nobody reads.
DETAIL_LIMIT = 10

#: Attribute changes shown per finding before we stop and say how many more.
CHANGE_LIMIT = 6

_RULE = "-" * 72

#: Severity labels, padded so the columns line up without a table library.
_LABELS = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH    ",
    Severity.MEDIUM: "MEDIUM  ",
    Severity.LOW: "LOW     ",
}


def render_terminal(report: Report) -> str:
    """The whole terminal report as one string."""
    lines: list[str] = []
    lines.extend(_header(report))
    lines.extend(_failures(report))
    lines.extend(_summary(report))
    lines.extend(_findings(report))
    lines.extend(_footer(report))
    return "\n".join(lines).rstrip() + "\n"


def _header(report: Report) -> list[str]:
    lines = ["", "crosswind - Terraform drift report", _RULE]
    detail = []
    if report.binary:
        detail.append(report.binary)
    if report.account:
        detail.append(f"account {report.account}")
    detail.append(f"{len(report.stacks)} stack{'s' if len(report.stacks) != 1 else ''}")
    detail.append(f"{report.duration_seconds:.1f}s")
    lines.append("  " + "  |  ".join(detail))
    lines.append("")
    return lines


def _failures(report: Report) -> list[str]:
    """Stacks we could not check, first and unmissable.

    This is above the findings deliberately. A reader who sees "no critical
    drift" without seeing "and we could not check prod" has been misled by
    the layout even though every individual line was true.
    """
    failed = report.failed_stacks
    if not failed:
        return []

    lines = [
        f"COULD NOT CHECK {len(failed)} STACK{'S' if len(failed) != 1 else ''}",
        f"  {FAILED_NOTE}",
        "",
    ]
    for stack in failed:
        lines.append(f"  ! {stack.path}")
        for line in (stack.error or "").splitlines()[:4]:
            lines.append(f"      {line}")
        lines.append("")
    lines.append(_RULE)
    lines.append("")
    return lines


def _summary(report: Report) -> list[str]:
    counts = report.counts
    total = len(report.reportable)

    if total == 0 and not report.failed_stacks:
        lines = [
            "No drift found at or above "
            f"{report.min_severity.label}."
            f"  ({len(report.clean_stacks)} stack"
            f"{'s' if len(report.clean_stacks) != 1 else ''} checked, all clean)"
        ]
        if report.ignored_total:
            lines.append(
                f"  {report.ignored_total} finding"
                f"{'s' if report.ignored_total != 1 else ''} suppressed by .crosswindignore."
            )
        lines.append("")
        return lines

    parts = [f"{counts[level.value]} {level.label}" for level in Severity if counts[level.value]]
    lines = [
        f"{total} finding{'s' if total != 1 else ''}" + (f": {', '.join(parts)}" if parts else ""),
        f"  {len(report.drifted_stacks)} of {len(report.stacks)} stacks have drift.",
    ]
    if report.ignored_total:
        lines.append(f"  {report.ignored_total} suppressed by .crosswindignore.")
    if total > DETAIL_LIMIT:
        lines.append(f"  Showing the first {DETAIL_LIMIT}; the full list is in the report.")
    lines.append("")
    return lines


def _findings(report: Report) -> list[str]:
    findings = report.reportable
    if not findings:
        return []

    lines = [_RULE, ""]
    for finding in findings[:DETAIL_LIMIT]:
        lines.extend(_one(finding))
    remaining = findings[DETAIL_LIMIT:]
    if remaining:
        lines.append(f"  ... and {len(remaining)} more:")
        for finding in remaining:
            lines.append(f"    {_LABELS[finding.severity]}  {finding.stack}  {finding.address}")
        lines.append("")
    return lines


def _one(finding: Finding) -> list[str]:
    lines = [
        f"  [{_LABELS[finding.severity].strip()}] {finding.address}",
        f"      stack: {finding.stack}   ({finding.kind.label})",
    ]

    for change in finding.changes[:CHANGE_LIMIT]:
        lines.append(f"      {change.path}: {_value(change.before)} -> {_value(change.after)}")
    extra = len(finding.changes) - CHANGE_LIMIT
    if extra > 0:
        lines.append(f"      ... and {extra} more attribute{'s' if extra != 1 else ''}")

    lines.append(f"      why: {finding.severity_reason}  [rule: {finding.severity_rule}]")
    lines.append(f"      who: {_who(finding)}")
    if finding.cost:
        # The basis travels with the figure, here as everywhere else. A
        # number without its arithmetic is a number nobody can check, and
        # the terminal is where most people will see it first.
        lines.append(f"      cost: ~${finding.cost.monthly_usd:,.2f}/month difference")
        for line in _wrap(finding.cost.basis, width=62):
            lines.append(f"            {line}")
    lines.append(f"      do: {finding.recommendation.label} - {finding.recommendation_reason}")
    lines.append("")
    return lines


def _who(finding: Finding) -> str:
    """One line about attribution, including when there isn't any.

    "unknown" is stated rather than left blank: a blank field reads as a bug,
    and the whole point is that we would rather say we don't know than guess.
    """
    attribution = finding.attribution
    if not attribution.known or attribution.event is None:
        return f"unknown ({reason(attribution.reason)})"
    event = attribution.event
    when = event.event_time.strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"{attribution.actor} via {event.event_name} at {when} "
        f"[{attribution.confidence.label} confidence, event {event.event_id}]"
    )


def _wrap(text: str, *, width: int) -> list[str]:
    """Wrap a sentence to `width`, for the indented continuation lines.

    `textwrap` would do this, but it also collapses and re-flows in ways that
    matter for the arithmetic in a cost basis — breaking `$0.0832/hour`
    across lines makes it unreadable. Splitting on spaces keeps every token
    whole.
    """
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


def _value(value: object) -> str:
    """One attribute value, short enough for a terminal line."""
    if value is None:
        return "(none)"
    text = str(value)
    return text if len(text) <= 48 else text[:45] + "..."


def _footer(report: Report) -> list[str]:
    lines = [_RULE]
    if report.attribution_note:
        lines.append(f"  Note: {report.attribution_note}")
    for note in report.notes:
        lines.append(f"  Note: {note}")

    unknown = sum(
        1 for finding in report.reportable if finding.attribution.confidence is Confidence.UNKNOWN
    )
    if report.reportable and unknown:
        lines.append(
            f"  {unknown} of {len(report.reportable)} findings could not be attributed "
            f"to anyone. Crosswind never guesses a name."
        )
    lines.append(
        "  Crosswind is read-only. It has changed nothing, and recommends rather than acts."
    )
    lines.append("")
    return lines
