"""Markdown, for a PR comment and a GitHub job summary.

Those two readers have the same constraint: a comment nobody can collapse is
a comment people learn to scroll past. So the shape is a summary table, the
findings that matter in full, and everything else inside `<details>`.

Specific things GitHub makes you care about:

- A job summary has a **1 MiB limit** and is silently truncated past it, so
  the detail is capped rather than unbounded.
- Pipe characters in a table cell break the table. Attribute values are
  user-chosen and absolutely do contain them, so cells are escaped.
- `<details>` renders in both comments and summaries; `<summary>` must not
  contain a block element.
- No ANSI, no terminal box characters.
"""

from __future__ import annotations

from crosswind.core.findings import Finding, Severity
from crosswind.core.report.words import READ_ONLY_NOTE, reason
from crosswind.core.scan import Report

#: Findings rendered in full. The rest go in a collapsed table.
DETAIL_LIMIT = 20

#: Attribute changes per finding before the list is cut.
CHANGE_LIMIT = 10

#: A GitHub job summary is truncated past 1 MiB without telling you. Well
#: under it, because a report that long has already failed as communication.
MAX_CHARS = 900_000

_BADGES = {
    Severity.CRITICAL: "**CRITICAL**",
    Severity.HIGH: "**High**",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
}


def render_markdown(report: Report) -> str:
    """The report as Markdown."""
    blocks: list[str] = []
    blocks.append(_heading(report))
    blocks.append(_summary_table(report))

    failures = _failures(report)
    if failures:
        blocks.append(failures)

    if report.reportable:
        blocks.append(_findings(report))

    blocks.append(_footer(report))
    text = "\n\n".join(block for block in blocks if block).rstrip() + "\n"

    if len(text) > MAX_CHARS:
        cut = text[:MAX_CHARS].rsplit("\n\n", 1)[0]
        text = cut + (
            "\n\n> This report was truncated to fit GitHub's job summary limit. "
            "The JSON export has everything.\n"
        )
    return text


def _heading(report: Report) -> str:
    total = len(report.reportable)
    failed = len(report.failed_stacks)

    if failed and total:
        headline = (
            f"{total} drift finding{_s(total)}, and {failed} stack{_s(failed)} could not be checked"
        )
    elif failed:
        headline = f"{failed} stack{_s(failed)} could not be checked"
    elif total:
        headline = f"{total} drift finding{_s(total)}"
    else:
        headline = "No drift found"

    return f"## Crosswind: {headline}"


def _summary_table(report: Report) -> str:
    counts = report.counts
    rows = [
        "| | |",
        "|---|---|",
        f"| Stacks checked | {len(report.stacks)} |",
        f"| With drift | {len(report.drifted_stacks)} |",
        f"| Clean | {len(report.clean_stacks)} |",
    ]
    if report.failed_stacks:
        rows.append(f"| **Could not check** | **{len(report.failed_stacks)}** |")
    rows.append(
        f"| Findings | {counts['critical']} critical, {counts['high']} high, "
        f"{counts['medium']} medium, {counts['low']} low |"
    )
    if report.ignored_total:
        rows.append(f"| Suppressed by `.crosswindignore` | {report.ignored_total} |")
    rows.append(f"| Threshold | `{report.min_severity.label}` |")
    if report.binary:
        rows.append(f"| Ran with | {_cell(report.binary)} |")
    return "\n".join(rows)


def _failures(report: Report) -> str:
    """The stacks we could not check, before the findings.

    Not collapsed, and not below the findings: a reader who sees "no critical
    drift" without seeing this has been misled by the ordering.
    """
    failed = report.failed_stacks
    if not failed:
        return ""

    lines = [
        f"### Could not check {len(failed)} stack{_s(len(failed))}",
        "",
        "These were **not** scanned and are not known to be clean.",
        "",
    ]
    for stack in failed:
        lines.append(f"<details><summary><code>{_cell(stack.path)}</code></summary>")
        lines.append("")
        lines.append("```")
        lines.append((stack.error or "no detail").strip()[:2000])
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    return "\n".join(lines)


def _findings(report: Report) -> str:
    findings = report.reportable
    lines = ["### Findings", ""]

    for finding in findings[:DETAIL_LIMIT]:
        lines.append(_one(finding))
        lines.append("")

    remaining = findings[DETAIL_LIMIT:]
    if remaining:
        lines.append(
            f"<details><summary>{len(remaining)} more finding{_s(len(remaining))}</summary>"
        )
        lines.append("")
        lines.append("| Severity | Stack | Resource | Rule |")
        lines.append("|---|---|---|---|")
        for finding in remaining:
            lines.append(
                f"| {_BADGES[finding.severity]} | {_cell(finding.stack)} | "
                f"`{_cell(finding.address)}` | `{_cell(finding.severity_rule)}` |"
            )
        lines.append("")
        lines.append("</details>")
    return "\n".join(lines)


def _one(finding: Finding) -> str:
    lines = [
        f"#### {_BADGES[finding.severity]} `{_cell(finding.address)}`",
        "",
        f"- **Stack:** `{_cell(finding.stack)}` ({finding.kind.label})",
        f"- **Why it matters:** {finding.severity_reason} "
        f"<sub>rule `{_cell(finding.severity_rule)}`</sub>",
        f"- **Who changed it:** {_who(finding)}",
    ]
    if finding.cost:
        lines.append(
            f"- **Cost:** about ${finding.cost.monthly_usd:,.2f}/month different. "
            f"{finding.cost.basis}"
        )
    lines.append(
        f"- **Recommendation:** {finding.recommendation.label} — {finding.recommendation_reason}"
    )

    if finding.changes:
        lines.append("")
        lines.append("| Attribute | In code (state) | Actually |")
        lines.append("|---|---|---|")
        for change in finding.changes[:CHANGE_LIMIT]:
            lines.append(
                f"| `{_cell(change.path)}` | {_value(change.before)} | {_value(change.after)} |"
            )
        extra = len(finding.changes) - CHANGE_LIMIT
        if extra > 0:
            lines.append(f"| | | _and {extra} more attribute{_s(extra)}_ |")
    return "\n".join(lines)


def _who(finding: Finding) -> str:
    attribution = finding.attribution
    if not attribution.known or attribution.event is None:
        return f"unknown — {reason(attribution.reason)}"
    event = attribution.event
    when = event.event_time.strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"`{_cell(attribution.actor or '')}` via `{_cell(event.event_name)}` "
        f"at {when} ({attribution.confidence.label} confidence, "
        f"event `{_cell(event.event_id)}`)"
    )


def _footer(report: Report) -> str:
    lines = ["---", ""]
    if report.attribution_note:
        lines.append(f"> {report.attribution_note}")
        lines.append("")
    for note in report.notes:
        lines.append(f"> {note}")
        lines.append("")
    lines.append(READ_ONLY_NOTE)
    return "\n".join(lines)


def _value(value: object) -> str:
    """An attribute value as a table cell."""
    if value is None:
        return "_(none)_"
    text = str(value)
    if len(text) > 60:
        text = text[:57] + "..."
    return f"`{_cell(text)}`"


def _cell(text: str) -> str:
    """Escape what would break a Markdown table or inject markup.

    Pipes end a cell, and attribute values genuinely contain them — a
    security group description, a policy document. Backticks would close an
    inline code span; angle brackets would be read as HTML in a comment.
    """
    return (
        text.replace("|", "\\|")
        .replace("`", "\\`")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def _s(count: int) -> str:
    return "s" if count != 1 else ""
