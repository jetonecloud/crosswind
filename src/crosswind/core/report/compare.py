"""Rendering a comparison of two reports.

Three formats rather than four. A comparison is something a person reads in a
terminal or a job summary, or a machine reads as JSON; the HTML report's
reader wants the current state, not a delta, and should be sent that.

The order is the same in every format and it is the point of the exercise:
stacks the later run could not check, then what is new, what got worse, and
what we cannot verify, before what persists and what was dealt with. Nobody
needs to be told about the good news first.

The values shown come from the input reports, which were redacted when they
were written. Nothing here sees a plan file.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from crosswind.core.compare import Comparison, Delta, Entry, unverified_reason
from crosswind.core.report.markdown import _cell

#: Entries per section rendered in full in the terminal.
TERMINAL_LIMIT = 15

#: Entries per section in Markdown before the rest are collapsed.
MARKDOWN_LIMIT = 50

#: Same reasoning as the Markdown report: GitHub silently truncates a job
#: summary past 1 MiB.
MAX_CHARS = 900_000

_RULE = "-" * 72

_HEADINGS: dict[Delta, str] = {
    Delta.NEW: "NEW",
    Delta.CHANGED: "CHANGED",
    Delta.UNVERIFIED: "NOT VERIFIED",
    Delta.PERSISTING: "STILL THERE",
    Delta.RESOLVED: "RESOLVED",
}

_EXPLAINERS: dict[Delta, str] = {
    Delta.NEW: "Drift the earlier run did not report.",
    Delta.CHANGED: "Still drifted, but something about it moved.",
    Delta.UNVERIFIED: "Gone from the later report, but not because anyone confirmed a fix.",
    Delta.PERSISTING: "Reported both times, unchanged.",
    Delta.RESOLVED: "Its stack was checked again and the drift is gone.",
}

_ORDER = (Delta.NEW, Delta.CHANGED, Delta.UNVERIFIED, Delta.PERSISTING, Delta.RESOLVED)


# --- terminal -------------------------------------------------------------


def render_compare_terminal(comparison: Comparison) -> str:
    lines: list[str] = ["", "crosswind - drift since the last report", _RULE]
    lines.append(f"  before: {_describe(comparison.before.data, comparison.before.source)}")
    lines.append(f"  after:  {_describe(comparison.after.data, comparison.after.source)}")
    lines.append("")

    if comparison.failed_stacks:
        count = len(comparison.failed_stacks)
        lines.append(f"COULD NOT CHECK {count} STACK{'S' if count != 1 else ''} IN THE LATER RUN")
        lines.append("  Nothing below can promise anything about these.")
        lines.append("")
        lines.extend(f"  ! {path}" for path in comparison.failed_stacks)
        lines.append("")
        lines.append(_RULE)
        lines.append("")

    lines.append(_headline(comparison))
    stack_lines = _stack_movements(comparison)
    lines.extend(f"  {line}" for line in stack_lines)
    lines.append("")

    for delta in _ORDER:
        entries = comparison.of(delta)
        if not entries:
            continue
        lines.append(_RULE)
        lines.append(f"{_HEADINGS[delta]} ({len(entries)})")
        lines.append(f"  {_EXPLAINERS[delta]}")
        lines.append("")
        detailed = delta in (Delta.NEW, Delta.CHANGED, Delta.UNVERIFIED)
        for entry in entries[:TERMINAL_LIMIT]:
            lines.extend(_terminal_entry(entry, detailed=detailed))
        if len(entries) > TERMINAL_LIMIT:
            lines.append(f"  ... and {len(entries) - TERMINAL_LIMIT} more (see --format json)")
        lines.append("")

    lines.append(_RULE)
    for note in comparison.notes:
        lines.append(f"  Note: {note}")
    lines.append(f"  {_verdict(comparison)}")
    return "\n".join(lines).rstrip() + "\n"


def _terminal_entry(entry: Entry, *, detailed: bool) -> list[str]:
    label = entry.severity.value.upper()
    if entry.worsened and entry.severity_before is not None:
        label = f"{entry.severity_before.value.upper()} -> {label}"
    lines = [f"  [{label}] {entry.address}", f"      stack: {entry.stack}"]
    if not detailed:
        return lines
    if entry.delta is Delta.UNVERIFIED:
        lines.append(f"      why not resolved: {unverified_reason(entry.reason)}")
    for difference in entry.differences:
        lines.append(f"      {difference}")
    if entry.delta is Delta.NEW:
        for path, before, after in _change_rows(entry.current)[:4]:
            lines.append(f"      {path}: {_short(before)} -> {_short(after)}")
    return lines


# --- markdown -------------------------------------------------------------


def render_compare_markdown(comparison: Comparison) -> str:
    blocks: list[str] = [f"## Crosswind: {_headline(comparison)}"]

    blocks.append(
        "| | Report | Generated | Min severity |\n"
        "|---|---|---|---|\n"
        f"| Before | `{_cell(comparison.before.source)}` | "
        f"{_cell(str(comparison.before.data.get('generated_at') or 'unknown'))} | "
        f"{comparison.before.min_severity.value} |\n"
        f"| After | `{_cell(comparison.after.source)}` | "
        f"{_cell(str(comparison.after.data.get('generated_at') or 'unknown'))} | "
        f"{comparison.after.min_severity.value} |"
    )

    summary = comparison.summary()
    blocks.append(
        "| New | Changed | Not verified | Still there | Resolved |\n"
        "|---:|---:|---:|---:|---:|\n"
        f"| {summary['new']} | {summary['changed']} | {summary['unverified']} | "
        f"{summary['persisting']} | {summary['resolved']} |"
    )

    if comparison.failed_stacks:
        rows = "\n".join(f"- `{_cell(path)}`" for path in comparison.failed_stacks)
        blocks.append(
            f"> [!WARNING]\n> **{len(comparison.failed_stacks)} stack(s) could not be "
            f"checked in the later run.** Nothing here can promise anything about them.\n\n"
            f"{rows}"
        )

    stack_lines = _stack_movements(comparison)
    if stack_lines:
        blocks.append("\n".join(f"- {_cell(line)}" for line in stack_lines))

    for delta in _ORDER:
        entries = comparison.of(delta)
        if not entries:
            continue
        table = _markdown_table(entries[:MARKDOWN_LIMIT], delta)
        heading = f"### {_HEADINGS[delta].capitalize()} ({len(entries)})"
        body = f"{_EXPLAINERS[delta]}\n\n{table}"
        if len(entries) > MARKDOWN_LIMIT:
            body += f"\n\n_{len(entries) - MARKDOWN_LIMIT} more in the JSON comparison._"
        if delta in (Delta.PERSISTING, Delta.RESOLVED):
            blocks.append(
                f"<details><summary>{_HEADINGS[delta].capitalize()} ({len(entries)})</summary>"
                f"\n\n{body}\n\n</details>"
            )
        else:
            blocks.append(f"{heading}\n\n{body}")

    if comparison.notes:
        blocks.append("\n>\n".join(f"> {_cell(note)}" for note in comparison.notes))
    blocks.append(f"_{_verdict(comparison)}_")

    text = "\n\n".join(blocks).rstrip() + "\n"
    if len(text) > MAX_CHARS:
        cut = text[:MAX_CHARS].rsplit("\n\n", 1)[0]
        text = cut + "\n\n> Truncated to fit GitHub's job summary limit. The JSON has it all.\n"
    return text


def _markdown_table(entries: Sequence[Entry], delta: Delta) -> str:
    if delta is Delta.UNVERIFIED:
        header = "| Severity | Resource | Stack | Why not resolved |\n|---|---|---|---|"
    elif delta is Delta.CHANGED:
        header = "| Severity | Resource | Stack | What changed |\n|---|---|---|---|"
    else:
        header = "| Severity | Resource | Stack | Attributes |\n|---|---|---|---|"
    rows = [header]
    for entry in entries:
        severity = entry.severity.value
        if entry.worsened and entry.severity_before is not None:
            severity = f"**{entry.severity_before.value} → {severity}**"
        if delta is Delta.UNVERIFIED:
            detail = unverified_reason(entry.reason)
        elif delta is Delta.CHANGED:
            # Escaped as `-&gt;` otherwise, which reads worse than an arrow.
            detail = "; ".join(entry.differences).replace(" -> ", " → ")
        else:
            detail = ", ".join(path for path, _, _ in _change_rows(entry.current)[:5])
        rows.append(
            f"| {severity} | `{_cell(entry.address)}` | `{_cell(entry.stack)}` | "
            f"{_cell(detail) or '-'} |"
        )
    return "\n".join(rows)


# --- json -----------------------------------------------------------------


def render_compare_json(comparison: Comparison) -> str:
    return (
        json.dumps(
            comparison.to_dict(),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )
        + "\n"
    )


# --- shared ---------------------------------------------------------------


def _headline(comparison: Comparison) -> str:
    new, worse = len(comparison.new), len(comparison.worsened)
    resolved, unverified = len(comparison.resolved), len(comparison.unverified)
    parts = []
    if new:
        parts.append(f"{new} new")
    if worse:
        parts.append(f"{worse} worse")
    if len(comparison.changed) > worse:
        parts.append(f"{len(comparison.changed) - worse} otherwise changed")
    if resolved:
        parts.append(f"{resolved} resolved")
    if unverified:
        parts.append(f"{unverified} not verified")
    if not parts:
        return "no change in drift"
    return ", ".join(parts)


def _stack_movements(comparison: Comparison) -> list[str]:
    lines = []
    if comparison.recovered_stacks:
        lines.append(
            f"Checked again after failing before: {', '.join(comparison.recovered_stacks)}"
        )
    if comparison.missing_stacks:
        lines.append(f"Not in the later run: {', '.join(comparison.missing_stacks)}")
    if comparison.added_stacks:
        lines.append(f"Not in the earlier run: {', '.join(comparison.added_stacks)}")
    return lines


def _verdict(comparison: Comparison) -> str:
    if comparison.failed_stacks:
        return "Exit 2: the later report has stacks it could not check."
    if comparison.regressions:
        count = len(comparison.regressions)
        return (
            f"Exit 1: {count} new or worsened finding{'s' if count != 1 else ''} at or above "
            f"{comparison.fail_threshold.value}."
        )
    return f"Exit 0: nothing new or worse at or above {comparison.fail_threshold.value}."


def _describe(data: Mapping[str, Any], source: str) -> str:
    generated = data.get("generated_at") or "unknown time"
    stacks = data.get("stacks") or []
    return f"{source} ({generated}, {len(stacks)} stack{'s' if len(stacks) != 1 else ''})"


def _change_rows(finding: Mapping[str, Any]) -> list[tuple[str, Any, Any]]:
    changes = finding.get("changes")
    if not isinstance(changes, list):
        return []
    return [
        (str(item.get("path")), item.get("before"), item.get("after"))
        for item in changes
        if isinstance(item, dict)
    ]


def _short(value: object) -> str:
    if value is None:
        return "(none)"
    text = str(value)
    return text if len(text) <= 48 else text[:45] + "..."


#: Format name to renderer, validated by the CLI like `RENDERERS`.
COMPARE_RENDERERS: dict[str, Callable[[Comparison], str]] = {
    "terminal": render_compare_terminal,
    "markdown": render_compare_markdown,
    "json": render_compare_json,
}

COMPARE_FORMATS = tuple(COMPARE_RENDERERS)


__all__ = [
    "COMPARE_FORMATS",
    "COMPARE_RENDERERS",
    "render_compare_json",
    "render_compare_markdown",
    "render_compare_terminal",
]
