"""Comparing two scans: what is new, what was dealt with, what we can't tell.

A scheduled scan answers "is there drift?" every morning. The question a team
actually has by Friday is different: *what changed since Monday?* That is a
diff of two JSON reports, keyed on the finding `id`, which is stable across
runs for the same resource in the same stack.

The naive diff gets one thing badly wrong, and it is the same thing the scan
itself is built to avoid. A finding that is missing from the later report has
not necessarily been fixed:

- its stack may have **failed** in the later run, so nobody looked;
- its stack may not have been **scanned at all** (a different `--path`, an
  `--exclude`, a stack that was moved);
- the later run may have used a **higher `--min-severity`**, so the finding
  exists and was filtered out;
- a **new ignore rule** may have suppressed it, which hides drift rather than
  fixing it.

Each of those is reported as `unverified`, with a reason code, and never as
`resolved`. Calling a hole in the later report "fixed" would be the comparison
equivalent of calling a broken stack clean.

This module works on the parsed JSON rather than on `Report` objects, because
its inputs are files written by an earlier run — possibly by an older
Crosswind — and not something this process built.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from crosswind.core.findings import Severity
from crosswind.core.scan import EXIT_CLEAN, EXIT_DRIFT, EXIT_ERROR

#: The comparison's own JSON contract, versioned the same way as the report.
COMPARE_SCHEMA_VERSION = "1.0"

#: The report schema majors this module knows how to read.
SUPPORTED_MAJORS = frozenset({1})


class CompareError(Exception):
    """A report could not be read, or is not one we understand."""


class Delta(Enum):
    """How a finding moved between the two reports."""

    #: In the later report, not in the earlier one.
    NEW = "new"
    #: In both, and something about it changed: severity or what differs.
    CHANGED = "changed"
    #: In both, unchanged.
    PERSISTING = "persisting"
    #: In the earlier report, and its stack was checked again and is clear of it.
    RESOLVED = "resolved"
    #: In the earlier report, missing from the later one, and we cannot say why.
    UNVERIFIED = "unverified"

    @property
    def label(self) -> str:
        return self.value


#: Why a disappeared finding is `unverified` rather than `resolved`. These are
#: the JSON contract, like the attribution reason codes.
UNVERIFIED_REASONS: dict[str, str] = {
    "stack_failed": "its stack could not be checked in the later run",
    "stack_not_scanned": "its stack was not part of the later run",
    "below_threshold": "the later run hid findings at this severity",
    "may_be_ignored": "the later run suppressed more findings in this stack",
}


@dataclass(frozen=True)
class ReportFile:
    """A report loaded from disk, validated just enough to compare."""

    source: str
    data: Mapping[str, Any]

    @property
    def generated_at(self) -> datetime | None:
        value = self.data.get("generated_at")
        if not isinstance(value, str):
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    @property
    def min_severity(self) -> Severity:
        value = self.data.get("min_severity")
        try:
            return Severity.parse(value) if isinstance(value, str) else Severity.LOW
        except ValueError:
            return Severity.LOW

    @property
    def account(self) -> str | None:
        value = self.data.get("account")
        return value if isinstance(value, str) else None

    @property
    def findings(self) -> dict[str, Mapping[str, Any]]:
        return {item["id"]: item for item in self.data["findings"]}

    @property
    def stacks(self) -> dict[str, Mapping[str, Any]]:
        return {item["path"]: item for item in self.data["stacks"]}


def load_report(path: Path | str) -> ReportFile:
    """Read and check a `crosswind scan --format json` file."""
    source = str(path)
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise CompareError(f"could not read {source}: {exc.strerror or exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CompareError(f"{source} is not JSON ({exc.msg} at line {exc.lineno})") from exc
    return parse_report(data, source=source)


def parse_report(data: Any, *, source: str = "<report>") -> ReportFile:
    """Check that `data` is a Crosswind report this version can compare."""
    if not isinstance(data, dict) or data.get("tool") != "crosswind":
        raise CompareError(
            f"{source} is not a Crosswind report. Write one with `crosswind scan --format json`."
        )
    version = data.get("schema_version")
    try:
        major = int(str(version).split(".")[0])
    except ValueError:
        major = -1
    if major not in SUPPORTED_MAJORS:
        raise CompareError(
            f"{source} has schema_version {version!r}; this Crosswind reads "
            f"{', '.join(f'{m}.x' for m in sorted(SUPPORTED_MAJORS))}."
        )
    findings = data.get("findings")
    stacks = data.get("stacks")
    if not isinstance(findings, list) or not isinstance(stacks, list):
        raise CompareError(f"{source} is missing its findings or stacks list.")
    for item in findings:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise CompareError(f"{source} has a finding without an id.")
    for item in stacks:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise CompareError(f"{source} has a stack without a path.")
    return ReportFile(source=source, data=data)


@dataclass(frozen=True)
class Entry:
    """One finding's movement between the two reports.

    `before` and `after` are the finding as each report recorded it, so a
    renderer can show both sides without going back to the files. One of
    them is `None` for `NEW`, `RESOLVED` and `UNVERIFIED`.
    """

    id: str
    delta: Delta
    before: Mapping[str, Any] | None = None
    after: Mapping[str, Any] | None = None
    #: For `UNVERIFIED`: one of `UNVERIFIED_REASONS`.
    reason: str | None = None
    #: For `CHANGED`: short sentences saying what changed.
    differences: tuple[str, ...] = ()

    @property
    def current(self) -> Mapping[str, Any]:
        """The most recent version of the finding we have."""
        found = self.after if self.after is not None else self.before
        assert found is not None
        return found

    @property
    def stack(self) -> str:
        return str(self.current.get("stack", ""))

    @property
    def address(self) -> str:
        return str(self.current.get("address", ""))

    @property
    def severity(self) -> Severity:
        return _severity(self.current)

    @property
    def severity_before(self) -> Severity | None:
        return _severity(self.before) if self.before is not None else None

    @property
    def worsened(self) -> bool:
        """A changed finding whose severity went up."""
        before = self.severity_before
        return (
            self.delta is Delta.CHANGED and before is not None and self.severity.rank < before.rank
        )

    def to_dict(self) -> dict[str, Any]:
        severity_before = self.severity_before
        return {
            "id": self.id,
            "delta": self.delta.value,
            "stack": self.stack,
            "address": self.address,
            "severity": self.severity.value,
            "severity_before": severity_before.value if severity_before else None,
            "worsened": self.worsened,
            "reason": self.reason,
            "differences": list(self.differences),
            "before": dict(self.before) if self.before is not None else None,
            "after": dict(self.after) if self.after is not None else None,
        }


@dataclass(frozen=True)
class Comparison:
    """Two reports, lined up."""

    before: ReportFile
    after: ReportFile
    entries: tuple[Entry, ...]
    #: Stacks that could not be checked in the later run.
    failed_stacks: tuple[str, ...] = ()
    #: Stacks that were failing before and were checked this time.
    recovered_stacks: tuple[str, ...] = ()
    #: Stacks in the earlier report and absent from the later one.
    missing_stacks: tuple[str, ...] = ()
    #: Stacks scanned in the later run and not in the earlier one.
    added_stacks: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    #: Only new and worsened findings at or above this count toward exit 1.
    fail_threshold: Severity = Severity.LOW

    def of(self, delta: Delta) -> tuple[Entry, ...]:
        return tuple(entry for entry in self.entries if entry.delta is delta)

    @property
    def new(self) -> tuple[Entry, ...]:
        return self.of(Delta.NEW)

    @property
    def changed(self) -> tuple[Entry, ...]:
        return self.of(Delta.CHANGED)

    @property
    def persisting(self) -> tuple[Entry, ...]:
        return self.of(Delta.PERSISTING)

    @property
    def resolved(self) -> tuple[Entry, ...]:
        return self.of(Delta.RESOLVED)

    @property
    def unverified(self) -> tuple[Entry, ...]:
        return self.of(Delta.UNVERIFIED)

    @property
    def worsened(self) -> tuple[Entry, ...]:
        return tuple(entry for entry in self.changed if entry.worsened)

    @property
    def regressions(self) -> tuple[Entry, ...]:
        """New or worsened findings at or above the threshold: what fails a build."""
        candidates = self.new + self.worsened
        return tuple(entry for entry in candidates if entry.severity.at_least(self.fail_threshold))

    @property
    def exit_code(self) -> int:
        """0 nothing got worse, 1 something did, 2 the later report has a hole.

        2 beats 1 for the same reason it does in a scan: a comparison whose
        later half could not see some stacks cannot promise anything about
        them, including that they did not get worse.
        """
        if self.failed_stacks:
            return EXIT_ERROR
        if self.regressions:
            return EXIT_DRIFT
        return EXIT_CLEAN

    def summary(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "changed": len(self.changed),
            "worsened": len(self.worsened),
            "persisting": len(self.persisting),
            "resolved": len(self.resolved),
            "unverified": len(self.unverified),
            "stacks_failed": len(self.failed_stacks),
            "stacks_recovered": len(self.recovered_stacks),
            "stacks_missing": len(self.missing_stacks),
            "stacks_added": len(self.added_stacks),
            "exit_code": self.exit_code,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": COMPARE_SCHEMA_VERSION,
            "tool": "crosswind",
            "kind": "comparison",
            "before": _report_header(self.before),
            "after": _report_header(self.after),
            "fail_threshold": self.fail_threshold.value,
            "summary": self.summary(),
            "notes": list(self.notes),
            "stacks": {
                "failed": list(self.failed_stacks),
                "recovered": list(self.recovered_stacks),
                "missing": list(self.missing_stacks),
                "added": list(self.added_stacks),
            },
            "entries": [entry.to_dict() for entry in self.entries],
        }


def compare(
    before: ReportFile,
    after: ReportFile,
    *,
    fail_threshold: Severity = Severity.LOW,
) -> Comparison:
    """Line up two reports, earlier first."""
    old_findings, new_findings = before.findings, after.findings
    old_stacks, new_stacks = before.stacks, after.stacks

    entries: list[Entry] = []
    for key, current in new_findings.items():
        previous = old_findings.get(key)
        if previous is None:
            entries.append(Entry(id=key, delta=Delta.NEW, after=current))
            continue
        differences = _differences(previous, current)
        entries.append(
            Entry(
                id=key,
                delta=Delta.CHANGED if differences else Delta.PERSISTING,
                before=previous,
                after=current,
                differences=differences,
            )
        )

    floor = after.min_severity
    for key, previous in old_findings.items():
        if key in new_findings:
            continue
        why = _why_unverified(previous, old_stacks, new_stacks, floor)
        entries.append(
            Entry(
                id=key,
                delta=Delta.UNVERIFIED if why else Delta.RESOLVED,
                before=previous,
                reason=why,
            )
        )

    entries.sort(key=_sort_key)

    failed = sorted(path for path, stack in new_stacks.items() if _failed(stack))
    recovered = sorted(
        path
        for path, stack in new_stacks.items()
        if not _failed(stack) and path in old_stacks and _failed(old_stacks[path])
    )
    missing = sorted(old_stacks.keys() - new_stacks.keys())
    added = sorted(new_stacks.keys() - old_stacks.keys())

    return Comparison(
        before=before,
        after=after,
        entries=tuple(entries),
        failed_stacks=tuple(failed),
        recovered_stacks=tuple(recovered),
        missing_stacks=tuple(missing),
        added_stacks=tuple(added),
        notes=_notes(before, after),
        fail_threshold=fail_threshold,
    )


def _why_unverified(
    finding: Mapping[str, Any],
    old_stacks: Mapping[str, Mapping[str, Any]],
    new_stacks: Mapping[str, Mapping[str, Any]],
    floor: Severity,
) -> str | None:
    """Why a vanished finding cannot be called resolved, or None if it can."""
    path = str(finding.get("stack", ""))
    stack = new_stacks.get(path)
    if stack is None:
        return "stack_not_scanned"
    if _failed(stack):
        return "stack_failed"
    if not _severity(finding).at_least(floor):
        return "below_threshold"
    old_stack = old_stacks.get(path)
    old_ignored = _int(old_stack.get("ignored")) if old_stack else 0
    if _int(stack.get("ignored")) > old_ignored:
        return "may_be_ignored"
    return None


def _differences(before: Mapping[str, Any], after: Mapping[str, Any]) -> tuple[str, ...]:
    """What changed about a finding present in both reports, in words.

    Attribution is deliberately not compared: a later run may find an event
    the earlier one could not, or lose one to CloudTrail's 90-day window,
    and neither means the drift itself moved.
    """
    found: list[str] = []
    old_severity, new_severity = _severity(before), _severity(after)
    if old_severity is not new_severity:
        found.append(f"severity {old_severity.value} -> {new_severity.value}")

    if before.get("drift_kind") != after.get("drift_kind"):
        found.append(f"drift kind {before.get('drift_kind')} -> {after.get('drift_kind')}")

    old_changes, new_changes = _changes(before), _changes(after)
    added = sorted(new_changes.keys() - old_changes.keys())
    removed = sorted(old_changes.keys() - new_changes.keys())
    moved = sorted(
        path
        for path in old_changes.keys() & new_changes.keys()
        if old_changes[path] != new_changes[path]
    )
    if added:
        found.append(f"now also differs: {', '.join(added)}")
    if removed:
        found.append(f"no longer differs: {', '.join(removed)}")
    if moved:
        found.append(f"different value now: {', '.join(moved)}")
    return tuple(found)


def _changes(finding: Mapping[str, Any]) -> dict[str, Any]:
    changes = finding.get("changes")
    if not isinstance(changes, list):
        return {}
    return {
        str(item.get("path")): (item.get("before"), item.get("after"))
        for item in changes
        if isinstance(item, dict)
    }


def _notes(before: ReportFile, after: ReportFile) -> tuple[str, ...]:
    notes: list[str] = []
    old_time, new_time = before.generated_at, after.generated_at
    if old_time and new_time:
        try:
            swapped = old_time > new_time
        except TypeError:  # one naive, one aware: not worth guessing
            swapped = False
        if swapped:
            notes.append(
                "The earlier report was generated after the later one. "
                "The arguments may be the wrong way round: earlier first."
            )
    if before.account and after.account and before.account != after.account:
        notes.append(
            f"The reports are from different AWS accounts ({before.account} and "
            f"{after.account}). Most findings will look new or resolved."
        )
    if after.min_severity.rank > before.min_severity.rank:
        notes.append(
            f"The later run used a lower --min-severity ({after.min_severity.value} "
            f"vs {before.min_severity.value}), so some findings may look new "
            f"only because the earlier run hid them."
        )
    return tuple(notes)


def _report_header(report: ReportFile) -> dict[str, Any]:
    summary = report.data.get("summary")
    return {
        "source": report.source,
        "generated_at": report.data.get("generated_at"),
        "account": report.account,
        "min_severity": report.min_severity.value,
        "schema_version": report.data.get("schema_version"),
        "stacks_scanned": len(report.data["stacks"]),
        "stacks_failed": (
            _int(summary.get("stacks_failed")) if isinstance(summary, dict) else None
        ),
    }


#: Display order: what needs attention first.
_DELTA_ORDER = {
    Delta.NEW: 0,
    Delta.CHANGED: 1,
    Delta.UNVERIFIED: 2,
    Delta.PERSISTING: 3,
    Delta.RESOLVED: 4,
}


def _sort_key(entry: Entry) -> tuple[Any, ...]:
    return (_DELTA_ORDER[entry.delta], entry.severity.rank, entry.stack, entry.address)


def _severity(finding: Mapping[str, Any]) -> Severity:
    value = finding.get("severity")
    try:
        return Severity.parse(value) if isinstance(value, str) else Severity.LOW
    except ValueError:
        return Severity.LOW


def _failed(stack: Mapping[str, Any]) -> bool:
    return stack.get("status") == "failed"


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def unverified_reason(code: str | None) -> str:
    """A reason code as words, passing an unknown code through."""
    if code is None:
        return ""
    return UNVERIFIED_REASONS.get(code, code)


__all__ = [
    "COMPARE_SCHEMA_VERSION",
    "CompareError",
    "Comparison",
    "Delta",
    "Entry",
    "ReportFile",
    "UNVERIFIED_REASONS",
    "compare",
    "load_report",
    "parse_report",
    "unverified_reason",
]
