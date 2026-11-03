"""Running the scan: stacks in, a report out.

The invariant this module exists to hold: **a stack that could not be
checked is never reported as clean.** Every failure path produces a
`StackResult` with `status=FAILED` and the error attached, the summary counts
those separately, and the exit code is 2 whether or not drift was also found.

Getting that wrong would make Crosswind worse than nothing: a team that runs
a drift checker every morning and sees "no drift" will stop looking, and a
stack that has been silently failing for a month is exactly where the drift
will be.

Concurrency is threads rather than processes, because the work is almost
entirely waiting — for Terraform to talk to a provider, for CloudTrail to
answer. Each stack gets its own `Workspace`, so two stacks can never share a
`TF_DATA_DIR` and race over provider installation.

Attribution runs **after** all the stacks, on the main thread, in one pass.
CloudTrail's rate limit is per account, so doing it per stack in parallel
would mean several threads discovering the same limit at once; one pass over
all findings also lets the cache do its job across stacks that share a
security group.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from crosswind.core import cost as cost_module
from crosswind.core import ignore as ignore_module
from crosswind.core.attribution.lookup import Lookup, NullLookup
from crosswind.core.attribution.mapping import Mapping, load_mapping
from crosswind.core.attribution.rank import attribute
from crosswind.core.config import Config
from crosswind.core.discover import Stack
from crosswind.core.findings import (
    Attribution,
    Finding,
    Severity,
    StackResult,
    StackStatus,
    count_by_severity,
    rank,
    stack_label,
)
from crosswind.core.plan import DriftedResource, MalformedPlan, parse_plan
from crosswind.core.redact import scrub_text
from crosswind.core.severity import RuleSet
from crosswind.core.terraform import Binary, Runner, TerraformError
from crosswind.core.workspace import workspace

#: Exit codes. 2 beats 1: if a stack failed and drift was found, the user
#: needs to know the report is incomplete more than they need to know there
#: is drift in the part we could read.
EXIT_CLEAN = 0
EXIT_DRIFT = 1
EXIT_ERROR = 2

SCHEMA_VERSION = "1.0"


@dataclass
class Report:
    """Everything a renderer needs. A pure value, built once.

    All four output formats are pure functions of this object, which is what
    makes it possible to assert that a secret absent from here is absent from
    every format.
    """

    stacks: tuple[StackResult, ...]
    started_at: datetime
    finished_at: datetime
    min_severity: Severity
    #: The binary that ran, for the header. `None` when nothing ran (demo).
    binary: str | None = None
    #: Account and identity, when we had credentials. Never the credentials.
    account: str | None = None
    identity: str | None = None
    #: Non-fatal things the user should know: config warnings, attribution
    #: being unavailable, ignore files in effect.
    notes: tuple[str, ...] = ()
    #: Set when attribution was skipped or stopped working, so the report can
    #: say so once instead of on every finding.
    attribution_note: str | None = None
    config_source: str | None = None

    @property
    def findings(self) -> tuple[Finding, ...]:
        """Every finding from every stack, most severe first."""
        return rank([finding for stack in self.stacks for finding in stack.findings])

    @property
    def reportable(self) -> tuple[Finding, ...]:
        """Findings at or above the threshold."""
        return tuple(
            finding for finding in self.findings if finding.severity.at_least(self.min_severity)
        )

    @property
    def failed_stacks(self) -> tuple[StackResult, ...]:
        """The stacks we could not check. Never counted as clean."""
        return tuple(stack for stack in self.stacks if stack.status is StackStatus.FAILED)

    @property
    def drifted_stacks(self) -> tuple[StackResult, ...]:
        return tuple(stack for stack in self.stacks if stack.status is StackStatus.DRIFTED)

    @property
    def clean_stacks(self) -> tuple[StackResult, ...]:
        return tuple(stack for stack in self.stacks if stack.status is StackStatus.CLEAN)

    @property
    def ignored_total(self) -> int:
        return sum(stack.ignored for stack in self.stacks)

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def exit_code(self) -> int:
        """0 clean, 1 drift at or above the threshold, 2 something failed.

        2 wins over 1 deliberately. A report with a hole in it is a different
        situation from a report with findings in it, and the more urgent one.
        """
        if self.failed_stacks:
            return EXIT_ERROR
        if self.reportable:
            return EXIT_DRIFT
        return EXIT_CLEAN

    @property
    def counts(self) -> dict[str, int]:
        return count_by_severity(self.reportable)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": "crosswind",
            "generated_at": self.finished_at.isoformat(),
            "started_at": self.started_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 2),
            "binary": self.binary,
            "account": self.account,
            "identity": self.identity,
            "config_source": self.config_source,
            "min_severity": self.min_severity.value,
            "summary": {
                "stacks_scanned": len(self.stacks),
                "stacks_clean": len(self.clean_stacks),
                "stacks_drifted": len(self.drifted_stacks),
                "stacks_failed": len(self.failed_stacks),
                "findings_total": len(self.findings),
                "findings_reported": len(self.reportable),
                "findings_ignored": self.ignored_total,
                "by_severity": self.counts,
                "exit_code": self.exit_code,
            },
            "attribution_note": self.attribution_note,
            "notes": list(self.notes),
            "stacks": [stack.to_dict() for stack in self.stacks],
            "findings": [finding.to_dict() for finding in self.reportable],
        }


@dataclass
class ScanRequest:
    """What to scan, and with what.

    A value object rather than fifteen arguments, mostly so the CLI and the
    tests construct a scan the same way.
    """

    stacks: Sequence[Stack]
    binary: Binary
    rules: RuleSet
    config: Config
    root: Path
    lookup: Lookup = field(default_factory=NullLookup)
    mapping: Mapping | None = None
    session_region: str | None = None
    notes: tuple[str, ...] = ()
    account: str | None = None
    identity: str | None = None


@dataclass(frozen=True)
class _StackScan:
    """A stack's result plus the parsed resources behind it.

    The resources carry the unredacted prior state, which is what the
    CloudTrail mapping needs to find a lookup value — and exactly what must
    never reach a `Finding`, since a `Finding` is what gets serialised. So
    they travel beside the result for the length of the scan and are dropped
    before a `Report` is built.
    """

    result: StackResult
    resources: tuple[DriftedResource, ...] = ()


def scan(request: ScanRequest) -> Report:
    """Scan every stack, then attribute the findings.

    Never raises for a per-stack failure: those become `FAILED` results. It
    can still raise for something that makes the whole run impossible, which
    the CLI turns into exit code 2.
    """
    started = datetime.now(UTC)
    workers = max(1, min(request.config.concurrency, len(request.stacks) or 1))

    scans: list[_StackScan] = []
    if request.stacks:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="crosswind") as pool:
            scans = list(pool.map(lambda stack: _scan_stack(stack, request), request.stacks))

    scans = sorted(scans, key=lambda scanned: scanned.result.path)
    results, attribution_note = _attribute_all(scans, request)

    return Report(
        stacks=tuple(results),
        started_at=started,
        finished_at=datetime.now(UTC),
        min_severity=request.config.min_severity,
        binary=request.binary.label,
        account=request.account,
        identity=request.identity,
        notes=request.notes,
        attribution_note=attribution_note,
        config_source=request.config.source,
    )


def _scan_stack(stack: Stack, request: ScanRequest) -> _StackScan:
    """One stack, start to finish, with every failure captured.

    The broad `except` is the point of this function. Anything that goes
    wrong here — Terraform missing, a provider erroring, a malformed plan, a
    permission problem, a bug of ours — has to come out as `FAILED` with a
    message, because the alternative is a stack that silently reads as clean.
    """
    label = stack_label(stack.path, request.root)
    started = time.monotonic()

    try:
        with workspace(prefix="crosswind-scan-") as space:
            runner = Runner(request.binary, space)

            init = runner.init(stack.path)
            if not init.ok:
                return _failed(label, _init_error(init.stderr or init.stdout), request, started)

            plan_path = space.plan_path(label)
            planned = runner.plan_refresh_only(
                stack.path,
                out=plan_path,
                var_files=tuple(request.config.var_files),
            )
            if not planned.ok:
                return _failed(
                    label, scrub_text(planned.stderr or planned.stdout), request, started
                )

            payload = runner.show_plan_json(stack.path, plan_path)
            summary = parse_plan(payload)

    except (TerraformError, MalformedPlan) as exc:
        return _failed(label, scrub_text(str(exc)), request, started)
    except OSError as exc:
        return _failed(label, scrub_text(f"Could not read the stack: {exc}"), request, started)
    except Exception as exc:  # noqa: BLE001 - see the docstring
        return _failed(
            label, scrub_text(f"Unexpected error while scanning: {exc!r}"), request, started
        )

    ignores = ignore_module.load(stack.path, extra_roots=[request.root])
    kept, suppressed = ignore_module.filter_all(summary.drift, ignores)

    findings = tuple(_to_finding(resource, label, request) for resource in kept)
    status = StackStatus.DRIFTED if findings else StackStatus.CLEAN

    return _StackScan(
        result=StackResult(
            path=label,
            status=status,
            findings=findings,
            binary=f"{request.binary.flavour} v{summary.terraform_version}",
            ignored=suppressed,
            duration_seconds=time.monotonic() - started,
        ),
        resources=tuple(kept),
    )


def _failed(label: str, error: str, request: ScanRequest, started: float) -> _StackScan:
    """A stack we could not check. Never clean, never silent."""
    return _StackScan(
        result=StackResult(
            path=label,
            status=StackStatus.FAILED,
            error=error,
            binary=request.binary.label,
            duration_seconds=time.monotonic() - started,
        )
    )


def _init_error(output: str) -> str:
    """Make the most common `init` failure actionable.

    `-lockfile=readonly` means a stack with no `.terraform.lock.hcl` fails,
    and the error Terraform gives is about dependency changes rather than
    about the missing file. Since the fix is one command, say so.
    """
    scrubbed = scrub_text(output)
    if "lock file is read-only" in output or "lockfile" in output.lower():
        return (
            "Terraform needs to write a provider lock file, and Crosswind will "
            "not modify your working tree. Run `terraform init` (or `tofu init`) "
            "in this stack once, commit the .terraform.lock.hcl it creates, and "
            "scan again.\n\n" + scrubbed
        )
    return scrubbed


def _to_finding(resource: DriftedResource, label: str, request: ScanRequest) -> Finding:
    """Score and price one drifted resource. Attribution comes later."""
    verdict = request.rules.score(resource)
    return Finding(
        stack=label,
        address=resource.address,
        resource_type=resource.resource_type,
        kind=resource.kind,
        changes=resource.changes,
        severity=verdict.severity,
        severity_rule=verdict.rule_id,
        severity_reason=verdict.reason,
        recommendation=verdict.recommendation,
        recommendation_reason=verdict.recommendation_reason,
        attribution=Attribution.unknown("not_attempted"),
        provider=resource.provider,
        region=_region_of(resource),
        cost=cost_module.estimate(resource),
    )


def _region_of(resource: DriftedResource) -> str | None:
    """The resource's region, if its state says.

    Most AWS resources do not carry one as an attribute; it is derivable from
    an ARN when there is one. `None` means "use the session's region", which
    is what the lookup does.
    """
    state = resource.raw_before or resource.raw_after or {}
    arn = state.get("arn")
    if isinstance(arn, str) and arn.startswith("arn:"):
        parts = arn.split(":")
        if len(parts) > 3 and parts[3]:
            return parts[3]
    region = state.get("region") or state.get("availability_zone")
    if isinstance(region, str) and region:
        # `eu-west-1a` is an AZ; the region is the AZ without its letter.
        return region[:-1] if region[-1].isalpha() and region[-2].isdigit() else region
    return None


def _attribute_all(
    scans: Sequence[_StackScan], request: ScanRequest
) -> tuple[list[StackResult], str | None]:
    """Attribute every finding in one pass, on one thread.

    One pass rather than per-stack-in-parallel because CloudTrail's rate
    limit is per account: several threads would just discover the same limit
    at the same time. One pass also lets the cache help across stacks that
    share a resource.

    Each finding is matched back to the `DriftedResource` it came from by
    address, because that is where the unredacted prior state lives — and
    the prior state is what the mapping reads a lookup value out of.
    """
    results = [scanned.result for scanned in scans]
    if not request.config.attribution or isinstance(request.lookup, NullLookup):
        return results, "Attribution was not run, so every finding says `unknown`."

    mapping = request.mapping or load_mapping()
    updated: list[StackResult] = []
    reasons: set[str] = set()

    for scanned in scans:
        result = scanned.result
        if not result.findings:
            updated.append(result)
            continue
        by_address = {resource.address: resource for resource in scanned.resources}
        findings = []
        for finding in result.findings:
            resource = by_address.get(finding.address)
            if resource is None:  # pragma: no cover - addresses are unique
                findings.append(finding)
                continue
            attribution = attribute(
                resource,
                lookup=request.lookup,
                mapping=mapping,
                window_hours=request.config.cloudtrail_window_hours,
                region=finding.region,
                session_region=request.session_region,
            )
            if attribution.reason:
                reasons.add(attribution.reason)
            findings.append(replace(finding, attribution=attribution))
        updated.append(replace(result, findings=tuple(findings)))

    return updated, _attribution_note(reasons)


def _attribution_note(reasons: set[str]) -> str | None:
    """One sentence about why attribution did not work, when it did not."""
    if "lookup_denied" in reasons:
        return (
            "CloudTrail lookups were denied, so findings say `unknown`. The "
            "credentials need `cloudtrail:LookupEvents`."
        )
    if "credentials_expired" in reasons:
        return "AWS credentials expired during the scan, so attribution is incomplete."
    if "credentials_invalid" in reasons:
        return "AWS credentials were rejected, so findings say `unknown`."
    if "throttled" in reasons:
        return (
            "CloudTrail throttled the scan, so some findings say `unknown`. "
            "Re-running will usually attribute more of them."
        )
    if "unmapped_resource_type" in reasons:
        return (
            "Some resource types have no CloudTrail mapping yet, so those "
            "findings say `unknown`. See docs/attribution.md."
        )
    return None
