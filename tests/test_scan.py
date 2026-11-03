"""Scan orchestration, exit codes, and the invariant that matters most.

A stack that could not be checked must never be reported as clean. These
tests drive the orchestrator with a fake Terraform runner so every failure
mode — a failed init, a failed plan, malformed JSON, an unexpected
exception — can be exercised without a cloud account.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from crosswind.core import scan as scan_module
from crosswind.core.config import Config
from crosswind.core.discover import Stack
from crosswind.core.findings import Severity, StackStatus
from crosswind.core.scan import (
    EXIT_CLEAN,
    EXIT_DRIFT,
    EXIT_ERROR,
    ScanRequest,
    scan,
)
from crosswind.core.severity import load_rules
from crosswind.core.terraform import Binary, Completed, TerraformError

BINARY = Binary(path=Path("/usr/bin/terraform"), flavour="terraform", version="1.15.8")


def drift_payload(address: str = "aws_security_group.web") -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.15.8",
        "resource_drift": [
            {
                "address": address,
                "mode": "managed",
                "type": "aws_security_group",
                "name": "web",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {
                    "actions": ["update"],
                    "before": {"id": "sg-abc", "ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]},
                    "after": {"id": "sg-abc", "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
                    "before_sensitive": {},
                    "after_sensitive": {},
                },
            }
        ],
    }


CLEAN_PAYLOAD = {"format_version": "1.2", "terraform_version": "1.15.8"}


class FakeRunner:
    """Stands in for `Runner` without starting a process.

    Behaviour is chosen per stack path, so one scan can mix a clean stack, a
    drifted one and a broken one — which is the case that matters.
    """

    def __init__(self, behaviour: dict[str, Any], binary: Binary, workspace: Any) -> None:
        self.behaviour = behaviour
        self.binary = binary
        self.workspace = workspace

    def _for(self, stack: Path) -> Any:
        return self.behaviour.get(stack.name, CLEAN_PAYLOAD)

    def init(self, stack: Path) -> Completed:
        spec = self._for(stack)
        if isinstance(spec, dict) and spec.get("_init_fails"):
            return Completed(args=("init",), returncode=1, stdout="", stderr=spec["_init_fails"])
        return Completed(args=("init",), returncode=0, stdout="", stderr="")

    def plan_refresh_only(self, stack: Path, *, out: Path, var_files: Any = ()) -> Completed:
        spec = self._for(stack)
        if isinstance(spec, dict) and spec.get("_plan_fails"):
            return Completed(args=("plan",), returncode=1, stdout="", stderr=spec["_plan_fails"])
        if isinstance(spec, dict) and spec.get("_raises"):
            raise TerraformError(spec["_raises"])
        if isinstance(spec, dict) and spec.get("_explodes"):
            raise RuntimeError(spec["_explodes"])
        out.write_text("fake plan")
        return Completed(args=("plan",), returncode=0, stdout="", stderr="")

    def show_plan_json(self, stack: Path, plan: Path) -> dict[str, Any]:
        spec = self._for(stack)
        if isinstance(spec, dict) and spec.get("_malformed"):
            return spec["_malformed"]
        return spec if isinstance(spec, dict) else CLEAN_PAYLOAD


@pytest.fixture()
def fake_runner(monkeypatch: pytest.MonkeyPatch):
    """Install a `FakeRunner` factory with a per-test behaviour table."""

    def install(behaviour: dict[str, Any]) -> None:
        monkeypatch.setattr(
            scan_module,
            "Runner",
            lambda binary, workspace, **kwargs: FakeRunner(behaviour, binary, workspace),
        )

    return install


def make_request(tmp_path: Path, names: list[str], **config_kwargs: Any) -> ScanRequest:
    stacks = []
    for name in names:
        path = tmp_path / name
        path.mkdir(parents=True, exist_ok=True)
        (path / "main.tf").write_text("# tf\n")
        stacks.append(Stack(path=path, reason="test"))
    return ScanRequest(
        stacks=stacks,
        binary=BINARY,
        rules=load_rules(),
        config=Config(**config_kwargs),
        root=tmp_path,
    )


# --- the happy paths ----------------------------------------------------


def test_a_clean_stack_is_clean_and_exits_zero(tmp_path: Path, fake_runner) -> None:
    fake_runner({"prod": CLEAN_PAYLOAD})
    report = scan(make_request(tmp_path, ["prod"]))
    assert [stack.status for stack in report.stacks] == [StackStatus.CLEAN]
    assert report.exit_code == EXIT_CLEAN
    assert report.findings == ()


def test_drift_is_found_and_exits_one(tmp_path: Path, fake_runner) -> None:
    fake_runner({"prod": drift_payload()})
    report = scan(make_request(tmp_path, ["prod"]))
    assert [stack.status for stack in report.stacks] == [StackStatus.DRIFTED]
    assert report.exit_code == EXIT_DRIFT
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.address == "aws_security_group.web"
    assert finding.severity is Severity.CRITICAL
    assert finding.severity_rule == "sg-ingress-public"


def test_several_stacks_are_scanned_and_sorted(tmp_path: Path, fake_runner) -> None:
    fake_runner({"a": drift_payload(), "b": CLEAN_PAYLOAD, "c": drift_payload()})
    report = scan(make_request(tmp_path, ["c", "a", "b"], concurrency=3))
    assert [stack.path for stack in report.stacks] == ["a", "b", "c"]


# --- the invariant ------------------------------------------------------


def test_a_failed_init_is_reported_as_could_not_check_not_clean(
    tmp_path: Path, fake_runner
) -> None:
    fake_runner({"prod": {"_init_fails": "Error: provider not found"}})
    report = scan(make_request(tmp_path, ["prod"]))
    assert report.stacks[0].status is StackStatus.FAILED
    assert report.stacks[0].error
    assert report.clean_stacks == ()
    assert report.exit_code == EXIT_ERROR


def test_a_failed_plan_is_reported_as_could_not_check(tmp_path: Path, fake_runner) -> None:
    fake_runner({"prod": {"_plan_fails": "Error: no valid credential sources"}})
    report = scan(make_request(tmp_path, ["prod"]))
    assert report.stacks[0].status is StackStatus.FAILED
    assert "credential" in (report.stacks[0].error or "")
    assert report.exit_code == EXIT_ERROR


def test_malformed_plan_json_fails_the_stack_rather_than_reading_as_clean(
    tmp_path: Path, fake_runner
) -> None:
    """The most dangerous bug this tool could have.

    A plan we cannot parse has an absent `resource_drift` key, exactly like a
    clean stack. The parser's strictness is what keeps these distinguishable.
    """
    fake_runner({"prod": {"_malformed": {"nonsense": True}}})
    report = scan(make_request(tmp_path, ["prod"]))
    assert report.stacks[0].status is StackStatus.FAILED
    assert report.exit_code == EXIT_ERROR


def test_a_terraform_error_fails_only_its_own_stack(tmp_path: Path, fake_runner) -> None:
    """One broken stack must not take the scan down with it."""
    fake_runner(
        {
            "broken": {"_raises": "terraform exploded"},
            "drifted": drift_payload(),
            "fine": CLEAN_PAYLOAD,
        }
    )
    report = scan(make_request(tmp_path, ["broken", "drifted", "fine"], concurrency=3))
    statuses = {stack.path: stack.status for stack in report.stacks}
    assert statuses == {
        "broken": StackStatus.FAILED,
        "drifted": StackStatus.DRIFTED,
        "fine": StackStatus.CLEAN,
    }
    assert len(report.findings) == 1


def test_an_unexpected_exception_still_becomes_a_failed_stack(tmp_path: Path, fake_runner) -> None:
    """Including a bug of ours. The alternative is a crash with no report."""
    fake_runner({"prod": {"_explodes": "a bug nobody expected"}})
    report = scan(make_request(tmp_path, ["prod"]))
    assert report.stacks[0].status is StackStatus.FAILED
    assert "a bug nobody expected" in (report.stacks[0].error or "")


def test_drift_and_a_failure_together_exit_two_and_still_report(
    tmp_path: Path, fake_runner
) -> None:
    """2 beats 1: a report with a hole in it is the more urgent situation.

    And the report is still written, which is the other half of the promise.
    """
    fake_runner({"broken": {"_init_fails": "boom"}, "drifted": drift_payload()})
    report = scan(make_request(tmp_path, ["broken", "drifted"], concurrency=2))
    assert report.exit_code == EXIT_ERROR
    assert len(report.reportable) == 1, "the drift we could see is still reported"
    assert len(report.failed_stacks) == 1


def test_a_missing_lock_file_error_explains_the_fix(tmp_path: Path, fake_runner) -> None:
    """`-lockfile=readonly` fails on a stack nobody has init'd.

    Terraform's own message talks about dependency changes rather than the
    missing file, so Crosswind says what to actually do.
    """
    fake_runner(
        {
            "prod": {
                "_init_fails": (
                    "Error: Provider dependency changes detected\nthe lock file is read-only"
                )
            }
        }
    )
    report = scan(make_request(tmp_path, ["prod"]))
    error = report.stacks[0].error or ""
    assert "terraform init" in error
    assert "will not modify your working tree" in error


# --- thresholds ---------------------------------------------------------


def test_min_severity_filters_what_is_reported(tmp_path: Path, fake_runner) -> None:
    fake_runner({"prod": _tag_drift()})
    request = make_request(tmp_path, ["prod"], min_severity=Severity.HIGH)
    report = scan(request)
    assert len(report.findings) == 1, "the finding is still found"
    assert report.reportable == (), "but not reported at this threshold"
    assert report.exit_code == EXIT_CLEAN


def test_min_severity_low_reports_everything(tmp_path: Path, fake_runner) -> None:
    fake_runner({"prod": _tag_drift()})
    report = scan(make_request(tmp_path, ["prod"], min_severity=Severity.LOW))
    assert len(report.reportable) == 1
    assert report.exit_code == EXIT_DRIFT


def _tag_drift() -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.15.8",
        "resource_drift": [
            {
                "address": "aws_instance.web",
                "mode": "managed",
                "type": "aws_instance",
                "name": "web",
                "change": {
                    "actions": ["update"],
                    "before": {"id": "i-abc", "tags": {"Owner": "alice"}},
                    "after": {"id": "i-abc", "tags": {"Owner": "bob"}},
                    "before_sensitive": {},
                    "after_sensitive": {},
                },
            }
        ],
    }


# --- ignore rules -------------------------------------------------------


def test_ignored_findings_are_counted_not_dropped(tmp_path: Path, fake_runner) -> None:
    fake_runner({"prod": drift_payload()})
    request = make_request(tmp_path, ["prod"])
    (request.root / ".crosswindignore").write_text("aws_security_group.*  ingress.*\n")
    report = scan(request)
    assert report.findings == ()
    assert report.ignored_total == 1
    assert report.stacks[0].status is StackStatus.CLEAN
    assert report.to_dict()["summary"]["findings_ignored"] == 1


# --- the report object --------------------------------------------------


def test_report_serialises_to_a_versioned_schema(tmp_path: Path, fake_runner) -> None:
    fake_runner({"prod": drift_payload()})
    report = scan(make_request(tmp_path, ["prod"]))
    payload = report.to_dict()
    assert payload["schema_version"] == scan_module.SCHEMA_VERSION
    assert payload["tool"] == "crosswind"
    assert payload["summary"]["exit_code"] == EXIT_DRIFT
    assert payload["summary"]["stacks_failed"] == 0
    # It must actually be JSON-serialisable, not merely dict-shaped.
    assert json.loads(json.dumps(payload))["findings"][0]["severity"] == "critical"


def test_every_finding_carries_its_rule_and_an_attribution(tmp_path: Path, fake_runner) -> None:
    fake_runner({"prod": drift_payload()})
    report = scan(make_request(tmp_path, ["prod"]))
    finding = report.findings[0]
    assert finding.severity_rule
    assert finding.severity_reason
    assert finding.recommendation_reason
    # Attribution was not run, so it must say unknown and name nobody.
    assert finding.attribution.actor is None
    assert finding.attribution.known is False


def test_attribution_disabled_is_stated_once_in_the_report(tmp_path: Path, fake_runner) -> None:
    fake_runner({"prod": drift_payload()})
    report = scan(make_request(tmp_path, ["prod"], attribution=False))
    assert report.attribution_note
    assert "unknown" in report.attribution_note


def test_an_empty_scan_is_clean_rather_than_an_error(tmp_path: Path, fake_runner) -> None:
    """No stacks found is not a failure, but the caller should be able to tell."""
    fake_runner({})
    report = scan(make_request(tmp_path, []))
    assert report.stacks == ()
    assert report.exit_code == EXIT_CLEAN


def test_counts_cover_all_four_severities(tmp_path: Path, fake_runner) -> None:
    """So a chart never has a missing key."""
    fake_runner({"prod": drift_payload()})
    report = scan(make_request(tmp_path, ["prod"]))
    assert set(report.counts) == {"critical", "high", "medium", "low"}


def test_a_cost_estimate_is_attached_where_one_is_defensible(tmp_path: Path, fake_runner) -> None:
    fake_runner(
        {
            "prod": {
                "format_version": "1.2",
                "terraform_version": "1.15.8",
                "resource_drift": [
                    {
                        "address": "aws_instance.web",
                        "mode": "managed",
                        "type": "aws_instance",
                        "name": "web",
                        "change": {
                            "actions": ["update"],
                            "before": {"id": "i-abc", "instance_type": "t3.micro"},
                            "after": {"id": "i-abc", "instance_type": "m5.2xlarge"},
                            "before_sensitive": {},
                            "after_sensitive": {},
                        },
                    }
                ],
            }
        }
    )
    report = scan(make_request(tmp_path, ["prod"]))
    cost = report.findings[0].cost
    assert cost is not None
    assert cost.monthly_usd > 0
    assert "upper bound" in cost.basis
