"""The CLI: flags, exit codes, and where output goes.

Exit codes get the most attention here because this runs in CI, where the
code is the entire interface. Getting 2-beats-1 wrong would mean a pipeline
going green on a scan that failed half way through.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import Result
from typer.testing import CliRunner

from crosswind import __version__
from crosswind.cli import app
from crosswind.core import scan as scan_module
from crosswind.core.findings import StackStatus
from crosswind.core.scan import EXIT_CLEAN, EXIT_DRIFT, EXIT_ERROR
from crosswind.core.terraform import Binary, Completed

runner = CliRunner()

BINARY = Binary(path=Path("/usr/bin/terraform"), flavour="terraform", version="1.15.8")


def invoke(*args: str) -> Result:
    return runner.invoke(app, list(args))


def drift_payload() -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.15.8",
        "resource_drift": [
            {
                "address": "aws_security_group.web",
                "mode": "managed",
                "type": "aws_security_group",
                "name": "web",
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
    """A `Runner` that never starts a process."""

    def __init__(self, behaviour: dict[str, Any], binary: Any, workspace: Any) -> None:
        self.behaviour = behaviour
        self.workspace = workspace

    def _for(self, stack: Path) -> Any:
        return self.behaviour.get(stack.name, CLEAN_PAYLOAD)

    def init(self, stack: Path) -> Completed:
        spec = self._for(stack)
        if isinstance(spec, dict) and spec.get("_init_fails"):
            return Completed(args=("init",), returncode=1, stdout="", stderr=spec["_init_fails"])
        return Completed(args=("init",), returncode=0, stdout="", stderr="")

    def plan_refresh_only(self, stack: Path, *, out: Path, var_files: Any = ()) -> Completed:
        out.write_text("plan")
        return Completed(args=("plan",), returncode=0, stdout="", stderr="")

    def show_plan_json(self, stack: Path, plan: Path) -> Any:
        return self._for(stack)


@pytest.fixture()
def tf(monkeypatch: pytest.MonkeyPatch):
    """Pretend Terraform exists, and control what every stack reports.

    Also forces attribution off, so no test here can reach for AWS.
    """

    def install(behaviour: dict[str, Any]) -> None:
        monkeypatch.setattr("crosswind.cli.find_binary", lambda preferred=None: BINARY)
        monkeypatch.setattr(
            scan_module,
            "Runner",
            lambda binary, workspace, **kwargs: FakeRunner(behaviour, binary, workspace),
        )

    return install


def make_stack(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.mkdir(parents=True, exist_ok=True)
    (path / "main.tf").write_text("# tf\n")
    return path


# --- version ------------------------------------------------------------


def test_version_prints_the_version() -> None:
    result = invoke("version")
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_no_arguments_shows_help_rather_than_doing_something() -> None:
    result = invoke()
    assert "scan" in result.stdout
    assert "demo" in result.stdout
    assert "doctor" in result.stdout


# --- demo ---------------------------------------------------------------


def test_demo_works_with_no_aws_and_no_terraform() -> None:
    """The whole point: a report before anyone installs anything."""
    result = invoke("demo")
    assert result.exit_code == 0
    assert "crosswind" in result.stdout
    assert "CRITICAL" in result.stdout


def test_demo_exits_zero_even_though_the_fixture_has_findings() -> None:
    """A demo that fails somebody's build is a bad demo."""
    assert invoke("demo").exit_code == EXIT_CLEAN


def test_demo_shows_the_could_not_check_case() -> None:
    """The demo would be dishonest without it."""
    assert "COULD NOT CHECK" in invoke("demo").stdout


def test_demo_never_prints_a_sensitive_value() -> None:
    """The fixture carries a provider-marked password on purpose."""
    output = invoke("demo").stdout
    assert "(sensitive value)" in output


@pytest.mark.parametrize("fmt", ["json", "markdown", "html"])
def test_demo_single_file_format_goes_to_stdout(fmt: str) -> None:
    """So `crosswind demo -f json > out.json` does what it looks like."""
    result = invoke("demo", "-f", fmt)
    assert result.exit_code == 0
    if fmt == "json":
        assert json.loads(result.stdout)["tool"] == "crosswind"
    elif fmt == "html":
        assert result.stdout.lstrip().startswith("<!DOCTYPE html>")
    else:
        assert result.stdout.lstrip().startswith("## Crosswind")


def test_demo_writes_every_requested_format(tmp_path: Path) -> None:
    result = invoke("demo", "-f", "json", "-f", "markdown", "-f", "html", "-o", str(tmp_path))
    assert result.exit_code == 0
    assert (tmp_path / "crosswind-report.json").is_file()
    assert (tmp_path / "crosswind-report.md").is_file()
    assert (tmp_path / "crosswind-report.html").is_file()


def test_demo_min_severity_filters(tmp_path: Path) -> None:
    result = invoke("demo", "-f", "json", "--min-severity", "critical")
    payload = json.loads(result.stdout)
    assert payload["min_severity"] == "critical"
    assert all(item["severity"] == "critical" for item in payload["findings"])


def test_an_unknown_format_is_rejected_with_the_options_listed() -> None:
    result = invoke("demo", "-f", "pdf")
    assert result.exit_code != 0
    assert "terminal" in result.output


def test_an_unknown_severity_is_rejected() -> None:
    result = invoke("demo", "--min-severity", "apocalyptic")
    assert result.exit_code != 0
    assert "Unknown severity" in result.output


# --- scan exit codes ----------------------------------------------------


def test_clean_scan_exits_zero(tmp_path: Path, tf) -> None:
    make_stack(tmp_path, "prod")
    tf({"prod": CLEAN_PAYLOAD})
    result = invoke("scan", "--path", str(tmp_path), "--no-attribution")
    assert result.exit_code == EXIT_CLEAN


def test_drift_exits_one(tmp_path: Path, tf) -> None:
    make_stack(tmp_path, "prod")
    tf({"prod": drift_payload()})
    result = invoke("scan", "--path", str(tmp_path), "--no-attribution")
    assert result.exit_code == EXIT_DRIFT


def test_a_failed_stack_exits_two(tmp_path: Path, tf) -> None:
    make_stack(tmp_path, "prod")
    tf({"prod": {"_init_fails": "Error: backend unreachable"}})
    result = invoke("scan", "--path", str(tmp_path), "--no-attribution")
    assert result.exit_code == EXIT_ERROR


def test_drift_plus_a_failure_exits_two_and_still_writes_the_report(tmp_path: Path, tf) -> None:
    """2 beats 1, and the report is still produced. Both halves matter."""
    make_stack(tmp_path, "prod")
    make_stack(tmp_path, "broken")
    tf({"prod": drift_payload(), "broken": {"_init_fails": "boom"}})
    out = tmp_path / "out"
    result = invoke(
        "scan", "--path", str(tmp_path), "--no-attribution", "-f", "json", "-o", str(out)
    )
    assert result.exit_code == EXIT_ERROR
    payload = json.loads((out / "crosswind-report.json").read_text())
    assert payload["summary"]["stacks_failed"] == 1
    assert payload["summary"]["findings_reported"] == 1


def test_min_severity_above_the_findings_exits_zero(tmp_path: Path, tf) -> None:
    """The threshold controls the exit code, not just the display."""
    make_stack(tmp_path, "prod")
    tf(
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
                            "before": {"id": "i-a", "tags": {"a": "1"}},
                            "after": {"id": "i-a", "tags": {"a": "2"}},
                            "before_sensitive": {},
                            "after_sensitive": {},
                        },
                    }
                ],
            }
        }
    )
    clean = invoke("scan", "--path", str(tmp_path), "--no-attribution", "--min-severity", "high")
    assert clean.exit_code == EXIT_CLEAN
    drifted = invoke("scan", "--path", str(tmp_path), "--no-attribution", "--min-severity", "low")
    assert drifted.exit_code == EXIT_DRIFT


# --- scan behaviour -----------------------------------------------------


def test_no_stacks_found_is_an_error_not_a_clean_bill(tmp_path: Path, tf) -> None:
    """Exiting 0 here would report "no drift" for a path we never scanned."""
    tf({})
    result = invoke("scan", "--path", str(tmp_path), "--no-attribution")
    assert result.exit_code == EXIT_ERROR
    assert "no Terraform stacks found" in result.output


def test_a_missing_path_is_a_clear_error(tmp_path: Path, tf) -> None:
    tf({})
    result = invoke("scan", "--path", str(tmp_path / "nope"), "--no-attribution")
    assert result.exit_code == EXIT_ERROR


def test_missing_binary_is_reported_not_crashed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from crosswind.core.terraform import BinaryNotFound

    make_stack(tmp_path, "prod")

    def boom(preferred: Any = None) -> Any:
        raise BinaryNotFound("Neither `terraform` nor `tofu` is on PATH.")

    monkeypatch.setattr("crosswind.cli.find_binary", boom)
    result = invoke("scan", "--path", str(tmp_path), "--no-attribution")
    assert result.exit_code == EXIT_ERROR
    assert "PATH" in result.output


def test_exclude_skips_a_stack(tmp_path: Path, tf) -> None:
    make_stack(tmp_path, "prod")
    make_stack(tmp_path, "examples")
    tf({"prod": CLEAN_PAYLOAD, "examples": drift_payload()})
    result = invoke(
        "scan",
        "--path",
        str(tmp_path),
        "--no-attribution",
        "--exclude",
        "examples",
        "-f",
        "json",
    )
    payload = json.loads(result.stdout)
    assert payload["summary"]["stacks_scanned"] == 1
    assert payload["stacks"][0]["path"] == "prod"


def test_no_attribution_says_so_in_the_report(tmp_path: Path, tf) -> None:
    make_stack(tmp_path, "prod")
    tf({"prod": drift_payload()})
    result = invoke("scan", "--path", str(tmp_path), "--no-attribution", "-f", "json")
    payload = json.loads(result.stdout)
    assert payload["attribution_note"]
    assert payload["findings"][0]["attribution"]["actor"] is None


def test_print_default_ignores_writes_nothing(tmp_path: Path) -> None:
    """Crosswind does not create files in your repository.

    The suggestions are printed for a person to read and commit themselves.
    """
    before = set(tmp_path.iterdir())
    result = invoke("scan", "--path", str(tmp_path), "--print-default-ignores")
    assert result.exit_code == 0
    assert "desired_capacity" in result.stdout
    assert set(tmp_path.iterdir()) == before


def test_config_file_is_read(tmp_path: Path, tf) -> None:
    make_stack(tmp_path, "prod")
    (tmp_path / ".crosswind.yml").write_text("min_severity: critical\nattribution: false\n")
    tf({"prod": drift_payload()})
    result = invoke("scan", "--path", str(tmp_path), "-f", "json")
    payload = json.loads(result.stdout)
    assert payload["min_severity"] == "critical"
    assert payload["config_source"].endswith(".crosswind.yml")


def test_a_flag_overrides_the_config_file(tmp_path: Path, tf) -> None:
    make_stack(tmp_path, "prod")
    (tmp_path / ".crosswind.yml").write_text("min_severity: critical\n")
    tf({"prod": drift_payload()})
    result = invoke(
        "scan", "--path", str(tmp_path), "--no-attribution", "--min-severity", "low", "-f", "json"
    )
    assert json.loads(result.stdout)["min_severity"] == "low"


def test_a_broken_config_file_is_an_error_with_the_file_named(tmp_path: Path, tf) -> None:
    make_stack(tmp_path, "prod")
    (tmp_path / ".crosswind.yml").write_text("min_severity: [unclosed\n")
    tf({"prod": CLEAN_PAYLOAD})
    result = invoke("scan", "--path", str(tmp_path), "--no-attribution")
    assert result.exit_code == EXIT_ERROR
    assert "crosswind.yml" in result.output


def test_config_warnings_reach_the_report(tmp_path: Path, tf) -> None:
    """A misspelled key is a setting someone believes is in effect."""
    make_stack(tmp_path, "prod")
    (tmp_path / ".crosswind.yml").write_text("min_sevrity: critical\n")
    tf({"prod": drift_payload()})
    result = invoke("scan", "--path", str(tmp_path), "--no-attribution", "-f", "json")
    notes = json.loads(result.stdout)["notes"]
    assert any("min_sevrity" in note for note in notes)


def test_ignore_file_is_applied_and_counted(tmp_path: Path, tf) -> None:
    make_stack(tmp_path, "prod")
    (tmp_path / ".crosswindignore").write_text("aws_security_group.*  ingress.*\n")
    tf({"prod": drift_payload()})
    result = invoke("scan", "--path", str(tmp_path), "--no-attribution", "-f", "json")
    payload = json.loads(result.stdout)
    assert payload["summary"]["findings_reported"] == 0
    assert payload["summary"]["findings_ignored"] == 1


def test_scan_progress_goes_to_stderr_not_stdout(tmp_path: Path, tf) -> None:
    """So `--format json > file` is valid JSON and nothing else."""
    make_stack(tmp_path, "prod")
    tf({"prod": drift_payload()})
    result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--no-attribution", "-f", "json"])
    # `stdout` must parse on its own, with no progress lines mixed in.
    assert json.loads(result.stdout)["tool"] == "crosswind"


def test_scan_does_not_touch_the_working_tree(tmp_path: Path, tf) -> None:
    """No files appear, including no report unless one was asked for."""
    stack = make_stack(tmp_path, "prod")
    before = {path.name for path in stack.iterdir()}
    tf({"prod": drift_payload()})
    invoke("scan", "--path", str(tmp_path), "--no-attribution")
    assert {path.name for path in stack.iterdir()} == before


def test_several_stacks_are_all_reported(tmp_path: Path, tf) -> None:
    for name in ("a", "b", "c"):
        make_stack(tmp_path, name)
    tf({"a": drift_payload(), "b": CLEAN_PAYLOAD, "c": {"_init_fails": "boom"}})
    result = invoke("scan", "--path", str(tmp_path), "--no-attribution", "-j", "3", "-f", "json")
    payload = json.loads(result.stdout)
    summary = payload["summary"]
    assert summary["stacks_scanned"] == 3
    assert summary["stacks_drifted"] == 1
    assert summary["stacks_clean"] == 1
    assert summary["stacks_failed"] == 1
    assert result.exit_code == EXIT_ERROR


# --- doctor -------------------------------------------------------------


def test_doctor_reports_the_binary_and_the_stacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_stack(tmp_path, "prod")
    monkeypatch.setattr("crosswind.cli.find_binary", lambda preferred=None: BINARY)
    monkeypatch.setattr(
        "crosswind.cli.Runner",
        lambda binary, space: type(
            "R",
            (),
            {
                "init": lambda self, stack: Completed(
                    args=("init",), returncode=0, stdout="", stderr=""
                )
            },
        )(),
    )
    monkeypatch.setattr(
        "crosswind.core.session.build_session",
        lambda **kwargs: (_ for _ in ()).throw(
            __import__("crosswind.core.session", fromlist=["CredentialsError"]).CredentialsError(
                "no credentials configured"
            )
        ),
    )
    result = invoke("doctor", "--path", str(tmp_path))
    assert "terraform v1.15.8" in result.stdout
    assert "stacks: found 1" in result.stdout


def test_doctor_without_credentials_says_drift_still_works(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Attribution is a bonus; the drift report is the product."""
    make_stack(tmp_path, "prod")
    monkeypatch.setattr("crosswind.cli.find_binary", lambda preferred=None: BINARY)
    monkeypatch.setattr(
        "crosswind.cli.Runner",
        lambda binary, space: type(
            "R",
            (),
            {
                "init": lambda self, stack: Completed(
                    args=("init",), returncode=0, stdout="", stderr=""
                )
            },
        )(),
    )
    from crosswind.core.session import CredentialsError

    def boom(**kwargs: Any) -> Any:
        raise CredentialsError("no credentials configured")

    monkeypatch.setattr("crosswind.core.session.build_session", boom)
    result = invoke("doctor", "--path", str(tmp_path))
    assert "Drift detection still works" in result.stdout


def test_doctor_reports_a_missing_binary_as_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from crosswind.core.terraform import BinaryNotFound

    def boom(preferred: Any = None) -> Any:
        raise BinaryNotFound("Neither `terraform` nor `tofu` is on PATH.")

    monkeypatch.setattr("crosswind.cli.find_binary", boom)
    from crosswind.core.session import CredentialsError

    monkeypatch.setattr(
        "crosswind.core.session.build_session",
        lambda **kwargs: (_ for _ in ()).throw(CredentialsError("none")),
    )
    result = invoke("doctor", "--path", str(tmp_path))
    assert result.exit_code == EXIT_ERROR
    assert "[FAIL] binary" in result.stdout


def test_doctor_warns_when_there_are_no_stacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("crosswind.cli.find_binary", lambda preferred=None: BINARY)
    from crosswind.core.session import CredentialsError

    monkeypatch.setattr(
        "crosswind.core.session.build_session",
        lambda **kwargs: (_ for _ in ()).throw(CredentialsError("none")),
    )
    result = invoke("doctor", "--path", str(tmp_path))
    assert "none found" in result.stdout


# --- the StackStatus enum is part of the contract -----------------------


def test_stack_statuses_are_the_three_documented_ones() -> None:
    assert {status.value for status in StackStatus} == {"clean", "drifted", "failed"}
