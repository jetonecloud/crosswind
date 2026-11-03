"""End-to-end, against a real Terraform or OpenTofu binary.

These tests create genuine drift — a real `apply`, then a file changed
behind Terraform's back — and run the whole pipeline over it. No cloud
account, no credentials: the `local` and `null` providers do everything
locally.

They are marked `e2e` and skipped when no binary is available, so
`pytest -m "not e2e"` is a complete unit run. CI runs them against both
Terraform and OpenTofu.

A thing worth knowing, discovered while writing these: the `local`
provider's `Read` compares a checksum and drops the resource from state on
any mismatch, so **a modified file is reported as `delete` drift, not
`update`**. That is real drift and exercises the whole path, but it means
the local providers cannot produce an `update` action. The `update` shape is
covered by `test_plan.py` against output captured from a real plan.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from crosswind.core.discover import Stack, discover
from crosswind.core.findings import DriftKind, StackStatus
from crosswind.core.report import FORMATS, render
from crosswind.core.scan import EXIT_CLEAN, EXIT_ERROR, ScanRequest
from crosswind.core.scan import scan as run_scan
from crosswind.core.severity import load_rules
from crosswind.core.terraform import BinaryNotFound, find_binary

pytestmark = pytest.mark.e2e

#: Set by CI to pin which binary these run against. Locally, whichever is
#: on PATH.
BINARY_ENV = "CROSSWIND_TEST_BINARY"

#: A secret seeded into the stack so the leak tests have something real to
#: look for. It goes through a provider that marks it sensitive and into the
#: plan file, which is exactly the path that matters.
SECRET = "tf-e2e-SUPERSECRET-9f3a2b1c"

#: A second secret in an attribute the provider does *not* mark, to exercise
#: the name-based redaction layer rather than the marker layer.
UNMARKED_SECRET = "tf-e2e-UNMARKED-7d1e4f88"

MAIN_TF = """\
terraform {
  required_version = ">= 1.5"
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "2.5.3"
    }
    null = {
      source  = "hashicorp/null"
      version = "3.2.4"
    }
  }
}

resource "local_file" "config" {
  filename = "${path.module}/out/config.json"
  content  = jsonencode({ mode = "strict", replicas = 2 })
}

resource "local_file" "notes" {
  filename = "${path.module}/out/notes.txt"
  content  = "original notes\\n"
}

resource "local_sensitive_file" "credential" {
  filename = "${path.module}/out/credential.txt"
  content  = "SECRET_PLACEHOLDER"
}

resource "null_resource" "keeper" {
  triggers = {
    api_token = "UNMARKED_PLACEHOLDER"
  }
}
"""


def _binary():
    try:
        return find_binary(os.environ.get(BINARY_ENV) or None)
    except BinaryNotFound:
        return None


BINARY = _binary()

needs_binary = pytest.mark.skipif(
    BINARY is None,
    reason="no terraform/tofu on PATH (set CROSSWIND_TEST_BINARY to pin one)",
)


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run Terraform for test *setup* only.

    Crosswind itself may not `apply`, and `test_safety.py` enforces that its
    wrapper cannot. Building a fixture needs a real resource to drift, so the
    setup does it directly rather than through the wrapper — which keeps the
    allowlist honest instead of carving an exception into it.
    """
    assert BINARY is not None
    env = dict(os.environ)
    env.update({"TF_IN_AUTOMATION": "1", "TF_INPUT": "0", "CHECKPOINT_DISABLE": "1"})
    return subprocess.run(  # noqa: S603 - test setup, fixed argv
        [str(BINARY.path), *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )


@pytest.fixture(scope="module")
def applied_stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """A real stack, really applied. Module-scoped: `init` is slow.

    Skips rather than fails if the provider registry is unreachable — an
    offline or network-restricted machine should not report a red suite for
    something that is not the code's fault.
    """
    if BINARY is None:
        pytest.skip("no terraform/tofu binary")

    stack = tmp_path_factory.mktemp("e2e-stack")
    (stack / "main.tf").write_text(
        MAIN_TF.replace("SECRET_PLACEHOLDER", SECRET).replace(
            "UNMARKED_PLACEHOLDER", UNMARKED_SECRET
        )
    )

    init = _run(["init", "-no-color", "-input=false"], stack)
    if init.returncode != 0:
        pytest.skip(f"provider install failed (offline?): {init.stderr[-400:]}")

    applied = _run(["apply", "-auto-approve", "-no-color", "-input=false"], stack)
    assert applied.returncode == 0, applied.stderr

    yield stack


@pytest.fixture()
def stack(applied_stack: Path, tmp_path: Path) -> Path:
    """A fresh copy of the applied stack, so each test can drift it freely."""
    target = tmp_path / "stack"
    shutil.copytree(applied_stack, target)
    return target


def scan_stack(path: Path, **config_kwargs: object):
    """Run the real pipeline over one stack, with attribution off."""
    from crosswind.core.config import Config

    assert BINARY is not None
    return run_scan(
        ScanRequest(
            stacks=[Stack(path=path, reason="e2e")],
            binary=BINARY,
            rules=load_rules(),
            config=Config(attribution=False, **config_kwargs),  # type: ignore[arg-type]
            root=path.parent,
        )
    )


# --- the clean case -----------------------------------------------------


@needs_binary
def test_an_untouched_stack_is_clean(stack: Path) -> None:
    """Nothing changed, so nothing is reported. Exit 0."""
    report = scan_stack(stack)
    assert [result.status for result in report.stacks] == [StackStatus.CLEAN]
    assert report.findings == ()
    assert report.exit_code == EXIT_CLEAN


# --- real drift ---------------------------------------------------------


@needs_binary
def test_a_file_changed_outside_terraform_is_detected(stack: Path) -> None:
    """The headline case: somebody edited something Terraform manages."""
    (stack / "out" / "notes.txt").write_text("edited by hand, outside Terraform\n")

    report = scan_stack(stack)
    assert report.stacks[0].status is StackStatus.DRIFTED
    addresses = {finding.address for finding in report.findings}
    assert "local_file.notes" in addresses
    assert report.exit_code == 1


@needs_binary
def test_a_deleted_file_is_detected(stack: Path) -> None:
    (stack / "out" / "config.json").unlink()

    report = scan_stack(stack)
    addresses = {finding.address for finding in report.findings}
    assert "local_file.config" in addresses
    finding = next(f for f in report.findings if f.address == "local_file.config")
    assert finding.kind is DriftKind.DELETED


@needs_binary
def test_the_local_provider_reports_a_modified_file_as_deleted(stack: Path) -> None:
    """Pins the behaviour the docs describe, so a provider change is noticed.

    `local_file`'s Read compares a checksum against the resource ID and drops
    the resource from state on a mismatch. If a future provider version
    reports `update` instead, this test fails and the note in `plan.py` needs
    revisiting.
    """
    (stack / "out" / "notes.txt").write_text("changed\n")
    report = scan_stack(stack)
    finding = next(f for f in report.findings if f.address == "local_file.notes")
    assert finding.kind is DriftKind.DELETED


@needs_binary
def test_several_drifted_resources_are_all_reported(stack: Path) -> None:
    (stack / "out" / "notes.txt").write_text("one\n")
    (stack / "out" / "config.json").write_text("{}")
    (stack / "out" / "credential.txt").write_text("rotated by hand")

    report = scan_stack(stack)
    addresses = {finding.address for finding in report.findings}
    assert addresses >= {
        "local_file.notes",
        "local_file.config",
        "local_sensitive_file.credential",
    }


@needs_binary
def test_every_finding_is_scored_and_explained(stack: Path) -> None:
    (stack / "out" / "notes.txt").write_text("changed\n")
    report = scan_stack(stack)
    for finding in report.findings:
        assert finding.severity_rule
        assert finding.severity_reason
        assert finding.recommendation_reason
        # Attribution was off, so it must say so and name nobody.
        assert finding.attribution.actor is None


# --- all four formats, from a real scan ---------------------------------


@needs_binary
def test_a_real_scan_produces_all_four_formats(stack: Path, tmp_path: Path) -> None:
    """The "done" criterion: real drift, four reports."""
    (stack / "out" / "notes.txt").write_text("changed\n")
    (stack / "out" / "config.json").unlink()

    report = scan_stack(stack)
    for fmt in FORMATS:
        output = render(report, fmt)
        assert output.strip(), fmt
        assert "local_file.notes" in output, fmt

    # And the JSON is really JSON.
    payload = json.loads(render(report, "json"))
    assert payload["summary"]["findings_reported"] >= 2


# --- the secret-leak tests ----------------------------------------------


@needs_binary
def test_a_provider_marked_secret_never_reaches_any_output(stack: Path) -> None:
    """`local_sensitive_file` marks `content` sensitive.

    The real value is in the state and therefore in the plan file Crosswind
    reads. It must not appear in any of the four formats.
    """
    (stack / "out" / "credential.txt").write_text("rotated by hand")
    report = scan_stack(stack)

    assert report.findings, "the drift must actually be detected"
    for fmt in FORMATS:
        output = render(report, fmt)
        assert SECRET not in output, f"{SECRET} leaked into {fmt}"


@needs_binary
def test_an_unmarked_secret_never_reaches_any_output(stack: Path) -> None:
    """`null_resource.triggers.api_token` is *not* marked sensitive.

    Only the name-based layer catches this one, which is the layer that
    exists because provider authors forget.
    """
    (stack / "out" / "notes.txt").write_text("changed\n")
    report = scan_stack(stack)

    for fmt in FORMATS:
        output = render(report, fmt)
        assert UNMARKED_SECRET not in output, f"{UNMARKED_SECRET} leaked into {fmt}"


@needs_binary
def test_no_secret_reaches_the_error_text_of_a_failed_stack(stack: Path) -> None:
    """A broken stack's error output is the one string we did not construct."""
    # Break the configuration so the plan fails after providers are installed.
    (stack / "main.tf").write_text(
        (stack / "main.tf").read_text() + '\nresource "local_file" "bad" {}\n'
    )
    report = scan_stack(stack)
    assert report.stacks[0].status is StackStatus.FAILED
    error = report.stacks[0].error or ""
    assert SECRET not in error
    assert UNMARKED_SECRET not in error


# --- the working tree is not touched ------------------------------------


@needs_binary
def test_a_scan_does_not_modify_the_working_tree(stack: Path) -> None:
    """The promise, checked by hashing everything before and after."""
    (stack / "out" / "notes.txt").write_text("changed\n")

    def snapshot() -> dict[str, tuple[int, float]]:
        return {
            path.relative_to(stack).as_posix(): (
                path.stat().st_size,
                path.stat().st_mtime,
            )
            for path in sorted(stack.rglob("*"))
            if path.is_file()
        }

    before = snapshot()
    scan_stack(stack)
    after = snapshot()

    assert set(after) == set(before), "files appeared or vanished"
    assert after == before, "a file was modified"


@needs_binary
def test_a_scan_does_not_modify_the_lock_file_or_state(stack: Path) -> None:
    """Named separately because these two are the ones that would hurt."""
    lock = stack / ".terraform.lock.hcl"
    state = stack / "terraform.tfstate"
    assert lock.is_file() and state.is_file()

    lock_before, state_before = lock.read_bytes(), state.read_bytes()
    (stack / "out" / "notes.txt").write_text("changed\n")
    scan_stack(stack)

    assert lock.read_bytes() == lock_before
    assert state.read_bytes() == state_before
    assert not (stack / "terraform.tfstate.backup").exists()


@needs_binary
def test_no_plan_file_is_left_behind_anywhere(stack: Path) -> None:
    """A plan file is a plain-text copy of the state. None may survive."""
    (stack / "out" / "notes.txt").write_text("changed\n")
    scan_stack(stack)
    assert list(stack.rglob("*.tfplan")) == []


@needs_binary
def test_a_stack_with_no_lock_file_is_reported_not_locked(
    applied_stack: Path, tmp_path: Path
) -> None:
    """`-lockfile=readonly` means we fail rather than write to their tree.

    The stack is reported as "could not check" with the fix named, and no
    lock file appears.
    """
    target = tmp_path / "nolock"
    shutil.copytree(applied_stack, target)
    (target / ".terraform.lock.hcl").unlink()
    shutil.rmtree(target / ".terraform", ignore_errors=True)

    report = scan_stack(target)
    assert report.stacks[0].status is StackStatus.FAILED
    assert report.exit_code == EXIT_ERROR
    error = report.stacks[0].error or ""
    assert "init" in error
    assert not (target / ".terraform.lock.hcl").exists(), "we wrote a lock file"


# --- failure paths against a real binary --------------------------------


@needs_binary
def test_a_broken_configuration_is_reported_as_could_not_check(stack: Path) -> None:
    (stack / "broken.tf").write_text("this is not valid HCL at all {{{\n")
    report = scan_stack(stack)
    assert report.stacks[0].status is StackStatus.FAILED
    assert report.stacks[0].error
    assert report.exit_code == EXIT_ERROR


@needs_binary
def test_one_broken_stack_does_not_stop_the_others(applied_stack: Path, tmp_path: Path) -> None:
    """The multi-stack promise, with a real binary behind it."""
    from crosswind.core.config import Config

    root = tmp_path / "tree"
    root.mkdir()
    good, bad = root / "good", root / "bad"
    shutil.copytree(applied_stack, good)
    shutil.copytree(applied_stack, bad)
    (good / "out" / "notes.txt").write_text("drifted\n")
    (bad / "broken.tf").write_text("nonsense {{{\n")

    assert BINARY is not None
    report = run_scan(
        ScanRequest(
            stacks=discover(root),
            binary=BINARY,
            rules=load_rules(),
            config=Config(attribution=False, concurrency=2),
            root=root,
        )
    )

    statuses = {result.path: result.status for result in report.stacks}
    assert statuses == {"bad": StackStatus.FAILED, "good": StackStatus.DRIFTED}
    # Drift was found *and* a stack failed: 2 wins, and the drift is still
    # in the report.
    assert report.exit_code == EXIT_ERROR
    assert report.reportable


@needs_binary
def test_an_unreadable_stack_directory_is_reported_not_crashed(
    applied_stack: Path, tmp_path: Path
) -> None:
    """A permissions problem is a "could not check", not a traceback."""
    if os.geteuid() == 0:
        pytest.skip("running as root; permissions are not enforced")

    target = tmp_path / "locked"
    shutil.copytree(applied_stack, target)
    (target / "main.tf").chmod(0)
    try:
        report = scan_stack(target)
        assert report.stacks[0].status is StackStatus.FAILED
        assert report.exit_code == EXIT_ERROR
    finally:
        (target / "main.tf").chmod(stat.S_IRUSR | stat.S_IWUSR)


# --- the binary itself --------------------------------------------------


@needs_binary
def test_the_binary_identifies_itself() -> None:
    """Terraform and OpenTofu are told apart by their own version output."""
    assert BINARY is not None
    assert BINARY.flavour in {"terraform", "tofu"}
    assert BINARY.version
    assert BINARY.label


@needs_binary
def test_the_report_records_which_binary_ran(stack: Path) -> None:
    (stack / "out" / "notes.txt").write_text("changed\n")
    report = scan_stack(stack)
    assert BINARY is not None
    assert BINARY.flavour in (report.stacks[0].binary or "")
