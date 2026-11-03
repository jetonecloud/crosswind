"""The tests that have to pass for Crosswind's central claim to be true.

If any test in this file fails, the tool can write to someone's
infrastructure and should not ship. They are deliberately paranoid and
deliberately structural: most of them assert something about the shape of the
code rather than about one function's behaviour, because the risk is a second
code path appearing, not the first one changing.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest

from crosswind.core import terraform
from crosswind.core.terraform import (
    ALLOWED_SUBCOMMANDS,
    KNOWN_WRITE_SUBCOMMANDS,
    Binary,
    ForbiddenSubcommand,
    Runner,
)
from crosswind.core.workspace import workspace

PACKAGE = Path(terraform.__file__).parent.parent


@pytest.fixture()
def runner(tmp_path: Path):
    """A `Runner` over a fake binary. No test here spawns a real process."""
    with workspace() as space:
        yield Runner(
            Binary(path=Path("/nonexistent/terraform"), flavour="terraform", version="1.15.8"),
            space,
        )


# --- the allowlist ------------------------------------------------------


@pytest.mark.parametrize("subcommand", sorted(KNOWN_WRITE_SUBCOMMANDS))
def test_write_subcommands_are_refused(runner: Runner, tmp_path: Path, subcommand: str) -> None:
    """Every subcommand that could change something is refused by name."""
    with pytest.raises(ForbiddenSubcommand) as excinfo:
        runner.run(subcommand, cwd=tmp_path)
    assert subcommand in str(excinfo.value)


def test_unknown_subcommands_are_refused(runner: Runner, tmp_path: Path) -> None:
    """The check is an allowlist, so a subcommand we've never heard of is out.

    This is the one that protects against a future Terraform release adding a
    destructive verb we didn't think to enumerate.
    """
    with pytest.raises(ForbiddenSubcommand):
        runner.run("some-future-subcommand", cwd=tmp_path)


def test_allowlist_and_write_list_do_not_overlap() -> None:
    """A write subcommand must never also be an allowed one."""
    assert not (ALLOWED_SUBCOMMANDS & KNOWN_WRITE_SUBCOMMANDS)


def test_allowlist_is_exactly_what_is_documented() -> None:
    """Pin the set, so widening it has to be a deliberate edit with a reason."""
    assert set(ALLOWED_SUBCOMMANDS) == {"version", "init", "providers", "plan", "show"}


def test_refusal_happens_before_a_process_is_started(
    runner: Runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing is spawned on the way to being refused."""
    calls: list[object] = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append(a))
    with pytest.raises(ForbiddenSubcommand):
        runner.run("apply", "-auto-approve", cwd=tmp_path)
    assert not calls


# --- flags --------------------------------------------------------------


@pytest.mark.parametrize(
    "flag",
    ["-auto-approve", "-destroy", "-migrate-state", "-reconfigure", "-force-copy"],
)
def test_dangerous_flags_are_refused_on_allowed_subcommands(
    runner: Runner, tmp_path: Path, flag: str
) -> None:
    """An allowed subcommand can't be smuggled a flag that changes things."""
    with pytest.raises(ForbiddenSubcommand):
        runner.run("plan", "-refresh-only", flag, cwd=tmp_path)


@pytest.mark.parametrize("arg", ["-target=aws_s3_bucket.a", "-replace=aws_instance.b"])
def test_valued_dangerous_flags_are_refused(runner: Runner, tmp_path: Path, arg: str) -> None:
    """`-target=x` is caught as well as a bare `-target`."""
    with pytest.raises(ForbiddenSubcommand):
        runner.run("plan", "-refresh-only", arg, cwd=tmp_path)


def test_plan_without_refresh_only_is_refused(runner: Runner, tmp_path: Path) -> None:
    """A plan that isn't refresh-only is a plan somebody could apply."""
    with pytest.raises(ForbiddenSubcommand) as excinfo:
        runner.run("plan", "-lock=false", cwd=tmp_path)
    assert "-refresh-only" in str(excinfo.value)


# --- structure ----------------------------------------------------------


def _python_files() -> list[Path]:
    return sorted(PACKAGE.rglob("*.py"))


def test_subprocess_is_imported_in_exactly_one_module() -> None:
    """One module may start a process. This is the test that keeps it that way.

    A new module that shells out would be a second code path to the same
    danger, bypassing the allowlist entirely. If this fails, the fix is to
    route the call through `Runner`, not to add the file to an exception list.
    """
    offenders = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            if any(name == "subprocess" or name.startswith("subprocess.") for name in names):
                offenders.append(path.relative_to(PACKAGE).as_posix())
    assert offenders == ["core/terraform.py"]


def test_no_other_process_spawning_apis_are_used() -> None:
    """`os.system`, `os.exec*`, `os.popen` and `os.spawn*` are all a way out."""
    banned = {"system", "popen", "execv", "execve", "execvp", "execvpe", "spawnv", "spawnl"}
    offenders: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr in banned
                and isinstance(node.value, ast.Name)
                and node.value.id == "os"
            ):
                offenders.append(f"{path.relative_to(PACKAGE).as_posix()}:os.{node.attr}")
    assert offenders == []


def test_the_word_apply_never_reaches_an_argv() -> None:
    """No string literal anywhere in the package is a write subcommand.

    Crude on purpose. A literal `"apply"` in the package is either a bug or a
    comment that should be reworded; either way a human should look at it.
    `terraform.py` is excluded because it names them to refuse them.
    """
    offenders: list[str] = []
    for path in _python_files():
        if path.name == "terraform.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and node.value in {
                "apply",
                "destroy",
                "force-unlock",
                "import",
            }:
                offenders.append(f"{path.relative_to(PACKAGE).as_posix()}:{node.lineno}")
    assert offenders == []
