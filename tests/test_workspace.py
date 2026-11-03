"""The private directory, and whether it really goes away."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from crosswind.core import workspace as ws
from crosswind.core.workspace import harden, workspace


def test_workspace_is_private_to_the_owner() -> None:
    """0700 on the root and on both subdirectories, from the moment they exist."""
    with workspace() as space:
        for path in (space.root, space.data_dir, space.plans):
            mode = stat.S_IMODE(path.stat().st_mode)
            assert mode == 0o700, f"{path} is {oct(mode)}"


def test_workspace_is_removed_on_the_way_out() -> None:
    with workspace() as space:
        root = space.root
        (space.plans / "a.tfplan").write_text("x")
        assert root.exists()
    assert not root.exists()


def test_workspace_is_removed_even_when_the_block_raises() -> None:
    """The interesting case: a stack that failed still leaves no plan file."""
    root: Path | None = None
    try:
        with workspace() as space:
            root = space.root
            (space.plans / "secret.tfplan").write_text("db-password")
            raise RuntimeError("the stack failed")
    except RuntimeError:
        pass
    assert root is not None and not root.exists()


def test_workspace_is_not_inside_the_users_tree(tmp_path: Path) -> None:
    """A plan file next to someone's code is one `git add -A` from a leak."""
    cwd = Path.cwd().resolve()
    with workspace() as space:
        assert cwd not in space.root.resolve().parents
        assert space.root.resolve() != cwd


def test_harden_removes_group_and_other_access(tmp_path: Path) -> None:
    """Terraform writes plan files 0644; we take that back down to 0600."""
    path = tmp_path / "p.tfplan"
    path.write_text("prior state with secrets")
    os.chmod(path, 0o644)
    harden(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_purge_removes_a_leaked_directory() -> None:
    """The `atexit`/signal path: whatever is still registered gets deleted.

    This is what stands between a Ctrl-C and a plain-text copy of someone's
    state in /tmp, so it is worth testing directly rather than trusting the
    context manager to be the only route.
    """
    space_root: Path
    with workspace() as space:
        space_root = space.root
        # Simulate the context manager never getting to its `finally`.
        ws._live.add(space_root)
    ws._live.add(space_root)
    space_root.mkdir(exist_ok=True)
    (space_root / "p.tfplan").write_text("secret")
    ws._purge()
    assert not space_root.exists()
    assert space_root not in ws._live


def test_plan_path_is_inside_the_workspace_and_filename_safe() -> None:
    """A stack path becomes a filename without escaping the directory."""
    with workspace() as space:
        path = space.plan_path("../../etc/passwd")
        assert path.parent == space.plans
        assert ".." not in path.name
        assert path.name.endswith(".tfplan")


def test_plan_path_never_produces_an_empty_name() -> None:
    with workspace() as space:
        assert space.plan_path("///").name == "stack.tfplan"
