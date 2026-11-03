"""A private directory for the things we must not leave lying around.

A Terraform plan file contains the entire prior state. That means every
attribute of every resource the stack manages, including the ones a provider
stored in plain text: database passwords, private keys, join tokens. It is the
single most sensitive artefact Crosswind touches, and we only need it for the
few milliseconds between `plan -out` writing it and `show -json` reading it
back.

So: one directory per run, created `0700` before anything is written into it,
every file inside it `chmod 0600` on arrival (Terraform writes plan files
`0644`), and removed on the way out. "On the way out" has to include the ways
out that aren't a clean return, which is why there is an `atexit` hook and a
signal handler as well as the `finally` in the context manager. A plan file
surviving a Ctrl-C is a plain-text copy of someone's production secrets in
`/tmp`.

The directory lives wherever the platform puts temporary files, never inside
the user's stack. Writing it next to their code would put secrets in reach of
their next `git add -A`.
"""

from __future__ import annotations

import atexit
import os
import shutil
import signal
import stat
import tempfile
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from types import FrameType
from typing import Any

#: What `signal.signal` accepts back: a handler function, or one of the two
#: integer dispositions it hands out for "default" and "ignore".
Handler = Callable[[int, FrameType | None], Any] | int | signal.Handlers | None

#: Directories we have created and not yet removed. Module-level because the
#: `atexit` hook and the signal handlers have no other way to find them, and
#: because a scan runs stacks in threads that all want the same guarantee.
_live: set[Path] = set()
_lock = threading.Lock()

#: Set once. Signal handlers chain to whatever was installed before us rather
#: than replacing it, so a caller embedding Crosswind keeps its own handling.
_handlers_installed = False


def _purge() -> None:
    """Remove every directory we still own. Safe to call more than once."""
    with _lock:
        paths = list(_live)
        _live.clear()
    for path in paths:
        shutil.rmtree(path, ignore_errors=True)


def _install_handlers() -> None:
    """Make Ctrl-C and `kill` delete the plan files before the process dies.

    `atexit` alone is not enough: the default `SIGTERM` disposition kills the
    process without running it. We clean up, re-install the previous handler,
    and re-raise the signal so the caller's own behaviour (and the correct
    exit status) is preserved — swallowing a `SIGTERM` to be tidy is its own
    kind of rude.
    """
    global _handlers_installed
    if _handlers_installed:
        return
    _handlers_installed = True

    atexit.register(_purge)

    def handler(signum: int, frame: FrameType | None) -> None:
        _purge()
        signal.signal(signum, previous.get(signum, signal.SIG_DFL))
        signal.raise_signal(signum)

    previous: dict[int, Handler] = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, handler)
        except (ValueError, OSError):
            # Not the main thread, or a platform without this signal. The
            # `atexit` hook and the `finally` still apply.
            pass


def harden(path: Path) -> None:
    """Take every permission off a file except the owner's read and write.

    Called after anything writes into the workspace, because the writer is
    usually Terraform and Terraform does not ask us what mode to use.
    """
    # A filesystem that doesn't do Unix modes (a Windows share, some container
    # volumes) raises here. The directory mode is the real control; this is the
    # belt to its braces.
    with suppress(OSError):
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


class Workspace:
    """A private scratch directory, and the paths inside it.

    One per stack scan. `data_dir` becomes `TF_DATA_DIR`, which is what keeps
    `.terraform/` out of the user's working tree; `plans` holds the plan files.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.data_dir = root / "tfdata"
        self.plans = root / "plans"
        self.data_dir.mkdir(mode=0o700)
        self.plans.mkdir(mode=0o700)

    def plan_path(self, name: str) -> Path:
        """Where a plan file for `name` should go. Does not create it."""
        return self.plans / f"{_slug(name)}.tfplan"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Workspace({self.root})"


@contextmanager
def workspace(prefix: str = "crosswind-") -> Iterator[Workspace]:
    """A `Workspace` that exists for the block and not afterwards.

    `mkdtemp` is `0700` by default and creates atomically, so there is no
    window in which the directory exists with a wider mode.
    """
    _install_handlers()
    root = Path(tempfile.mkdtemp(prefix=prefix))
    with _lock:
        _live.add(root)
    try:
        yield Workspace(root)
    finally:
        with _lock:
            _live.discard(root)
        shutil.rmtree(root, ignore_errors=True)


def _slug(name: str) -> str:
    """A filename-safe version of a stack path, kept readable for debugging."""
    safe = "".join(char if char.isalnum() or char in "-_" else "-" for char in name)
    return safe.strip("-")[:120] or "stack"
