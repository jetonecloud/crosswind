"""Finding the stacks worth scanning.

A "stack" is a directory you could run `terraform plan` in: it has `.tf` (or
`.tf.json`) files and it is not a module that only exists to be called by
something else.

Telling those apart is the whole problem, and it cannot be done perfectly
from the filesystem. What we use:

- A directory with no `.tf` files is not a stack.
- A directory under `modules/` is almost certainly a module. So is one with
  `variables.tf` and no `backend`/`provider` configuration and no state.
- A directory whose parent is also a stack is usually a module of it, and we
  do not descend into one.

Where it is ambiguous we **include** the directory. A false positive costs a
"could not check" line, which is visible and fixable with `--exclude`. A
false negative is a stack nobody is checking and nobody knows it.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

#: Terraform reads both.
TF_SUFFIXES = (".tf", ".tf.json")

#: Directory names that mean "this holds modules, not stacks". Checked as a
#: path component, so `infra/modules/vpc` is excluded and `infra/my-modules`
#: is not.
MODULE_DIRS = frozenset({"modules", "module", ".modules"})

#: Files that say a directory is meant to be run rather than called.
ROOT_MARKERS = ("backend.tf", "providers.tf", "provider.tf", "main.tf", "terragrunt.hcl")

#: Files that are evidence a directory has been run.
STATE_MARKERS = ("terraform.tfstate", ".terraform.lock.hcl", ".terraform")


@dataclass(frozen=True)
class Stack:
    """A directory we are going to try to scan."""

    path: Path
    #: Why we think this is a root module. Shown by `doctor` and useful when
    #: discovery picks up something unexpected.
    reason: str

    @property
    def name(self) -> str:
        return self.path.name


def is_stack_dir(path: Path) -> bool:
    """Does this directory contain Terraform configuration at all?"""
    if not path.is_dir():
        return False
    try:
        return any(entry.is_file() and entry.name.endswith(TF_SUFFIXES) for entry in path.iterdir())
    except OSError:
        return False


def looks_like_module(path: Path) -> bool:
    """Is this a module that exists to be called rather than run?

    Heuristic, and deliberately conservative — it only says yes when there is
    positive evidence. A directory with `variables.tf` and `outputs.tf` and no
    backend, no provider block and no state has never been run on its own.
    """
    if any(part in MODULE_DIRS for part in path.parts):
        return True

    names = set()
    try:
        names = {entry.name for entry in path.iterdir()}
    except OSError:
        return False

    if any(marker in names for marker in STATE_MARKERS):
        # It has been initialised or applied here, so somebody runs it here.
        return False
    if any(marker in names for marker in ROOT_MARKERS if marker != "main.tf"):
        return False

    # `variables.tf` plus `outputs.tf` and nothing that configures a backend
    # or a provider is the shape of a module.
    return "variables.tf" in names and "outputs.tf" in names


def excluded(path: Path, root: Path, patterns: tuple[str, ...]) -> bool:
    """Does any exclude pattern match this directory?

    Patterns are matched against the directory's name, its path relative to
    the scan root, and the absolute path — so `--exclude examples`,
    `--exclude 'infra/legacy/*'` and an absolute path all do what someone
    would expect, without them having to find out which one we implemented.
    """
    name = path.name
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        relative = path.as_posix()
    absolute = path.as_posix()

    for pattern in patterns:
        cleaned = pattern.rstrip("/")
        if (
            fnmatch.fnmatch(name, cleaned)
            or fnmatch.fnmatch(relative, cleaned)
            or fnmatch.fnmatch(absolute, cleaned)
            # A bare directory name should exclude everything under it.
            or relative == cleaned
            or relative.startswith(f"{cleaned}/")
        ):
            return True
    return False


def discover(root: Path, *, exclude: tuple[str, ...] = (), max_depth: int = 12) -> list[Stack]:
    """Stacks at or under `root`, in a stable order.

    If `root` is itself a stack, that is the only answer — `--path` pointing
    at one directory means one stack, not that directory plus everything
    nested inside it.

    Sorted by path so two runs produce reports that diff cleanly.
    """
    root = root.expanduser()
    if not root.exists():
        raise FileNotFoundError(f"{root} does not exist.")
    if not root.is_dir():
        raise NotADirectoryError(f"{root} is not a directory.")

    if is_stack_dir(root):
        return [Stack(path=root, reason="the path given")]

    found: list[Stack] = []
    _walk(root, root, exclude, found, depth=0, max_depth=max_depth)
    return sorted(found, key=lambda stack: stack.path.as_posix())


def _walk(
    current: Path,
    root: Path,
    exclude: tuple[str, ...],
    found: list[Stack],
    *,
    depth: int,
    max_depth: int,
) -> None:
    if depth > max_depth:
        return
    try:
        entries = sorted(current.iterdir(), key=lambda path: path.name)
    except OSError:
        # An unreadable directory is not a stack we can scan, and not an
        # error worth stopping a whole scan for.
        return

    for entry in entries:
        if not entry.is_dir() or entry.is_symlink():
            # Symlinks are skipped: following them makes cycles possible and
            # makes "what did we scan" much harder to answer.
            continue
        if excluded(entry, root, exclude):
            continue
        if is_stack_dir(entry):
            if looks_like_module(entry):
                continue
            found.append(Stack(path=entry, reason=_reason_for(entry)))
            # Do not descend: a stack's subdirectories are its modules.
            continue
        _walk(entry, root, exclude, found, depth=depth + 1, max_depth=max_depth)


def _reason_for(path: Path) -> str:
    """Why discovery picked this directory, in words."""
    try:
        names = {entry.name for entry in path.iterdir()}
    except OSError:  # pragma: no cover - raced with a deletion
        return "contains Terraform configuration"

    for marker in STATE_MARKERS:
        if marker in names:
            return f"has {marker}"
    for marker in ROOT_MARKERS:
        if marker in names:
            return f"has {marker}"
    return "contains Terraform configuration"
