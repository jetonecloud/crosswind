"""The only place Crosswind starts a process.

Crosswind's whole claim is that it cannot change your infrastructure. That
claim is worth exactly as much as the narrowest part of the code that can
build an argument list for `terraform`, so there is one function that can, it
takes a subcommand from a fixed set, and it refuses everything else before a
process exists.

Three things are enforced here rather than promised in a README:

1. **The subcommand allowlist.** `version`, `init`, `providers`, `plan`,
   `show`. `apply`, `destroy`, `import`, `state`, `taint`, `force-unlock` and
   everything else raise `ForbiddenSubcommand`. The check is an allowlist and
   not a denylist, so a subcommand added by a future Terraform release is
   refused by default rather than permitted by oversight.
2. **`plan` means `-refresh-only`.** A plan that isn't a refresh-only plan is
   a plan that could be applied. The wrapper adds the flag and asserts it is
   present, and rejects any argv carrying `-auto-approve`, `-destroy` or
   `-migrate-state`.
3. **The working tree is not written to.** `TF_DATA_DIR` points into the
   private workspace, `init` runs `-lockfile=readonly`, and nothing is passed
   that would rewrite config or state.

`tests/test_safety.py` asserts that `subprocess` is imported in this module
and nowhere else in the package, so a second code path can't appear without a
test failing.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from crosswind.core.workspace import Workspace, harden

#: The subcommands Crosswind is allowed to run. Read-only, every one of them.
#:
#: - `version`  -- which binary is this, for `doctor` and the report header
#: - `init`     -- install providers into TF_DATA_DIR so a plan can run
#: - `providers`-- the provider list, for `doctor`
#: - `plan`     -- always `-refresh-only`; the actual drift detection
#: - `show`     -- render a plan file we wrote as JSON
ALLOWED_SUBCOMMANDS: frozenset[str] = frozenset({"version", "init", "providers", "plan", "show"})

#: Named only so the error message can be specific about why the answer is no.
#: This is documentation, not the control: the allowlist above is the control,
#: and a subcommand missing from this set is still refused.
KNOWN_WRITE_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "apply",
        "destroy",
        "import",
        "state",
        "taint",
        "untaint",
        "force-unlock",
        "refresh",
        "login",
        "logout",
        "workspace",
        "init-backend",
        "push",
        "test",
    }
)

#: Flags that would turn a read into a write, or move state around. None of
#: these can reach a process even on an allowed subcommand.
FORBIDDEN_FLAGS: tuple[str, ...] = (
    "-auto-approve",
    "-destroy",
    "-migrate-state",
    "-reconfigure",
    "-force-copy",
    "-backend=true",
    "-replace",
    "-target",
)

#: Binaries we know how to drive, in the order `doctor` and `scan` look for
#: them. Terraform first only because it is the more common of the two; a
#: `--binary` always wins.
KNOWN_BINARIES: tuple[str, ...] = ("terraform", "tofu")

#: How long any one Terraform invocation may take before we give up. A refresh
#: of a large stack genuinely can take minutes, so this is generous; it exists
#: to stop a hung provider from hanging a scheduled scan forever.
DEFAULT_TIMEOUT = 900

_VERSION_RE = re.compile(r"v?(\d+\.\d+\.\d+(?:-\w+)?)")


class TerraformError(RuntimeError):
    """Terraform ran and failed, or could not be run at all."""

    def __init__(self, message: str, *, stderr: str = "", returncode: int | None = None) -> None:
        super().__init__(message)
        self.stderr = stderr
        self.returncode = returncode


class ForbiddenSubcommand(TerraformError):
    """Something asked for a subcommand that is not on the allowlist.

    This is a programming error in Crosswind, not a user error. It is a hard
    failure with no fallback: the point of the allowlist is that there is
    nothing sensible to do when it trips.
    """


class BinaryNotFound(TerraformError):
    """No `terraform` or `tofu` on PATH, or the named binary isn't there."""


@dataclass(frozen=True)
class Binary:
    """Which executable we're driving, and what it says it is."""

    path: Path
    #: `terraform` or `tofu`, as the binary reports itself rather than as the
    #: file happens to be named — people rename and symlink these.
    flavour: str
    version: str

    @property
    def label(self) -> str:
        return f"{self.flavour} v{self.version}"


@dataclass(frozen=True)
class Completed:
    """What a finished invocation produced."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _check(subcommand: str, args: Sequence[str]) -> None:
    """Refuse anything that isn't provably a read. Raises or returns."""
    if subcommand not in ALLOWED_SUBCOMMANDS:
        allowed = ", ".join(sorted(ALLOWED_SUBCOMMANDS))
        hint = (
            " Crosswind never performs write operations."
            if subcommand in KNOWN_WRITE_SUBCOMMANDS
            else ""
        )
        raise ForbiddenSubcommand(
            f"Refusing to run `{subcommand}`: not one of the allowed "
            f"read-only subcommands ({allowed}).{hint}"
        )

    for arg in args:
        # Compare on the flag itself so `-target=x` is caught alongside
        # `-target x`.
        flag = arg.split("=", 1)[0]
        for forbidden in FORBIDDEN_FLAGS:
            if arg == forbidden or flag == forbidden.split("=", 1)[0]:
                raise ForbiddenSubcommand(
                    f"Refusing to run `{subcommand}` with `{arg}`: that flag can "
                    f"change infrastructure or state."
                )

    if subcommand == "plan" and "-refresh-only" not in args:
        raise ForbiddenSubcommand(
            "Refusing to run `plan` without `-refresh-only`: a plan that is not "
            "refresh-only proposes changes to resources."
        )


def find_binary(preferred: str | Path | None = None) -> Binary:
    """Locate a Terraform-compatible binary and ask it what it is.

    `preferred` is `--binary`: a name on `PATH` or a path to an executable. We
    believe the binary's own `version` output over its filename, because
    `tofu` symlinked to `terraform` is a real thing people do and the two
    differ in ways that matter (the provider registry host in
    `provider_name`, for one).
    """
    candidates: list[str | Path] = [preferred] if preferred is not None else list(KNOWN_BINARIES)

    for candidate in candidates:
        resolved = _resolve(candidate)
        if resolved is None:
            continue
        return _identify(resolved)

    if preferred is not None:
        raise BinaryNotFound(
            f"`{preferred}` is not an executable and is not on PATH. Pass "
            f"`--binary` with a path, or install Terraform or OpenTofu."
        )
    raise BinaryNotFound(
        "Neither `terraform` nor `tofu` is on PATH. Install one, or point `--binary` at it."
    )


def _resolve(candidate: str | Path) -> Path | None:
    """A usable executable path for `candidate`, or `None`."""
    path = Path(candidate)
    if path.is_absolute() or os.sep in str(candidate):
        return path if path.is_file() and os.access(path, os.X_OK) else None
    found = shutil.which(str(candidate))
    return Path(found) if found else None


def _identify(path: Path) -> Binary:
    """Run `version -json` and work out what we're talking to."""
    result = _run_raw(path, ["version", "-json"], cwd=None, env=_base_env({}), timeout=60)
    if result.ok:
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            payload = {}
        version = str(payload.get("terraform_version") or "").strip()
        # OpenTofu reports itself in `product_name`; Terraform omits the key.
        product = str(payload.get("product_name") or "").strip().lower()
        if version:
            flavour = "tofu" if "tofu" in product or "tofu" in path.name.lower() else "terraform"
            return Binary(path=path, flavour=flavour, version=version)

    # `version -json` landed in Terraform 0.13 and OpenTofu has always had it,
    # but falling back to the human output costs nothing and means an odd
    # build still gets a usable answer.
    plain = _run_raw(path, ["version"], cwd=None, env=_base_env({}), timeout=60)
    if not plain.ok:
        raise BinaryNotFound(
            f"`{path}` did not respond to `version`.",
            stderr=plain.stderr,
            returncode=plain.returncode,
        )
    first = plain.stdout.splitlines()[0] if plain.stdout.splitlines() else ""
    match = _VERSION_RE.search(first)
    flavour = "tofu" if "tofu" in first.lower() or "opentofu" in first.lower() else "terraform"
    return Binary(path=path, flavour=flavour, version=match.group(1) if match else "unknown")


def _base_env(extra: Mapping[str, str]) -> dict[str, str]:
    """The environment every invocation gets.

    Starts from the real environment because that is where the AWS credential
    chain, proxy settings and the user's own `TF_*` configuration live. We
    then pin the handful of things that keep the run quiet, non-interactive
    and out of the user's way.
    """
    env = dict(os.environ)
    env.update(
        {
            # No colour: we parse some of this, and ANSI in a captured error
            # message ends up in a report.
            "TF_IN_AUTOMATION": "1",
            "TF_INPUT": "0",
            # Terraform's own CLI checkpoint call is the one piece of network
            # traffic it makes that has nothing to do with the user's
            # infrastructure. Crosswind promises no telemetry; that has to
            # include the telemetry we would otherwise cause.
            "CHECKPOINT_DISABLE": "1",
        }
    )
    env.update(extra)
    return env


def _run_raw(
    binary: Path,
    args: Sequence[str],
    *,
    cwd: Path | None,
    env: Mapping[str, str],
    timeout: int,
) -> Completed:
    """Spawn the process. The only `subprocess` call in the package.

    Deliberately boring and deliberately alone. Everything interesting
    happens in `_check` before we get here.
    """
    argv = [str(binary), *args]
    try:
        proc = subprocess.run(  # noqa: S603 - argv is built from an allowlist
            argv,
            cwd=str(cwd) if cwd else None,
            env=dict(env),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            # Nothing should ever prompt, but a stdin that is closed rather
            # than inherited turns "waits forever" into "fails immediately".
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise BinaryNotFound(f"`{binary}` could not be executed.") from exc
    except subprocess.TimeoutExpired as exc:
        raise TerraformError(f"`{' '.join(args[:2])}` did not finish within {timeout}s.") from exc
    return Completed(
        args=tuple(argv),
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
    )


class Runner:
    """Runs read-only Terraform against one stack, in a private workspace.

    Holds the binary and the workspace so callers don't have to thread
    `TF_DATA_DIR` through by hand and get it wrong once.
    """

    def __init__(
        self,
        binary: Binary,
        workspace: Workspace,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self.binary = binary
        self.workspace = workspace
        self.timeout = timeout
        self._extra_env = dict(env or {})

    def run(self, subcommand: str, *args: str, cwd: Path) -> Completed:
        """Run one allowed subcommand. Raises `ForbiddenSubcommand` otherwise."""
        _check(subcommand, args)
        env = _base_env({**self._extra_env, "TF_DATA_DIR": str(self.workspace.data_dir)})
        return _run_raw(
            self.binary.path,
            [subcommand, *args],
            cwd=cwd,
            env=env,
            timeout=self.timeout,
        )

    # --- the three things a scan actually does ---------------------------

    def init(self, stack: Path) -> Completed:
        """Install providers into our own data dir, touching nothing of theirs.

        `-lockfile=readonly` is the important flag. Without it `init` may
        update `.terraform.lock.hcl` — adding hashes for the platform it just
        ran on — and that is a modification to the user's tree and to a file
        that is usually committed. With it, `init` fails rather than writes,
        which is the behaviour we want: a stack with no lock file is reported
        as "could not check" with the fix named, not silently locked by us.

        `-backend=false` is *not* passed: a refresh needs to read the real
        state, which means the real backend.
        """
        return self.run(
            "init",
            "-input=false",
            "-no-color",
            "-lockfile=readonly",
            cwd=stack,
        )

    def plan_refresh_only(
        self,
        stack: Path,
        *,
        out: Path,
        var_files: Sequence[Path] = (),
    ) -> Completed:
        """The drift detection itself.

        `-refresh-only` proposes updates to state rather than to resources;
        `-lock=false` means we never take a state lock, so a crashed scan can
        never leave one behind for somebody else to break; `-input=false`
        means a missing variable is an error rather than a hang.

        `-detailed-exitcode` is deliberately *not* used. It returns 2 when
        there is drift, which collides with Crosswind's own exit code 2 for
        "could not check", and we are going to parse the JSON anyway.
        """
        args = [
            "-refresh-only",
            "-lock=false",
            "-input=false",
            "-no-color",
            f"-out={out}",
        ]
        for var_file in var_files:
            args.append(f"-var-file={var_file}")
        result = self.run("plan", *args, cwd=stack)
        if out.exists():
            # Terraform writes plan files 0644. It holds the prior state, so
            # that is wider than it has any business being, even for the few
            # milliseconds before `show` reads it back.
            harden(out)
        return result

    def show_plan_json(self, stack: Path, plan: Path) -> dict[str, Any]:
        """Parse a plan file we wrote into the documented JSON representation.

        Raises `TerraformError` on anything that isn't a JSON object, because
        "we could not read the plan" has to be an error. Returning `{}` here
        would make a broken stack indistinguishable from a clean one, which is
        the failure mode the tool exists to avoid.
        """
        result = self.run("show", "-json", str(plan), cwd=stack)
        if not result.ok:
            raise TerraformError(
                "`show -json` failed on a plan file we had just written.",
                stderr=result.stderr,
                returncode=result.returncode,
            )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise TerraformError(f"`show -json` produced output that is not JSON: {exc}.") from exc
        if not isinstance(payload, dict):
            raise TerraformError("`show -json` produced JSON that is not an object.")
        return payload

    def providers(self, stack: Path) -> Completed:
        """The provider list, for `doctor`."""
        return self.run("providers", cwd=stack)
