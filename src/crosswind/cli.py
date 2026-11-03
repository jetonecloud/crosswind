"""The command line: `demo`, `scan`, `doctor`, `version`.

This module owns all the I/O. Everything under `core/` returns values; the
CLI is the only place that prints, writes a file, or chooses an exit code.
That split is what makes the rest of the package testable without a
filesystem, and it means there is one place to check that nothing sensitive
is written anywhere.

Exit codes, which matter more here than usual because this runs in CI:

- **0** no drift at or above `--min-severity`
- **1** drift found at or above `--min-severity`
- **2** a stack could not be checked, or the tool itself failed

2 beats 1. If drift and a scan error both happen, the report is still
written and the exit code is 2 — a report with a hole in it is a different
situation from a report with findings in it, and the more urgent one.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated

import click
import typer

from crosswind import __version__
from crosswind.core import config as config_module
from crosswind.core import discover as discover_module
from crosswind.core import ignore as ignore_module
from crosswind.core import session as session_module
from crosswind.core.attribution.lookup import CloudTrailLookup, NullLookup
from crosswind.core.attribution.mapping import load_mapping
from crosswind.core.config import ConfigError
from crosswind.core.findings import Severity
from crosswind.core.report import EXTENSIONS, FORMATS, render
from crosswind.core.scan import EXIT_ERROR, Report, ScanRequest
from crosswind.core.scan import scan as run_scan
from crosswind.core.severity import RuleError, load_rules
from crosswind.core.terraform import (
    Binary,
    Runner,
    TerraformError,
    find_binary,
)
from crosswind.core.workspace import workspace
from crosswind.demo import demo_report

app = typer.Typer(
    name="crosswind",
    help=(
        "Read-only Terraform drift checker: what changed outside Terraform, "
        "who changed it, and why it matters."
    ),
    add_completion=False,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

#: Report filenames. Timestamped would make every run a new file and a
#: scheduled scan a directory nobody prunes; a stable name overwrites, which
#: is what a CI artifact wants.
REPORT_STEM = "crosswind-report"


def _err(message: str) -> None:
    """Everything that is not the report itself goes to stderr.

    So `crosswind scan --format json > report.json` works, and a progress
    note never ends up parsed as part of the output.
    """
    click.echo(message, err=True)


@app.command()
def version() -> None:
    """Print the version and exit."""
    click.echo(f"crosswind {__version__}")


@app.command()
def demo(
    formats: Annotated[
        list[str] | None,
        typer.Option(
            "--format",
            "-f",
            help=f"Output format, repeatable. One of: {', '.join(FORMATS)}.",
        ),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", "-o", help="Where to write file formats."),
    ] = None,
    min_severity: Annotated[
        str | None,
        typer.Option("--min-severity", help="Hide findings below this severity."),
    ] = None,
) -> None:
    """Show what a report looks like, using bundled fixtures.

    No AWS account, no credentials, and no Terraform binary needed. The
    report goes through exactly the same renderers a real scan uses, so what
    you see here is what you get.
    """
    try:
        threshold = Severity.parse(min_severity) if min_severity else Severity.LOW
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--min-severity") from exc

    chosen = _validate_formats(formats or ["terminal"])
    report = demo_report(min_severity=threshold)
    _emit(report, chosen, output_dir)

    _err("")
    _err("This was a sample report. To scan your own stacks:")
    _err("    crosswind doctor --path <dir>     # check your setup first")
    _err("    crosswind scan --path <dir>")
    # Deliberately exit 0 regardless of the fixture's findings. A demo that
    # fails the build of whatever is running it is a bad demo.
    raise typer.Exit(0)


@app.command()
def doctor(
    path: Annotated[
        Path,
        typer.Option("--path", "-p", help="Directory to check for stacks."),
    ] = Path(),
    binary: Annotated[
        str | None,
        typer.Option("--binary", help="terraform or tofu, or a path to one."),
    ] = None,
    profile: Annotated[str | None, typer.Option("--profile", help="AWS profile to use.")] = None,
    role_arn: Annotated[
        str | None, typer.Option("--role-arn", help="Role to assume for CloudTrail.")
    ] = None,
    region: Annotated[str | None, typer.Option("--region", help="AWS region.")] = None,
) -> None:
    """Check the binary, credentials, state access, and CloudTrail access.

    Runs the cheapest possible version of each thing a scan needs, and says
    which ones would fail. Nothing here writes anything.
    """
    ok = True
    click.echo("crosswind doctor")
    click.echo("")

    # --- the binary ---
    found: Binary | None = None
    try:
        found = find_binary(binary)
        click.echo(f"  [ok]   binary: {found.label} at {found.path}")
    except TerraformError as exc:
        ok = False
        click.echo(f"  [FAIL] binary: {exc}")

    # --- stacks ---
    stacks: list[discover_module.Stack] = []
    try:
        loaded = config_module.load(config_module.find_config(path))
        stacks = discover_module.discover(path, exclude=loaded.all_excludes)
        if stacks:
            click.echo(f"  [ok]   stacks: found {len(stacks)}")
            for item in stacks[:10]:
                click.echo(f"           - {item.path} ({item.reason})")
            if len(stacks) > 10:
                click.echo(f"           ... and {len(stacks) - 10} more")
        else:
            click.echo(f"  [warn] stacks: none found under {path}")
    except (OSError, ConfigError) as exc:
        ok = False
        click.echo(f"  [FAIL] stacks: {exc}")

    # --- state access, via a real init on the first stack ---
    if found is not None and stacks:
        ok = _check_state(found, stacks[0]) and ok
    elif found is not None:
        click.echo("  [skip] state: no stack to try")

    # --- credentials ---
    identity = None
    try:
        aws = session_module.build_session(profile=profile, region=region, role_arn=role_arn)
        identity = session_module.whoami(aws)
        click.echo(f"  [ok]   credentials: {identity.arn}")
        if identity.is_root:
            click.echo(
                "           This is the account root user. Use a dedicated "
                "read-only role instead - see iam/role.cfn.yaml."
            )
    except session_module.CredentialsError as exc:
        # Not a failure of the tool: drift detection works without AWS
        # credentials, it just cannot attribute anything.
        click.echo(f"  [warn] credentials: {exc}")
        click.echo("           Drift detection still works; attribution will say unknown.")

    # --- CloudTrail ---
    if identity is not None:
        try:
            lookup = CloudTrailLookup(aws)
            lookup.events_for(
                value="crosswind-doctor-probe",
                region=region or aws.region_name or "us-east-1",
                window_hours=1,
            )
            click.echo("  [ok]   cloudtrail: LookupEvents works")
        except Exception as exc:  # noqa: BLE001 - reported, never raised onward
            reason = getattr(exc, "reason", "lookup_failed")
            click.echo(f"  [warn] cloudtrail: {exc} ({reason})")
            click.echo(
                "           Attribution needs cloudtrail:LookupEvents. "
                "Findings will say unknown without it."
            )
    else:
        click.echo("  [skip] cloudtrail: no credentials to try with")

    click.echo("")
    if ok:
        click.echo("Ready to scan.")
        raise typer.Exit(0)
    click.echo("Something above needs fixing before a scan will work.")
    raise typer.Exit(EXIT_ERROR)


def _check_state(found: Binary, stack: discover_module.Stack) -> bool:
    """Try a real `init` on one stack, in a throwaway data dir.

    This is the only part of `doctor` that does real work, and it is the part
    most likely to find the actual problem: a backend nobody can reach, or a
    missing lock file.
    """
    try:
        with workspace(prefix="crosswind-doctor-") as space:
            result = Runner(found, space).init(stack.path)
        if result.ok:
            click.echo(f"  [ok]   state: readable in {stack.path}")
            return True
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        click.echo(f"  [FAIL] state: init failed in {stack.path}")
        for line in detail[:5]:
            click.echo(f"           {line}")
        if any("lock file is read-only" in line for line in detail):
            click.echo(
                "           Crosswind will not write to your working tree. Run "
                "`terraform init` there once and commit the lock file."
            )
        return False
    except TerraformError as exc:
        click.echo(f"  [FAIL] state: {exc}")
        return False


@app.command()
def scan(
    path: Annotated[
        Path,
        typer.Option("--path", "-p", help="Stack directory, or a tree to search."),
    ] = Path(),
    profile: Annotated[
        str | None, typer.Option("--profile", help="AWS profile for CloudTrail.")
    ] = None,
    role_arn: Annotated[
        str | None, typer.Option("--role-arn", help="Role to assume for CloudTrail.")
    ] = None,
    region: Annotated[str | None, typer.Option("--region", help="AWS region.")] = None,
    var_file: Annotated[
        list[Path] | None,
        typer.Option("--var-file", help="Passed to Terraform as -var-file. Repeatable."),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", help="Directory or glob to skip. Repeatable."),
    ] = None,
    concurrency: Annotated[
        int | None, typer.Option("--concurrency", "-j", help="Stacks to scan at once.")
    ] = None,
    min_severity: Annotated[
        str | None,
        typer.Option(
            "--min-severity",
            help="Hide findings below this, and exit 0 if nothing reaches it.",
        ),
    ] = None,
    formats: Annotated[
        list[str] | None,
        typer.Option(
            "--format",
            "-f",
            help=f"Output format, repeatable. One of: {', '.join(FORMATS)}.",
        ),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", "-o", help="Where to write file formats."),
    ] = None,
    no_attribution: Annotated[
        bool,
        typer.Option(
            "--no-attribution",
            help="Skip CloudTrail entirely. Every finding will say unknown.",
        ),
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Config file. Defaults to the nearest .crosswind.yml."),
    ] = None,
    binary: Annotated[
        str | None,
        typer.Option("--binary", help="terraform or tofu, or a path to one."),
    ] = None,
    print_default_ignores: Annotated[
        bool,
        typer.Option(
            "--print-default-ignores",
            help="Print a suggested .crosswindignore and exit. Writes nothing.",
        ),
    ] = False,
) -> None:
    """Scan one stack, or discover stacks under a directory.

    Runs `plan -refresh-only` against each stack, scores what it finds, and
    attributes it to a CloudTrail event where the evidence supports one.
    Never writes to your working tree, your state, or AWS.
    """
    if print_default_ignores:
        # Printed, not written. Crosswind does not create files in your repo.
        click.echo(ignore_module.DEFAULT_SUGGESTIONS, nl=False)
        raise typer.Exit(0)

    try:
        loaded = config_module.load(config or config_module.find_config(path))
        settings = config_module.merge_flags(
            loaded,
            min_severity=min_severity,
            concurrency=concurrency,
            formats=formats or (),
            output_dir=output_dir,
            no_attribution=no_attribution,
            exclude=exclude or (),
            var_files=var_file or (),
            region=region,
            binary=binary,
        )
    except (ConfigError, ValueError) as exc:
        _err(f"crosswind: {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    chosen = _validate_formats(settings.formats or ["terminal"])

    try:
        rules = load_rules(settings.severity_overrides)
    except RuleError as exc:
        _err(f"crosswind: {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    try:
        found = find_binary(settings.binary)
    except TerraformError as exc:
        _err(f"crosswind: {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    try:
        stacks = discover_module.discover(path, exclude=settings.all_excludes)
    except OSError as exc:
        _err(f"crosswind: {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    if not stacks:
        _err(f"crosswind: no Terraform stacks found under {path}.")
        _err("           Point --path at a directory with .tf files in it,")
        _err("           or run `crosswind doctor --path <dir>` to see what was skipped.")
        raise typer.Exit(EXIT_ERROR)

    notes = list(settings.warnings)
    lookup: CloudTrailLookup | NullLookup = NullLookup()
    account = identity_arn = None
    session_region = settings.region

    if settings.attribution:
        try:
            aws = session_module.build_session(
                profile=profile, region=settings.region, role_arn=role_arn
            )
            whoami = session_module.whoami(aws)
            account, identity_arn = whoami.account, whoami.arn
            session_region = settings.region or aws.region_name
            lookup = CloudTrailLookup(aws)
        except session_module.CredentialsError as exc:
            # Degrade rather than fail: the drift report is the product.
            notes.append(
                f"Attribution is unavailable ({exc}). Drift detection is unaffected; "
                f"every finding will say unknown."
            )

    _err(f"Scanning {len(stacks)} stack{'s' if len(stacks) != 1 else ''} with {found.label}...")

    try:
        # Aliased on import: this function is also called `scan`, and the
        # shadowing silently passed a `ScanRequest` in as `--path`.
        report = run_scan(
            ScanRequest(
                stacks=stacks,
                binary=found,
                rules=rules,
                config=settings,
                root=path,
                lookup=lookup,
                mapping=load_mapping(),
                session_region=session_region,
                notes=tuple(notes),
                account=account,
                identity=identity_arn,
            )
        )
    except KeyboardInterrupt:
        # The workspace's signal handlers have already deleted the plan
        # files. Say so, because "did that leave secrets in /tmp" is the
        # first thing a careful person will wonder.
        _err("")
        _err("crosswind: interrupted. Temporary plan files were deleted.")
        raise typer.Exit(EXIT_ERROR) from None

    _emit(report, chosen, settings.output_dir)
    raise typer.Exit(report.exit_code)


def _validate_formats(requested: Sequence[str]) -> list[str]:
    """Deduplicate and check `--format`, keeping the order asked for."""
    seen: list[str] = []
    for fmt in requested:
        cleaned = fmt.strip().lower()
        if cleaned not in FORMATS:
            raise typer.BadParameter(
                f"{fmt!r} is not a format. Available: {', '.join(FORMATS)}.",
                param_hint="--format",
            )
        if cleaned not in seen:
            seen.append(cleaned)
    return seen


def _emit(report: Report, formats: list[str], output_dir: Path | None) -> None:
    """Print the terminal report and write the file formats.

    The terminal format always goes to stdout; the others go to files unless
    one of them is the only format and there is no `--output-dir`, in which
    case it goes to stdout so `crosswind scan -f json > out.json` does what
    it looks like it does.
    """
    to_stdout = [fmt for fmt in formats if fmt == "terminal"]
    to_file = [fmt for fmt in formats if fmt != "terminal"]

    if len(formats) == 1 and to_file and output_dir is None:
        click.echo(render(report, to_file[0]), nl=False)
        return

    for fmt in to_stdout:
        click.echo(render(report, fmt), nl=False)

    if not to_file:
        return

    target = output_dir or Path.cwd()
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _err(f"crosswind: could not create {target}: {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    for fmt in to_file:
        destination = target / f"{REPORT_STEM}{EXTENSIONS[fmt]}"
        try:
            destination.write_text(render(report, fmt), encoding="utf-8")
        except OSError as exc:
            _err(f"crosswind: could not write {destination}: {exc}")
            raise typer.Exit(EXIT_ERROR) from exc
        _err(f"Wrote {destination}")


def main() -> None:
    """Entry point for the `crosswind` script."""
    try:
        app()
    except KeyboardInterrupt:  # pragma: no cover - depends on timing
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":  # pragma: no cover
    main()
