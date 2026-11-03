"""`.crosswind.yml`, and the flags that override it.

Precedence, most important first: a command-line flag, then the config file,
then the built-in default. That is the order people expect, and it means a
config file can set a team's defaults without stopping anyone overriding them
for one run.

The config file is **read from the repository being scanned**, which makes it
untrusted input. It can set severities, ignore paths and output options; it
cannot name a Terraform subcommand, an executable, a predicate outside the
closed vocabulary, or anything else that would turn a config file into code.
Unknown keys are reported rather than ignored, because a silently-misspelled
key is a setting someone believes is in effect.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from crosswind.core.findings import Severity

CONFIG_FILENAME = ".crosswind.yml"

#: Alternative name, because half the world writes `.yaml`.
CONFIG_FILENAME_ALT = ".crosswind.yaml"

#: Keys we understand at the top level. Anything else is a warning.
KNOWN_KEYS = frozenset(
    {
        "version",
        "severity",
        "exclude",
        "min_severity",
        "concurrency",
        "formats",
        "output_dir",
        "attribution",
        "var_files",
        "region",
        "binary",
        "cloudtrail_window_hours",
    }
)

DEFAULT_CONCURRENCY = 4
DEFAULT_FORMATS: tuple[str, ...] = ("terminal",)

#: Directory names never worth descending into while discovering stacks.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git",
    ".terraform",
    ".terragrunt-cache",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "vendor",
    ".idea",
    ".vscode",
)


class ConfigError(ValueError):
    """The config file is not usable. Loud rather than guessed at."""


@dataclass
class Config:
    """Everything a scan needs that isn't a path.

    Defaults here are the defaults of the tool, so this dataclass doubles as
    the documentation for them.
    """

    min_severity: Severity = Severity.LOW
    concurrency: int = DEFAULT_CONCURRENCY
    formats: tuple[str, ...] = DEFAULT_FORMATS
    output_dir: Path | None = None
    attribution: bool = True
    exclude: tuple[str, ...] = ()
    var_files: tuple[Path, ...] = ()
    region: str | None = None
    binary: str | None = None
    cloudtrail_window_hours: int = 24 * 14
    #: Raw severity-rule overrides, passed to `severity.load_rules`. Validated
    #: there rather than here, so there is one place that knows what a rule is.
    severity_overrides: list[dict[str, Any]] = field(default_factory=list)
    #: Keys we did not recognise, surfaced as warnings. A misspelled key is a
    #: setting someone thinks is in effect.
    warnings: list[str] = field(default_factory=list)
    #: Where this came from, for `doctor` and the report header.
    source: str | None = None

    @property
    def all_excludes(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(DEFAULT_EXCLUDES + self.exclude))


def find_config(start: Path) -> Path | None:
    """The nearest `.crosswind.yml` at or above `start`.

    Walks up so a monorepo can keep one file at the root rather than one per
    stack. Stops at the filesystem root; does not look in `$HOME`, because a
    config outside the repository is a surprise to anyone reading the repo.
    """
    current = start.resolve() if start.is_dir() else start.resolve().parent
    for directory in [current, *current.parents]:
        for name in (CONFIG_FILENAME, CONFIG_FILENAME_ALT):
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def load(path: Path | None) -> Config:
    """Read a config file, or return the defaults if there isn't one."""
    if path is None:
        return Config()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not read {path}: {exc}") from exc

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc

    if raw is None:
        return Config(source=str(path))
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} should contain a mapping, not {type(raw).__name__}.")

    config = Config(source=str(path))
    config.warnings = [
        f"{path}: unknown key `{key}` — ignored." for key in raw if key not in KNOWN_KEYS
    ]

    if "min_severity" in raw:
        try:
            config.min_severity = Severity.parse(str(raw["min_severity"]))
        except ValueError as exc:
            raise ConfigError(f"{path}: {exc}") from exc

    if "concurrency" in raw:
        config.concurrency = _positive_int(raw["concurrency"], "concurrency", path)

    if "cloudtrail_window_hours" in raw:
        config.cloudtrail_window_hours = _positive_int(
            raw["cloudtrail_window_hours"], "cloudtrail_window_hours", path
        )

    if "formats" in raw:
        config.formats = tuple(str(item) for item in _as_list(raw["formats"]))

    if "output_dir" in raw:
        config.output_dir = Path(str(raw["output_dir"])).expanduser()

    if "attribution" in raw:
        config.attribution = bool(raw["attribution"])

    if "exclude" in raw:
        config.exclude = tuple(str(item) for item in _as_list(raw["exclude"]))

    if "var_files" in raw:
        config.var_files = tuple(
            Path(str(item)).expanduser() for item in _as_list(raw["var_files"])
        )

    if "region" in raw:
        config.region = str(raw["region"])

    if "binary" in raw:
        # Deliberately *not* used to locate an executable by path from a
        # config file in a scanned repository: that would let a repo choose
        # what binary runs. `doctor` and `scan` resolve it through
        # `find_binary`, which only accepts a name on PATH or an explicit
        # `--binary`. Here it is a name, nothing more.
        binary = str(raw["binary"]).strip()
        if "/" in binary or "\\" in binary:
            raise ConfigError(
                f"{path}: `binary` must be a command name such as `terraform` or "
                f"`tofu`, not a path. Use `--binary` on the command line if you "
                f"need to point at a specific executable."
            )
        config.binary = binary

    if "severity" in raw:
        overrides = raw["severity"]
        if not isinstance(overrides, list):
            raise ConfigError(
                f"{path}: `severity` should be a list of rules. See docs/severity-rules.md."
            )
        config.severity_overrides = [item for item in overrides if isinstance(item, dict)]

    return config


def merge_flags(
    config: Config,
    *,
    min_severity: str | None = None,
    concurrency: int | None = None,
    formats: Sequence[str] = (),
    output_dir: Path | None = None,
    no_attribution: bool = False,
    exclude: Sequence[str] = (),
    var_files: Sequence[Path] = (),
    region: str | None = None,
    binary: str | None = None,
) -> Config:
    """Apply command-line flags over a loaded config.

    A flag that was not given is `None` or empty, never a default, so that
    "not specified" and "specified as the default value" stay distinguishable
    and a config file setting is not silently overwritten by a default.
    """
    if min_severity is not None:
        config.min_severity = Severity.parse(min_severity)
    if concurrency is not None:
        config.concurrency = max(1, concurrency)
    if formats:
        config.formats = tuple(formats)
    if output_dir is not None:
        config.output_dir = output_dir
    if no_attribution:
        config.attribution = False
    if exclude:
        config.exclude = tuple(config.exclude) + tuple(exclude)
    if var_files:
        config.var_files = tuple(var_files)
    if region is not None:
        config.region = region
    if binary is not None:
        config.binary = binary
    return config


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _positive_int(value: Any, key: str, path: Path) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{path}: `{key}` should be a whole number.") from exc
    if number < 1:
        raise ConfigError(f"{path}: `{key}` should be at least 1.")
    return number
