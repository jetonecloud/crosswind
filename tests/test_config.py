"""`.crosswind.yml`, and what it is not allowed to do."""

from __future__ import annotations

from pathlib import Path

import pytest

from crosswind.core.config import (
    CONFIG_FILENAME,
    Config,
    ConfigError,
    find_config,
    load,
    merge_flags,
)
from crosswind.core.findings import Severity


def write(path: Path, body: str) -> Path:
    target = path / CONFIG_FILENAME
    target.write_text(body)
    return target


def test_defaults_when_there_is_no_file() -> None:
    config = load(None)
    assert config.min_severity is Severity.LOW
    assert config.attribution is True
    assert config.concurrency >= 1


def test_reads_the_settings_it_knows(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        """
        version: 1
        min_severity: high
        concurrency: 8
        formats: [json, html]
        attribution: false
        exclude: ["examples", "test-fixtures"]
        region: eu-west-1
        """,
    )
    config = load(path)
    assert config.min_severity is Severity.HIGH
    assert config.concurrency == 8
    assert config.formats == ("json", "html")
    assert config.attribution is False
    assert config.exclude == ("examples", "test-fixtures")
    assert config.region == "eu-west-1"


def test_unknown_keys_are_warned_about_not_ignored(tmp_path: Path) -> None:
    """A misspelled key is a setting someone believes is in effect."""
    path = write(tmp_path, "min_sevrity: high\n")
    config = load(path)
    assert any("min_sevrity" in warning for warning in config.warnings)
    # And the real setting kept its default rather than being silently set.
    assert config.min_severity is Severity.LOW


def test_an_empty_file_is_fine(tmp_path: Path) -> None:
    path = write(tmp_path, "")
    config = load(path)
    assert config.min_severity is Severity.LOW
    assert config.source == str(path)


def test_invalid_yaml_is_an_error(tmp_path: Path) -> None:
    path = write(tmp_path, "min_severity: [unclosed\n")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load(path)


def test_a_non_mapping_file_is_an_error(tmp_path: Path) -> None:
    path = write(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(ConfigError, match="mapping"):
        load(path)


def test_unknown_severity_is_an_error(tmp_path: Path) -> None:
    path = write(tmp_path, "min_severity: extremely-bad\n")
    with pytest.raises(ConfigError, match="Unknown severity"):
        load(path)


def test_non_numeric_concurrency_is_an_error(tmp_path: Path) -> None:
    path = write(tmp_path, "concurrency: lots\n")
    with pytest.raises(ConfigError, match="whole number"):
        load(path)


def test_zero_concurrency_is_an_error(tmp_path: Path) -> None:
    path = write(tmp_path, "concurrency: 0\n")
    with pytest.raises(ConfigError, match="at least 1"):
        load(path)


def test_severity_must_be_a_list(tmp_path: Path) -> None:
    path = write(tmp_path, "severity:\n  tags-only-change: high\n")
    with pytest.raises(ConfigError, match="list of rules"):
        load(path)


# --- the security boundary ---------------------------------------------


def test_binary_cannot_be_a_path(tmp_path: Path) -> None:
    """The config file comes from the repository being scanned.

    Letting it name an executable by path would let a scanned repo choose
    what Crosswind runs, which is a straightforward code execution bug.
    """
    path = write(tmp_path, "binary: /tmp/evil/terraform\n")
    with pytest.raises(ConfigError, match="not a path"):
        load(path)


def test_binary_cannot_be_a_relative_path(tmp_path: Path) -> None:
    path = write(tmp_path, "binary: ./terraform\n")
    with pytest.raises(ConfigError, match="not a path"):
        load(path)


def test_binary_as_a_plain_command_name_is_allowed(tmp_path: Path) -> None:
    path = write(tmp_path, "binary: tofu\n")
    assert load(path).binary == "tofu"


# --- discovery ---------------------------------------------------------


def test_find_config_walks_up_to_the_repo_root(tmp_path: Path) -> None:
    """A monorepo keeps one config at the top, not one per stack."""
    write(tmp_path, "min_severity: high\n")
    stack = tmp_path / "infra" / "prod" / "network"
    stack.mkdir(parents=True)
    found = find_config(stack)
    assert found is not None
    assert found.parent == tmp_path


def test_find_config_prefers_the_nearest(tmp_path: Path) -> None:
    write(tmp_path, "min_severity: low\n")
    stack = tmp_path / "infra"
    stack.mkdir()
    write(stack, "min_severity: critical\n")
    found = find_config(stack)
    assert found is not None
    assert load(found).min_severity is Severity.CRITICAL


def test_find_config_accepts_the_yaml_spelling(tmp_path: Path) -> None:
    (tmp_path / ".crosswind.yaml").write_text("min_severity: high\n")
    assert find_config(tmp_path) is not None


def test_find_config_returns_none_when_there_is_nothing(tmp_path: Path) -> None:
    stack = tmp_path / "deep" / "nested"
    stack.mkdir(parents=True)
    # tmp_path has no config; anything found above it would be outside the
    # test's control, so only assert on the negative within tmp_path.
    found = find_config(stack)
    assert found is None or tmp_path not in found.parents


# --- flag precedence ---------------------------------------------------


def test_flags_override_the_config_file() -> None:
    config = Config(min_severity=Severity.LOW, concurrency=2)
    merged = merge_flags(config, min_severity="critical", concurrency=16)
    assert merged.min_severity is Severity.CRITICAL
    assert merged.concurrency == 16


def test_absent_flags_leave_the_config_alone() -> None:
    """ "Not specified" and "specified as the default" must stay distinct.

    Otherwise a default-valued flag silently overwrites a config file setting
    the user put there on purpose.
    """
    config = Config(min_severity=Severity.HIGH, concurrency=8, attribution=False)
    merged = merge_flags(config)
    assert merged.min_severity is Severity.HIGH
    assert merged.concurrency == 8
    assert merged.attribution is False


def test_no_attribution_flag_can_only_turn_it_off() -> None:
    """There is no `--attribution` to turn it back on, and that is deliberate:
    the flag answers one question."""
    config = Config(attribution=True)
    assert merge_flags(config, no_attribution=True).attribution is False
    assert merge_flags(Config(attribution=True), no_attribution=False).attribution is True


def test_exclude_flags_add_to_the_config_rather_than_replacing() -> None:
    """A team's shared excludes should not vanish because someone added one."""
    config = Config(exclude=("from-config",))
    merged = merge_flags(config, exclude=["from-flag"])
    assert set(merged.exclude) == {"from-config", "from-flag"}


def test_default_excludes_are_always_present() -> None:
    config = Config(exclude=("mine",))
    assert ".terraform" in config.all_excludes
    assert ".git" in config.all_excludes
    assert "mine" in config.all_excludes


def test_all_excludes_does_not_duplicate() -> None:
    config = Config(exclude=(".git", "mine"))
    assert len(config.all_excludes) == len(set(config.all_excludes))
