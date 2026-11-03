"""Stack discovery, and erring towards including an ambiguous directory."""

from __future__ import annotations

from pathlib import Path

import pytest

from crosswind.core.discover import discover, excluded, is_stack_dir, looks_like_module


def stack(path: Path, *files: str) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    for name in files or ("main.tf",):
        (path / name).write_text("# terraform\n")
    return path


def test_a_directory_with_tf_files_is_a_stack(tmp_path: Path) -> None:
    assert is_stack_dir(stack(tmp_path / "infra"))


def test_a_directory_with_no_tf_files_is_not(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "readme.md").write_text("hi")
    assert not is_stack_dir(tmp_path / "docs")


def test_tf_json_counts(tmp_path: Path) -> None:
    """Terraform reads both spellings, so discovery has to as well."""
    assert is_stack_dir(stack(tmp_path / "generated", "main.tf.json"))


def test_a_path_that_is_itself_a_stack_is_the_only_result(tmp_path: Path) -> None:
    """`--path` at one directory means one stack, not that plus its modules."""
    root = stack(tmp_path / "infra")
    stack(root / "submodule")
    found = discover(root)
    assert [item.path for item in found] == [root]


def test_discovers_stacks_recursively(tmp_path: Path) -> None:
    stack(tmp_path / "infra" / "prod")
    stack(tmp_path / "infra" / "staging")
    stack(tmp_path / "tooling")
    found = discover(tmp_path)
    assert {item.path.name for item in found} == {"prod", "staging", "tooling"}


def test_results_are_sorted_so_reports_diff_cleanly(tmp_path: Path) -> None:
    for name in ("zebra", "alpha", "middle"):
        stack(tmp_path / name)
    found = discover(tmp_path)
    paths = [item.path.as_posix() for item in found]
    assert paths == sorted(paths)


def test_does_not_descend_into_a_stack(tmp_path: Path) -> None:
    """A stack's subdirectories are its modules, not more stacks."""
    root = stack(tmp_path / "infra" / "prod")
    stack(root / "vpc")
    found = discover(tmp_path)
    assert [item.path for item in found] == [root]


def test_modules_directory_is_skipped(tmp_path: Path) -> None:
    stack(tmp_path / "modules" / "vpc")
    stack(tmp_path / "live" / "prod")
    found = discover(tmp_path)
    assert [item.path.name for item in found] == ["prod"]


def test_a_module_shaped_directory_is_skipped(tmp_path: Path) -> None:
    """variables.tf + outputs.tf, no backend, no provider, no state."""
    path = stack(tmp_path / "vpc", "main.tf", "variables.tf", "outputs.tf")
    assert looks_like_module(path)
    assert discover(tmp_path) == []


def test_a_module_shaped_directory_that_has_been_initialised_is_a_stack(
    tmp_path: Path,
) -> None:
    """Somebody runs it here, whatever its file layout suggests."""
    path = stack(tmp_path / "vpc", "main.tf", "variables.tf", "outputs.tf")
    (path / ".terraform.lock.hcl").write_text("# lock\n")
    assert not looks_like_module(path)
    assert [item.path for item in discover(tmp_path)] == [path]


def test_a_directory_with_a_backend_is_a_stack_despite_variables(tmp_path: Path) -> None:
    path = stack(tmp_path / "prod", "main.tf", "variables.tf", "outputs.tf", "backend.tf")
    assert not looks_like_module(path)


def test_a_directory_with_only_variables_is_ambiguous_and_included(tmp_path: Path) -> None:
    """Ambiguity resolves towards scanning it.

    A false positive costs one visible "could not check" line. A false
    negative is a stack nobody is checking and nobody knows it.
    """
    path = stack(tmp_path / "thing", "main.tf", "variables.tf")
    assert not looks_like_module(path)
    assert [item.path for item in discover(tmp_path)] == [path]


def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    """Following them makes cycles possible and "what did we scan" unanswerable."""
    real = stack(tmp_path / "real")
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:  # pragma: no cover - Windows without privileges
        pytest.skip("symlinks not available")
    found = discover(tmp_path)
    assert [item.path for item in found] == [real]


def test_every_stack_carries_a_reason(tmp_path: Path) -> None:
    """Useful when discovery picks up something unexpected."""
    stack(tmp_path / "prod", "main.tf", "backend.tf")
    found = discover(tmp_path)
    assert found[0].reason
    assert "backend.tf" in found[0].reason or "main.tf" in found[0].reason


def test_missing_path_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        discover(tmp_path / "nope")


def test_a_file_path_is_an_error(tmp_path: Path) -> None:
    target = tmp_path / "main.tf"
    target.write_text("# tf")
    with pytest.raises(NotADirectoryError):
        discover(target)


def test_max_depth_stops_runaway_walks(tmp_path: Path) -> None:
    deep = tmp_path
    for index in range(8):
        deep = deep / f"level{index}"
    stack(deep)
    assert discover(tmp_path, max_depth=3) == []
    assert len(discover(tmp_path, max_depth=12)) == 1


# --- excludes -----------------------------------------------------------


def test_exclude_by_directory_name(tmp_path: Path) -> None:
    stack(tmp_path / "examples" / "demo")
    stack(tmp_path / "live" / "prod")
    found = discover(tmp_path, exclude=("examples",))
    assert [item.path.name for item in found] == ["prod"]


def test_exclude_by_relative_glob(tmp_path: Path) -> None:
    stack(tmp_path / "infra" / "legacy")
    stack(tmp_path / "infra" / "current")
    found = discover(tmp_path, exclude=("infra/legacy",))
    assert [item.path.name for item in found] == ["current"]


def test_exclude_with_a_wildcard(tmp_path: Path) -> None:
    stack(tmp_path / "test-one")
    stack(tmp_path / "test-two")
    stack(tmp_path / "real")
    found = discover(tmp_path, exclude=("test-*",))
    assert [item.path.name for item in found] == ["real"]


def test_exclude_matches_on_name_relative_and_absolute(tmp_path: Path) -> None:
    path = stack(tmp_path / "infra" / "prod")
    assert excluded(path, tmp_path, ("prod",))
    assert excluded(path, tmp_path, ("infra/prod",))
    assert excluded(path, tmp_path, (path.as_posix(),))
    assert not excluded(path, tmp_path, ("staging",))


def test_exclude_tolerates_a_trailing_slash(tmp_path: Path) -> None:
    """People type `--exclude examples/` and should not be surprised."""
    path = stack(tmp_path / "examples")
    assert excluded(path, tmp_path, ("examples/",))


def test_default_dot_directories_do_not_become_stacks(tmp_path: Path) -> None:
    """`.terraform` holds vendored modules with real .tf files in them."""
    stack(tmp_path / ".terraform" / "modules" / "vendored")
    stack(tmp_path / "live")
    found = discover(tmp_path, exclude=(".terraform", ".git"))
    assert [item.path.name for item in found] == ["live"]
