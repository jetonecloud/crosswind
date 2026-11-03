"""Shared fixtures.

The plan files in `fixtures/plans/` are real output, generated locally
against Terraform v1.15.8 and OpenTofu v1.13.2 with the `local` and `null`
providers. They contain no credentials — the only secret-shaped values in
them are the deliberate `db-password-ORIGINAL` and `SUPERSECRET-TOKEN-AAA`
strings that `test_redact.py` asserts never escape into a report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
PLANS = FIXTURES / "plans"


def load_plan(name: str) -> dict[str, Any]:
    """One of the captured plan JSON files, by filename stem."""
    path = PLANS / f"{name}.json"
    payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return payload


@pytest.fixture()
def terraform_delete_drift() -> dict[str, Any]:
    """Terraform 1.15.8, three `local` resources modified outside Terraform."""
    return load_plan("terraform-1.15.8-local-delete-drift")


@pytest.fixture()
def terraform_module_drift() -> dict[str, Any]:
    """Terraform 1.15.8, drift across count, for_each and a module."""
    return load_plan("terraform-1.15.8-module-count-foreach-drift")


@pytest.fixture()
def opentofu_delete_drift() -> dict[str, Any]:
    """OpenTofu 1.13.2, the same situation as the Terraform fixture."""
    return load_plan("opentofu-1.13.2-local-delete-drift")


@pytest.fixture()
def opentofu_clean() -> dict[str, Any]:
    """OpenTofu 1.13.2 with no drift — note `resource_drift` is absent."""
    return load_plan("opentofu-1.13.2-no-drift")
