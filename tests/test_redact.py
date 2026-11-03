"""Redaction, both layers of it.

The name-based layer exists because the provider-marker layer has a failure
mode: an author who forgot. So these tests cover attributes that are *not*
marked sensitive and must still be redacted.
"""

from __future__ import annotations

from typing import Any

import pytest

from crosswind.core.plan import parse_plan
from crosswind.core.redact import (
    MAX_VALUE_CHARS,
    PLACEHOLDER,
    is_opaque_name,
    is_sensitive_name,
    marked_sensitive,
    scrub,
    scrub_text,
)

# --- layer two: name matching ------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "password",
        "master_password",
        "db_password",
        "secret_string",
        "token",
        "session_token",
        "private_key",
        "tls_private_key",
        "api_key",
        "secret_access_key",
        "credentials",
        "ingress.0.auth_token",
        "environment.variables.DATABASE_PASSWORD",
    ],
)
def test_secret_shaped_names_are_sensitive(path: str) -> None:
    assert is_sensitive_name(path)


@pytest.mark.parametrize(
    "path", ["instance_type", "cidr_blocks", "tags.Name", "desired_capacity", "ami"]
)
def test_ordinary_names_are_not_sensitive(path: str) -> None:
    """Over-redaction is cheap but not free: a report of nothing but
    placeholders is useless."""
    assert not is_sensitive_name(path)


@pytest.mark.parametrize(
    "path",
    [
        # "Encryption was turned off" is a high-severity finding. Redacting
        # the boolean that says so would hide the thing we exist to report.
        "encrypted",
        "storage_encrypted",
        "encryption_enabled",
        # Public by construction; only the private key is secret.
        "certificate_arn",
        "certificate_body",
        # Modes and identifiers, not secrets.
        "auth_type",
        "authentication_mode",
        "kms_key_id",
        "key_name",
    ],
)
def test_security_relevant_names_are_deliberately_not_redacted(path: str) -> None:
    """The names that look secret-shaped but must stay readable.

    Each of these was either in the sensitive list or an obvious candidate,
    and each one would have hidden a finding a reader needs. The reasoning is
    recorded next to the list in `redact.py`.
    """
    assert not is_sensitive_name(path)


def test_unmarked_password_is_still_redacted() -> None:
    """The case layer two exists for: a provider that forgot to mark it.

    `before_sensitive` is empty here, so only the name match saves us.
    """
    payload: dict[str, Any] = {
        "format_version": "1.2",
        "terraform_version": "1.15.8",
        "resource_drift": [
            {
                "address": "aws_db_instance.legacy",
                "mode": "managed",
                "type": "aws_db_instance",
                "name": "legacy",
                "change": {
                    "actions": ["update"],
                    "before": {"master_password": "LEAKED-BEFORE-VALUE"},
                    "after": {"master_password": "LEAKED-AFTER-VALUE"},
                    "before_sensitive": {},
                    "after_sensitive": {},
                },
            }
        ],
    }
    entry = parse_plan(payload).drift[0]
    change = entry.changes[0]
    assert change.before == change.after == PLACEHOLDER
    assert change.redacted is True
    # It was not the provider that saved us here, and the report should be
    # able to say so.
    assert change.provider_sensitive is False
    assert "LEAKED" not in repr(entry.changes)


# --- layer one: walking the marker structure ---------------------------


def test_marked_sensitive_reads_a_nested_object() -> None:
    """The real shape, from `local_sensitive_file`: `{"content": true}`."""
    marker = {"content": True, "content_base64": True}
    assert marked_sensitive(marker, ["content"])
    assert not marked_sensitive(marker, ["filename"])


def test_marked_sensitive_handles_true_at_a_parent_level() -> None:
    """`true` on a block means everything underneath it is sensitive.

    This is the case a flat attribute-name lookup gets wrong, which is why
    the walk exists.
    """
    marker = {"environment": True}
    assert marked_sensitive(marker, ["environment"])
    assert marked_sensitive(marker, ["environment", "variables", "DB_HOST"])


def test_marked_sensitive_handles_lists() -> None:
    marker = {"ingress": [False, {"description": True}]}
    assert marked_sensitive(marker, ["ingress", 1, "description"])
    assert not marked_sensitive(marker, ["ingress", 0, "description"])


def test_marked_sensitive_handles_the_plain_false_case() -> None:
    """Terraform emits a bare `false` for "none of this", as the fixtures show."""
    assert not marked_sensitive(False, ["anything"])
    assert not marked_sensitive(None, ["anything"])


def test_marked_sensitive_handles_everything_true() -> None:
    assert marked_sensitive(True, ["whatever", 0, "nested"])


# --- scrub -------------------------------------------------------------


def test_scalars_pass_through() -> None:
    assert scrub("t3.micro", "instance_type") == ("t3.micro", False)
    assert scrub(3, "desired_capacity") == (3, False)
    assert scrub(True, "encrypted_flag") == (True, False)
    assert scrub(None, "tags") == (None, False)


def test_long_values_are_truncated() -> None:
    """A 4 KB blob in a table is unreadable and a good hiding place."""
    value, redacted = scrub("x" * 5000, "description")
    assert redacted is True
    assert len(value) < 300
    assert value.endswith("(truncated)")


def test_containers_are_summarised_not_dumped() -> None:
    assert scrub([1, 2, 3], "cidr_blocks") == ("(3 items)", True)
    assert scrub({"a": 1}, "tags") == ("(1 keys)", True)


def test_user_data_is_never_shown() -> None:
    """A startup script is both too long to read and a classic secret carrier."""
    assert is_opaque_name("user_data")
    value, redacted = scrub("#!/bin/bash\nexport API_KEY=abc123\n", "user_data")
    assert redacted is True
    assert "abc123" not in value
    assert "characters, not shown" in value


def test_scrub_text_trims_and_masks_account_ids() -> None:
    """Terraform error output is the one string in a report we didn't build."""
    text = "Error: AccessDenied for arn:aws:iam::123456789012:role/thing\n" + "\n".join(
        f"line {i}" for i in range(50)
    )
    scrubbed = scrub_text(text)
    assert "123456789012" not in scrubbed
    assert "<account>" in scrubbed
    assert "more lines" in scrubbed
    assert len(scrubbed.splitlines()) <= 13


def test_scrub_text_leaves_a_short_message_alone() -> None:
    assert scrub_text("  Error: no credentials found  ") == "Error: no credentials found"


def test_max_value_chars_is_a_sane_bound() -> None:
    """Pinned so a well-meaning bump has to be deliberate."""
    assert 50 <= MAX_VALUE_CHARS <= 500
