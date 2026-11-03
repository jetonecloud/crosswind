"""Keeping secrets out of the report, twice.

A plan file is the prior state, and the prior state is where providers keep
the things you would least like in a shared HTML file: `aws_db_instance`
passwords, `tls_private_key` PEMs, Lambda environment variables, raw
`user_data`. Crosswind's whole job is to show you attribute values that
changed, so this is not a theoretical risk — it is the default behaviour
unless something stops it.

Two layers, because each one fails differently:

1. **Terraform's own markers.** Providers declare which attributes are
   sensitive, and the plan JSON carries that as `before_sensitive` /
   `after_sensitive`. This is the authoritative source and we honour it. It
   fails when a provider author forgets, which happens.
2. **Name matching.** Any attribute path containing `password`, `token`,
   `secret`, `private_key` and friends is redacted whatever the markers say.
   This fails on a secret in an attribute called something else entirely —
   `connection_string`, say — which is why it is the second layer and not the
   only one.

The important structural decision: **redaction happens once, at the parser
boundary.** A `Finding` is built from already-redacted values, so no renderer
can leak something, and there is one place to audit rather than four. The
secret-leak tests seed a known string into a plan fixture and assert it
appears in none of the four formats.

One thing worth being honest about: the *names* of attributes, resource
addresses, and the structure of a diff are not redacted, and are not secret
in the same way, but they do describe someone's infrastructure. A report is
sensitive even when every value in it is `(sensitive value)`.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

#: Shown in place of anything redacted. Matches the string Terraform itself
#: prints, so a reader who knows Terraform already knows what it means.
PLACEHOLDER = "(sensitive value)"

#: Substrings that make an attribute path sensitive regardless of what the
#: provider declared. Matched case-insensitively against the whole dotted
#: path, so `ingress.0.password` is caught as well as `password`.
#:
#: Erring towards over-redaction on purpose: a redacted value a user wanted to
#: see is an annoyance, and a leaked one is an incident. `--show-redacted` is
#: deliberately not a flag.
#:
#: Four names that look like they belong here and deliberately do not:
#:
#: - **`encrypted`**. `encrypted`, `storage_encrypted` and
#:   `encryption_enabled` are booleans, and "encryption was turned off" is one
#:   of the highest-severity findings Crosswind produces. Redacting it would
#:   hide the exact drift the tool exists to surface.
#: - **`certificate`**. A certificate body, chain or ARN is public by
#:   construction — only the private key is secret, and `private_key` covers
#:   that. Redacting `certificate_arn` would hide a changed TLS certificate on
#:   a listener, which is a real finding.
#: - **`auth`**. Matches `auth_type`, `authentication_mode` and `authorizer_id`,
#:   none of which are secret and all of which are worth seeing. The secret
#:   case, `auth_token`, is caught by `token`.
#: - **`key`** on its own. Too broad to be useful: `key_name`, `kms_key_id` and
#:   `hash_key` are all identifiers.
SENSITIVE_NAME_PARTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "private_key",
    "privatekey",
    "credential",
    "api_key",
    "apikey",
    "access_key",
    "session_key",
    "ciphertext",
    "salt",
    "signature",
)

#: Long values get cut. A 16 KB `user_data` blob in a diff is unreadable, and
#: it is also the most likely place for a secret nobody marked to be hiding.
MAX_VALUE_CHARS = 200

#: Attributes whose value is a whole document rather than a scalar. We show
#: that they changed and how long they are, never the content — a policy
#: document or a startup script is both too long to read in a table and too
#: likely to carry something private.
OPAQUE_NAME_PARTS: tuple[str, ...] = ("user_data", "cloud_init")

_TRUNCATION = "... (truncated)"


def is_sensitive_name(path: str) -> bool:
    """Does this attribute path look like it holds a secret?"""
    lowered = path.lower()
    return any(part in lowered for part in SENSITIVE_NAME_PARTS)


def is_opaque_name(path: str) -> bool:
    """Is this an attribute we summarise rather than show?"""
    lowered = path.lower()
    return any(part in lowered for part in OPAQUE_NAME_PARTS)


def marked_sensitive(marker: Any, path: Sequence[str | int]) -> bool:
    """Walk a `*_sensitive` structure alongside a path into the value.

    Terraform's marker mirrors the shape of the value rather than listing
    attribute names: for an object it is `{"content": true}`, for a list
    `[false, true]`, and for "all of this is sensitive" just `true`. A `true`
    at any level means everything underneath it is sensitive, which is the
    case that a flat name lookup would get wrong.
    """
    node = marker
    for step in path:
        if node is True:
            return True
        if isinstance(node, dict):
            if not isinstance(step, str) or step not in node:
                return False
            node = node[step]
        elif isinstance(node, list):
            if not isinstance(step, int) or step >= len(node):
                return False
            node = node[step]
        else:
            return False
    return node is True


def scrub(value: Any, path: str) -> tuple[Any, bool]:
    """A value fit to print, and whether we changed it to get there.

    Returns `(value, redacted)`. Scalars come back as-is unless they are
    long; containers are summarised rather than dumped, because a report that
    prints a whole `ingress` block as JSON is a report nobody reads.
    """
    if is_sensitive_name(path):
        return PLACEHOLDER, True
    if value is None:
        return None, False
    if is_opaque_name(path) and isinstance(value, str):
        return f"({len(value)} characters, not shown)", True
    if isinstance(value, bool | int | float):
        return value, False
    if isinstance(value, str):
        if len(value) > MAX_VALUE_CHARS:
            return value[:MAX_VALUE_CHARS] + _TRUNCATION, True
        return value, False
    if isinstance(value, list):
        return f"({len(value)} items)", True
    if isinstance(value, dict):
        return f"({len(value)} keys)", True
    return str(value)[:MAX_VALUE_CHARS], False


#: Account IDs, so a report can be shared without naming the account. Not a
#: secret, but reliably unwelcome in a screenshot.
_ACCOUNT_ID = re.compile(r"\b\d{12}\b")


def scrub_text(text: str) -> str:
    """Scrub a free-text string — an error message, usually.

    Terraform error output quotes configuration and occasionally values, and
    it is the one thing in a report that we did not construct ourselves. Long
    output is cut to the first few lines: the useful part of a Terraform
    error is at the top, and the rest is a stack of provider context that can
    contain anything.
    """
    lines = [line.rstrip() for line in text.strip().splitlines() if line.strip()]
    kept = lines[:12]
    joined = "\n".join(kept)
    if len(lines) > len(kept):
        joined += f"\n... ({len(lines) - len(kept)} more lines)"
    return _ACCOUNT_ID.sub("<account>", joined)[:4000]
