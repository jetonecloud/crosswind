"""The JSON export: the contract for anything programmatic.

Versioned, because somebody is going to build a dashboard on it and should
not have it break silently. The rules, documented in `docs/json-schema.md`:

- Adding a key is a minor bump. Consumers must ignore keys they don't know.
- Removing or re-typing a key is a major bump.
- `null` is used for "we don't know" and is never omitted — a missing key and
  a null key should not be different questions for a consumer to ask.

Sorted keys and a trailing newline, so two reports of an unchanged account
diff to nothing.
"""

from __future__ import annotations

import json

from crosswind.core.scan import Report


def render_json(report: Report) -> str:
    """The report as JSON, stable enough to diff between runs."""
    return (
        json.dumps(
            report.to_dict(),
            indent=2,
            sort_keys=True,
            # Resource names and tags are user-chosen and frequently not
            # ASCII. Escaping them makes the export unreadable for no gain.
            ensure_ascii=False,
            default=str,
        )
        + "\n"
    )
