"""The four ways a report comes out.

Every renderer is a pure function of a `Report`. None of them reach for a
plan file, a session, or the filesystem; none of them can redact anything,
because redaction already happened at the parser boundary. That is what makes
the secret-leak test meaningful: seed a value into a plan, and assert it
appears in none of the four outputs.

The formats exist for four different readers:

- **terminal** — the person who ran it, deciding whether to care.
- **json** — a machine. Versioned, documented in `docs/json-schema.md`.
- **markdown** — a PR comment or a GitHub job summary.
- **html** — a manager who did not run the tool and will not install it.
"""

from __future__ import annotations

from collections.abc import Callable

from crosswind.core.report.html import render_html
from crosswind.core.report.json_out import render_json
from crosswind.core.report.markdown import render_markdown
from crosswind.core.report.terminal import render_terminal
from crosswind.core.scan import Report

#: Format name to renderer. The CLI validates `--format` against the keys, so
#: adding one here is all it takes to make it available.
RENDERERS: dict[str, Callable[[Report], str]] = {
    "terminal": render_terminal,
    "json": render_json,
    "markdown": render_markdown,
    "html": render_html,
}

#: File extension per format. `terminal` has none: it goes to stdout and is
#: never written to a file.
EXTENSIONS: dict[str, str] = {
    "json": ".json",
    "markdown": ".md",
    "html": ".html",
}

FORMATS = tuple(RENDERERS)


def render(report: Report, fmt: str) -> str:
    """Render `report` in one format."""
    try:
        return RENDERERS[fmt](report)
    except KeyError:
        available = ", ".join(FORMATS)
        raise ValueError(f"Unknown format {fmt!r}. Available: {available}.") from None


__all__ = [
    "EXTENSIONS",
    "FORMATS",
    "RENDERERS",
    "render",
    "render_html",
    "render_json",
    "render_markdown",
    "render_terminal",
]
