"""Suppressing drift somebody has already decided about.

Some drift is expected by design. An autoscaling group's `desired_capacity`
is *supposed* to differ from the code — that is what autoscaling does. An ECS
service's `desired_count` is the same story. A drift report that leads with
those every morning is a report people stop opening, and a tool nobody opens
finds nothing.

So: `.crosswindignore`, which looks like `.gitignore` because everybody
already knows how that works.

    # one pattern per line, '#' starts a comment
    aws_autoscaling_group.*          desired_capacity
    module.legacy.*                                     # the whole module
    aws_ecs_service.api             desired_count

The first field is a glob against the resource address, the optional second
is a glob against the attribute path. An address-only line suppresses the
whole resource; with an attribute, only matching attributes are dropped, and
if a resource has other drift it is still reported.

**Two deliberate decisions.**

*Ignored findings are counted, never silently dropped.* Every report shows
"N findings suppressed by .crosswindignore". The failure mode this guards
against is identical to reporting a broken stack as clean: a reader believing
they have seen everything.

*The shipped defaults are suggestions, not defaults.* Crosswind writes
nothing, so it cannot create an ignore file for you, and applying a built-in
ignore list without being asked would mean silently hiding findings a user
never opted out of. `crosswind scan --print-default-ignores` prints a
starting file for you to read and commit.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from crosswind.core.plan import DriftedResource

IGNORE_FILENAME = ".crosswindignore"

#: A suggested starting point, printed by `--print-default-ignores`. Never
#: applied unless a user puts it in a file themselves.
#:
#: Everything here is drift that is expected by design rather than drift that
#: is unimportant — the distinction matters, because the second kind should be
#: a severity rule and not an ignore.
DEFAULT_SUGGESTIONS = """\
# .crosswindignore — drift Crosswind should not report.
#
# Format: <address glob> [attribute glob]
# One per line. '#' starts a comment. An address with no attribute
# suppresses the whole resource.
#
# These are suggestions, not defaults: Crosswind applies nothing you have not
# put in this file. Delete the ones that do not apply to you.

# Autoscaling is supposed to change these. Pair each one with a
# `lifecycle { ignore_changes = [...] }` in the code, or the next apply will
# fight your scaler.
*                                   desired_capacity
*                                   desired_count

# Set by a deploy pipeline rather than by Terraform, in most setups.
aws_ecs_service.*                   task_definition
aws_lambda_function.*               last_modified
aws_lambda_function.*               source_code_hash
aws_lambda_function.*               qualified_arn
aws_lambda_function.*               version

# Timestamps and computed values that change without anything changing.
*                                   tags_all.LastModified
*                                   latest_revision

# Managed by the service, not by you.
aws_autoscaling_group.*             load_balancers.*
aws_autoscaling_group.*             target_group_arns.*
"""


@dataclass(frozen=True)
class Pattern:
    """One line from an ignore file."""

    address: str
    attribute: str | None
    #: Where it came from, so `--explain`-style output and a confused user can
    #: find the line that hid something.
    source: str
    line_number: int

    def matches_address(self, address: str) -> bool:
        return fnmatch.fnmatch(address, self.address)

    def matches_attribute(self, path: str) -> bool:
        return self.attribute is None or fnmatch.fnmatch(path, self.attribute)

    @property
    def whole_resource(self) -> bool:
        return self.attribute is None

    def __str__(self) -> str:
        suffix = f" {self.attribute}" if self.attribute else ""
        return f"{self.address}{suffix}"


@dataclass(frozen=True)
class Decision:
    """What the ignore rules did to one drifted resource."""

    #: `None` when the whole resource was suppressed.
    resource: DriftedResource | None
    #: Patterns that matched, for the "why is this not in my report" question.
    matched: tuple[Pattern, ...] = ()

    @property
    def suppressed_entirely(self) -> bool:
        return self.resource is None


@dataclass(frozen=True)
class IgnoreFile:
    """The patterns from one or more `.crosswindignore` files."""

    patterns: tuple[Pattern, ...] = ()

    @property
    def active(self) -> bool:
        return bool(self.patterns)

    def apply(self, resource: DriftedResource) -> Decision:
        """Drop whatever the patterns say to drop.

        A resource matched by an address-only pattern disappears. A resource
        whose *every* attribute is matched also disappears — there would be
        nothing left to show. Otherwise the matching attributes are removed
        and the resource is reported with the rest.
        """
        whole = [
            pattern
            for pattern in self.patterns
            if pattern.whole_resource and pattern.matches_address(resource.address)
        ]
        if whole:
            return Decision(resource=None, matched=tuple(whole))

        kept = []
        matched: list[Pattern] = []
        for change in resource.changes:
            hit = next(
                (
                    pattern
                    for pattern in self.patterns
                    if pattern.matches_address(resource.address)
                    and pattern.matches_attribute(change.path)
                ),
                None,
            )
            if hit is None:
                kept.append(change)
            else:
                matched.append(hit)

        if not matched:
            return Decision(resource=resource)
        if not kept:
            # Every attribute was ignored, so there is nothing to report. The
            # resource still counts towards the suppressed total.
            return Decision(resource=None, matched=tuple(matched))

        return Decision(resource=replace(resource, changes=tuple(kept)), matched=tuple(matched))


def parse(text: str, *, source: str = IGNORE_FILENAME) -> IgnoreFile:
    """Parse ignore-file text. Unparseable lines are skipped, not fatal.

    A typo in an ignore file should not stop a scan: the consequence of
    ignoring the line is that a finding appears, which is the safe direction.
    The consequence of failing the scan is that nobody sees any findings.
    """
    patterns: list[Pattern] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        address = fields[0]
        attribute = fields[1] if len(fields) > 1 else None
        patterns.append(
            Pattern(
                address=address,
                attribute=attribute,
                source=source,
                line_number=number,
            )
        )
    return IgnoreFile(patterns=tuple(patterns))


def load(stack: Path, extra_roots: Iterable[Path] = ()) -> IgnoreFile:
    """Collect ignore files for a stack.

    Looked for in the stack directory and in each root given — in practice
    the scan root, so a monorepo can keep one file at the top rather than one
    per stack. Patterns from all of them apply together; there is no
    overriding, because a negation syntax is the part of `.gitignore` nobody
    can remember the rules for.
    """
    patterns: list[Pattern] = []
    seen: set[Path] = set()
    for directory in [stack, *extra_roots]:
        candidate = (directory / IGNORE_FILENAME).resolve()
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        try:
            text = candidate.read_text(encoding="utf-8")
        except OSError:
            continue
        patterns.extend(parse(text, source=str(candidate)).patterns)
    return IgnoreFile(patterns=tuple(patterns))


def filter_all(
    resources: Sequence[DriftedResource], ignores: IgnoreFile
) -> tuple[tuple[DriftedResource, ...], int]:
    """Apply the ignore file to a stack's drift.

    Returns what survived and how many resources were suppressed, so the
    caller can report the count rather than leave a reader guessing.
    """
    kept: list[DriftedResource] = []
    suppressed = 0
    for resource in resources:
        decision = ignores.apply(resource)
        if decision.suppressed_entirely:
            suppressed += 1
        else:
            assert decision.resource is not None
            kept.append(decision.resource)
    return tuple(kept), suppressed
