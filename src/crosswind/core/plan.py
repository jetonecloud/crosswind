"""Turning Terraform's plan JSON into something we can reason about.

Everything in here was written against output generated locally from
Terraform v1.15.8 and OpenTofu v1.13.2, kept in `tests/fixtures/plans/`. The
notes below are what that output actually does, not what the documentation
implies.

**`resource_drift` is absent, not empty, on a clean stack.** Both binaries
omit the key entirely. So the parser uses `.get`, and the *caller* is
responsible for having established that the plan succeeded — which is why
`show_plan_json` raises rather than returning `{}`. "No drift key" must mean
"no drift" only when we already know the plan worked.

**Key on `type`, never on `provider_name`.** The same resource is
`registry.terraform.io/hashicorp/aws` under Terraform and
`registry.opentofu.org/hashicorp/aws` under OpenTofu. `aws_security_group` is
`aws_security_group` in both.

**A `delete` action is one fact, not forty.** When a provider's refresh finds
the resource gone, `after` is `null` and `before` is the entire prior state.
Emitting one change per attribute would bury the only thing that matters, so
a deletion becomes a single synthetic change.

**Sensitive markers mirror the value's shape.** `before_sensitive` is
`{"content": true}`, or `[false, true]`, or just `true` — not a list of
names. We walk it alongside the value. See `redact.marked_sensitive`.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from crosswind.core.findings import AttributeChange, DriftKind
from crosswind.core.redact import PLACEHOLDER, marked_sensitive, scrub

#: Plan JSON representation versions we have actually tested against. Both
#: Terraform 1.15.8 and OpenTofu 1.13.2 emit 1.2. A newer major would be a
#: breaking change to the format and worth refusing; a newer minor is additive
#: by Terraform's own compatibility promise, so we proceed and say so.
SUPPORTED_FORMAT_MAJOR = 1

#: Attributes that are a restatement of another attribute rather than a fact
#: about the resource. Terraform reports a drifted `local_file` with six
#: changed checksum fields, all of which say the same thing as `content`.
#:
#: This is a display concern, not a detection one: the resource is still
#: reported as drifted, and the suppressed paths are counted so nothing
#: vanishes silently. Kept here rather than in the ignore file because it is
#: about the format rather than about any user's expectations.
DERIVED_SUFFIXES: tuple[str, ...] = (
    "_sha1",
    "_sha256",
    "_sha512",
    "_md5",
    "_base64sha256",
    "_base64sha512",
    "_hash",
    "_fingerprint",
)


class MalformedPlan(ValueError):
    """The plan JSON is not shaped the way the documented format says.

    Raised rather than worked around. A stack whose plan we cannot parse is
    reported as "could not check", because the alternative is reporting it as
    clean on the strength of a key we failed to read.
    """


@dataclass(frozen=True)
class DriftedResource:
    """One entry from `resource_drift`, parsed and redacted.

    `address` is carried through verbatim — including `[0]` and `["alpha"]`
    index suffixes and any `module.foo.` prefix — because the address is what
    a user greps for in their own code.
    """

    address: str
    resource_type: str
    name: str
    kind: DriftKind
    changes: tuple[AttributeChange, ...]
    provider: str | None = None
    module_address: str | None = None
    #: `int` for a `count` resource, `str` for `for_each`, `None` otherwise.
    index: int | str | None = None
    #: The raw `before` object, unredacted, for the severity engine and the
    #: CloudTrail mapping to read identifiers out of. Never rendered, never
    #: serialised — the redacted `changes` are what reaches a report.
    raw_before: dict[str, Any] | None = None
    raw_after: dict[str, Any] | None = None
    #: Attribute paths we dropped as derived restatements, so a report can say
    #: how many rather than pretend there were none.
    suppressed: tuple[str, ...] = ()

    @property
    def is_deleted(self) -> bool:
        return self.kind is DriftKind.DELETED


@dataclass(frozen=True)
class PlanSummary:
    """A parsed refresh-only plan."""

    format_version: str
    terraform_version: str
    drift: tuple[DriftedResource, ...]
    #: `True` when the plan JSON says the run errored. Terraform sets
    #: `errored` even on some runs that exit 0, so it is worth reading.
    errored: bool = False

    @property
    def has_drift(self) -> bool:
        return bool(self.drift)


def parse_plan(payload: dict[str, Any]) -> PlanSummary:
    """Parse the output of `terraform show -json <planfile>`.

    Raises `MalformedPlan` on anything that isn't recognisably the documented
    format. Being strict here is what lets the caller trust a missing
    `resource_drift` key to mean "no drift".
    """
    if not isinstance(payload, dict):
        raise MalformedPlan("Plan JSON is not an object.")

    raw_version = payload.get("format_version")
    if not isinstance(raw_version, str) or not raw_version:
        raise MalformedPlan(
            "Plan JSON has no `format_version`. This does not look like the "
            "output of `terraform show -json`."
        )
    major = raw_version.split(".", 1)[0]
    if not major.isdigit() or int(major) != SUPPORTED_FORMAT_MAJOR:
        raise MalformedPlan(
            f"Plan JSON format version {raw_version} is not supported "
            f"(expected {SUPPORTED_FORMAT_MAJOR}.x). Crosswind would have to "
            f"guess at the structure, so it is refusing instead."
        )

    entries = payload.get("resource_drift", [])
    if not isinstance(entries, list):
        raise MalformedPlan("`resource_drift` is present but is not a list.")

    drift = tuple(_parse_entry(entry) for entry in entries if _is_managed(entry))
    return PlanSummary(
        format_version=raw_version,
        terraform_version=str(payload.get("terraform_version") or "unknown"),
        drift=drift,
        errored=bool(payload.get("errored")),
    )


def _is_managed(entry: Any) -> bool:
    """Only managed resources drift.

    Data sources appear in a refresh-only plan's other sections and re-read on
    every run by design; reporting one as drift would be noise with no action
    attached.
    """
    return isinstance(entry, dict) and entry.get("mode", "managed") == "managed"


def _parse_entry(entry: dict[str, Any]) -> DriftedResource:
    address = entry.get("address")
    if not isinstance(address, str) or not address:
        raise MalformedPlan("A `resource_drift` entry has no `address`.")

    change = entry.get("change")
    if not isinstance(change, dict):
        raise MalformedPlan(f"`{address}` has no `change` object.")

    actions = change.get("actions")
    if not isinstance(actions, list) or not actions:
        raise MalformedPlan(f"`{address}` has no `change.actions`.")

    before = change.get("before")
    after = change.get("after")
    kind = _kind_for(actions)

    if kind is DriftKind.DELETED:
        changes: tuple[AttributeChange, ...] = (
            AttributeChange(
                path="(resource)",
                before="present",
                after="absent",
            ),
        )
        suppressed: tuple[str, ...] = ()
    else:
        changes, suppressed = _diff(
            before if isinstance(before, dict) else {},
            after if isinstance(after, dict) else {},
            change.get("before_sensitive"),
            change.get("after_sensitive"),
        )

    return DriftedResource(
        address=address,
        resource_type=str(entry.get("type") or ""),
        name=str(entry.get("name") or ""),
        kind=kind,
        changes=changes,
        provider=_provider_short(entry.get("provider_name")),
        module_address=entry.get("module_address") or None,
        index=entry.get("index"),
        raw_before=before if isinstance(before, dict) else None,
        raw_after=after if isinstance(after, dict) else None,
        suppressed=suppressed,
    )


def _kind_for(actions: Sequence[Any]) -> DriftKind:
    """Map a plan action list onto what we tell the user happened.

    `["delete"]` in `resource_drift` does not mean Terraform wants to delete
    anything — it means the refresh could not find the resource, so it has
    dropped out of state. `["delete", "create"]` is a replacement.
    """
    normalised = [str(action) for action in actions]
    if normalised == ["delete"]:
        return DriftKind.DELETED
    if "delete" in normalised and "create" in normalised:
        return DriftKind.REPLACED
    return DriftKind.CHANGED


def _provider_short(provider_name: Any) -> str | None:
    """`registry.terraform.io/hashicorp/aws` -> `hashicorp/aws`.

    The registry host differs between Terraform and OpenTofu for identical
    providers, and carrying it into a report invites someone to read meaning
    into the difference. Nothing keys on this value.
    """
    if not isinstance(provider_name, str) or not provider_name:
        return None
    parts = provider_name.split("/")
    return "/".join(parts[-2:]) if len(parts) >= 2 else provider_name


def _is_derived(path: str) -> bool:
    """Is this attribute a restatement of another one?"""
    leaf = path.rsplit(".", 1)[-1]
    return any(leaf.endswith(suffix) for suffix in DERIVED_SUFFIXES)


def _diff(
    before: dict[str, Any],
    after: dict[str, Any],
    before_sensitive: Any,
    after_sensitive: Any,
) -> tuple[tuple[AttributeChange, ...], tuple[str, ...]]:
    """Every leaf attribute whose value is not the same on both sides.

    Flattened to dotted paths so a rule can match `ingress.0.cidr_blocks.1`
    and a report can print one line per real difference. Attributes that are
    equal are dropped: Terraform puts the whole object in `before`, and only
    the differences are drift.
    """
    flat_before = dict(_flatten(before))
    flat_after = dict(_flatten(after))

    changes: list[AttributeChange] = []
    suppressed: list[str] = []
    for path in _ordered_paths(flat_before, flat_after):
        old = flat_before.get(path)
        new = flat_after.get(path)
        if old == new:
            continue
        # `after` legitimately omits attributes that are computed and not yet
        # known. That is not drift, it is the plan saying "ask me later".
        if path not in flat_after and path in flat_before and not after:
            continue
        if _is_derived(path):
            suppressed.append(path)
            continue

        steps = _steps(path)
        provider_sensitive = marked_sensitive(before_sensitive, steps) or marked_sensitive(
            after_sensitive, steps
        )
        scrubbed_before, redacted_before = scrub(old, path)
        scrubbed_after, redacted_after = scrub(new, path)
        if provider_sensitive:
            # The provider says this is a secret. We do not second-guess it,
            # and we do not print a length or a shape either.
            scrubbed_before = PLACEHOLDER if old is not None else None
            scrubbed_after = PLACEHOLDER if new is not None else None
            redacted_before = redacted_after = True

        changes.append(
            AttributeChange(
                path=path,
                before=scrubbed_before,
                after=scrubbed_after,
                redacted=redacted_before or redacted_after,
                provider_sensitive=provider_sensitive,
            )
        )
    return tuple(changes), tuple(suppressed)


def _ordered_paths(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Union of both sides' paths, `before` order first, then new ones.

    Stable ordering matters: it is what makes two reports of an unchanged
    account diff to nothing.
    """
    seen = list(before)
    seen.extend(path for path in after if path not in before)
    return seen


def _flatten(value: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Walk a plan value into `(dotted.path, leaf)` pairs.

    Lists are indexed by position. That is imperfect for a set-typed
    attribute, where the provider's ordering is arbitrary and a reordering
    reads as a change — see the limitations in the README. Indexing by
    position is still better than the alternatives: hashing the element makes
    the path meaningless to a reader, and refusing to descend turns every
    security group rule change into "(4 items) -> (4 items)".
    """
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _flatten(item, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _flatten(item, f"{prefix}.{index}" if prefix else str(index))
    else:
        yield prefix, value


def _steps(path: str) -> list[str | int]:
    """`ingress.0.cidr_blocks` -> `["ingress", 0, "cidr_blocks"]`.

    Needed because the sensitivity marker is a structure mirroring the value,
    so walking it requires knowing which steps were list indices.
    """
    steps: list[str | int] = []
    for part in path.split("."):
        steps.append(int(part) if part.isdigit() else part)
    return steps
