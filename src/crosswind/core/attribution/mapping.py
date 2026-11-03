"""Reading the resource-type map, so contributors don't have to read Python.

The map is `data/cloudtrail.yml`. Everything interesting about a resource
type — which attribute holds the value CloudTrail knows it by, whether its
service logs to `us-east-1`, which event names change which attribute — lives
there rather than here.

Keyed on the Terraform resource type. Not the provider name: Terraform and
OpenTofu report different registry hosts for byte-identical providers, and
`aws_security_group` is `aws_security_group` in both.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any

import yaml

DATA_FILE = "cloudtrail.yml"

#: CloudTrail logs these services to us-east-1 whatever region the resource
#: is in. Used as a fallback for types not in the map; the per-type `global`
#: flag wins where it is set.
DEFAULT_GLOBAL_SERVICES = frozenset(
    {"iam", "route53", "cloudfront", "sts", "organizations", "shield", "waf"}
)


@dataclass(frozen=True)
class ResourceMapping:
    """How to look up one Terraform resource type in CloudTrail."""

    terraform_type: str
    resource_type: str
    lookup_attributes: tuple[str, ...]
    events: frozenset[str]
    attribute_events: tuple[tuple[str, frozenset[str]], ...] = ()
    #: True for services that log only to us-east-1. Getting this wrong means
    #: searching an empty region and reporting "unknown" for a change that is
    #: sitting right there in another region's trail.
    is_global: bool = False

    def lookup_value(self, state: dict[str, Any] | None) -> str | None:
        """The value to hand CloudTrail as `ResourceName`.

        Tries the mapped attributes in order and takes the first that is
        present and non-empty. Returns `None` when the prior state has none
        of them, which is an honest "we cannot look this up" rather than a
        lookup on a guessed value.
        """
        if not state:
            return None
        for attribute in self.lookup_attributes:
            value = state.get(attribute)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, int | float) and not isinstance(value, bool):
                return str(value)
        return None

    def events_for(self, attribute_paths: tuple[str, ...]) -> frozenset[str]:
        """Event names expected for these specific attributes.

        Falls back to the type's general event list when no attribute-specific
        mapping matches. The distinction matters for ranking: an event that
        changes the attribute that actually drifted is much better evidence
        than an event that merely touched the same resource.
        """
        matched: set[str] = set()
        for pattern, names in self.attribute_events:
            if any(fnmatch.fnmatch(path, pattern) for path in attribute_paths):
                matched.update(names)
        return frozenset(matched) if matched else self.events


@dataclass(frozen=True)
class Mapping:
    """The whole map."""

    resources: dict[str, ResourceMapping] = field(default_factory=dict)
    global_services: frozenset[str] = DEFAULT_GLOBAL_SERVICES

    def for_type(self, terraform_type: str) -> ResourceMapping | None:
        """The mapping for a resource type, or `None` if we have none.

        `None` is the honest answer and becomes `unmapped_resource_type` in
        the report — which doubles as a to-do list for contributors.
        """
        return self.resources.get(terraform_type)

    def is_global_type(self, terraform_type: str) -> bool:
        """Does this type's service log only to us-east-1?

        Consulted even for unmapped types, by looking at the provider prefix:
        `aws_iam_something_new` is still an IAM resource, and guessing the
        region right is free.
        """
        mapped = self.resources.get(terraform_type)
        if mapped is not None:
            return mapped.is_global
        parts = terraform_type.split("_")
        return len(parts) > 1 and parts[1] in self.global_services

    @property
    def covered_types(self) -> tuple[str, ...]:
        return tuple(sorted(self.resources))


@lru_cache(maxsize=1)
def load_mapping() -> Mapping:
    """The shipped map, parsed once."""
    raw = yaml.safe_load(
        resources.files("crosswind.data").joinpath(DATA_FILE).read_text(encoding="utf-8")
    )
    if not isinstance(raw, dict):
        raise ValueError(f"{DATA_FILE} should contain a mapping.")

    global_services = (
        frozenset(str(name).lower() for name in raw.get("global_services", ()))
        or DEFAULT_GLOBAL_SERVICES
    )

    entries = raw.get("resources") or {}
    if not isinstance(entries, dict):
        raise ValueError(f"{DATA_FILE}: `resources` should be a mapping.")

    resources_map: dict[str, ResourceMapping] = {}
    for terraform_type, body in entries.items():
        if not isinstance(body, dict):
            continue
        attribute_events = tuple(
            (str(pattern), frozenset(str(name) for name in _as_list(names)))
            for pattern, names in (body.get("attribute_events") or {}).items()
        )
        resources_map[str(terraform_type)] = ResourceMapping(
            terraform_type=str(terraform_type),
            resource_type=str(body.get("resource_type") or ""),
            lookup_attributes=tuple(
                str(name) for name in _as_list(body.get("lookup_attributes")) or ["id"]
            ),
            events=frozenset(str(name) for name in _as_list(body.get("events"))),
            attribute_events=attribute_events,
            is_global=bool(body.get("global", False)),
        )

    return Mapping(resources=resources_map, global_services=global_services)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
