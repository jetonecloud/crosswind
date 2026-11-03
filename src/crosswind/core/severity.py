"""Deciding how much a drifted resource matters.

The rules are data — `data/severity.yml`, plus whatever a project adds in
`.crosswind.yml`. This module is the engine that reads them, and it is
deliberately small.

Two decisions worth defending:

**The predicate vocabulary is closed.** A rule can say `when: became_public`
but it cannot say `when: <expression>`. An expression language in a config
file that Crosswind loads from the repository it is scanning is a remote code
execution bug with extra steps. The cost is that adding a genuinely new kind
of predicate needs a Python change; the benefit is that a malicious
`.crosswind.yml` can at worst mis-score a finding.

**First match wins, in file order.** Not "highest severity wins". A reader
who adds a rule at the top expects it to take effect, and a scoring system
where you have to know every other rule to predict the outcome is a scoring
system nobody will edit. The shipped file is ordered most-specific first for
this reason, and `default` is last.

Every finding carries `severity_rule`. If you cannot trace a severity to a
line in a YAML file, the tool is asking to be trusted rather than checked.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

import yaml

from crosswind.core.findings import AttributeChange, DriftKind, Recommendation, Severity
from crosswind.core.plan import DriftedResource

DATA_FILE = "severity.yml"

#: Values that mean "the whole internet" in a CIDR or principal field.
PUBLIC_CIDRS = frozenset({"0.0.0.0/0", "::/0", "0000:0000:0000:0000:0000:0000:0000:0000/0"})

#: Values that mean "anyone" in a principal or ACL field.
PUBLIC_PRINCIPALS = frozenset(
    {"*", "all", "public-read", "public-read-write", "authenticated-read", "none"}
)

#: Rough ordering for instance sizes, so `became_larger` can say something
#: useful about `t3.micro` -> `t3.large`. Not a price list and not exhaustive:
#: it is only used to decide a direction, and an unknown size simply means we
#: decline to have an opinion.
SIZE_ORDER: tuple[str, ...] = (
    "nano",
    "micro",
    "small",
    "medium",
    "large",
    "xlarge",
    "2xlarge",
    "3xlarge",
    "4xlarge",
    "6xlarge",
    "8xlarge",
    "9xlarge",
    "10xlarge",
    "12xlarge",
    "16xlarge",
    "18xlarge",
    "24xlarge",
    "32xlarge",
    "metal",
)

_TRUTHY = frozenset({"true", "1", "yes", "enabled", "on"})
_FALSEY = frozenset({"false", "0", "no", "disabled", "off", ""})


class RuleError(ValueError):
    """A severity rule file is not usable.

    Raised loudly. A rule file we half-understood would produce severities
    nobody could explain, which is worse than refusing to start.
    """


@dataclass(frozen=True)
class Rule:
    """One scoring rule, as loaded from YAML."""

    id: str
    severity: Severity
    reason: str
    recommend: Recommendation
    recommend_reason: str
    types: tuple[str, ...] = ("*",)
    paths: tuple[str, ...] = ("*",)
    when: str = "any_change"
    kinds: tuple[str, ...] = ()
    #: Where this rule came from, so an unexpected severity is traceable to a
    #: file rather than just to an id.
    source: str = "builtin"

    def matches_type(self, resource_type: str) -> bool:
        return any(fnmatch.fnmatch(resource_type, pattern) for pattern in self.types)

    def matches_kind(self, kind: DriftKind) -> bool:
        return not self.kinds or kind.value in self.kinds

    def matching_paths(self, changes: Sequence[AttributeChange]) -> list[AttributeChange]:
        return [
            change
            for change in changes
            if any(fnmatch.fnmatch(change.path, pattern) for pattern in self.paths)
        ]


@dataclass(frozen=True)
class Verdict:
    """What the engine decided, and which rule decided it."""

    severity: Severity
    rule_id: str
    reason: str
    recommendation: Recommendation
    recommendation_reason: str
    #: The attribute paths that made the rule fire. Lets a report point at
    #: the one line out of forty that earned the severity.
    triggered_by: tuple[str, ...] = ()


@dataclass
class RuleSet:
    """The loaded rules, in the order they are evaluated."""

    rules: list[Rule] = field(default_factory=list)

    def score(self, resource: DriftedResource) -> Verdict:
        """The first rule that matches. There is always one: `default`."""
        for rule in self.rules:
            if not rule.matches_type(resource.resource_type):
                continue
            if not rule.matches_kind(resource.kind):
                continue

            if not resource.changes:
                # A drifted resource with no renderable attribute changes:
                # every difference was a derived restatement we suppressed, or
                # the provider reported the resource as drifted without
                # saying how. It is still drift. A catch-all rule can score it
                # on the resource type alone, but a rule that asks a question
                # about a specific attribute has nothing to look at and must
                # not fire — scoring `became_public` against no value at all
                # is how a tool invents a critical finding.
                if rule.paths == ("*",) and rule.when == "any_change":
                    return self._verdict(rule, ())
                continue

            candidates = rule.matching_paths(resource.changes)
            if not candidates and rule.paths != ("*",):
                continue
            triggered = [
                change for change in (candidates or resource.changes) if _holds(rule.when, change)
            ]
            if not triggered:
                continue
            return Verdict(
                severity=rule.severity,
                rule_id=rule.id,
                reason=_tidy(rule.reason),
                recommendation=rule.recommend,
                recommendation_reason=_tidy(rule.recommend_reason),
                triggered_by=tuple(change.path for change in triggered),
            )

        # Only reachable if someone removed `default` from the file. Scoring
        # nothing is not an option, so say so plainly rather than crash.
        return Verdict(
            severity=Severity.LOW,
            rule_id="unscored",
            reason=(
                "No severity rule matched, and the rule set has no `default` rule. "
                "This is a gap in the rules, not a judgement about the resource."
            ),
            recommendation=Recommendation.INVESTIGATE,
            recommendation_reason="Read the diff, and add a rule so the next one is scored.",
            triggered_by=tuple(change.path for change in resource.changes),
        )

    def _verdict(self, rule: Rule, triggered: Sequence[AttributeChange]) -> Verdict:
        return Verdict(
            severity=rule.severity,
            rule_id=rule.id,
            reason=_tidy(rule.reason),
            recommendation=rule.recommend,
            recommendation_reason=_tidy(rule.recommend_reason),
            triggered_by=tuple(change.path for change in triggered),
        )


def load_rules(overrides: Sequence[dict[str, Any]] = ()) -> RuleSet:
    """The shipped rules, with a project's own merged in.

    Overrides are matched by `id`: an override with an existing id replaces
    that rule in place, keeping its position in the evaluation order, and one
    with a new id goes in front of everything shipped. That means a project
    can soften a rule it disagrees with without having to re-state the other
    thirty, and a new project-specific rule wins over a general shipped one.
    """
    raw = yaml.safe_load(
        resources.files("crosswind.data").joinpath(DATA_FILE).read_text(encoding="utf-8")
    )
    if not isinstance(raw, dict) or not isinstance(raw.get("rules"), list):
        raise RuleError(f"{DATA_FILE} has no `rules` list.")

    rules = [_parse_rule(entry, source="builtin") for entry in raw["rules"]]
    by_id = {rule.id: index for index, rule in enumerate(rules)}

    new_rules: list[Rule] = []
    for entry in overrides:
        rule = _parse_rule(entry, source=".crosswind.yml")
        if rule.id in by_id:
            rules[by_id[rule.id]] = rule
        else:
            new_rules.append(rule)

    return RuleSet(rules=new_rules + rules)


def _parse_rule(entry: Any, *, source: str) -> Rule:
    if not isinstance(entry, dict):
        raise RuleError(f"A rule in {source} is not a mapping.")
    rule_id = entry.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise RuleError(f"A rule in {source} has no `id`.")

    try:
        severity = Severity.parse(str(entry.get("severity", "")))
    except ValueError as exc:
        raise RuleError(f"Rule `{rule_id}` in {source}: {exc}") from exc

    when = str(entry.get("when", "any_change"))
    if when not in PREDICATES:
        allowed = ", ".join(sorted(PREDICATES))
        raise RuleError(
            f"Rule `{rule_id}` in {source} uses unknown predicate `{when}`. "
            f"The vocabulary is closed on purpose; use one of: {allowed}."
        )

    recommend_raw = str(entry.get("recommend", "investigate"))
    try:
        recommend = Recommendation(recommend_raw)
    except ValueError as exc:
        allowed = ", ".join(option.value for option in Recommendation)
        raise RuleError(
            f"Rule `{rule_id}` in {source} has unknown recommendation "
            f"`{recommend_raw}`. Use one of: {allowed}."
        ) from exc

    kinds = tuple(str(kind) for kind in _as_list(entry.get("kinds")))
    for kind in kinds:
        if kind not in {option.value for option in DriftKind}:
            raise RuleError(f"Rule `{rule_id}` in {source} has unknown drift kind `{kind}`.")

    return Rule(
        id=rule_id,
        severity=severity,
        reason=str(entry.get("reason", "")).strip() or "No reason given in the rule.",
        recommend=recommend,
        recommend_reason=str(entry.get("recommend_reason", "")).strip()
        or "No recommendation given in the rule.",
        types=tuple(str(item) for item in _as_list(entry.get("types"))) or ("*",),
        paths=tuple(str(item) for item in _as_list(entry.get("paths"))) or ("*",),
        when=when,
        kinds=kinds,
        source=source,
    )


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _tidy(text: str) -> str:
    """YAML folded scalars arrive with newlines. Reports want one paragraph."""
    return " ".join(text.split())


# --- the predicate vocabulary ------------------------------------------
#
# Each takes one `AttributeChange` and answers yes or no. They are
# deliberately forgiving: a predicate that cannot tell returns False, so an
# unparseable value falls through to a less specific rule rather than
# inventing a critical finding.


def _p_any_change(change: AttributeChange) -> bool:
    return True


def _p_became_public(change: AttributeChange) -> bool:
    """Did this open something to the world?"""
    after = _as_text(change.after)
    before = _as_text(change.before)
    if after in PUBLIC_CIDRS and before not in PUBLIC_CIDRS:
        return True
    if after in PUBLIC_PRINCIPALS and before not in PUBLIC_PRINCIPALS:
        return True
    # A public-access *block* going off is the same event as a CIDR opening.
    # `block_public_acls: true -> false` reads as "became public" even though
    # the literal value got smaller.
    path = change.path.lower()
    if "block_public" in path or "restrict_public" in path or "ignore_public" in path:
        return _truthy(change.before) and not _truthy(change.after)
    if "publicly_accessible" in path or "public_ip" in path:
        return not _truthy(change.before) and _truthy(change.after)
    # An IAM policy document that gained a `"Principal": "*"`.
    if _is_policy_path(change.path):
        return _policy_has_public_principal(change.after) and not _policy_has_public_principal(
            change.before
        )
    return False


def _p_widened_cidr(change: AttributeChange) -> bool:
    """Does the new CIDR cover strictly more addresses than the old one?"""
    before = _as_network(change.before)
    after = _as_network(change.after)
    if before is None or after is None:
        return False
    if before.version != after.version:
        return False
    return after.num_addresses > before.num_addresses


def _p_encryption_disabled(change: AttributeChange) -> bool:
    if _truthy(change.before) and not _truthy(change.after):
        return True
    # A KMS key reference being removed is encryption going away, even though
    # the value was never a boolean.
    path = change.path.lower()
    if "kms" in path or "sse" in path:
        return bool(_as_text(change.before)) and not _as_text(change.after)
    return False


def _p_logging_disabled(change: AttributeChange) -> bool:
    if _truthy(change.before) and not _truthy(change.after):
        return True
    return bool(_as_text(change.before)) and not _as_text(change.after)


def _p_deletion_protection_removed(change: AttributeChange) -> bool:
    """Protection off, or `skip_final_snapshot` on — both remove a safety net."""
    if "skip_final_snapshot" in change.path.lower():
        return not _truthy(change.before) and _truthy(change.after)
    return _truthy(change.before) and not _truthy(change.after)


def _p_iam_widened(change: AttributeChange) -> bool:
    """Did a policy document gain a wildcard it did not have?

    Counts wildcards rather than reasoning about permission sets. A real
    policy-equivalence check needs an IAM evaluation engine, and getting it
    subtly wrong would produce confident nonsense. Counting is crude, honest,
    and catches the change that actually happens — someone pasting `"*"`.
    """
    before = _wildcard_count(change.before)
    after = _wildcard_count(change.after)
    if before is None or after is None:
        return False
    return after > before


def _p_became_larger(change: AttributeChange) -> bool:
    return _direction(change) == 1


def _p_became_smaller(change: AttributeChange) -> bool:
    return _direction(change) == -1


#: The closed vocabulary. A rule naming anything not in here fails to load.
PREDICATES: dict[str, Any] = {
    "any_change": _p_any_change,
    "became_public": _p_became_public,
    "widened_cidr": _p_widened_cidr,
    "encryption_disabled": _p_encryption_disabled,
    "logging_disabled": _p_logging_disabled,
    "deletion_protection_removed": _p_deletion_protection_removed,
    "iam_widened": _p_iam_widened,
    "became_larger": _p_became_larger,
    "became_smaller": _p_became_smaller,
}


def _holds(predicate: str, change: AttributeChange) -> bool:
    return bool(PREDICATES[predicate](change))


# --- value coercion ----------------------------------------------------


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip()


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, int | float):
        return value != 0
    return _as_text(value).lower() in _TRUTHY


def _as_network(value: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    text = _as_text(value)
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def _is_policy_path(path: str) -> bool:
    lowered = path.lower()
    return "policy" in lowered or "principal" in lowered


def _as_policy(value: Any) -> Any:
    """A policy attribute is a JSON string in the state. Sometimes it's a dict."""
    if isinstance(value, dict | list):
        return value
    text = _as_text(value)
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _policy_has_public_principal(value: Any) -> bool:
    policy = _as_policy(value)
    if policy is None:
        # A redacted or truncated value. Fall back to the string, which is
        # still enough to spot `"Principal": "*"`.
        return bool(re.search(r'"Principal"\s*:\s*(\*|"\*")', _as_text(value)))
    return _walk_for_public_principal(policy)


def _walk_for_public_principal(node: Any) -> bool:
    if isinstance(node, dict):
        for key, item in node.items():
            if key.lower() == "principal" and _is_star(item):
                return True
            if _walk_for_public_principal(item):
                return True
    elif isinstance(node, list):
        return any(_walk_for_public_principal(item) for item in node)
    return False


def _is_star(node: Any) -> bool:
    if node == "*":
        return True
    if isinstance(node, dict):
        return any(_is_star(item) for item in node.values())
    if isinstance(node, list):
        return any(_is_star(item) for item in node)
    return False


def _wildcard_count(value: Any) -> int | None:
    """How many `*` appear in Action/Resource/Principal positions."""
    policy = _as_policy(value)
    if policy is None:
        text = _as_text(value)
        return text.count("*") if text else None
    count = 0

    def walk(node: Any, key: str | None = None) -> None:
        nonlocal count
        if isinstance(node, dict):
            for inner_key, item in node.items():
                walk(item, inner_key.lower())
        elif isinstance(node, list):
            for item in node:
                walk(item, key)
        elif isinstance(node, str) and key in {"action", "resource", "principal", "aws"}:
            count += node.count("*")

    walk(policy)
    return count


def _direction(change: AttributeChange) -> int:
    """1 if the value went up, -1 if down, 0 if we can't tell."""
    before_num, after_num = _as_number(change.before), _as_number(change.after)
    if before_num is not None and after_num is not None:
        if after_num > before_num:
            return 1
        if after_num < before_num:
            return -1
        return 0

    before_rank = _size_rank(change.before)
    after_rank = _size_rank(change.after)
    if before_rank is not None and after_rank is not None:
        if after_rank > before_rank:
            return 1
        if after_rank < before_rank:
            return -1
    return 0


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    text = _as_text(value)
    try:
        return float(text)
    except ValueError:
        return None


def _size_rank(value: Any) -> int | None:
    """`db.t3.large` -> the index of `large` in `SIZE_ORDER`.

    Only a direction, never a price. `cache.m5.large` to `cache.r5.large` is
    a family change with no size change, and this correctly declines to call
    it either way.
    """
    text = _as_text(value).lower()
    if not text:
        return None
    suffix = text.rsplit(".", 1)[-1]
    try:
        return SIZE_ORDER.index(suffix)
    except ValueError:
        return None
