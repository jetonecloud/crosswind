"""Scoring, and whether a severity can be traced to a rule."""

from __future__ import annotations

from typing import Any

import pytest

from crosswind.core.findings import AttributeChange, DriftKind, Recommendation, Severity
from crosswind.core.plan import DriftedResource
from crosswind.core.severity import PREDICATES, RuleError, RuleSet, load_rules


def drifted(
    resource_type: str,
    changes: list[tuple[str, Any, Any]],
    kind: DriftKind = DriftKind.CHANGED,
) -> DriftedResource:
    return DriftedResource(
        address=f"{resource_type}.thing",
        resource_type=resource_type,
        name="thing",
        kind=kind,
        changes=tuple(
            AttributeChange(path=path, before=before, after=after)
            for path, before, after in changes
        ),
    )


@pytest.fixture(scope="module")
def rules() -> RuleSet:
    return load_rules()


# --- the examples the brief names --------------------------------------


def test_public_ingress_on_a_security_group_is_critical(rules: RuleSet) -> None:
    verdict = rules.score(
        drifted("aws_security_group", [("ingress.0.cidr_blocks.0", "10.0.0.0/8", "0.0.0.0/0")])
    )
    assert verdict.severity is Severity.CRITICAL
    assert verdict.rule_id == "sg-ingress-public"
    assert verdict.recommendation is Recommendation.REVERT


def test_iam_policy_widening_is_critical(rules: RuleSet) -> None:
    before = (
        '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}'
    )
    after = '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    verdict = rules.score(drifted("aws_iam_role_policy", [("policy", before, after)]))
    assert verdict.severity is Severity.CRITICAL
    assert verdict.rule_id == "iam-policy-widened"


def test_encryption_disabled_is_high(rules: RuleSet) -> None:
    verdict = rules.score(drifted("aws_ebs_volume", [("encrypted", True, False)]))
    assert verdict.severity is Severity.HIGH
    assert verdict.rule_id == "encryption-disabled"


def test_public_access_change_is_critical(rules: RuleSet) -> None:
    """A public-access block going off reads as "became public" even though
    the boolean got smaller."""
    verdict = rules.score(
        drifted("aws_s3_bucket_public_access_block", [("block_public_acls", True, False)])
    )
    assert verdict.severity is Severity.CRITICAL
    assert verdict.rule_id == "s3-public-access"


def test_instance_size_change_is_medium(rules: RuleSet) -> None:
    verdict = rules.score(drifted("aws_instance", [("instance_type", "t3.micro", "t3.large")]))
    assert verdict.severity is Severity.MEDIUM
    assert verdict.rule_id == "instance-size-changed"
    assert verdict.recommendation is Recommendation.UPDATE_CODE


def test_tag_only_change_is_low(rules: RuleSet) -> None:
    verdict = rules.score(drifted("aws_instance", [("tags.Owner", "alice", "bob")]))
    assert verdict.severity is Severity.LOW
    assert verdict.rule_id == "tags-only-change"


# --- traceability ------------------------------------------------------


def test_every_verdict_names_a_rule_and_a_reason(rules: RuleSet) -> None:
    """A severity nobody can trace to a rule is a severity nobody will act on."""
    cases = [
        drifted("aws_instance", [("instance_type", "t3.micro", "t3.large")]),
        drifted("aws_security_group", [("ingress.0.cidr_blocks.0", "10.0.0.0/8", "0.0.0.0/0")]),
        drifted("some_unknown_type", [("whatever", 1, 2)]),
        drifted("aws_s3_bucket", [], kind=DriftKind.DELETED),
    ]
    for resource in cases:
        verdict = rules.score(resource)
        assert verdict.rule_id
        assert verdict.reason
        assert verdict.recommendation_reason
        assert any(rule.id == verdict.rule_id for rule in rules.rules)


def test_unmatched_resource_falls_through_to_default(rules: RuleSet) -> None:
    verdict = rules.score(drifted("random_pet", [("length", 2, 3)]))
    assert verdict.rule_id == "default"
    assert verdict.severity is Severity.LOW


def test_resource_with_every_change_suppressed_is_still_scored(rules: RuleSet) -> None:
    """Drift with nothing renderable left is still drift, and must get a rule.

    This happens when every differing attribute was a derived restatement the
    parser suppressed. Falling through to `unscored` would put a finding in
    the report that no rule claims responsibility for.
    """
    verdict = rules.score(drifted("aws_instance", []))
    assert verdict.rule_id == "default"
    assert verdict.severity is Severity.LOW


def test_attribute_predicates_do_not_fire_on_a_resource_with_no_changes(
    rules: RuleSet,
) -> None:
    """A rule asking `became_public` has nothing to look at, so it must not fire.

    Otherwise a resource with no visible diff could be scored critical on the
    strength of a predicate evaluating against nothing.
    """
    verdict = rules.score(drifted("aws_security_group", []))
    assert verdict.severity is not Severity.CRITICAL
    assert verdict.rule_id == "default"


def test_reasons_are_one_paragraph_not_a_yaml_block(rules: RuleSet) -> None:
    """Folded YAML scalars arrive with newlines; a table cell wants one line."""
    verdict = rules.score(drifted("aws_ebs_volume", [("encrypted", True, False)]))
    assert "\n" not in verdict.reason
    assert "  " not in verdict.reason


def test_deleted_resource_is_scored_as_high(rules: RuleSet) -> None:
    verdict = rules.score(
        drifted("aws_s3_bucket", [("(resource)", "present", "absent")], kind=DriftKind.DELETED)
    )
    assert verdict.severity is Severity.HIGH
    assert verdict.rule_id == "resource-deleted"


# --- predicates --------------------------------------------------------


def change(path: str, before: Any, after: Any) -> AttributeChange:
    return AttributeChange(path=path, before=before, after=after)


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        ("10.0.0.0/8", "0.0.0.0/0", True),
        ("0.0.0.0/0", "0.0.0.0/0", False),  # already public, not a new exposure
        ("10.0.0.0/8", "10.0.0.0/16", False),  # narrowed
        ("fd00::/8", "::/0", True),
    ],
)
def test_became_public(before: str, after: str, expected: bool) -> None:
    assert PREDICATES["became_public"](change("cidr_blocks.0", before, after)) is expected


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        ("10.0.0.0/16", "10.0.0.0/8", True),
        ("10.0.0.0/8", "10.0.0.0/16", False),
        ("10.0.0.0/8", "10.0.0.0/8", False),
        # Mixing address families is not a widening we can reason about.
        ("10.0.0.0/8", "::/0", False),
        ("not-a-cidr", "0.0.0.0/0", False),
    ],
)
def test_widened_cidr(before: str, after: str, expected: bool) -> None:
    assert PREDICATES["widened_cidr"](change("cidr_blocks.0", before, after)) is expected


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        (True, False, True),
        (False, True, False),
        ("true", "false", True),
        ("enabled", "disabled", True),
        (True, True, False),
    ],
)
def test_encryption_disabled(before: Any, after: Any, expected: bool) -> None:
    assert PREDICATES["encryption_disabled"](change("encrypted", before, after)) is expected


def test_encryption_disabled_catches_a_removed_kms_key() -> None:
    """Encryption going away is not always a boolean flipping."""
    assert PREDICATES["encryption_disabled"](
        change("kms_key_id", "arn:aws:kms:us-east-1:1:key/abc", "")
    )


def test_iam_widened_counts_wildcards_in_meaningful_positions() -> None:
    """A `*` in a Sid or a description is not a permission change."""
    before = '{"Statement":[{"Sid":"nothing*","Action":"s3:GetObject","Resource":"arn:x"}]}'
    after = '{"Statement":[{"Sid":"nothing*","Action":"s3:*","Resource":"arn:x"}]}'
    assert PREDICATES["iam_widened"](change("policy", before, after))

    # Same wildcard count in Action/Resource: not a widening.
    same = '{"Statement":[{"Sid":"other*","Action":"s3:GetObject","Resource":"arn:x"}]}'
    assert not PREDICATES["iam_widened"](change("policy", before, same))


def test_iam_widened_handles_an_unparseable_policy_without_inventing_a_finding() -> None:
    """A truncated or redacted policy must not score as critical on a guess."""
    assert not PREDICATES["iam_widened"](change("policy", None, None))


def test_became_public_finds_a_wildcard_principal() -> None:
    before = '{"Statement":[{"Principal":{"AWS":"arn:aws:iam::1:root"},"Action":"sts:AssumeRole"}]}'
    after = '{"Statement":[{"Principal":"*","Action":"sts:AssumeRole"}]}'
    assert PREDICATES["became_public"](change("assume_role_policy", before, after))


def test_became_larger_understands_instance_sizes() -> None:
    assert PREDICATES["became_larger"](change("instance_type", "t3.micro", "t3.large"))
    assert PREDICATES["became_smaller"](change("instance_type", "db.r5.4xlarge", "db.r5.large"))
    # A family change at the same size is neither.
    assert not PREDICATES["became_larger"](change("instance_type", "m5.large", "r5.large"))
    assert not PREDICATES["became_smaller"](change("instance_type", "m5.large", "r5.large"))


def test_became_larger_handles_plain_numbers() -> None:
    assert PREDICATES["became_larger"](change("allocated_storage", 100, 500))
    assert PREDICATES["became_smaller"](change("allocated_storage", 500, 100))


def test_deletion_protection_predicate_handles_skip_final_snapshot() -> None:
    """Turning `skip_final_snapshot` *on* removes a safety net, unlike the rest."""
    assert PREDICATES["deletion_protection_removed"](change("skip_final_snapshot", False, True))
    assert PREDICATES["deletion_protection_removed"](change("deletion_protection", True, False))


# --- overrides ---------------------------------------------------------


def test_override_replaces_a_shipped_rule_in_place() -> None:
    """A project that disagrees with a shipped severity can say so."""
    overrides = [
        {
            "id": "tags-only-change",
            "severity": "medium",
            "reason": "We bill by tag, so tags matter here.",
            "types": ["*"],
            "paths": ["tags.*"],
            "recommend": "update_code",
            "recommend_reason": "Fix the tag in code.",
        }
    ]
    rules = load_rules(overrides)
    verdict = rules.score(drifted("aws_instance", [("tags.CostCentre", "a", "b")]))
    assert verdict.severity is Severity.MEDIUM
    assert verdict.reason == "We bill by tag, so tags matter here."
    # Replaced, not appended.
    assert sum(1 for rule in rules.rules if rule.id == "tags-only-change") == 1


def test_a_new_override_rule_wins_over_shipped_rules() -> None:
    """A project-specific rule is more specific than anything we shipped."""
    overrides = [
        {
            "id": "our-sacred-bastion",
            "severity": "critical",
            "reason": "The bastion host is not allowed to change at all.",
            "types": ["aws_instance"],
            "paths": ["*"],
            "recommend": "revert",
            "recommend_reason": "Ask the platform team.",
        }
    ]
    rules = load_rules(overrides)
    verdict = rules.score(drifted("aws_instance", [("instance_type", "t3.micro", "t3.large")]))
    assert verdict.rule_id == "our-sacred-bastion"


def test_shipped_rules_are_unaffected_by_an_override_of_another_rule() -> None:
    rules = load_rules([{"id": "tags-only-change", "severity": "high", "reason": "x"}])
    verdict = rules.score(drifted("aws_ebs_volume", [("encrypted", True, False)]))
    assert verdict.rule_id == "encryption-disabled"


# --- a bad rule file ---------------------------------------------------


def test_unknown_predicate_is_refused_with_the_vocabulary_listed() -> None:
    """The closed vocabulary is a security boundary, so the error says so."""
    with pytest.raises(RuleError, match="vocabulary is closed"):
        load_rules([{"id": "x", "severity": "high", "reason": "r", "when": "os.system"}])


def test_unknown_severity_is_refused() -> None:
    with pytest.raises(RuleError, match="Unknown severity"):
        load_rules([{"id": "x", "severity": "catastrophic", "reason": "r"}])


def test_unknown_recommendation_is_refused() -> None:
    with pytest.raises(RuleError, match="unknown recommendation"):
        load_rules([{"id": "x", "severity": "high", "reason": "r", "recommend": "delete_it"}])


def test_rule_without_an_id_is_refused() -> None:
    with pytest.raises(RuleError, match="no `id`"):
        load_rules([{"severity": "high", "reason": "r"}])


def test_unknown_drift_kind_is_refused() -> None:
    with pytest.raises(RuleError, match="unknown drift kind"):
        load_rules([{"id": "x", "severity": "high", "reason": "r", "kinds": ["exploded"]}])


# --- the shipped file itself -------------------------------------------


def test_shipped_rules_all_have_a_reason_and_a_recommendation(rules: RuleSet) -> None:
    """Every rule has to be able to explain itself to a reader."""
    for rule in rules.rules:
        assert rule.reason and "No reason given" not in rule.reason, rule.id
        assert rule.recommend_reason and "No recommendation" not in rule.recommend_reason, rule.id


def test_shipped_rule_ids_are_unique(rules: RuleSet) -> None:
    ids = [rule.id for rule in rules.rules]
    assert len(ids) == len(set(ids))


def test_default_rule_is_last(rules: RuleSet) -> None:
    """First match wins, so a catch-all anywhere else would mask everything."""
    assert rules.rules[-1].id == "default"
    assert rules.rules[-1].types == ("*",)


def test_all_four_severities_are_used_by_the_shipped_rules(rules: RuleSet) -> None:
    """If a level is never reachable, it is decoration rather than a signal."""
    assert {rule.severity for rule in rules.rules} == set(Severity)
