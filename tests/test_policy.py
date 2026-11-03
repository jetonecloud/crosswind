"""The IAM policy must contain nothing that can change anything.

This is the same class of test as `test_safety.py`: if it fails, the thing
we tell people about Crosswind is not true. A role deployed from
`role.cfn.yaml` is held to the same bar as the flat `policy.json`, because
the template is what people actually deploy.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

IAM = Path(__file__).parent.parent / "iam"
POLICY = IAM / "policy.json"
TEMPLATE = IAM / "role.cfn.yaml"

#: Read-only verb prefixes. An action has to start with one of these.
#:
#: `Simulate` is deliberately absent. `iam:SimulatePrincipalPolicy` would let
#: Crosswind work out what its own role is allowed to do, which sounds useful
#: and is a permission nobody needs to grant a drift checker.
READ_PREFIXES = ("Get", "List", "Describe")

#: Read-only actions that do not follow the naming convention. Each one is
#: here deliberately and needs a reason.
EXCEPTIONS = {
    # The whole of attribution. Reads the CloudTrail event history; cannot
    # read trail configuration and cannot write.
    "cloudtrail:LookupEvents",
    # API Gateway models its read permission as the HTTP verb.
    "apigateway:GET",
    # Decrypting state. Note there is no Encrypt or GenerateDataKey: Crosswind
    # reads state and never writes it.
    "kms:Decrypt",
    # Identity, for `doctor` and the report header.
    "sts:GetCallerIdentity",
}

#: Verbs that would make this a write. Checked explicitly as well as by the
#: prefix allowlist, so the failure message is specific.
WRITE_VERBS = (
    "Create",
    "Put",
    "Delete",
    "Update",
    "Modify",
    "Set",
    "Attach",
    "Detach",
    "Add",
    "Remove",
    "Tag",
    "Untag",
    "Enable",
    "Disable",
    "Start",
    "Stop",
    "Reboot",
    "Terminate",
    "Run",
    "Invoke",
    "Associate",
    "Disassociate",
    "Authorize",
    "Revoke",
    "Import",
    "Export",
    "Copy",
    "Restore",
    "Reset",
    "Register",
    "Deregister",
    "Assume",
    "Generate",
    "Encrypt",
    "Schedule",
    "Cancel",
    "Accept",
    "Reject",
    "Replace",
    "Apply",
    "Execute",
    "Send",
    "Publish",
    "Write",
)


def _actions_from_statements(statements: list[dict]) -> list[str]:
    actions: list[str] = []
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        raw = statement.get("Action", [])
        if isinstance(raw, str):
            raw = [raw]
        actions.extend(str(action) for action in raw)
    return actions


@pytest.fixture(scope="module")
def policy_actions() -> list[str]:
    document = json.loads(POLICY.read_text(encoding="utf-8"))
    return _actions_from_statements(document["Statement"])


@pytest.fixture(scope="module")
def template_actions() -> list[str]:
    """Actions from the CloudFormation template.

    CloudFormation's short-form intrinsics (`!Ref`, `!Sub`, `!If`) are not
    valid YAML tags, so they are registered as opaque strings. We only care
    about the `Action` lists, which contain no intrinsics.
    """

    class Loader(yaml.SafeLoader):
        pass

    def opaque(loader: yaml.Loader, suffix: str, node: yaml.Node) -> str:
        return f"<{suffix}>"

    Loader.add_multi_constructor("!", opaque)

    document = yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=Loader)
    actions: list[str] = []
    for resource in document["Resources"].values():
        if resource.get("Type") != "AWS::IAM::ManagedPolicy":
            continue
        statements = resource["Properties"]["PolicyDocument"]["Statement"]
        # `!If`-wrapped statements load as the opaque string; skip those and
        # rely on `policy.json` covering the same permissions.
        actions.extend(
            _actions_from_statements([item for item in statements if isinstance(item, dict)])
        )
    return actions


# --- the flat policy ----------------------------------------------------


def test_policy_is_valid_json() -> None:
    document = json.loads(POLICY.read_text(encoding="utf-8"))
    assert document["Version"] == "2012-10-17"
    assert document["Statement"]


def test_policy_has_no_write_actions(policy_actions: list[str]) -> None:
    """The central claim, checked on every commit."""
    offenders = []
    for action in policy_actions:
        if action in EXCEPTIONS:
            continue
        service, _, verb = action.partition(":")
        if verb.startswith(WRITE_VERBS):
            offenders.append(action)
    assert not offenders, f"write-capable actions in policy.json: {offenders}"


def test_policy_actions_are_all_read_verbs(policy_actions: list[str]) -> None:
    """An allowlist, so an unfamiliar verb fails rather than slipping through."""
    offenders = []
    for action in policy_actions:
        if action in EXCEPTIONS:
            continue
        service, _, verb = action.partition(":")
        if not service or not verb:
            offenders.append(action)
            continue
        if not verb.startswith(READ_PREFIXES):
            offenders.append(action)
    assert not offenders, (
        f"actions that are not Get/List/Describe and not a named exception: "
        f"{offenders}. Add a reason to EXCEPTIONS if one of these is genuinely "
        f"read-only."
    )


def test_policy_has_no_bare_wildcard_action(policy_actions: list[str]) -> None:
    """`*` or `service:*` would make every other check meaningless."""
    for action in policy_actions:
        assert action != "*", "policy.json grants every action"
        assert not action.endswith(":*"), f"{action} grants every action in a service"


def test_policy_never_grants_object_or_secret_contents(policy_actions: list[str]) -> None:
    """Reading bucket *configuration* is needed; reading the data is not.

    `s3:GetObject` appears only in the state-read statement, scoped to the
    state bucket's ARN. It must never appear on `"*"`.
    """
    document = json.loads(POLICY.read_text(encoding="utf-8"))
    for statement in document["Statement"]:
        raw = statement.get("Action", [])
        actions = [raw] if isinstance(raw, str) else raw
        resources = statement.get("Resource", [])
        resources = [resources] if isinstance(resources, str) else resources

        if "s3:GetObject" in actions:
            assert "*" not in resources, "s3:GetObject must be scoped to the state bucket, never *"
        # The value of a secret is never needed: Terraform refreshing a
        # secret reads its metadata, and Crosswind would redact the value
        # anyway.
        assert "secretsmanager:GetSecretValue" not in actions
        assert "ssm:GetParameter" not in actions


def test_kms_grants_decrypt_but_not_encrypt(policy_actions: list[str]) -> None:
    """Crosswind reads state and never writes it."""
    assert "kms:Decrypt" in policy_actions
    for forbidden in ("kms:Encrypt", "kms:GenerateDataKey", "kms:ReEncrypt"):
        assert forbidden not in policy_actions


def test_policy_includes_what_attribution_actually_needs(
    policy_actions: list[str],
) -> None:
    assert "cloudtrail:LookupEvents" in policy_actions
    assert "sts:GetCallerIdentity" in policy_actions


def test_policy_does_not_read_cloudtrail_configuration(
    policy_actions: list[str],
) -> None:
    """Only the event history is needed, not the trails themselves."""
    for action in policy_actions:
        assert action.startswith("cloudtrail:") is False or action == "cloudtrail:LookupEvents"


# --- the template people actually deploy --------------------------------


def test_template_is_parseable(template_actions: list[str]) -> None:
    assert template_actions


def test_template_has_no_write_actions(template_actions: list[str]) -> None:
    """Held to the same bar as policy.json, since this is what gets deployed."""
    offenders = []
    for action in template_actions:
        if action in EXCEPTIONS:
            continue
        service, _, verb = action.partition(":")
        if verb.startswith(WRITE_VERBS):
            offenders.append(action)
    assert not offenders, f"write-capable actions in role.cfn.yaml: {offenders}"


def test_template_has_no_bare_wildcard_action(template_actions: list[str]) -> None:
    for action in template_actions:
        assert action != "*"
        assert not action.endswith(":*")


def test_template_oidc_trust_is_pinned_to_a_branch() -> None:
    """`repo:owner/repo:*` lets a pull request assume the role.

    For a role that can read state and IAM policies, that is the difference
    between a drift checker and a credential.
    """
    text = TEMPLATE.read_text(encoding="utf-8")
    assert "ref:refs/heads/" in text
    assert not re.search(r'token\.actions\.githubusercontent\.com:sub".*repo:\$\{[^}]+\}:\*', text)


def test_template_kms_statement_is_decrypt_only() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    assert "kms:Decrypt" in text
    assert "kms:Encrypt" not in text
    assert "kms:GenerateDataKey" not in text


def test_template_can_be_deployed_without_the_broad_policy() -> None:
    """The narrow path documented in iam/README.md has to actually exist."""
    text = TEMPLATE.read_text(encoding="utf-8")
    assert "IncludeRefreshPermissions" in text
    assert "WantsRefresh" in text


def test_the_tradeoff_is_documented_honestly() -> None:
    """The brief asks for an honest explanation, so assert it is there.

    Crude as a test, but the alternative is shipping a broad policy with no
    account of what it can read.
    """
    readme = (IAM / "README.md").read_text(encoding="utf-8")
    for required in (
        "lambda:GetFunctionConfiguration",
        "narrowest practical option",
        "IncludeRefreshPermissions=false",
        "cloudtrail:LookupEvents",
        "--no-attribution",
    ):
        assert required in readme, f"iam/README.md should mention {required}"
