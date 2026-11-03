"""AWS credentials, via the standard chain and nothing else.

Crosswind never accepts an access key. There is no `--access-key` flag, no
prompt, no config file key, and nothing is written to disk. `boto3.Session`
resolves credentials the way every other AWS tool does — environment
variables, `~/.aws/config` and `~/.aws/credentials`, SSO, a container or
instance role, `AWS_PROFILE` — and `--role-arn` assumes a role *from*
whatever that chain produced.

That is a deliberate limit rather than a missing feature. A tool that accepts
a pasted secret key teaches people to paste secret keys, and the ones they
paste end up in shell history and CI logs.

Credentials are only used for CloudTrail attribution. Drift detection itself
runs through Terraform, which resolves its own credentials via the provider
in the usual way — so a scan with no AWS credentials at all still produces a
drift report, just one with every finding attributed to `unknown`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

#: How long an assumed-role session lasts. Short: a scan takes minutes, and a
#: longer session is a longer window for a leaked token to matter.
SESSION_DURATION_SECONDS = 3600

SESSION_NAME = "crosswind-scan"


class CredentialsError(RuntimeError):
    """Credentials are missing, expired, or cannot assume the role asked for.

    Carries a `reason` so attribution can report precisely which it was —
    "no credentials" and "expired credentials" need different fixes and a
    user should not have to guess which one they have.
    """

    def __init__(self, message: str, *, reason: str = "credentials_unavailable") -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class Identity:
    """Who we are, as STS reports it.

    Shown by `doctor` and put in the report header. A reader of a drift
    report should be able to tell which account it is about.
    """

    account: str
    arn: str
    user_id: str

    @property
    def is_root(self) -> bool:
        """The account root user. Never the right thing to scan as."""
        return self.arn.endswith(":root")

    @property
    def label(self) -> str:
        return f"{self.arn} (account {self.account})"


def build_session(
    *,
    profile: str | None = None,
    region: str | None = None,
    role_arn: str | None = None,
) -> Any:
    """A `boto3.Session` from the standard chain, optionally assuming a role.

    Raises `CredentialsError` with a specific reason rather than letting a
    botocore exception out, because every caller wants to degrade attribution
    to `unknown` and say why.
    """
    try:
        base = boto3.Session(profile_name=profile, region_name=region)
    except BotoCoreError as exc:
        raise CredentialsError(
            f"Could not build an AWS session: {exc}", reason="credentials_unavailable"
        ) from exc

    if role_arn is None:
        return base

    try:
        sts = base.client("sts")
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=SESSION_NAME,
            DurationSeconds=SESSION_DURATION_SECONDS,
        )
    except ClientError as exc:
        code = _code(exc)
        raise CredentialsError(
            f"Could not assume {role_arn} ({code}).", reason=_reason_for(code)
        ) from exc
    except BotoCoreError as exc:
        raise CredentialsError(
            f"Could not assume {role_arn}: {exc}", reason="credentials_unavailable"
        ) from exc

    credentials = assumed["Credentials"]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region or base.region_name,
    )


def whoami(session: Any) -> Identity:
    """Ask STS who these credentials belong to.

    The one call Crosswind makes that is not CloudTrail. It is also the
    cheapest possible check that credentials work at all, which is what
    `doctor` uses it for.
    """
    try:
        response = session.client("sts").get_caller_identity()
    except ClientError as exc:
        code = _code(exc)
        raise CredentialsError(
            f"AWS rejected these credentials ({code}).", reason=_reason_for(code)
        ) from exc
    except BotoCoreError as exc:
        raise CredentialsError(
            f"No usable AWS credentials found: {exc}", reason="credentials_unavailable"
        ) from exc

    return Identity(
        account=str(response.get("Account") or ""),
        arn=str(response.get("Arn") or ""),
        user_id=str(response.get("UserId") or ""),
    )


def _code(exc: ClientError) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict):
            return str(error.get("Code") or "")
    return type(exc).__name__


def _reason_for(code: str) -> str:
    if code in {"ExpiredToken", "ExpiredTokenException", "TokenRefreshRequired"}:
        return "credentials_expired"
    if code in {"InvalidClientTokenId", "UnrecognizedClientException", "SignatureDoesNotMatch"}:
        return "credentials_invalid"
    if code in {"AccessDenied", "AccessDeniedException"}:
        return "credentials_denied"
    return "credentials_unavailable"
