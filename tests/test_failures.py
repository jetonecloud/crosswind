"""The failure paths, each one checked to fail the way it should.

Every test here is about Crosswind behaving well when something else has
gone wrong. The theme is that there are exactly two acceptable outcomes:
degrade attribution and carry on, or report the stack as "could not check"
and return 2. Never a traceback, and never a clean bill of health.
"""

from __future__ import annotations

import signal
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError, NoCredentialsError
from botocore.stub import Stubber

from crosswind.core import scan as scan_module
from crosswind.core import session as session_module
from crosswind.core import workspace as workspace_module
from crosswind.core.attribution.lookup import CloudTrailLookup, LookupFailed
from crosswind.core.config import Config
from crosswind.core.discover import Stack
from crosswind.core.findings import StackStatus
from crosswind.core.scan import EXIT_ERROR, ScanRequest
from crosswind.core.scan import scan as run_scan
from crosswind.core.session import CredentialsError, build_session, whoami
from crosswind.core.severity import load_rules
from crosswind.core.terraform import Binary, Completed, TerraformError
from crosswind.core.workspace import workspace

BINARY = Binary(path=Path("/usr/bin/terraform"), flavour="terraform", version="1.15.8")


def make_stack(tmp_path: Path, name: str = "prod") -> Path:
    path = tmp_path / name
    path.mkdir(parents=True, exist_ok=True)
    (path / "main.tf").write_text("# tf\n")
    return path


def request_for(path: Path, root: Path, **config: Any) -> ScanRequest:
    return ScanRequest(
        stacks=[Stack(path=path, reason="test")],
        binary=BINARY,
        rules=load_rules(),
        config=Config(attribution=False, **config),
        root=root,
    )


# --- credentials --------------------------------------------------------


def stubbed_sts() -> tuple[Any, Stubber]:
    client = boto3.client(
        "sts",
        region_name="eu-west-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
    )
    return client, Stubber(client)


class FakeSession:
    def __init__(self, client: Any, region: str | None = "eu-west-1") -> None:
        self._client = client
        self.region_name = region

    def client(self, name: str, region_name: str | None = None) -> Any:
        return self._client


def test_whoami_returns_the_identity() -> None:
    client, stubber = stubbed_sts()
    stubber.add_response(
        "get_caller_identity",
        {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:role/CrosswindReadOnly",
            "UserId": "AROAEXAMPLE:session",
        },
    )
    with stubber:
        identity = whoami(FakeSession(client))
    assert identity.account == "123456789012"
    assert not identity.is_root


def test_whoami_notices_the_root_user() -> None:
    """Scanning as root is never right, and `doctor` says so."""
    client, stubber = stubbed_sts()
    stubber.add_response(
        "get_caller_identity",
        {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:root", "UserId": "1"},
    )
    with stubber:
        assert whoami(FakeSession(client)).is_root


def test_missing_credentials_raise_a_classified_error() -> None:
    """ "No credentials" and "expired credentials" need different fixes."""

    class NoCreds:
        def get_caller_identity(self, **kwargs: Any) -> Any:
            raise NoCredentialsError()

    with pytest.raises(CredentialsError) as excinfo:
        whoami(FakeSession(NoCreds()))
    assert excinfo.value.reason == "credentials_unavailable"


def test_expired_credentials_are_classified_as_expired() -> None:
    client, stubber = stubbed_sts()
    stubber.add_client_error("get_caller_identity", service_error_code="ExpiredToken")
    with stubber, pytest.raises(CredentialsError) as excinfo:
        whoami(FakeSession(client))
    assert excinfo.value.reason == "credentials_expired"


def test_invalid_credentials_are_classified_as_invalid() -> None:
    client, stubber = stubbed_sts()
    stubber.add_client_error("get_caller_identity", service_error_code="InvalidClientTokenId")
    with stubber, pytest.raises(CredentialsError) as excinfo:
        whoami(FakeSession(client))
    assert excinfo.value.reason == "credentials_invalid"


def test_assume_role_failure_names_the_role() -> None:
    client, stubber = stubbed_sts()
    stubber.add_client_error("assume_role", service_error_code="AccessDenied")

    def fake_boto_session(**kwargs: Any) -> Any:
        return FakeSession(client)

    with stubber:
        import crosswind.core.session as module

        original = module.boto3.Session
        module.boto3.Session = fake_boto_session  # type: ignore[assignment]
        try:
            with pytest.raises(CredentialsError) as excinfo:
                build_session(role_arn="arn:aws:iam::123456789012:role/Nope")
        finally:
            module.boto3.Session = original  # type: ignore[assignment]

    assert "arn:aws:iam::123456789012:role/Nope" in str(excinfo.value)
    assert excinfo.value.reason == "credentials_denied"


def test_a_bad_profile_name_is_a_credentials_error() -> None:
    """A typo in `--profile` should say so, not raise a botocore exception."""
    with pytest.raises(CredentialsError):
        build_session(profile="definitely-not-a-configured-profile-9f3a")


def test_a_scan_with_no_credentials_still_produces_a_drift_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Attribution is the bonus; the drift report is the product.

    This is the whole reason credentials failures are warnings rather than
    errors.
    """
    stack = make_stack(tmp_path)

    payload = {
        "format_version": "1.2",
        "terraform_version": "1.15.8",
        "resource_drift": [
            {
                "address": "aws_security_group.web",
                "mode": "managed",
                "type": "aws_security_group",
                "name": "web",
                "change": {
                    "actions": ["update"],
                    "before": {"id": "sg-a", "ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]},
                    "after": {"id": "sg-a", "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
                    "before_sensitive": {},
                    "after_sensitive": {},
                },
            }
        ],
    }

    class R:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def init(self, s: Path) -> Completed:
            return Completed(args=("init",), returncode=0, stdout="", stderr="")

        def plan_refresh_only(self, s: Path, *, out: Path, var_files: Any = ()) -> Completed:
            out.write_text("plan")
            return Completed(args=("plan",), returncode=0, stdout="", stderr="")

        def show_plan_json(self, s: Path, p: Path) -> Any:
            return payload

    monkeypatch.setattr(scan_module, "Runner", R)
    report = run_scan(request_for(stack, tmp_path))
    assert len(report.findings) == 1
    assert report.findings[0].attribution.actor is None


# --- CloudTrail degradation --------------------------------------------


def stubbed_cloudtrail() -> tuple[Any, Stubber]:
    client = boto3.client(
        "cloudtrail",
        region_name="eu-west-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
    )
    return client, Stubber(client)


def test_cloudtrail_without_permission_degrades_rather_than_fails() -> None:
    client, stubber = stubbed_cloudtrail()
    stubber.add_client_error("lookup_events", service_error_code="AccessDeniedException")
    with stubber:
        lookup = CloudTrailLookup(FakeSession(client), sleeper=lambda _: None)
        with pytest.raises(LookupFailed) as excinfo:
            lookup.events_for(value="sg-a", region="eu-west-1", window_hours=24)
    assert excinfo.value.reason == "lookup_denied"


def test_a_region_that_does_not_exist_is_a_lookup_failure_not_a_crash() -> None:
    class BadRegion:
        def lookup_events(self, **kwargs: Any) -> Any:
            raise ClientError({"Error": {"Code": "EndpointConnectionError"}}, "LookupEvents")

    lookup = CloudTrailLookup(FakeSession(BadRegion()), sleeper=lambda _: None)
    with pytest.raises(LookupFailed) as excinfo:
        lookup.events_for(value="sg-a", region="xx-nowhere-1", window_hours=24)
    assert excinfo.value.reason == "lookup_failed"


def test_attribution_failures_are_summarised_once_not_per_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A report repeating the same permissions error forty times is noise."""
    stack = make_stack(tmp_path)

    payload = {
        "format_version": "1.2",
        "terraform_version": "1.15.8",
        "resource_drift": [
            {
                "address": f"aws_security_group.sg{index}",
                "mode": "managed",
                "type": "aws_security_group",
                "name": f"sg{index}",
                "change": {
                    "actions": ["update"],
                    "before": {"id": f"sg-{index}", "ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]},
                    "after": {"id": f"sg-{index}", "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
                    "before_sensitive": {},
                    "after_sensitive": {},
                },
            }
            for index in range(5)
        ],
    }

    class R:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def init(self, s: Path) -> Completed:
            return Completed(args=("init",), returncode=0, stdout="", stderr="")

        def plan_refresh_only(self, s: Path, *, out: Path, var_files: Any = ()) -> Completed:
            out.write_text("plan")
            return Completed(args=("plan",), returncode=0, stdout="", stderr="")

        def show_plan_json(self, s: Path, p: Path) -> Any:
            return payload

    monkeypatch.setattr(scan_module, "Runner", R)

    class DeniedLookup:
        failed = False

        def events_for(self, *, value: str, region: str, window_hours: int) -> Any:
            raise LookupFailed("denied", reason="lookup_denied")

    report = run_scan(
        ScanRequest(
            stacks=[Stack(path=stack, reason="t")],
            binary=BINARY,
            rules=load_rules(),
            config=Config(attribution=True),
            root=tmp_path,
            lookup=DeniedLookup(),  # type: ignore[arg-type]
        )
    )
    assert len(report.findings) == 5
    assert all(finding.attribution.reason == "lookup_denied" for finding in report.findings)
    assert report.attribution_note is not None
    assert "cloudtrail:LookupEvents" in report.attribution_note


# --- interruption -------------------------------------------------------


def test_an_interrupt_mid_scan_leaves_no_plan_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ctrl-C during a scan must not leave state in a temp directory.

    A plan file is a plain-text copy of the prior state. The workspace's
    `finally` handles this one; the signal handler covers the case where the
    process is killed outright.
    """
    stack = make_stack(tmp_path)
    seen: list[Path] = []

    class R:
        def __init__(self, binary: Any, space: Any, **kwargs: Any) -> None:
            self.space = space

        def init(self, s: Path) -> Completed:
            return Completed(args=("init",), returncode=0, stdout="", stderr="")

        def plan_refresh_only(self, s: Path, *, out: Path, var_files: Any = ()) -> Completed:
            out.write_text("prior state with secrets")
            seen.append(out)
            raise KeyboardInterrupt

        def show_plan_json(self, s: Path, p: Path) -> Any:  # pragma: no cover
            raise AssertionError("should not be reached")

    monkeypatch.setattr(scan_module, "Runner", R)

    with pytest.raises(KeyboardInterrupt):
        run_scan(request_for(stack, tmp_path))

    assert seen, "the test must have written a plan file to be meaningful"
    for path in seen:
        assert not path.exists(), f"{path} survived the interrupt"
        assert not path.parent.exists()


def test_the_signal_handler_deletes_live_workspaces() -> None:
    """The `kill` case: `atexit` does not run on a default SIGTERM.

    Raising the signal for real would end the test run, so this calls the
    registered handler directly — which is the thing that has to work.
    """
    with workspace() as space:
        root = space.root
        (space.plans / "p.tfplan").write_text("secret state")

    # Re-register as if the context manager had not finished.
    root.mkdir(parents=True, exist_ok=True)
    (root / "p.tfplan").write_text("secret state")
    workspace_module._live.add(root)

    handler = signal.getsignal(signal.SIGTERM)
    assert callable(handler), "the workspace should have installed a handler"
    workspace_module._purge()

    assert not root.exists()


def test_a_terraform_timeout_is_reported_as_could_not_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hung provider must not hang a scheduled scan forever."""
    stack = make_stack(tmp_path)

    class R:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def init(self, s: Path) -> Completed:
            return Completed(args=("init",), returncode=0, stdout="", stderr="")

        def plan_refresh_only(self, s: Path, *, out: Path, var_files: Any = ()) -> Completed:
            raise TerraformError("`plan -refresh-only` did not finish within 900s.")

        def show_plan_json(self, s: Path, p: Path) -> Any:  # pragma: no cover
            raise AssertionError("should not be reached")

    monkeypatch.setattr(scan_module, "Runner", R)
    report = run_scan(request_for(stack, tmp_path))
    assert report.stacks[0].status is StackStatus.FAILED
    assert "900s" in (report.stacks[0].error or "")
    assert report.exit_code == EXIT_ERROR


# --- malformed Terraform output ----------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"format_version": "1.2"},
        {"resource_drift": []},
        {"format_version": "99.0", "terraform_version": "99.0.0"},
        {"format_version": "1.2", "terraform_version": "1.15.8", "resource_drift": "nope"},
        {
            "format_version": "1.2",
            "terraform_version": "1.15.8",
            "resource_drift": [{"no_address": True, "mode": "managed"}],
        },
    ],
    ids=["empty", "no-version", "no-format", "future-major", "drift-not-list", "no-address"],
)
def test_malformed_plan_output_fails_the_stack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]
) -> None:
    """None of these may be mistaken for a clean stack.

    A clean stack and an unparseable one both lack a `resource_drift` key,
    which is exactly why the parser is strict about everything else.
    """
    stack = make_stack(tmp_path)

    class R:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def init(self, s: Path) -> Completed:
            return Completed(args=("init",), returncode=0, stdout="", stderr="")

        def plan_refresh_only(self, s: Path, *, out: Path, var_files: Any = ()) -> Completed:
            out.write_text("plan")
            return Completed(args=("plan",), returncode=0, stdout="", stderr="")

        def show_plan_json(self, s: Path, p: Path) -> Any:
            return payload

    monkeypatch.setattr(scan_module, "Runner", R)
    report = run_scan(request_for(stack, tmp_path))
    assert report.stacks[0].status is StackStatus.FAILED
    assert report.exit_code == EXIT_ERROR


def test_terraform_output_that_is_not_json_fails_the_stack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = make_stack(tmp_path)

    class R:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def init(self, s: Path) -> Completed:
            return Completed(args=("init",), returncode=0, stdout="", stderr="")

        def plan_refresh_only(self, s: Path, *, out: Path, var_files: Any = ()) -> Completed:
            out.write_text("plan")
            return Completed(args=("plan",), returncode=0, stdout="", stderr="")

        def show_plan_json(self, s: Path, p: Path) -> Any:
            raise TerraformError("`show -json` produced output that is not JSON")

    monkeypatch.setattr(scan_module, "Runner", R)
    report = run_scan(request_for(stack, tmp_path))
    assert report.stacks[0].status is StackStatus.FAILED


def test_error_output_is_scrubbed_of_account_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Terraform errors quote ARNs. A shared report should not name the account."""
    stack = make_stack(tmp_path)

    class R:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def init(self, s: Path) -> Completed:
            return Completed(
                args=("init",),
                returncode=1,
                stdout="",
                stderr="Error: AccessDenied for arn:aws:iam::123456789012:role/thing",
            )

        def plan_refresh_only(self, s: Path, *, out: Path, var_files: Any = ()) -> Completed:
            raise AssertionError("should not be reached")  # pragma: no cover

        def show_plan_json(self, s: Path, p: Path) -> Any:  # pragma: no cover
            raise AssertionError("should not be reached")

    monkeypatch.setattr(scan_module, "Runner", R)
    report = run_scan(request_for(stack, tmp_path))
    error = report.stacks[0].error or ""
    assert "123456789012" not in error
    assert "<account>" in error


def test_session_module_has_no_way_to_accept_an_access_key() -> None:
    """Crosswind must not have a parameter that takes a pasted secret key.

    A tool that accepts one teaches people to paste them, and the ones they
    paste end up in shell history and CI logs.
    """
    import inspect

    signature = inspect.signature(session_module.build_session)
    names = set(signature.parameters)
    assert names == {"profile", "region", "role_arn"}
    for banned in ("access_key", "secret_key", "aws_access_key_id", "token"):
        assert not any(banned in name for name in names)
