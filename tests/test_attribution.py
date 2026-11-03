"""Attribution: the ranking, the limits, and never guessing a person.

CloudTrail is stubbed with `botocore`'s own `Stubber`, which validates the
request shape against the real service model — so a parameter we got wrong
fails here rather than in someone's account.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import ANY, Stubber

from crosswind.core.attribution import load_mapping
from crosswind.core.attribution.lookup import (
    RETENTION_DAYS,
    CloudTrailLookup,
    LookupFailed,
    NullLookup,
    resolve_region,
)
from crosswind.core.attribution.rank import SCORE_FLOOR, attribute, rank_candidates
from crosswind.core.findings import AttributeChange, Confidence, DriftKind, Event
from crosswind.core.plan import DriftedResource


def drifted(
    resource_type: str = "aws_security_group",
    paths: tuple[str, ...] = ("ingress.0.cidr_blocks.0",),
    raw_before: dict[str, Any] | None = None,
) -> DriftedResource:
    return DriftedResource(
        address=f"{resource_type}.web",
        resource_type=resource_type,
        name="web",
        kind=DriftKind.CHANGED,
        changes=tuple(
            AttributeChange(path=path, before="10.0.0.0/8", after="0.0.0.0/0") for path in paths
        ),
        raw_before=raw_before if raw_before is not None else {"id": "sg-0123456789abcdef0"},
    )


def event(
    name: str = "AuthorizeSecurityGroupIngress",
    *,
    username: str | None = "alice",
    minutes_ago: int = 30,
    event_id: str = "e-1",
    principal_type: str | None = "IAMUser",
    resources: tuple[tuple[str, str], ...] = (("AWS::EC2::SecurityGroup", "sg-0123456789abcdef0"),),
    read_only: bool | None = False,
) -> Event:
    return Event(
        event_id=event_id,
        event_name=name,
        event_time=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        username=username,
        event_source="ec2.amazonaws.com",
        region="eu-west-1",
        principal_type=principal_type,
        resources=resources,
        read_only=read_only,
    )


class FakeLookup:
    """A lookup with a canned answer, or a canned failure."""

    def __init__(self, events: tuple[Event, ...] = (), error: LookupFailed | None = None) -> None:
        self._events = events
        self._error = error
        self.calls: list[dict[str, Any]] = []

    def events_for(self, *, value: str, region: str, window_hours: int) -> tuple[Event, ...]:
        self.calls.append({"value": value, "region": region, "window_hours": window_hours})
        if self._error:
            raise self._error
        return self._events

    @property
    def failed(self) -> bool:
        return False


@pytest.fixture(scope="module")
def mapping():
    return load_mapping()


# --- the mapping file ---------------------------------------------------


def test_mapping_covers_every_resource_family_the_brief_requires(mapping) -> None:
    """The eleven families named in the brief, each with at least one type."""
    required = {
        "security groups": ["aws_security_group", "aws_security_group_rule"],
        "IAM roles and policies": ["aws_iam_role", "aws_iam_policy"],
        "S3 buckets": ["aws_s3_bucket"],
        "EC2 instances": ["aws_instance"],
        "RDS instances": ["aws_db_instance"],
        "Lambda functions": ["aws_lambda_function"],
        "load balancers": ["aws_lb", "aws_lb_listener"],
        "ECS services": ["aws_ecs_service"],
        "autoscaling groups": ["aws_autoscaling_group"],
        "KMS keys": ["aws_kms_key"],
        "Route 53 records": ["aws_route53_record"],
    }
    missing = {
        family: [name for name in types if mapping.for_type(name) is None]
        for family, types in required.items()
    }
    assert not any(missing.values()), missing


def test_global_services_are_flagged(mapping) -> None:
    """IAM and Route 53 log to us-east-1 wherever the resource lives.

    Getting this wrong is the single most common cause of a real change
    attributing to "unknown".
    """
    assert mapping.for_type("aws_iam_role").is_global is True
    assert mapping.for_type("aws_route53_record").is_global is True
    assert mapping.for_type("aws_security_group").is_global is False


def test_unmapped_iam_types_are_still_treated_as_global(mapping) -> None:
    """A new IAM resource we have no entry for is still an IAM resource."""
    assert mapping.is_global_type("aws_iam_some_future_thing") is True
    assert mapping.is_global_type("aws_ec2_some_future_thing") is False


def test_lookup_value_takes_the_first_present_attribute(mapping) -> None:
    sg = mapping.for_type("aws_security_group")
    assert sg.lookup_value({"id": "sg-abc", "name": "web"}) == "sg-abc"
    assert sg.lookup_value({"name": "web"}) == "web"
    assert sg.lookup_value({}) is None
    assert sg.lookup_value(None) is None


def test_lookup_value_ignores_empty_strings(mapping) -> None:
    sg = mapping.for_type("aws_security_group")
    assert sg.lookup_value({"id": "   ", "name": "web"}) == "web"


def test_attribute_events_are_tighter_than_the_general_list(mapping) -> None:
    """`ModifyVolume` on a changed `size` is better evidence than `CreateTags`."""
    volume = mapping.for_type("aws_ebs_volume")
    for_size = volume.events_for(("size",))
    assert "ModifyVolume" in for_size
    assert "CreateTags" not in for_size
    # And an unmapped attribute falls back to everything the type can do.
    assert "CreateTags" in volume.events_for(("something_else",))


def test_every_mapped_type_has_at_least_one_event(mapping) -> None:
    for name in mapping.covered_types:
        entry = mapping.for_type(name)
        assert entry.events or entry.attribute_events, name
        assert entry.lookup_attributes, name


def test_resolve_region_sends_global_services_to_us_east_1() -> None:
    assert (
        resolve_region(is_global=True, resource_region="eu-west-1", session_region="eu-west-1")
        == "us-east-1"
    )
    assert (
        resolve_region(is_global=False, resource_region="eu-west-1", session_region="us-east-2")
        == "eu-west-1"
    )
    assert (
        resolve_region(is_global=False, resource_region=None, session_region="ap-south-1")
        == "ap-south-1"
    )
    assert resolve_region(is_global=False, resource_region=None, session_region=None) == "us-east-1"


# --- ranking ------------------------------------------------------------


def test_expected_event_name_outranks_an_unrelated_one(mapping) -> None:
    """Both events name the resource; only one changes what drifted."""
    expected = mapping.for_type("aws_security_group").events_for(("ingress.0.cidr_blocks.0",))
    ranked = rank_candidates(
        [
            event("CreateTags", event_id="tags", minutes_ago=5),
            event("AuthorizeSecurityGroupIngress", event_id="authz", minutes_ago=60),
        ],
        lookup_value="sg-abc",
        expected_events=expected,
        window_hours=24,
    )
    assert ranked[0][0].event_id == "authz"


def test_recency_breaks_a_tie_between_equally_good_events(mapping) -> None:
    expected = frozenset({"AuthorizeSecurityGroupIngress"})
    ranked = rank_candidates(
        [
            event(event_id="older", minutes_ago=600),
            event(event_id="newer", minutes_ago=10),
        ],
        lookup_value="sg-abc",
        expected_events=expected,
        window_hours=24,
    )
    assert ranked[0][0].event_id == "newer"


def test_a_human_outranks_an_aws_service(mapping) -> None:
    """Attributing drift to `AWSService` is true and useless when a person
    is also in the running."""
    expected = frozenset({"AuthorizeSecurityGroupIngress"})
    ranked = rank_candidates(
        [
            event(
                event_id="svc", username="AWSService", minutes_ago=5, principal_type="AWSService"
            ),
            event(event_id="human", username="bob", minutes_ago=5),
        ],
        lookup_value="sg-abc",
        expected_events=expected,
        window_hours=24,
    )
    assert ranked[0][0].event_id == "human"


def test_an_event_naming_a_different_resource_is_not_an_exact_match(mapping) -> None:
    """One API call can touch several resources.

    `LookupEvents` returns a `Resources` list per event, so an event that
    names three security groups should only count as an exact match for the
    one we are actually asking about.
    """
    other = event(
        resources=(("AWS::EC2::SecurityGroup", "sg-somethingelse"),),
        username="eve",
    )
    result = attribute(
        drifted(),
        lookup=FakeLookup((other,)),
        mapping=mapping,
        window_hours=24,
    )
    assert result.confidence is not Confidence.HIGH


def test_read_only_events_are_discarded_by_the_client() -> None:
    """A `Describe` call cannot have caused drift.

    Filtered in the client rather than in ranking, so they never become
    candidates and never take up room under the event cap.
    """
    client, stubber = stubbed_cloudtrail()
    stubber.add_response(
        "lookup_events",
        cloudtrail_response(
            [
                raw_event(event_id="read", name="DescribeSecurityGroups", read_only="true"),
                raw_event(event_id="write", name="AuthorizeSecurityGroupIngress"),
            ]
        ),
    )
    with stubber:
        lookup = CloudTrailLookup(FakeSession(client), sleeper=lambda _: None)
        events = lookup.events_for(value="sg-abc", region="eu-west-1", window_hours=24)
    assert [e.event_id for e in events] == ["write"]


def test_region_is_read_from_the_event_blob_not_a_summary_field() -> None:
    """`LookupEvents` returns no region field; it is inside `CloudTrailEvent`."""
    client, stubber = stubbed_cloudtrail()
    stubber.add_response("lookup_events", cloudtrail_response([raw_event()]))
    with stubber:
        lookup = CloudTrailLookup(FakeSession(client), sleeper=lambda _: None)
        events = lookup.events_for(value="sg-abc", region="us-east-2", window_hours=24)
    assert events[0].region == "eu-west-1"


def test_resources_are_carried_through_for_the_reader() -> None:
    """A reader should be able to see what CloudTrail said the event touched."""
    client, stubber = stubbed_cloudtrail()
    stubber.add_response("lookup_events", cloudtrail_response([raw_event()]))
    with stubber:
        lookup = CloudTrailLookup(FakeSession(client), sleeper=lambda _: None)
        events = lookup.events_for(value="sg-abc", region="eu-west-1", window_hours=24)
    assert events[0].resources == (("AWS::EC2::SecurityGroup", "sg-abc"),)
    assert events[0].to_dict()["resources"] == [
        {"type": "AWS::EC2::SecurityGroup", "name": "sg-abc"}
    ]


def test_an_arn_in_cloudtrail_matches_a_name_we_looked_up() -> None:
    """We may look up `app-role` and CloudTrail may record the full ARN."""
    assert event(
        resources=(("AWS::IAM::Role", "arn:aws:iam::123456789012:role/app-role"),)
    ).mentions("app-role")


def test_ranking_is_stable_so_two_reports_diff_clean() -> None:
    """Same input, same order, every time."""
    events = [event(event_id=f"e-{i}", minutes_ago=30) for i in range(5)]
    first = [
        pair[0].event_id
        for pair in rank_candidates(
            events, lookup_value="sg-abc", expected_events=frozenset(), window_hours=24
        )
    ]
    second = [
        pair[0].event_id
        for pair in rank_candidates(
            list(reversed(events)),
            lookup_value="sg-abc",
            expected_events=frozenset(),
            window_hours=24,
        )
    ]
    assert first == second


# --- confidence ---------------------------------------------------------


def test_resource_match_plus_expected_event_is_high_confidence(mapping) -> None:
    result = attribute(
        drifted(),
        lookup=FakeLookup((event("AuthorizeSecurityGroupIngress", username="alice"),)),
        mapping=mapping,
        window_hours=24,
    )
    assert result.confidence is Confidence.HIGH
    assert result.actor == "alice"
    assert result.event is not None
    assert result.event.event_name == "AuthorizeSecurityGroupIngress"


def test_resource_match_with_an_unexpected_event_is_medium(mapping) -> None:
    """Probably the right resource, possibly the wrong event."""
    result = attribute(
        drifted(),
        lookup=FakeLookup((event("SomeUnrelatedCall", username="alice"),)),
        mapping=mapping,
        window_hours=24,
    )
    assert result.confidence is Confidence.MEDIUM
    assert result.actor == "alice"


def test_confidence_is_not_a_score_threshold(mapping) -> None:
    """A pile of weak signals must not add up to `high`.

    This is the property that stops the feature producing confident wrong
    answers: `high` requires both the resource match and the event name, not
    a total above some number.
    """
    # Very recent and resource-matched, but the event name is not expected.
    result = attribute(
        drifted(),
        lookup=FakeLookup((event("TotallyUnrelated", minutes_ago=0),)),
        mapping=mapping,
        window_hours=24,
    )
    assert result.score is not None and result.score > SCORE_FLOOR
    assert result.confidence is not Confidence.HIGH


# --- "unknown" names nobody --------------------------------------------


def test_no_events_is_unknown_and_names_nobody(mapping) -> None:
    result = attribute(drifted(), lookup=FakeLookup(()), mapping=mapping, window_hours=24)
    assert result.confidence is Confidence.UNKNOWN
    assert result.actor is None
    assert result.event is None
    assert result.reason == "no_matching_events"
    assert result.known is False


def test_unmapped_resource_type_is_unknown_with_a_reason(mapping) -> None:
    """Honest, and a to-do list for contributors."""
    result = attribute(
        drifted(resource_type="aws_some_new_service"),
        lookup=FakeLookup((event(),)),
        mapping=mapping,
        window_hours=24,
    )
    assert result.reason == "unmapped_resource_type"
    assert result.actor is None


def test_no_lookup_value_is_unknown_rather_than_a_guessed_lookup(mapping) -> None:
    """The prior state has nothing CloudTrail would know this resource by."""
    result = attribute(
        drifted(raw_before={"description": "no id here"}),
        lookup=FakeLookup((event(),)),
        mapping=mapping,
        window_hours=24,
    )
    assert result.reason == "no_lookup_value"
    assert result.actor is None


def test_lookup_failure_degrades_to_unknown_and_keeps_the_reason(mapping) -> None:
    """A CloudTrail failure must never fail the scan."""
    lookup = FakeLookup(error=LookupFailed("denied", reason="lookup_denied"))
    result = attribute(drifted(), lookup=lookup, mapping=mapping, window_hours=24)
    assert result.confidence is Confidence.UNKNOWN
    assert result.reason == "lookup_denied"
    assert result.actor is None


def test_expired_credentials_are_reported_as_such(mapping) -> None:
    lookup = FakeLookup(error=LookupFailed("expired", reason="credentials_expired"))
    result = attribute(drifted(), lookup=lookup, mapping=mapping, window_hours=24)
    assert result.reason == "credentials_expired"


def test_an_event_older_than_retention_is_unknown(mapping) -> None:
    """CloudTrail's event history is 90 days; older is not a real answer."""
    stale = event(minutes_ago=(RETENTION_DAYS + 5) * 24 * 60)
    result = attribute(
        drifted(),
        lookup=FakeLookup((stale,)),
        mapping=mapping,
        window_hours=(RETENTION_DAYS + 30) * 24,
    )
    assert result.reason == "outside_cloudtrail_retention"
    assert result.actor is None


def test_null_lookup_disables_attribution_without_a_separate_code_path(mapping) -> None:
    """`--no-attribution` and `demo` use the same ranking code as a real scan."""
    result = attribute(drifted(), lookup=NullLookup(), mapping=mapping, window_hours=24)
    assert result.confidence is Confidence.UNKNOWN
    assert result.actor is None


def test_an_unnamed_principal_is_described_not_invented(mapping) -> None:
    """CloudTrail sometimes records no `Username`. We say so."""
    result = attribute(
        drifted(),
        lookup=FakeLookup((event(username=None, principal_type="AssumedRole"),)),
        mapping=mapping,
        window_hours=24,
    )
    assert result.actor == "unnamed AssumedRole"


def test_global_resource_is_looked_up_in_us_east_1(mapping) -> None:
    """The lookup region, not just the flag, has to be right."""
    lookup = FakeLookup((event("UpdateAssumeRolePolicy", username="carol"),))
    attribute(
        DriftedResource(
            address="aws_iam_role.app",
            resource_type="aws_iam_role",
            name="app",
            kind=DriftKind.CHANGED,
            changes=(AttributeChange(path="assume_role_policy", before="a", after="b"),),
            raw_before={"name": "app-role"},
        ),
        lookup=lookup,
        mapping=mapping,
        window_hours=24,
        region="eu-west-1",
    )
    assert lookup.calls[0]["region"] == "us-east-1"
    assert lookup.calls[0]["value"] == "app-role"


# --- the CloudTrail client, against botocore's own model ---------------


def cloudtrail_response(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {"Events": events}


def raw_event(
    event_id: str = "e-1",
    name: str = "AuthorizeSecurityGroupIngress",
    username: str = "alice",
    principal_type: str = "IAMUser",
    read_only: str = "false",
    resource_name: str = "sg-abc",
) -> dict[str, Any]:
    """A `LookupEvents` event with exactly the fields the real one has.

    There is no `AwsRegion` here, because the API does not return one — the
    region is inside `CloudTrailEvent`. `Stubber` validates this against
    botocore's service model, so an invented field fails the test.
    """
    return {
        "EventId": event_id,
        "EventName": name,
        "EventTime": datetime.now(UTC) - timedelta(minutes=10),
        "Username": username,
        "EventSource": "ec2.amazonaws.com",
        "ReadOnly": read_only,
        "Resources": [{"ResourceType": "AWS::EC2::SecurityGroup", "ResourceName": resource_name}],
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {"type": principal_type},
                "awsRegion": "eu-west-1",
                "readOnly": read_only == "true",
            }
        ),
    }


class FakeSession:
    """A boto3 session whose client is a stubbed one."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def client(self, name: str, region_name: str | None = None) -> Any:
        return self._client


def stubbed_cloudtrail() -> tuple[Any, Stubber]:
    client = boto3.client(
        "cloudtrail",
        region_name="eu-west-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
    )
    return client, Stubber(client)


def test_lookup_sends_a_request_the_real_service_would_accept() -> None:
    """`Stubber` validates against botocore's service model.

    So a misnamed parameter or a wrong shape fails here rather than in
    someone's account.
    """
    client, stubber = stubbed_cloudtrail()
    stubber.add_response(
        "lookup_events",
        cloudtrail_response([raw_event()]),
        {
            "LookupAttributes": [{"AttributeKey": "ResourceName", "AttributeValue": "sg-abc"}],
            "StartTime": ANY,
            "EndTime": ANY,
            "MaxResults": 50,
        },
    )
    with stubber:
        lookup = CloudTrailLookup(FakeSession(client), sleeper=lambda _: None)
        events = lookup.events_for(value="sg-abc", region="eu-west-1", window_hours=24)
    assert len(events) == 1
    assert events[0].event_name == "AuthorizeSecurityGroupIngress"
    assert events[0].username == "alice"
    assert events[0].principal_type == "IAMUser"


def test_lookup_caches_so_one_resource_is_one_request() -> None:
    """Several drifted attributes on one resource must not be several calls."""
    client, stubber = stubbed_cloudtrail()
    stubber.add_response("lookup_events", cloudtrail_response([raw_event()]))
    with stubber:
        lookup = CloudTrailLookup(FakeSession(client), sleeper=lambda _: None)
        first = lookup.events_for(value="sg-abc", region="eu-west-1", window_hours=24)
        second = lookup.events_for(value="sg-abc", region="eu-west-1", window_hours=24)
    # Only one response was queued; a second call would have raised.
    assert first == second
    stubber.assert_no_pending_responses()


def test_throttling_is_retried_with_backoff() -> None:
    """`LookupEvents` allows about 2 requests/second, enforced per account."""
    client, stubber = stubbed_cloudtrail()
    stubber.add_client_error("lookup_events", service_error_code="ThrottlingException")
    stubber.add_client_error("lookup_events", service_error_code="ThrottlingException")
    stubber.add_response("lookup_events", cloudtrail_response([raw_event()]))

    slept: list[float] = []
    with stubber:
        lookup = CloudTrailLookup(FakeSession(client), sleeper=slept.append)
        events = lookup.events_for(value="sg-abc", region="eu-west-1", window_hours=24)
    assert len(events) == 1
    assert len(slept) == 2, "should have backed off once per throttle"


def test_sustained_throttling_gives_up_with_a_reason() -> None:
    """Spending ten minutes being throttled is worse than saying so: the
    drift report is already finished."""
    client, stubber = stubbed_cloudtrail()
    for _ in range(5):
        stubber.add_client_error("lookup_events", service_error_code="ThrottlingException")
    with stubber:
        lookup = CloudTrailLookup(FakeSession(client), sleeper=lambda _: None)
        with pytest.raises(LookupFailed) as excinfo:
            lookup.events_for(value="sg-abc", region="eu-west-1", window_hours=24)
    assert excinfo.value.reason == "throttled"


def test_access_denied_is_not_retried() -> None:
    """Retrying a permissions error is just a slower failure."""
    client, stubber = stubbed_cloudtrail()
    stubber.add_client_error("lookup_events", service_error_code="AccessDenied")
    with stubber:
        lookup = CloudTrailLookup(FakeSession(client), sleeper=lambda _: None)
        with pytest.raises(LookupFailed) as excinfo:
            lookup.events_for(value="sg-abc", region="eu-west-1", window_hours=24)
    assert excinfo.value.reason == "lookup_denied"
    stubber.assert_no_pending_responses()


def test_expired_token_is_classified_precisely() -> None:
    client, stubber = stubbed_cloudtrail()
    stubber.add_client_error("lookup_events", service_error_code="ExpiredToken")
    with stubber:
        lookup = CloudTrailLookup(FakeSession(client), sleeper=lambda _: None)
        with pytest.raises(LookupFailed) as excinfo:
            lookup.events_for(value="sg-abc", region="eu-west-1", window_hours=24)
    assert excinfo.value.reason == "credentials_expired"


def test_failure_budget_stops_further_lookups() -> None:
    """Once attribution has clearly stopped working, stop paying for it."""
    client, stubber = stubbed_cloudtrail()
    stubber.add_client_error("lookup_events", service_error_code="AccessDenied")
    with stubber:
        lookup = CloudTrailLookup(FakeSession(client), failure_budget=1, sleeper=lambda _: None)
        with pytest.raises(LookupFailed):
            lookup.events_for(value="sg-a", region="eu-west-1", window_hours=24)
        assert lookup.failed
        # No further responses are queued, so a second request would error
        # against the stub. It must not make one.
        with pytest.raises(LookupFailed) as excinfo:
            lookup.events_for(value="sg-b", region="eu-west-1", window_hours=24)
    assert excinfo.value.reason == "lookup_denied"


def test_window_is_clamped_to_cloudtrail_retention() -> None:
    """Asking for a year is a slower way to get 90 days."""
    client, stubber = stubbed_cloudtrail()
    stubber.add_response("lookup_events", cloudtrail_response([raw_event()]))
    with stubber:
        lookup = CloudTrailLookup(FakeSession(client), sleeper=lambda _: None)
        lookup.events_for(value="sg-abc", region="eu-west-1", window_hours=24 * 365)
        # The clamped window is the cache key, so the same call with the
        # clamped value must hit the cache rather than the service.
        lookup.events_for(value="sg-abc", region="eu-west-1", window_hours=RETENTION_DAYS * 24)
    stubber.assert_no_pending_responses()


def test_malformed_events_are_skipped_not_fatal() -> None:
    """An event with no ID or an unparseable time is dropped quietly."""
    client, stubber = stubbed_cloudtrail()
    stubber.add_response(
        "lookup_events",
        cloudtrail_response(
            [
                {"EventName": "NoIdHere", "EventTime": datetime.now(UTC)},
                raw_event(event_id="good"),
            ]
        ),
    )
    with stubber:
        lookup = CloudTrailLookup(FakeSession(client), sleeper=lambda _: None)
        events = lookup.events_for(value="sg-abc", region="eu-west-1", window_hours=24)
    assert [e.event_id for e in events] == ["good"]


def test_a_non_aws_exception_is_wrapped_rather_than_escaping() -> None:
    """Attribution must not be able to crash a scan."""

    class Boom:
        def lookup_events(self, **kwargs: Any) -> Any:
            raise ClientError({"Error": {"Code": "InternalError"}}, "LookupEvents")

    lookup = CloudTrailLookup(FakeSession(Boom()), sleeper=lambda _: None)
    with pytest.raises(LookupFailed) as excinfo:
        lookup.events_for(value="sg-abc", region="eu-west-1", window_hours=24)
    assert excinfo.value.reason == "lookup_failed"
