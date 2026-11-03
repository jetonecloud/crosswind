"""`crosswind demo`: a real report, no AWS and no Terraform.

The point of a demo is to answer "what do I get?" before anyone installs a
Terraform binary or decides which IAM role to create. So this builds a
`Report` directly from bundled fixtures and hands it to the same renderers a
real scan uses. There is no demo-only rendering path, which means the demo
cannot drift away from the thing it is demonstrating.

The fixture is a plausible small AWS estate with the kinds of drift that
actually happen: somebody opened a security group during an incident, a
database got resized by hand, an ECS service is running a task definition the
code does not name, a bucket lost its public-access block, and one stack has
a backend nobody can reach. Two findings are attributed, one is `unknown` so
the honest case is visible, and one stack fails so the "could not check" path
is on the page.

Every value here is invented. The account is `000000000000`, the IDs are
obviously fake, and `tests/test_demo.py` asserts there are no real-looking
credentials in it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from crosswind.core.findings import (
    AttributeChange,
    Attribution,
    Confidence,
    CostEstimate,
    DriftKind,
    Event,
    Finding,
    Recommendation,
    Severity,
    StackResult,
    StackStatus,
)
from crosswind.core.scan import Report

#: The demo account. Deliberately not a real-looking ID.
DEMO_ACCOUNT = "000000000000"

DEMO_IDENTITY = "arn:aws:iam::000000000000:role/CrosswindReadOnlyRole"


def _event(
    event_id: str,
    name: str,
    *,
    username: str,
    hours_ago: float,
    source: str,
    region: str = "eu-west-1",
    principal_type: str = "AssumedRole",
    resources: tuple[tuple[str, str], ...] = (),
) -> Event:
    return Event(
        event_id=event_id,
        event_name=name,
        event_time=_now() - timedelta(hours=hours_ago),
        username=username,
        event_source=source,
        region=region,
        principal_type=principal_type,
        resources=resources,
        read_only=False,
    )


def _now() -> datetime:
    """The demo's reference time.

    Read once per call rather than frozen at import, so the report says
    "three hours ago" whenever somebody runs it rather than dating itself to
    whenever the package was built.
    """
    return datetime.now(UTC)


def demo_report(min_severity: Severity = Severity.LOW) -> Report:
    """A complete `Report` built from fixtures. No I/O of any kind."""
    started = _now() - timedelta(seconds=9)

    network = StackResult(
        path="infra/prod/network",
        status=StackStatus.DRIFTED,
        binary="terraform v1.15.8",
        duration_seconds=3.4,
        findings=(
            Finding(
                stack="infra/prod/network",
                address="aws_security_group.api",
                resource_type="aws_security_group",
                kind=DriftKind.CHANGED,
                changes=(
                    AttributeChange(
                        path="ingress.0.cidr_blocks.0",
                        before="10.0.0.0/8",
                        after="0.0.0.0/0",
                    ),
                    AttributeChange(
                        path="ingress.0.description",
                        before="internal API traffic",
                        after="temp debug - REMOVE",
                    ),
                ),
                severity=Severity.CRITICAL,
                severity_rule="sg-ingress-public",
                severity_reason=(
                    "An inbound security group rule now accepts traffic from the "
                    "whole internet. Anything listening on that port is reachable "
                    "from anywhere."
                ),
                recommendation=Recommendation.REVERT,
                recommendation_reason=(
                    "Revert unless this was a deliberate, reviewed change. If it was "
                    "deliberate, put it in the code with a comment saying why."
                ),
                attribution=Attribution(
                    confidence=Confidence.HIGH,
                    actor="dmitri",
                    score=0.94,
                    event=_event(
                        "7f3c1e8a-4b2d-4c6f-9a1e-2d5b8c0a3f71",
                        "AuthorizeSecurityGroupIngress",
                        username="dmitri",
                        hours_ago=19,
                        source="ec2.amazonaws.com",
                        resources=(("AWS::EC2::SecurityGroup", "sg-0demo0api0000001"),),
                    ),
                ),
                provider="hashicorp/aws",
                region="eu-west-1",
            ),
            Finding(
                stack="infra/prod/network",
                address="aws_lb_listener.public",
                resource_type="aws_lb_listener",
                kind=DriftKind.CHANGED,
                changes=(
                    AttributeChange(
                        path="ssl_policy",
                        before="ELBSecurityPolicy-TLS13-1-2-2021-06",
                        after="ELBSecurityPolicy-2016-08",
                    ),
                ),
                severity=Severity.MEDIUM,
                severity_rule="lb-listener-changed",
                severity_reason=(
                    "A load balancer listener or its certificate differs from the code."
                ),
                recommendation=Recommendation.INVESTIGATE,
                recommendation_reason=(
                    "Check what is serving traffic now. A certificate swapped by "
                    "hand is often a renewal nobody automated."
                ),
                attribution=Attribution.unknown("no_matching_events"),
                provider="hashicorp/aws",
                region="eu-west-1",
            ),
        ),
    )

    data = StackResult(
        path="infra/prod/data",
        status=StackStatus.DRIFTED,
        binary="terraform v1.15.8",
        duration_seconds=4.1,
        ignored=2,
        findings=(
            Finding(
                stack="infra/prod/data",
                address="aws_s3_bucket_public_access_block.exports",
                resource_type="aws_s3_bucket_public_access_block",
                kind=DriftKind.CHANGED,
                changes=(
                    AttributeChange(path="block_public_acls", before=True, after=False),
                    AttributeChange(path="block_public_policy", before=True, after=False),
                ),
                severity=Severity.CRITICAL,
                severity_rule="s3-public-access",
                severity_reason=(
                    "Public access protections on this bucket were weakened, which "
                    "can expose its contents to anonymous readers."
                ),
                recommendation=Recommendation.REVERT,
                recommendation_reason=(
                    "Revert. A bucket made public outside Terraform is almost never intentional."
                ),
                attribution=Attribution(
                    confidence=Confidence.MEDIUM,
                    actor="ci-deploy-session",
                    score=0.63,
                    event=_event(
                        "c2e9a540-8d13-47bb-b0cf-6a4e1d93b28c",
                        "PutBucketPublicAccessBlock",
                        username="ci-deploy-session",
                        hours_ago=52,
                        source="s3.amazonaws.com",
                        resources=(("AWS::S3::Bucket", "demo-prod-exports"),),
                    ),
                ),
                provider="hashicorp/aws",
                region="eu-west-1",
            ),
            Finding(
                stack="infra/prod/data",
                address="aws_db_instance.primary",
                resource_type="aws_db_instance",
                kind=DriftKind.CHANGED,
                changes=(
                    AttributeChange(
                        path="instance_class", before="db.t3.medium", after="db.m5.large"
                    ),
                    AttributeChange(path="backup_retention_period", before=14, after=7),
                    # Marked sensitive by the provider: it is never shown, and
                    # the demo carries it so the behaviour is visible.
                    AttributeChange(
                        path="password",
                        before="(sensitive value)",
                        after="(sensitive value)",
                        redacted=True,
                        provider_sensitive=True,
                    ),
                ),
                severity=Severity.MEDIUM,
                severity_rule="instance-size-changed",
                severity_reason=(
                    "The instance size differs from the code. This changes what you "
                    "pay and will be reverted by the next apply."
                ),
                recommendation=Recommendation.UPDATE_CODE,
                recommendation_reason=(
                    "If the new size is right, put it in the code - otherwise the "
                    "next apply undoes it, probably during a deploy nobody is watching."
                ),
                attribution=Attribution(
                    confidence=Confidence.HIGH,
                    actor="priya",
                    score=0.88,
                    event=_event(
                        "15b7d3ef-62a9-4f08-8e71-9c0b4a2d6e53",
                        "ModifyDBInstance",
                        username="priya",
                        hours_ago=7,
                        source="rds.amazonaws.com",
                        resources=(("AWS::RDS::DBInstance", "demo-prod-primary"),),
                    ),
                ),
                cost=CostEstimate(
                    monthly_usd=75.19,
                    basis=(
                        "db.m5.large at $0.1710/hour versus db.t3.medium at "
                        "$0.0680/hour, over 730 hours: $75.19/month more than the "
                        "code describes. RDS on-demand, single-AZ list price in "
                        "us-east-1, checked 2026-11. This is an upper bound - "
                        "Savings Plans, Reserved Instances and Spot all make it "
                        "lower. A Multi-AZ instance costs roughly double these rates."
                    ),
                ),
                provider="hashicorp/aws",
                region="eu-west-1",
            ),
        ),
    )

    services = StackResult(
        path="infra/prod/services",
        status=StackStatus.DRIFTED,
        binary="tofu v1.13.2",
        duration_seconds=2.8,
        findings=(
            Finding(
                stack="infra/prod/services",
                address='aws_ecs_service.api["worker"]',
                resource_type="aws_ecs_service",
                kind=DriftKind.CHANGED,
                changes=(
                    AttributeChange(
                        path="task_definition",
                        before="arn:aws:ecs:eu-west-1:000000000000:task-definition/api:41",
                        after="arn:aws:ecs:eu-west-1:000000000000:task-definition/api:47",
                    ),
                ),
                severity=Severity.MEDIUM,
                severity_rule="ecs-task-definition-changed",
                severity_reason=(
                    "The running task definition is not the one the code points at, "
                    "so the deployed image may not be the one in the repository."
                ),
                recommendation=Recommendation.INVESTIGATE,
                recommendation_reason=(
                    "Normal if you deploy images outside Terraform - in which case "
                    "add an ignore rule and a `lifecycle.ignore_changes` so it stops "
                    "reappearing."
                ),
                attribution=Attribution.unknown("outside_cloudtrail_retention"),
                provider="hashicorp/aws",
                region="eu-west-1",
            ),
            Finding(
                stack="infra/prod/services",
                address="aws_iam_role.worker",
                resource_type="aws_iam_role",
                kind=DriftKind.CHANGED,
                changes=(
                    AttributeChange(
                        path="policy",
                        before='{"Statement":[{"Action":"s3:GetObject","Resource":"arn:aws:s3:::demo-prod-exports/*"}]}',
                        after='{"Statement":[{"Action":"s3:*","Resource":"*"}]}',
                    ),
                ),
                severity=Severity.CRITICAL,
                severity_rule="iam-policy-widened",
                severity_reason=(
                    "An IAM policy now grants more than the code does - a wildcard "
                    "action, resource, or principal. This is the fastest way for a "
                    "small change to become an account-wide one."
                ),
                recommendation=Recommendation.REVERT,
                recommendation_reason=(
                    "Revert. If the extra permission is genuinely needed, add it to "
                    "the code scoped to the specific actions and resources."
                ),
                attribution=Attribution(
                    confidence=Confidence.HIGH,
                    actor="dmitri",
                    score=0.91,
                    event=_event(
                        "e840b16c-9f2a-4d55-a3b8-71c6e0f4928d",
                        "PutRolePolicy",
                        username="dmitri",
                        hours_ago=20,
                        source="iam.amazonaws.com",
                        # IAM logs to us-east-1 whatever region the role is
                        # "in". The demo shows that, because it is the thing
                        # people get wrong.
                        region="us-east-1",
                        resources=(
                            (
                                "AWS::IAM::Role",
                                "arn:aws:iam::000000000000:role/demo-prod-worker",
                            ),
                        ),
                    ),
                ),
                provider="hashicorp/aws",
                region="us-east-1",
            ),
            Finding(
                stack="infra/prod/services",
                address="aws_autoscaling_group.workers",
                resource_type="aws_autoscaling_group",
                kind=DriftKind.CHANGED,
                changes=(
                    AttributeChange(path="tags.CostCentre", before="platform", after="eng-ops"),
                ),
                severity=Severity.LOW,
                severity_rule="tags-only-change",
                severity_reason=(
                    "Only tags differ. Worth reconciling for cost allocation, but "
                    "nothing is at risk."
                ),
                recommendation=Recommendation.UPDATE_CODE,
                recommendation_reason=(
                    "Put the tags in the code, or in a default_tags block if "
                    "everything should have them."
                ),
                attribution=Attribution.unknown("no_matching_events"),
                provider="hashicorp/aws",
                region="eu-west-1",
            ),
        ),
    )

    # A stack we could not check. The demo would be dishonest without one:
    # this is the case the whole design is built around.
    legacy = StackResult(
        path="infra/legacy/billing",
        status=StackStatus.FAILED,
        binary="terraform v1.15.8",
        duration_seconds=1.2,
        error=(
            "Error: Failed to get existing workspaces: S3 bucket does not exist.\n"
            "\n"
            "The referenced S3 bucket must have been previously created. If the S3\n"
            "bucket was created within the last minute, please wait for a minute or\n"
            "two and try again.\n"
            "\n"
            "Bucket: demo-legacy-tfstate"
        ),
    )

    sandbox = StackResult(
        path="infra/sandbox",
        status=StackStatus.CLEAN,
        binary="terraform v1.15.8",
        duration_seconds=2.1,
    )

    return Report(
        stacks=(data, legacy, network, services, sandbox),
        started_at=started,
        finished_at=_now(),
        min_severity=min_severity,
        binary="terraform v1.15.8",
        account=DEMO_ACCOUNT,
        identity=DEMO_IDENTITY,
        notes=(
            "This is a sample report built from bundled fixtures. No AWS account "
            "was contacted and no Terraform ran.",
        ),
        attribution_note=(
            "Two findings could not be attributed: one has no matching CloudTrail "
            "event, and one is older than CloudTrail's 90-day history."
        ),
    )
