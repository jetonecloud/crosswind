# Attribution

Attribution answers "who changed this" from CloudTrail. It is the feature
most likely to be quoted in a meeting, which is exactly why it is built to
say **"we don't know"** rather than to produce a plausible name.

`Attribution.unknown()` is the only way to construct an attribution without
an event, and it forces the actor to `None`. There is no code path in
Crosswind that produces a name without the evidence for it.

## How a finding gets a name

1. **Look up the resource type** in
   [`cloudtrail.yml`](../src/crosswind/data/cloudtrail.yml). No entry means
   `unknown (unmapped_resource_type)` — honest, and a to-do list.
2. **Derive a lookup value** from the prior state, using the mapped
   attributes in order. Usually `id`, sometimes `name` or an ARN. If the
   state has none of them, `unknown (no_lookup_value)`: looking up a guessed
   value would produce confident nonsense.
3. **Pick a region.** Global services go to `us-east-1` regardless of where
   the resource appears to live. See [below](#the-us-east-1-trap).
4. **Call `LookupEvents`** filtered by `ResourceName`, within the window.
   Read-only events are discarded — a `Describe` call cannot have caused
   drift.
5. **Rank the candidates** and take the best, if it clears the floor.
6. **Assign a confidence** from which evidence is present.

## Ranking

Three signals, weighted by how much they actually tell you.

| Signal | Weight | Why |
|---|---|---|
| The event's own `Resources` list names the drifted resource | 0.5 | The strongest evidence there is. Matters for calls that touch several resources at once — a `ModifySecurityGroupRules` naming three groups is only an exact match for the one we asked about. |
| The event name is one the mapping associates with the attribute that changed | 0.3 | `ModifyVolume` on a changed `size` is a much better story than `CreateTags` on the same volume. |
| The event is recent within the window | 0.2 | Later events are likelier to be the cause. The weakest signal by far. |

The floor is **0.45**, deliberately above the recency weight on its own:
"this event is recent" is not evidence that it caused anything.

Events from `AWSService` and similar principals are scored down but not
removed, so a human actor wins a tie — while "an AWS service did this"
remains a real answer when it's the only one.

Ties break towards the more recent event, then the event ID, so two runs over
an unchanged account rank identically and the reports diff clean.

## Confidence

Confidence is **not** a threshold on the score. That would let three weak
signals add up to `high`, which is exactly the kind of confident wrong answer
this feature cannot afford. It is a statement about which evidence is
present:

| Level | Means |
|---|---|
| `high` | Exact resource match **and** an expected event name. Both. |
| `medium` | Exact resource match, but the event name isn't one we associate with the attribute that changed. Probably the right resource, possibly the wrong event. |
| `low` | Cleared the floor on something else. Worth showing with the event ID; not worth repeating in a meeting. |
| `unknown` | No answer. Names nobody. |

Every attributed finding carries the event ID, name, time, principal and the
resources CloudTrail associated with it — so a reader can paste the ID into
the console and see what we saw. **A name is evidence of an API call, not
proof of intent.**

## What CloudTrail cannot tell you

These are the API's limits, not ours, and each one is surfaced in the report
rather than hidden.

### Management events only

`LookupEvents` serves management events. A change made through a data-plane
API — writing an S3 object, invoking a Lambda — is not recorded unless the
account opted into data events and pays for them, and even then
`LookupEvents` does not serve them.

In practice this is rarely a problem for drift, because drift is almost
always a configuration change and configuration changes are management
events. But a bucket whose *contents* changed is invisible, and so is
anything done through a service's own data plane.

### Ninety days

`LookupEvents` serves the event history, not a trail's S3 bucket. Drift older
than that attributes to `unknown (outside_cloudtrail_retention)`. If you need
longer, the events are in your trail's bucket and Athena can query them —
Crosswind does not, because that would mean asking for bucket access and
running queries that cost money.

The window is `cloudtrail_window_hours` (default 14 days), clamped to 90.
Widening it finds older changes and makes each lookup slower.

### Up to about 15 minutes of delay

Events take time to appear. Drift created moments before a scan may
legitimately attribute to `unknown`. Re-running later usually resolves it.

### The us-east-1 trap

CloudTrail records global-service events in **`us-east-1`** whatever region
the resource appears to be in: IAM, Route 53, CloudFront, STS, Organisations,
Shield, global-scope WAF.

**This is the single most common reason a real change attributes to
nothing** — the lookup goes to `eu-west-1`, finds an empty trail, and
reports `unknown`. The mapping file carries `global: true` per resource type,
and unmapped types fall back to checking the service prefix, so
`aws_iam_some_future_thing` is still treated as global.

If you add a mapping for a global service and forget the flag, attribution
for it silently stops working. There is no error — just a resource that never
has an answer.

### Rate limits

`LookupEvents` allows roughly **two requests per second per account per
region**, enforced per account rather than per caller — so a scan competing
with someone else's tooling gets throttled even when it is behaving.

Crosswind handles this with a shared token bucket under the quota,
exponential backoff with full jitter (every thread picking the same delay is
how a throttle becomes a thundering herd), a per-run cache keyed on
`(region, value, window)` so one resource is one lookup and two stacks
sharing a security group is still one lookup, and a failure budget that stops
trying after repeated failures.

When the budget runs out, remaining findings say
`unknown (throttled)` and the report says so once. **Attribution stopping
never fails the scan** — the drift report is the product and it is already
finished.

## Failures degrade, never fail

| What happened | Result |
|---|---|
| No credentials | Every finding `unknown`, warning in the report, scan exits normally |
| No `cloudtrail:LookupEvents` | `unknown (lookup_denied)`, with the action named |
| Credentials expired mid-scan | `unknown (credentials_expired)` |
| Throttled past the budget | `unknown (throttled)` |
| `--no-attribution` | `unknown (attribution_disabled)` |

In every case the drift report is complete. Attribution is the bonus feature;
detection is the product.

## Adding a resource type

The highest-value contribution per line of diff, and it needs no Python.
Edit [`cloudtrail.yml`](../src/crosswind/data/cloudtrail.yml):

```yaml
  aws_thing:
    resource_type: AWS::Service::Thing     # CloudTrail's own ResourceType
    lookup_attributes: [name, id, arn]     # tried in order, first non-empty wins
    global: false                          # true only for us-east-1-only services
    events:
      - UpdateThing
      - TagResource
    attribute_events:                      # optional, and much stronger evidence
      "size": [UpdateThing]
      "tags*": [TagResource, UntagResource]
```

Finding the right values:

- **`lookup_attributes`** must name attributes actually present in the state
  *and* be what CloudTrail knows the resource by. `terraform state show
  aws_thing.example` tells you the first; a real CloudTrail event tells you
  the second.
- **`events`** — make the change by hand in a test account, then look at what
  CloudTrail recorded. Guessing from the API reference usually gets the name
  nearly right, and nearly right matches nothing.
- **`attribute_events`** is where the quality is. It is the difference between
  `medium` and `high` confidence, because it distinguishes "an event touched
  this resource" from "an event changed the thing that drifted".
- **`global`** — check whether the service's events appear in `us-east-1`
  when the resource is elsewhere. If in doubt, make the change in a non-`us-east-1`
  region and look.

### Currently mapped

Security groups and their rules, IAM roles / policies / users / instance
profiles, S3 buckets and their configuration sub-resources, EC2 instances,
EBS volumes, RDS instances and clusters, Lambda functions and permissions,
load balancers / listeners / target groups, ECS services / clusters / task
definitions, autoscaling groups, launch templates, KMS keys and aliases,
Route 53 records and zones, SQS, SNS, DynamoDB, CloudWatch log groups, EFS,
ElastiCache, CloudFront, API Gateway, EKS, Secrets Manager.

Anything else reports `unknown (unmapped_resource_type)`, which is the honest
answer and also the to-do list. Drift detection is unaffected — it covers
everything Terraform manages, regardless of what is in this file.

## Why not guess harder

We could attribute on weaker evidence — the most recent write event in the
region, say, or the person who most often touches that resource type. Both
would produce a name most of the time.

They would also, some of the time, name the wrong colleague in a document
that gets forwarded. "Dmitri opened the security group" is a sentence with
consequences, and a drift report is not the place to be approximately right
about who did what. The floor is where it is on purpose, and
`unknown (no_matching_events)` is a feature.
