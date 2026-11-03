# JSON schema

`crosswind scan --format json` writes a versioned document. This is the
contract for anything programmatic — a dashboard, a diff between runs, a
Slack bot somebody writes.

Current version: **`1.0`**.

## Compatibility

- **Adding a key bumps the minor version.** Consumers must ignore keys they
  don't recognise.
- **Removing a key, renaming one, or changing its type bumps the major
  version.**
- **`null` means "we don't know" and is never omitted.** A missing key and a
  null key should not be different questions for a consumer to ask.
- Keys are sorted and the file ends with a newline, so two reports of an
  unchanged account diff to nothing.

Check `schema_version` and refuse a major you don't know:

```python
import json

with open("crosswind-report.json") as handle:
    report = json.load(handle)

major = int(report["schema_version"].split(".")[0])
if major != 1:
    raise SystemExit(f"unsupported schema version {report['schema_version']}")
```

## Top level

```json
{
  "schema_version": "1.0",
  "tool": "crosswind",
  "generated_at": "2026-11-03T14:30:00+00:00",
  "started_at": "2026-11-03T14:29:48+00:00",
  "duration_seconds": 12.4,
  "binary": "terraform v1.15.8",
  "account": "123456789012",
  "identity": "arn:aws:iam::123456789012:role/CrosswindReadOnlyRole",
  "config_source": "/repo/.crosswind.yml",
  "min_severity": "low",
  "summary": { },
  "attribution_note": null,
  "notes": [],
  "stacks": [ ],
  "findings": [ ]
}
```

| Key | Type | Notes |
|---|---|---|
| `schema_version` | string | `major.minor`. Check this. |
| `tool` | string | Always `"crosswind"`. |
| `generated_at` | string | ISO 8601 with offset, when the scan finished. |
| `started_at` | string | ISO 8601 with offset. |
| `duration_seconds` | number | Wall clock for the whole scan. |
| `binary` | string \| null | What ran. `null` for `demo`. |
| `account` | string \| null | AWS account ID. `null` without credentials. |
| `identity` | string \| null | The ARN the scan ran as. Never a credential. |
| `config_source` | string \| null | Path to the config file used, if any. |
| `min_severity` | string | The threshold in effect. |
| `attribution_note` | string \| null | One sentence when attribution was skipped or degraded. |
| `notes` | string[] | Config warnings and other non-fatal things. |

## `summary`

The numbers, so a consumer doesn't have to count arrays.

```json
{
  "stacks_scanned": 5,
  "stacks_clean": 1,
  "stacks_drifted": 3,
  "stacks_failed": 1,
  "findings_total": 7,
  "findings_reported": 7,
  "findings_ignored": 2,
  "by_severity": { "critical": 3, "high": 0, "medium": 3, "low": 1 },
  "exit_code": 2
}
```

`findings_total` counts everything found; `findings_reported` counts what
cleared `min_severity`. `findings_ignored` is what `.crosswindignore`
suppressed — reported rather than hidden, so a consumer can tell "clean" from
"quiet".

`by_severity` always has all four keys, including zeros, so a chart never
gaps.

**`stacks_failed` is the one to branch on.** A non-zero value means the
report is incomplete and the clean-looking parts of it may not be.
`by_severity` says nothing about a stack that was never read.

## `stacks`

One entry per stack, including the ones that failed.

```json
{
  "path": "infra/prod/network",
  "status": "drifted",
  "error": null,
  "binary": "terraform v1.15.8",
  "ignored": 0,
  "duration_seconds": 3.4,
  "findings": [ ]
}
```

| `status` | Meaning |
|---|---|
| `clean` | Scanned, no drift. |
| `drifted` | Scanned, drift found. |
| `failed` | **Could not be scanned. Not known to be clean.** |

`error` is set only when `status` is `failed`, and is already scrubbed of
account IDs. `path` is relative to the scan root.

A `failed` stack has an empty `findings` array. **Do not read that as "no
problems here."** It means nothing was read.

## `findings`

The top-level `findings` array holds everything at or above
`min_severity`, across all stacks, most severe first. Each stack's own
`findings` array holds its own, unfiltered by the threshold — so the top
level is what to report and the per-stack lists are the full picture.

```json
{
  "id": "infra/prod/network::aws_security_group.api",
  "stack": "infra/prod/network",
  "address": "aws_security_group.api",
  "resource_type": "aws_security_group",
  "provider": "hashicorp/aws",
  "region": "eu-west-1",
  "drift_kind": "changed",
  "severity": "critical",
  "severity_rule": "sg-ingress-public",
  "severity_reason": "An inbound security group rule now accepts traffic from the whole internet.",
  "recommendation": "revert",
  "recommendation_reason": "Revert unless this was a deliberate, reviewed change.",
  "changes": [ ],
  "attribution": { },
  "cost": null
}
```

| Key | Type | Notes |
|---|---|---|
| `id` | string | `<stack>::<address>`. Stable across runs, so two reports can be diffed to see what was actually dealt with. |
| `address` | string | The Terraform address, verbatim — including `[0]`, `["key"]` and any `module.foo.` prefix. What you grep for. |
| `resource_type` | string | `aws_security_group`. Identical under Terraform and OpenTofu. |
| `provider` | string \| null | `hashicorp/aws`. The registry host is stripped, since it differs between the two tools for identical providers. |
| `region` | string \| null | Derived from an ARN in the state where possible. |
| `drift_kind` | string | `changed`, `deleted` or `replaced`. |
| `severity` | string | `critical`, `high`, `medium` or `low`. |
| `severity_rule` | string | The rule id from `severity.yml` that scored it. Always present. |
| `recommendation` | string | `revert`, `update_code` or `investigate`. Crosswind never performs any of them. |

`drift_kind: deleted` means the refresh could not find the resource, so it
has dropped out of state — **not** that Terraform wants to delete anything.

### `changes`

One entry per attribute that differs. A `deleted` resource has a single
synthetic entry with `path: "(resource)"`, because "the thing is gone" is one
fact rather than forty.

```json
{
  "path": "ingress.0.cidr_blocks.0",
  "before": "10.0.0.0/8",
  "after": "0.0.0.0/0",
  "redacted": false,
  "provider_sensitive": false
}
```

| Key | Type | Notes |
|---|---|---|
| `path` | string | Dotted path. List elements are indexed by position. |
| `before` | any \| null | What state said. Scalars pass through; containers are summarised as `"(3 items)"`. |
| `after` | any \| null | What the provider found. |
| `redacted` | boolean | We changed the value — a secret, a truncation, or a summarised container. |
| `provider_sensitive` | boolean | The *provider* marked this sensitive, as opposed to our name matching catching it. |

A redacted value is the string `"(sensitive value)"`. Both flags are exposed
because they mean different things: `provider_sensitive` is a promise from
the provider author, `redacted` alone is our guess from the attribute name.

**Values are truncated at 200 characters** and `user_data` is never included
at all, only its length. Do not build anything that needs the full value —
the JSON export is a report, not a state dump.

### `attribution`

```json
{
  "confidence": "high",
  "actor": "dmitri",
  "reason": null,
  "score": 0.94,
  "event": {
    "event_id": "7f3c1e8a-4b2d-4c6f-9a1e-2d5b8c0a3f71",
    "event_name": "AuthorizeSecurityGroupIngress",
    "event_time": "2026-11-02T19:29:00+00:00",
    "username": "dmitri",
    "event_source": "ec2.amazonaws.com",
    "region": "eu-west-1",
    "principal_type": "AssumedRole",
    "resources": [
      { "type": "AWS::EC2::SecurityGroup", "name": "sg-0demo0api0000001" }
    ],
    "read_only": false
  }
}
```

| `confidence` | Meaning |
|---|---|
| `high` | Exact resource match **and** an event name expected for the attribute that changed. |
| `medium` | Exact resource match, but not an expected event name. |
| `low` | Cleared the floor on something else. |
| `unknown` | No answer. `actor` and `event` are `null`, and `reason` says why. |

**When `confidence` is `unknown`, `actor` is always `null`.** There is no code
path that produces a name without an event. Branch on `confidence`, not on
whether `actor` is truthy.

`reason` values, for when you want to branch on *why*:

| `reason` | Meaning |
|---|---|
| `no_matching_events` | CloudTrail answered, with nothing that fits. |
| `unmapped_resource_type` | No mapping for this resource type yet. A to-do, not a limit. |
| `no_lookup_value` | State had no identifier CloudTrail would know. |
| `outside_cloudtrail_retention` | Older than 90 days. |
| `below_confidence_floor` | Candidates existed, none convincing. |
| `attribution_disabled` / `not_attempted` | `--no-attribution`, or no credentials. |
| `lookup_denied` | No `cloudtrail:LookupEvents` permission. |
| `credentials_expired` / `credentials_invalid` | What it says. |
| `throttled` | CloudTrail rate-limited past the retry budget. Re-running usually attributes more. |
| `lookup_failed` | Something else. |

`username` is copied from CloudTrail exactly, not normalised — it can be an
IAM user, a role session name, or `AWSService`. `score` is the internal
ranking value, exposed for debugging; don't build thresholds on it, because
`confidence` is the stable contract and the weights may change.

### `cost`

`null` far more often than not, and that is the normal case.

```json
{
  "monthly_usd": 75.19,
  "annual_usd": 902.28,
  "basis": "db.m5.large at $0.1710/hour versus db.t3.medium at $0.0680/hour, over 730 hours: ... This is an upper bound - Savings Plans, Reserved Instances and Spot all make it lower."
}
```

A figure appears only where the attribute has an unambiguous price and both
values are in the static table. `basis` is a sentence someone can check with
a calculator, and always says the number is an upper bound. If you render
`monthly_usd`, render `basis` with it — a number without its arithmetic is a
number nobody can check.

## Diffing two runs

`id` is stable, so:

```python
import json


def load(path):
    with open(path) as handle:
        report = json.load(handle)
    return {item["id"]: item for item in report["findings"]}


before, after = load("monday.json"), load("friday.json")

print("fixed:    ", sorted(before.keys() - after.keys()))
print("new:      ", sorted(after.keys() - before.keys()))
print("remaining:", sorted(before.keys() & after.keys()))
```

Before trusting "fixed", check `summary.stacks_failed` in the later run. A
finding that disappears because its stack stopped being scannable has not
been fixed.

## Exit codes

`summary.exit_code` repeats the process exit code, so a consumer reading only
the file knows what the process returned.

| Code | Meaning |
|---|---|
| 0 | No drift at or above `min_severity` |
| 1 | Drift found at or above `min_severity` |
| 2 | A stack could not be checked, or the tool failed |
