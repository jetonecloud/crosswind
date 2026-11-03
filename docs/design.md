# Design

This is the architecture, and the decisions behind it. It was written before
the code and updated as things were learned, so where a decision turned out to
be wrong the reasoning for the replacement is here too.

## The problem

Terraform knows what your infrastructure is supposed to look like. AWS knows
what it actually looks like. When those disagree, somebody changed something
outside Terraform — a console click during an incident, a script, another
tool — and the next `terraform apply` will quietly revert it, or fail.

`terraform plan -refresh-only` already tells you *that* something changed. It
doesn't tell you who changed it, whether it matters, or what to do about it.
Crosswind is the layer on top: attribution from CloudTrail, severity from a
rule set you can read, and a recommendation per finding.

## Shape of the thing

```
crosswind scan
      |
      +-- discover stacks            core/discover.py
      +-- for each stack (threads)   core/scan.py
      |      |
      |      +-- terraform init -lockfile=readonly   core/terraform.py
      |      +-- terraform plan -refresh-only -out=<private tmp>
      |      +-- terraform show -json <plan>
      |      +-- parse resource_drift                core/plan.py
      |      +-- redact                              core/redact.py
      |      +-- apply ignore rules                  core/ignore.py
      |      +-- score severity                      core/severity.py
      |      +-- attach cost estimate                core/cost.py
      |
      +-- attribute findings (CloudTrail)   core/attribution/
      +-- render                            core/report/
```

One pass, no daemon, no state of its own. A scan reads, decides, prints, and
exits.

## What Terraform actually emits

Everything below was generated locally against Terraform v1.15.8 and OpenTofu
v1.13.2 using the `local` and `null` providers, not recalled from memory. The
captured output is in [`tests/fixtures/plans/`](../tests/fixtures/plans/) and
is what the parser tests run against.

| | Terraform 1.15.8 | OpenTofu 1.13.2 |
|---|---|---|
| Plan JSON `format_version` | `1.2` | `1.2` |
| Drift lives in | `resource_drift` | `resource_drift` |
| Key present when there is no drift | **no — absent entirely** | **no — absent entirely** |
| Extra top-level keys | `applyable`, `complete`, `prior_state` | `prior_state` |
| `provider_name` host | `registry.terraform.io/...` | `registry.opentofu.org/...` |
| `plan -detailed-exitcode` with drift | `2` | `2` |

A `resource_drift` entry:

```json
{
  "address": "local_file.config",
  "mode": "managed",
  "type": "local_file",
  "name": "config",
  "provider_name": "registry.terraform.io/hashicorp/local",
  "change": {
    "actions": ["delete"],
    "before": { "content": "...", "filename": "./out/config.json" },
    "after": null,
    "after_unknown": {},
    "before_sensitive": { "content": true },
    "after_sensitive": false
  }
}
```

Decisions that fell out of reading real output:

- **`resource_drift` is absent, not empty, when a stack is clean.** The parser
  uses `.get("resource_drift", [])`. Treating a missing key as an error would
  have made every clean stack a failure; treating a failure as a missing key
  would have made every broken stack look clean, which is the one thing the
  tool must never do.
- **Sensitive markers are not a flat list of names.** `before_sensitive` is
  either a boolean or a structure mirroring the value — `{"content": true}`
  for an object, `[false, true]` for a list. Redaction walks the value and the
  marker together rather than looking attributes up by name. See
  [Redaction](#redaction).
- **Key on `type`, never on `provider_name`.** The same AWS resource is
  `registry.terraform.io/hashicorp/aws` under Terraform and
  `registry.opentofu.org/hashicorp/aws` under OpenTofu. Every mapping and
  severity rule keys on `type` (`aws_security_group`), which is identical
  across both.
- **`index` is an `int` for `count` and a `str` for `for_each`**, and
  `module_address` appears only for resources inside a module. Addresses are
  carried through verbatim as the finding's identity, because the address is
  what a user greps for in their own code.
- **A modified file is reported by the `local` provider as `delete`, not
  `update`.** That provider's `Read` compares a checksum and drops the
  resource from state on any mismatch. It is real drift and good enough for
  end-to-end tests, but it means the local providers cannot produce an
  `update` action. The real `update` change object used to validate the parser
  was captured from a normal (non-refresh) plan, where the change
  representation is the identical schema — see
  `terraform-1.15.8-update-change.json`. This is the one place where the AWS
  fixtures are hand-authored rather than generated, and they are authored to
  match that verified schema exactly.

## Safety

The hard requirement is that Crosswind can never write. Three layers, because
one is a promise and three is a design.

**1. One wrapper, one allowlist.** Every invocation of `terraform`/`tofu` goes
through `core/terraform.py`. The subcommand is checked against
`ALLOWED_SUBCOMMANDS = {"version", "init", "providers", "plan", "show"}` and
anything else raises `ForbiddenSubcommand` before a process is spawned. There
is no second code path that builds an argv — a test asserts that the only
`subprocess` call in the package is the one inside the wrapper. `plan` is
additionally checked to carry `-refresh-only`, and the argv is scanned for
apply-ish flags (`-auto-approve`, `-destroy`).

**2. Flags that make writing impossible.** `-refresh-only` (a plan that
proposes state changes rather than resource changes), `-lock=false` (never
takes a state lock, so it can never leave a stale one), `-input=false` (never
blocks on a prompt in CI).

**3. The working tree is read-only in practice.** Verified by experiment:

- `TF_DATA_DIR` pointed at a private temp directory relocates `.terraform/`
  entirely. Nothing is written to the user's.
- `init -lockfile=readonly` leaves `.terraform.lock.hcl` byte-identical. If no
  lock file exists, `init` fails cleanly without writing one — Crosswind
  reports that stack as "could not check" and says to run `terraform init`
  once itself. Creating a lock file on the user's behalf would be a write to
  the tree, so we don't.
- `plan -refresh-only` does not write state and does not create
  `terraform.tfstate.backup`. Confirmed by hashing before and after.

**Plan files.** A plan file contains the full prior state, which means
credentials, private keys, and everything else a provider stashed in an
attribute. They are written into a per-run directory created with
`mkdtemp(mode=0o700)`, `chmod 0600` on each file (Terraform creates them
`0644`), and deleted in a `finally` plus an `atexit` hook plus `SIGINT`/
`SIGTERM` handlers. The directory is never inside the user's stack.

**What this does not protect against**, stated plainly here and in the threat
model: `plan` runs provider code and evaluates the configuration, including
`external` data sources and provisioner-adjacent constructs that execute
programs. Crosswind cannot sandbox that. Scan code you trust, with read-only
credentials.

## Parsing and the finding model

`core/plan.py` turns a `resource_drift` entry into a `DriftedResource` holding
an ordered list of `AttributeChange(path, before, after, sensitive)`.

- `before`/`after` are flattened to dotted paths (`ingress.0.cidr_blocks.1`)
  so that rules and reports can talk about one attribute rather than a blob.
- Attributes whose before and after are equal are dropped. Terraform includes
  the whole object in `before`; only the differences are drift.
- A `delete` action (`after: null`) becomes a single synthetic change with
  `after = None` and a `resource_deleted` marker, rather than one change per
  attribute. "The thing is gone" is one fact, not forty.
- Computed-only attribute noise (`content_sha1`, `content_md5`, …) is not
  special-cased in the parser. Suppressing it is the ignore file's job, which
  keeps the parser honest and the suppression visible to the user.

## Redaction

Two layers, because provider authors forget to mark things.

1. **Terraform's own markers.** The `before_sensitive`/`after_sensitive`
   structure is walked in lockstep with the value. Anything marked is replaced
   with `"(sensitive value)"` before it reaches a `Finding`.
2. **Name-based.** An attribute path matching `password`, `secret`, `token`,
   `private_key`, `credential`, `passwd`, `api_key`, `access_key`,
   `session_key`, `certificate`, `salt`, or `signature` (case-insensitive,
   substring) is redacted regardless of markers.

Redaction happens at the boundary between the parser and the model, not at the
boundary between the model and each renderer. A renderer cannot leak what was
never put in the object, and that is one place to audit rather than four. The
secret-leak tests seed known values into a plan fixture and assert the string
appears in none of the four output formats, nor in logs.

Values are also truncated to 200 characters. A 4 KB user-data blob in a diff
is not useful to a reader and is a good way to leak something nobody marked.

## Severity

Rules live in [`src/crosswind/data/severity.yml`](../src/crosswind/data/severity.yml),
not in code, so a contributor can add one without touching the engine. A rule
matches on resource `type` (glob), attribute `path` (glob), and optionally a
`when` predicate from a small fixed vocabulary (`became_public`,
`widened_cidr`, `encryption_disabled`, `iam_widened`, `became_larger`,
`any_change`). The vocabulary is fixed deliberately: an arbitrary expression
language in a severity file is a way to ship a sandbox escape in a YAML file.

Every finding carries `severity_rule` — the id of the rule that set it — and
the report shows it. A severity nobody can trace to a rule is a severity
nobody will believe. Where no rule matches, the default is `low` from the rule
`default`, which is also in the file.

Per-project overrides go in `.crosswind.yml` under `severity:`. They are
merged by rule id, so a project can raise or lower a shipped rule, or add its
own, without vendoring the whole file.

## Ignore rules

`.crosswindignore` is line-based, `#` comments, each line
`<address glob> [attribute glob]`. Discovered next to the stack or at the repo
root. A shipped default list covers the drift that is expected by design —
`aws_autoscaling_group desired_capacity`, `aws_ecs_service desired_count` —
but it is **suggested, not applied**: `crosswind scan` writes nothing, so the
defaults live in `docs/` and in a `--print-default-ignores` output for the
user to paste. Silently ignoring findings a user never opted out of is the
same failure mode as reporting a broken stack as clean.

Ignored findings are counted and shown as a one-line total, never dropped
without trace.

## Attribution

CloudTrail `LookupEvents`, and its limits drive the whole design:

- **Management events only.** Data-plane changes (an S3 object write) are
  invisible. Said in the report, not just the docs.
- **90 days.** Drift older than the retention window attributes to `unknown`
  with reason `outside_cloudtrail_retention`.
- **Regional, except global services.** IAM, Route 53, CloudFront and STS log
  to `us-east-1` regardless of where you are. The mapping file carries a
  `global: true` flag per resource type and the lookup is routed accordingly.
- **Hard rate limits.** `LookupEvents` is about 2 requests/second per account
  per region. Requests are serialised through a token bucket, retried with
  exponential backoff and jitter on `ThrottlingException`, and every lookup is
  cached by `(region, attribute, value, window)` for the life of the run.

Mappings live in
[`src/crosswind/data/cloudtrail.yml`](../src/crosswind/data/cloudtrail.yml):
per Terraform resource type, the CloudTrail `ResourceType`, how to derive the
lookup value from the drifted resource's attributes, whether the service is
global, and the event names that plausibly cause each kind of change.

Ranking. Candidates get a score from three signals, and the best one wins only
if it clears a floor:

| Signal | Weight |
|---|---|
| CloudTrail resource name/ARN matches the drifted resource exactly | 0.5 |
| Event name is one the mapping associates with the changed attribute | 0.3 |
| Event is recent relative to the lookup window | 0.2 |

`high` confidence needs an exact resource match *and* an expected event name.
`medium` is an exact resource match alone. `low` is anything else that clears
the floor. Below the floor, or no events at all, is `unknown` — and `unknown`
names no person. Every attributed finding carries the event ID, event name,
event time, and the principal exactly as CloudTrail recorded it, so a reader
can go and look it up themselves.

A CloudTrail failure — no permission, throttled past the retry budget, region
unavailable — degrades that finding to `unknown` with the reason attached. It
never fails the scan. Drift reporting is the product; attribution is the
bonus.

## Cost

Conservative or absent. An estimate is only attached where the change has an
unambiguous price attached to it (an instance type change, a storage size
change), uses us-east-1 on-demand list prices from a static table, and carries
a `basis` sentence a reader can check with a calculator. Where the number
would depend on utilisation, data transfer, or a commitment we can't see, no
figure is shown at all. A wrong dollar figure in a report to a manager is
worse than no dollar figure.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No drift at or above `--min-severity` |
| 1 | Drift found at or above `--min-severity` |
| 2 | A stack could not be checked, or the tool itself failed |

2 beats 1. If a stack failed *and* drift was found, the exit code is 2 and the
report is still written, with the failed stacks listed as "could not check".
A stack that could not be scanned is never rendered as clean — the summary
counts it separately and the terminal output says so in the first three lines.

## Output

Four renderers over one `Report` object, all pure functions of it.

- **Terminal.** Rich, ordered by severity. A summary a person reads in ten
  seconds and then decides whether to open the HTML.
- **JSON.** Versioned (`schema_version`), documented in
  [`docs/json-schema.md`](json-schema.md). The contract for anything
  programmatic. Additive changes bump the minor, breaking ones the major.
- **Markdown.** Sized for a PR comment and a GitHub job summary, which means
  no ANSI, collapsible sections for detail, and a table that renders on
  GitHub.
- **HTML.** One file, no external assets, no fetches when opened. Same teal
  and the same severity colours as Preflight's PDF, because it goes to the
  same reader — a manager who did not run the tool.

## What is deliberately not here

Auto-remediation, a watch mode, a server, a dashboard, Slack, other clouds,
and discovery of resources Terraform doesn't manage. The last one is the most
commonly requested and the most misleading in a v1: finding "unmanaged"
resources well needs per-service enumeration across every region, and a bad
version of it produces a list of things that are fine.
