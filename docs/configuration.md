# Configuration

Three files, all optional, all read from the repository you are scanning.

| File | What it does |
|---|---|
| `.crosswind.yml` | Settings and severity overrides |
| `.crosswindignore` | Drift you have already decided about |
| `.terraform.lock.hcl` | Not ours, but required — see [installation](installation.md) |

Precedence, most important first: **a command-line flag**, then **the config
file**, then **the built-in default**. A flag you did not pass is "not
specified" rather than "specified as the default", so a default-valued flag
never silently overwrites something you put in the config on purpose.

## `.crosswind.yml`

Found by walking up from `--path` to the filesystem root, so a monorepo keeps
one file at the top rather than one per stack. `--config` points at a
specific file. `.crosswind.yaml` works too.

```yaml
version: 1

# Hide findings below this, and exit 0 if nothing reaches it.
# critical | high | medium | low. Default: low.
min_severity: medium

# Stacks to scan at once. Default: 4.
concurrency: 8

# Default output formats. terminal | json | markdown | html.
formats: [terminal, html]

# Where file formats are written. Default: the working directory.
output_dir: reports

# Set false to skip CloudTrail entirely. Default: true.
attribution: true

# How far back to look for a CloudTrail event, in hours. Default: 336 (14
# days). Clamped to CloudTrail's 90-day retention, because asking for more
# is a slower way to get the same answer.
cloudtrail_window_hours: 336

# Directories or globs never to scan. Added to the built-in list
# (.git, .terraform, node_modules, .venv and so on), not replacing it.
exclude:
  - examples
  - "infra/legacy/*"

# Passed to Terraform as -var-file.
var_files:
  - shared.tfvars

# AWS region for CloudTrail lookups. Global services still go to us-east-1.
region: eu-west-1

# terraform or tofu. A *name*, not a path — see the note below.
binary: tofu

# Severity rule overrides. See below.
severity: []
```

Unknown keys produce a warning that appears in the report rather than being
ignored, because a misspelled key is a setting someone believes is in effect.

### `binary` must be a name, not a path

```yaml
binary: tofu              # fine
binary: /opt/bin/tofu     # rejected
```

This file comes from the repository being scanned, which makes it untrusted
input. Letting it name an executable by path would let a scanned repo choose
what Crosswind runs. Use `--binary` on the command line if you need to point
at a specific executable — that is your decision, made outside the repo.

## Severity overrides

Rules are merged by `id`. An override with an id that already exists replaces
that rule **in place**, keeping its position in the evaluation order, so you
can soften or sharpen a shipped rule without restating the other twenty-two.
An override with a new id goes **in front of** everything shipped, because a
project-specific rule is more specific than anything general we wrote.

```yaml
severity:
  # We bill by tag, so a missing tag is not a shrug.
  - id: tags-only-change
    severity: medium
    reason: >
      Tags differ from the code. We allocate cost by tag, so this affects
      the monthly report.
    types: ["*"]
    paths: ["tags.*"]
    recommend: update_code
    recommend_reason: Put the tag in the code so it stops drifting back.

  # The bastion is not allowed to change at all.
  - id: bastion-is-frozen
    severity: critical
    reason: The bastion host is change-controlled. Any difference is an incident.
    types: ["aws_instance"]
    paths: ["*"]
    recommend: revert
    recommend_reason: Revert, then ask the platform team.
```

The full field reference and the closed predicate vocabulary are in
[`severity-rules.md`](severity-rules.md). The vocabulary is closed on purpose:
an expression language in a file loaded from a scanned repository would be
remote code execution with extra steps.

A rule that fails to load — unknown severity, unknown predicate, no `id` — is
a hard error rather than a warning. A rule set we half-understood would
produce severities nobody could explain.

## `.crosswindignore`

Line-based, `#` for comments, shaped like `.gitignore` because everybody
already knows how that works.

```
# <address glob> [attribute glob]

# Autoscaling is supposed to change these.
*                              desired_capacity
aws_ecs_service.*              desired_count

# Set by our deploy pipeline, not by Terraform.
aws_ecs_service.*              task_definition
aws_lambda_function.*          source_code_hash

# The whole module. No attribute means the whole resource.
module.legacy.*
```

The first field is a glob against the **resource address** — the thing you
would grep for in your own code, including `[0]` and `["key"]` suffixes and
any `module.foo.` prefix. The optional second is a glob against the
**dotted attribute path** as it appears in a report, like
`ingress.0.cidr_blocks.1`.

- An address-only line suppresses the whole resource.
- With an attribute, only matching attributes are dropped — and if the
  resource has *other* drift it is still reported. An ignored
  `desired_capacity` does not hide a changed `min_size` on the same group.
- A resource whose every attribute is matched disappears, because there would
  be nothing left to show. It still counts towards the suppressed total.

Looked for in the stack directory and at the scan root, and patterns from
both apply together. There is no negation syntax, deliberately — the `!`
rules in `.gitignore` are the part nobody can remember.

A malformed line is skipped rather than failing the scan. The consequence of
ignoring a bad line is that a finding appears, which is the safe direction;
the consequence of failing is that nobody sees any findings.

### Suppressed findings are counted, never silently dropped

Every report shows the total:

```
7 findings: 3 critical, 3 medium, 1 low
  3 of 5 stacks have drift.
  2 suppressed by .crosswindignore.
```

That is the point. Hiding findings without saying how many is the same
failure as calling a broken stack clean: a reader believes they have seen
everything.

### Getting a starting file

```sh
crosswind scan --print-default-ignores > .crosswindignore
```

That prints a suggested file covering drift that is expected by design, for
you to read and commit. **It is not applied until you do.** Crosswind writes
nothing to your repository, and applying a built-in ignore list would mean
silently hiding findings you never opted out of.

Pair each ignore with a `lifecycle { ignore_changes = [...] }` in the
Terraform itself, or the next apply will fight whatever is changing it.

## Ignore vs. severity: which to use

A useful distinction, and getting it wrong is how a report becomes noise:

- **`.crosswindignore`** is for drift that is *expected*. An autoscaling
  group's current capacity differing from the code is not a problem, it is
  what autoscaling does.
- **A severity override** is for drift that matters *less* than we scored it.
  You still want to see it; you just don't want it at the top.

If you find yourself ignoring something because it is noisy rather than
expected, a severity override is usually the better answer — and if a shipped
rule is wrong for everyone rather than just for you,
[open an issue](https://github.com/jetonecloud/crosswind/issues).

## Everything as flags

Every setting has a flag, for CI and for one-off runs:

```sh
crosswind scan \
  --path infra \
  --min-severity high \
  --concurrency 8 \
  --format markdown --format html \
  --output-dir reports \
  --exclude examples \
  --exclude 'infra/legacy/*' \
  --var-file shared.tfvars \
  --region eu-west-1 \
  --binary tofu \
  --role-arn arn:aws:iam::111111111111:role/CrosswindReadOnlyRole
```

`--format` and `--exclude` and `--var-file` are repeatable. `--exclude` adds
to whatever the config file set rather than replacing it, so a team's shared
excludes don't vanish because someone added one of their own.
