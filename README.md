# Crosswind

Crosswind is a command-line tool that finds the changes somebody made to your
infrastructure outside Terraform, works out who made them and when, and tells
you whether each one matters. It reads your state, reads CloudTrail, and
prints you a report you can read, diff, or send to the person who needs to
make a decision about it.

It is read-only by construction and open source (Apache-2.0). It cannot run
`apply`, it cannot write to your state, and it does not touch your working
tree.

## Getting started

```sh
pipx install crosswind
crosswind demo     # see what a report looks like, no account needed
```

`uv tool install crosswind` and Docker work too — see
[`docs/installation.md`](docs/installation.md). You need Terraform or OpenTofu
on your `PATH`; Crosswind drives whichever it finds and `--binary` picks one.

## Checking a stack

```sh
crosswind doctor --path infra/prod    # is everything in place?
crosswind scan   --path infra/prod
```

`doctor` first. It checks the binary, your credentials, whether the state
backend is readable and whether CloudTrail will answer, and tells you which
of those would fail — in about two seconds, before you wait on a real scan.

Point `--path` at one stack and it scans that stack. Point it at a tree and
it finds the stacks in it, skipping anything that looks like a module rather
than a root. Attribution needs AWS credentials, which Crosswind takes from
the standard chain (`AWS_PROFILE`, SSO, an instance role, `--role-arn`) and
never from a flag you paste a key into.

```sh
crosswind scan --path . --concurrency 8          # a monorepo
crosswind scan --path . --min-severity high      # only what's urgent
crosswind scan --path . --no-attribution         # skip CloudTrail entirely
crosswind scan --path . --exclude examples       # skip a directory
```

No credentials? The drift report still works in full. Every finding will just
say `unknown` where the name would be.

## What you get

Four formats, off one scan, each for a different reader:

```sh
crosswind scan --path . --format terminal                        # the default
crosswind scan --path . --format html --output-dir reports
crosswind scan --path . --format markdown >> "$GITHUB_STEP_SUMMARY"
crosswind scan --path . --format json | jq '.findings[0]'
```

- **Terminal** — ordered by severity, short enough to read in ten seconds.
  Plain ASCII, so it survives a CI log and a ticket.
- **HTML** — one self-contained file for the person who did not run the tool.
  No external assets, no JavaScript, nothing fetched when it's opened.
- **Markdown** — sized for a PR comment or a GitHub job summary.
- **JSON** — a versioned schema, documented in
  [`docs/json-schema.md`](docs/json-schema.md).

Every finding carries the stack, the resource address, the attributes that
differ with their before and after values, a severity with the rule that set
it, who CloudTrail says changed it with the event ID to check, and whether we
think you should revert the change or update the code.

### Sample output

```
crosswind - Terraform drift report
------------------------------------------------------------------------
  terraform v1.15.8  |  account 000000000000  |  5 stacks  |  9.0s

COULD NOT CHECK 1 STACK
  These were not scanned. They are not known to be clean.

  ! infra/legacy/billing
      Error: Failed to get existing workspaces: S3 bucket does not exist.

------------------------------------------------------------------------

7 findings: 3 critical, 3 medium, 1 low
  3 of 5 stacks have drift.
  2 suppressed by .crosswindignore.

------------------------------------------------------------------------

  [CRITICAL] aws_security_group.api
      stack: infra/prod/network   (changed)
      ingress.0.cidr_blocks.0: 10.0.0.0/8 -> 0.0.0.0/0
      ingress.0.description: internal API traffic -> temp debug - REMOVE
      why: An inbound security group rule now accepts traffic from the whole
           internet. Anything listening on that port is reachable from anywhere.
           [rule: sg-ingress-public]
      who: dmitri via AuthorizeSecurityGroupIngress at 2026-11-02 19:29 UTC
           [high confidence, event 7f3c1e8a-4b2d-4c6f-9a1e-2d5b8c0a3f71]
      do: revert - Revert unless this was a deliberate, reviewed change. If it
          was deliberate, put it in the code with a comment saying why.
```

`crosswind demo` prints that whole report, including the HTML, from bundled
fixtures.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No drift at or above `--min-severity` |
| 1 | Drift found at or above `--min-severity` |
| 2 | A stack could not be checked, or the tool failed |

2 beats 1. If a stack fails *and* drift is found, you get 2 and the report is
still written, with the failed stacks listed as "could not check". A stack
Crosswind could not scan is never shown as clean — see
[Limitations](#limitations).

## Severity and noise

Severity rules live in
[`src/crosswind/data/severity.yml`](src/crosswind/data/severity.yml), which is
a data file you can read and argue with. Public ingress on a security group is
critical; an IAM policy gaining a wildcard is critical; encryption or
public-access changes are high; an instance size change is medium; tags are
low. Every finding names the rule that scored it, so a severity you disagree
with is one you can trace to a line and override in `.crosswind.yml`.

Drift that is expected by design — an autoscaling group's `desired_capacity`,
an ECS service's `desired_count` — belongs in `.crosswindignore`:

```sh
crosswind scan --print-default-ignores > .crosswindignore
```

That prints a suggested file for you to read and commit. It is not applied
until you do: hiding findings nobody opted out of is the same failure as
calling a broken stack clean. Suppressed findings are counted and the total
is shown, so you can always tell "clean" from "quiet".

Dollar figures appear only where the arithmetic is unambiguous — an instance
size, a storage size — and every one shows its working. Where the number would
depend on utilisation or a commitment we can't see, there is no number.
[`docs/severity-rules.md`](docs/severity-rules.md) has the whole rule set.

## In CI

```yaml
- uses: jetonecloud/crosswind@v0
  with:
    path: infra/prod
    role-arn: arn:aws:iam::111111111111:role/CrosswindReadOnlyRole
    aws-region: eu-west-1
    fail-on-drift: false
```

Writes a job summary, uploads the reports as an artifact, and authenticates
with OIDC so there is no access key in your repository. A scheduled example is
in
[`examples/workflows/scheduled-drift-check.yml`](examples/workflows/scheduled-drift-check.yml);
the options are in [`docs/github-actions.md`](docs/github-actions.md).

`fail-on-drift: false` is worth considering for a scheduled scan. A check that
goes red every morning is a check people mute. A stack that could not be
checked fails the job regardless, because that is a hole in the report rather
than a finding in it.

## Permissions and your data

Three separate things, of very different sizes:

- **Attribution** needs `cloudtrail:LookupEvents` and
  `sts:GetCallerIdentity`. That's it — the only two API calls Crosswind
  itself makes.
- **Reading state** needs `s3:GetObject` and friends on your state bucket,
  and `kms:Decrypt` on its key. Scoped to that bucket and that key, and
  there is no `kms:Encrypt`, because Crosswind reads state and never writes
  it.
- **Refreshing** needs whatever read permissions your providers need, which
  depends on what your stacks manage rather than on anything Crosswind
  decides. The shipped policy is broad: `Describe*`/`Get*`/`List*` across
  common services.

That third one deserves a real conversation rather than a reassuring
sentence, and [`iam/README.md`](iam/README.md) has it — including what the
broad policy can actually read, and how to replace it with a genuinely
minimal one for your estate. Deploy the role from
[`iam/role.cfn.yaml`](iam/role.cfn.yaml) once, or add `LookupEvents` to a
read-only role you already have and pass `--role-arn`.

A scan reads your state, reads CloudTrail, prints the report and writes the
files you asked for. No telemetry, no upload, nothing to opt out of. The only
network traffic is Terraform's and the AWS SDK's, and Crosswind sets
`CHECKPOINT_DISABLE` so it doesn't cause Terraform's version check either.

**Plan files contain secrets.** A plan file holds the entire prior state,
which includes every attribute a provider stored in plain text. Crosswind
writes them into a `0700` temp directory, `chmod 0600`s them, and deletes them
on the way out — including on a failure and on Ctrl-C. Values the provider
marked sensitive never reach a report, and a second layer redacts anything
whose name looks like a secret regardless. [`SECURITY.md`](SECURITY.md) has
the threat model.

## Limitations

Read these before you rely on it.

- **It only checks resources Terraform already manages.** Crosswind compares
  your state to reality. A resource somebody created in the console that
  Terraform has never known about is invisible to it. Finding unmanaged
  resources is a different problem and it is not in v1.
- **Attribution depends on CloudTrail, and CloudTrail has limits.**
  Management events only, so a change made through a data-plane API is not
  recorded. Ninety days of history, so older drift attributes to `unknown`.
  Events take up to about 15 minutes to appear. If there is no matching
  event, Crosswind says `unknown` and names nobody — it will not guess a
  person.
- **AWS is the only cloud with attribution in v1.** Drift detection works for
  any provider Terraform can refresh; the "who" only works for AWS.
- **Read-only depends on the credentials you use.** The design makes
  Crosswind unable to issue a write, and the tests enforce that. But
  `terraform plan` evaluates your configuration and runs your providers, and
  a configuration can contain an `external` data source or a provider that
  does whatever it likes. Crosswind cannot sandbox that. **Scan only code you
  trust, with read-only credentials.**
- **A set-typed attribute can read as drift when nothing changed.** Providers
  return set elements in arbitrary order, and Crosswind diffs by position, so
  a reordered `cidr_blocks` can appear as a change. `.crosswindignore` is the
  workaround.
- **`terraform init` must have been run in the stack already.** Crosswind runs
  `init -lockfile=readonly` so it never writes to your tree, which means a
  stack with no `.terraform.lock.hcl` is reported as "could not check" with
  the fix named rather than being locked on your behalf.
- **HashiCorp's registry and releases are geo-restricted.** In the affected
  regions `registry.terraform.io` returns an error instead of a provider, so
  Terraform cannot initialise a stack at all. OpenTofu has no such
  restriction, which is why the Docker image ships it.

## Contributing

Welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Adding a severity rule or a
CloudTrail resource mapping is a change to a YAML file, not to any code, and
is a good first contribution.

## License

Apache License 2.0, see [`LICENSE`](LICENSE). Attribution for third-party
content is in [`NOTICE`](NOTICE).

## Want help fixing what it finds?

That's what we do at [Jet1](https://jetonecloud.com): deploys, AWS
infrastructure, cost work, and on-call, with an SLA, and you own everything we
build. [Book a 20-minute call](https://jetonecloud.com/book).
