# Threat model

What Crosswind can and cannot be made to do, who has to be trusted, and the
places where the honest answer is "this is not protected".

[`SECURITY.md`](../SECURITY.md) is the policy and the reporting process. This
is the reasoning.

## What Crosswind handles

| Asset | Sensitivity |
|---|---|
| Terraform state | **Highest.** Every attribute of every managed resource, including plaintext secrets providers chose to store |
| Plan files | Same as state — a plan file *is* the prior state |
| AWS credentials | Never touched directly; resolved by the SDK |
| CloudTrail events | Who did what, when |
| Reports | Describe your infrastructure; values redacted, structure not |

## Who has to be trusted

**Trusted:**

- The Terraform/OpenTofu binary on your `PATH`
- Your Terraform configuration and its providers — see
  [the big caveat](#the-big-caveat-plan-executes-your-configuration)
- Whoever can write to the repository being scanned
- The AWS credentials you provide

**Not trusted, and defended against:**

- `.crosswind.yml` and `.crosswindignore` contents, as *data*
- Attribute values from state, including names and tags
- CloudTrail event contents
- Terraform's stdout and stderr

**Out of scope:**

- An attacker who already has your credentials
- An attacker who can modify the Crosswind installation
- AWS itself, or a compromised provider

## Attacker scenarios

### Someone commits a malicious `.crosswind.yml`

The config file comes from the repository being scanned, so it is attacker-
controlled in any repo where a PR can change it.

| Attempt | Outcome |
|---|---|
| `binary: /tmp/evil` | **Rejected.** A path in `binary` is refused; only a bare command name is accepted. A path has to come from `--binary` on the command line, which is your decision made outside the repo. |
| `when: os.system("...")` | **Rejected.** The predicate vocabulary is closed. An unknown predicate fails to load, loudly. |
| Mis-scoring a finding to `low` | **Possible.** This is the residual risk, and it is accepted. |
| `output_dir: /etc` | Writes fail on permissions. Crosswind writes only the report files you asked for, named `crosswind-report.*`. |
| A YAML bomb | `yaml.safe_load`, so no arbitrary object construction. A deeply nested document can consume memory; the failure mode is a crash, not execution. |

The mis-scoring risk is why severity is never the only signal: the raw
`changes` are in the report regardless, and `severity_rule` names the rule
that scored it — so an override hiding something is visible to anyone reading
the finding.

### Someone puts markup in a resource name or tag

Perfectly possible — tags are free text.

- **HTML**: every interpolated value goes through `html.escape(quote=True)`.
  Tested with `"><img src=x onerror=alert(1)>` as a tag value and
  `<script>alert(1)</script>` in an address, asserting no tag survives as
  markup.
- **Markdown**: pipes, backticks and angle brackets escaped — a GitHub
  comment renders HTML, and an unescaped pipe also breaks the table.
- **JSON**: `json.dumps` handles it.
- **Terminal**: ASCII-only output and no ANSI pass-through, so no escape
  sequence injection.

### Terraform's error output contains something sensitive

Terraform error text quotes configuration and occasionally values, and it is
the one string in a report that Crosswind did not construct. It is scrubbed:
account IDs replaced, truncated to the first twelve lines and 4000
characters. The end-to-end tests assert seeded secrets do not appear in a
failed stack's error text.

### Crosswind is interrupted mid-scan

A plain-text copy of state surviving in `/tmp` is the worst realistic
outcome, so there are four layers:

1. `finally` in the workspace context manager
2. An `atexit` hook
3. `SIGINT` and `SIGTERM` handlers — needed because the default `SIGTERM`
   disposition kills the process without running `atexit`
4. The directory is `0700` and each file `0600` in the meantime

The signal handlers chain to whatever was installed before, and re-raise, so
a caller embedding Crosswind keeps its own behaviour and the right exit
status.

One bug worth recording because it was real: the handler installation
originally marked itself done *before* attempting to install, and
`signal.signal` raises off the main thread. Since a scan creates workspaces
from worker threads, a worker getting there first meant the handlers were
never installed at all — on exactly the path they exist for. Now the flag is
only set on success, `scan()` installs them on the main thread before
starting its pool, and a test pins the ordering.

### An attacker reads a report

A report names your stacks, resources, regions and layout. Values are
redacted; **structure is not**, and structure is intelligence.

Mitigations are mostly yours: the Action's artifact retention defaults to 14
days, `.gitignore` covers `reports/` and `crosswind-report-*`, and the HTML
has no external references so opening it does not tell anyone that you did.
Treat a report like any internal document.

### A malicious CloudTrail event

CloudTrail content is attacker-influenced if an attacker can cause API calls
with chosen names — a role session name, for instance.

Event text is escaped like any other value, and the event ID travels with
every name so a reader can verify independently. Crosswind does not act on
event contents; it displays them.

## The big caveat: `plan` executes your configuration

**This is the limitation that matters most, and no amount of care in
Crosswind fixes it.**

`terraform plan` is not a parser. It evaluates expressions, instantiates
providers, and runs provider code. A configuration can:

- Use an `external` data source, which **executes a program** and is designed
  to
- Specify a provider from any registry, which is a downloaded binary that
  runs with your privileges
- Read local files through `file()` and the `local` provider

Crosswind cannot sandbox any of this. It is Terraform's execution model, and
a tool that runs `plan` inherits it entirely.

**Scan only configurations you trust, with read-only credentials.**

Two consequences worth being explicit about:

- A malicious Terraform configuration can do anything your credentials allow,
  with or without Crosswind. Running `plan` on untrusted Terraform is the
  risk; Crosswind is incidental to it.
- Scanning a repository where untrusted contributors can change `.tf` files —
  a public repo taking PRs — means running their code. Use a scheduled scan
  on a trusted branch rather than a PR-triggered one, which is why the
  shipped OIDC trust policy pins to a branch.

## Why the working tree is read-only

Not only politeness. If Crosswind wrote to the tree it would:

- Modify `.terraform.lock.hcl`, a committed file, creating spurious diffs and
  possibly changing provider versions for everyone
- Need write access to a directory that may be a mounted repository
- Risk leaving a plan file — a plaintext copy of state — somewhere a
  `git add -A` would catch it

So: `TF_DATA_DIR` into a private temp directory, `init -lockfile=readonly`,
and plan files outside the tree. Verified by hashing every file in a real
stack before and after a scan, not by assertion.

The cost is real and accepted: a stack with no committed lock file cannot be
scanned, and is reported as "could not check" with the fix named.

## Why the Terraform wrapper is shaped the way it is

An **allowlist** of five subcommands, not a denylist of dangerous ones. A
denylist is a bet that you enumerated every current and future dangerous
subcommand. An allowlist means a subcommand added by a future Terraform
release is refused by default, and the worst case is a feature we have to
add deliberately.

`tests/test_safety.py` asserts structural properties rather than behaviour:
`subprocess` is imported in exactly one module, no `os.system`/`exec`/`popen`
appears anywhere, and no write subcommand exists as a string literal outside
the module that refuses it. The risk being defended against is not the first
code path changing — it is a *second* one appearing.

## Why `unknown` names nobody

Attribution is the most quotable output, and a wrong name is the most
expensive mistake available. "Dmitri opened the security group" is a sentence
with consequences.

So `Attribution.unknown()` is the only constructor that omits an event, and
it forces `actor` to `None`. Confidence is a statement about which evidence
exists rather than a threshold on a score, because a score threshold lets
three weak signals add up to a confident wrong answer.

We could attribute on weaker evidence and produce a name most of the time.
The remaining fraction would be wrong, in a document that gets forwarded.

## Residual risks

Accepted, and listed so nobody is surprised:

| Risk | Why accepted |
|---|---|
| A malicious configuration can execute code via `plan` | Inherent to Terraform. Documented prominently. |
| A malicious `.crosswind.yml` can mis-score a finding | Bounded: the raw diff is still shown and the rule is named. |
| A report leaks infrastructure structure | Inherent to the product. Short artifact retention, `.gitignore` entries. |
| The refresh IAM policy is broad | Inherent to refreshing. [`iam/README.md`](../iam/README.md) documents what it can read and how to narrow it. |
| `cloudtrail:LookupEvents` cannot be resource-scoped | AWS does not support it. `--no-attribution` is the alternative. |
| A set-typed attribute can read as drift | Position-based diffing. The alternatives are worse; `.crosswindignore` is the workaround. |
| A provider could leak a secret in an unmarked, oddly-named attribute | Two redaction layers, neither perfect. Truncation at 200 chars limits the blast radius. |

## What would be a vulnerability

Please report these (see [`SECURITY.md`](../SECURITY.md)):

- Any way to make Crosswind invoke a Terraform write operation
- Any way to make it modify the working tree, state, or lock file
- A sensitive value reaching any output, log line, or error message
- Credentials written to disk or transmitted anywhere
- A plan file surviving a scan, a crash, or a signal
- **A stack that failed to scan being reported as clean** — a security issue,
  not a cosmetic one, because the entire value of the tool is that a clean
  report means something
