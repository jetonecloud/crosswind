# Security Policy

Crosswind reads your Terraform state and your CloudTrail history. Both are
sensitive, and the tool's only real claim is that it cannot change anything.
Read this before running it against infrastructure you care about.

## Threat model and guarantees

### What is guaranteed by construction

- **Read-only, enforced in one place.** Every invocation of `terraform` or
  `tofu` goes through a single function in
  [`core/terraform.py`](src/crosswind/core/terraform.py) with an allowlist of
  five subcommands: `version`, `init`, `providers`, `plan`, `show`. It is an
  allowlist, not a denylist, so a subcommand added by a future Terraform
  release is refused by default. `apply`, `destroy`, `import`, `state`,
  `taint` and `force-unlock` raise before a process is created.
- **There is only one code path that can start a process.**
  [`tests/test_safety.py`](tests/test_safety.py) asserts that `subprocess` is
  imported in exactly one module, that `os.system`/`os.exec*`/`os.popen` are
  used nowhere, and that no write subcommand appears as a string literal
  outside the module that refuses it. A second route to the same danger
  cannot appear without a test failing.
- **`plan` always means `-refresh-only`.** Enforced in the wrapper, not just
  passed by callers. A refresh-only plan proposes changes to *state*, not to
  resources. `-lock=false` means Crosswind never takes a state lock and so
  can never leave a stale one. Flags that would turn a read into a write
  (`-auto-approve`, `-destroy`, `-migrate-state`, `-target`, `-replace`) are
  refused on every subcommand.
- **Your working tree is not written to.** Verified by experiment, not
  assumed: `TF_DATA_DIR` relocates `.terraform/` into a private temp
  directory, `init -lockfile=readonly` leaves `.terraform.lock.hcl`
  byte-identical, and `plan -refresh-only` writes neither state nor
  `terraform.tfstate.backup`. The end-to-end tests hash every file in the
  stack before and after a scan and assert nothing changed.
- **The IAM policy contains no write action.**
  [`iam/policy.json`](iam/policy.json) is `Get`/`List`/`Describe` plus two
  named exceptions (`cloudtrail:LookupEvents`, `apigateway:GET`).
  [`tests/test_policy.py`](tests/test_policy.py) fails the build on anything
  else, and holds the CloudFormation template to the same bar. There is
  `kms:Decrypt` and deliberately no `kms:Encrypt`.
- **Credentials are never handled directly.** Crosswind uses the standard AWS
  SDK chain — environment, shared config, SSO, instance or task role,
  `assume-role`. There is no flag, prompt or config key that accepts an
  access key, and a test asserts `build_session` has no parameter that could.
  Nothing is written to disk and nothing is transmitted anywhere.
- **Nothing leaves your machine.** A scan reads, decides, prints and writes
  the local files you asked for. No telemetry and no upload. Crosswind also
  sets `CHECKPOINT_DISABLE=1`, so it does not cause Terraform's own version
  check either — the only network traffic is your providers' and the AWS
  SDK's.

### Plan files are the sensitive artefact

A Terraform plan file contains the **entire prior state**: every attribute of
every resource the stack manages, including the ones providers store in plain
text — database passwords, private keys, join tokens. Crosswind needs one for
the few milliseconds between `plan -out` writing it and `show -json` reading
it back.

- Created in a per-run directory from `mkdtemp(mode=0o700)`, which creates
  atomically so there is no window at a wider mode.
- Each file `chmod 0600` on arrival, because Terraform writes them `0644`.
- Never inside your stack directory — a plan file next to your code is one
  `git add -A` from a committed secret.
- Deleted in a `finally`, an `atexit` hook, and `SIGINT`/`SIGTERM` handlers.
  `atexit` alone is not enough: the default `SIGTERM` disposition kills the
  process without running it.

### Secrets in reports

Two layers, because each fails differently:

1. **Terraform's own markers.** The plan JSON carries `before_sensitive` and
   `after_sensitive`, which mirror the *shape* of the value rather than
   listing names, so Crosswind walks them in lockstep with the value. A
   `true` on a parent block means everything beneath it is sensitive.
2. **Name matching.** Any attribute path containing `password`, `secret`,
   `token`, `private_key`, `credential`, `api_key`, `access_key`,
   `ciphertext`, `salt` or `signature` is redacted whatever the markers say.
   This layer exists because provider authors forget.

Redaction happens **once**, at the boundary between the parser and the
finding model — so no renderer can leak what was never put in the object, and
there is one place to audit rather than four. `user_data` and cloud-init
attributes are never shown at all, only their length. Values are truncated at
200 characters.

The end-to-end tests seed two real secrets into a real stack — one through a
provider that marks it sensitive, one in an attribute that is not marked — and
assert neither appears in any of the four output formats.

There is deliberately no `--show-secrets` flag.

### What is *not* guaranteed

This is the part worth reading twice.

- **`terraform plan` executes your configuration.** It evaluates expressions,
  runs provider code, and can run arbitrary programs via an `external` data
  source or a provider that chooses to. Crosswind cannot sandbox any of that
  — it is Terraform's execution model, not ours. **Scan only configurations
  you trust, with read-only credentials.** A malicious Terraform
  configuration can do anything your credentials allow, with or without
  Crosswind.
- **`.crosswind.yml` is read from the repository being scanned**, which makes
  it untrusted input. It can set severities, thresholds and output options. It
  cannot name a Terraform subcommand, cannot point at an executable (a path
  in `binary` is rejected; only a bare command name is accepted), and cannot
  express a predicate outside a closed vocabulary — an expression language in
  a config file loaded from a scanned repo would be remote code execution
  with extra steps.
- **Read-only ultimately depends on the credentials you give it.** The design
  makes Crosswind unable to issue a write and the tests enforce it, but a
  role with write permissions is still a role with write permissions. Use the
  read-only role.
- **A report is sensitive even when every value in it is redacted.** It names
  your resources, your stacks and your layout. Treat an HTML report like any
  other internal document. The GitHub Action's artifact retention defaults to
  14 days for this reason.
- **Attribution names whoever CloudTrail recorded.** That text is copied
  through, not verified. CloudTrail's `Username` can be an IAM user, a role
  session name, or `AWSService`. The event ID travels with it so a reader can
  check. Crosswind never produces a name without an event — but a name is
  evidence of an API call, not proof of intent.

## Supported versions

Only the latest released version is supported with security fixes. Please
update before reporting an issue, to confirm it still reproduces.

## Verifying a release

Crosswind is distributed through
[GitHub releases](https://github.com/jetonecloud/crosswind/releases) rather
than PyPI, and installs pin a tag. Every release carries a `checksums.txt`
and a signed build provenance attestation.

```sh
gh release download v0.1.0 --repo jetonecloud/crosswind
sha256sum --check --ignore-missing checksums.txt
```

The attestation is the part that matters: it ties the artifact to the
workflow run and the commit that produced it, so a wheel uploaded by hand —
even by someone with write access to the repository — does not verify.

```sh
gh attestation verify crosswind-0.1.0-py3-none-any.whl \
  --repo jetonecloud/crosswind
```

The container image is attested the same way:

```sh
gh attestation verify oci://ghcr.io/jetonecloud/crosswind:0.1.0 \
  --repo jetonecloud/crosswind
```

Installing with `pipx install git+https://...@v0.1.0` resolves the tag
through git, so you get whatever that tag points at. A tag is mutable by
anyone with write access; if that matters to your threat model, install the
attested wheel from the release instead of resolving a tag.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Email **security@jetonecloud.com** with:

- A description of the issue and its potential impact
- Steps to reproduce (a minimal repro is ideal)
- The Crosswind version, Terraform/OpenTofu version, and platform

We aim to acknowledge within 2 business days and will keep you updated. We're
happy to credit reporters in release notes if you'd like.

**Treat these as critical and report them immediately:**

- Any way to make Crosswind invoke a write operation — a Terraform subcommand
  outside the allowlist, a flag that mutates, or a second process-spawning
  code path.
- Any way to make it modify the working tree, the state, or the lock file.
- A sensitive value reaching any output format, log line, or error message.
- Credentials being written to disk or transmitted anywhere.
- A stack that failed to scan being reported as clean. This is a security
  issue, not a cosmetic one: the whole value of the tool is that a clean
  report means something.

## Scope

In scope: the `crosswind` CLI, the composite GitHub Action, the published
container image, and the generated IAM policy and role template.

Out of scope: vulnerabilities in Terraform, OpenTofu, AWS, or third-party
dependencies with their own disclosure process — please report those upstream,
and let us know so we can track the fix.
