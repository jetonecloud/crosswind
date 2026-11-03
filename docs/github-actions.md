# GitHub Actions

Crosswind ships a composite action that installs it, assumes a role via OIDC,
scans, writes a job summary and uploads the reports.

```yaml
- uses: jetonecloud/crosswind@v0
  with:
    path: infra/prod
    role-arn: arn:aws:iam::111111111111:role/CrosswindReadOnlyRole
    aws-region: eu-west-1
```

A complete scheduled workflow with a per-environment matrix is in
[`examples/workflows/scheduled-drift-check.yml`](../examples/workflows/scheduled-drift-check.yml).

## Before it works

Two things, once:

1. **Deploy the role** from
   [`iam/role.cfn.yaml`](../iam/role.cfn.yaml) with your repository in
   `GitHubRepository`. Read [`iam/README.md`](../iam/README.md) first — the
   refresh permissions are broad and the reasons are worth your attention.

   ```sh
   aws cloudformation deploy \
     --template-file iam/role.cfn.yaml \
     --stack-name crosswind-role \
     --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides \
       GitHubRepository=your-org/your-repo \
       GitHubBranch=main \
       StateBucket=your-tfstate-bucket
   ```

2. **The GitHub OIDC provider** must exist in the account:

   ```sh
   aws iam create-open-id-connect-provider \
     --url https://token.actions.githubusercontent.com \
     --client-id-list sts.amazonaws.com
   ```

There are no secrets to configure. The role is assumed from the job's own
identity token, so there is no access key anywhere in your repository.

## Permissions block

```yaml
permissions:
  contents: read
  id-token: write
```

`id-token: write` is what lets GitHub mint the OIDC token. It grants nothing
in your repository — the name is confusing, and it is the one permission
people miss.

## A Terraform binary is needed

The action does not install one, because you should be using the same tool
your team applies with. Add a setup step first:

```yaml
- uses: opentofu/setup-opentofu@v1
  with:
    tofu_version: 1.13.2

# or

- uses: hashicorp/setup-terraform@v3
  with:
    terraform_version: 1.9.8
    terraform_wrapper: false    # <-- required
```

**`terraform_wrapper: false` matters.** The default wrapper intercepts stdout
to capture output for later steps, which corrupts `show -json` and makes
every stack fail to parse.

## Inputs

| Input | Default | Notes |
|---|---|---|
| `path` | `.` | One stack, or a tree to search. |
| `role-arn` | — | Omit to skip attribution entirely. Drift detection still works. |
| `aws-region` | — | Required when `role-arn` is set. |
| `min-severity` | `low` | `critical`, `high`, `medium`, `low`. |
| `fail-on-drift` | `true` | See below. |
| `binary` | — | `terraform` or `tofu`. Match your setup step. |
| `config` | — | Path to a `.crosswind.yml`. |
| `var-file` | — | Newline-separated paths. |
| `exclude` | — | Newline-separated directories or globs. |
| `concurrency` | `4` | Stacks at once. |
| `formats` | `markdown,html,json` | Comma-separated. |
| `output-dir` | `crosswind-reports` | |
| `job-summary` | `true` | Write the Markdown report to the job summary. |
| `upload-artifact` | `true` | |
| `artifact-name` | `crosswind-report` | Include a matrix value if you scan several environments. |
| `artifact-retention-days` | `14` | Short on purpose: a report names your resources. |
| `crosswind-version` | — | Pin for a reproducible job. |
| `python-version` | `3.12` | |

## Outputs

| Output | Notes |
|---|---|
| `exit-code` | `0` clean, `1` drift, `2` a stack could not be checked |
| `findings` | Count at or above the threshold |
| `critical` | Count of critical findings |
| `failed-stacks` | Stacks that could not be checked |
| `report-json` | Path to the JSON report |

These come from the JSON report's own `summary` block, not from parsing
prose, so they always agree with the report.

## `fail-on-drift`, and the one thing it doesn't control

```yaml
fail-on-drift: false
```

Worth considering for a scheduled scan. A check that goes red every morning
is a check people mute, and a muted check is worse than no check. With it off
you get a warning annotation and a job summary, and the job stays green.

**A stack that could not be checked always fails the job**, whatever this is
set to. That is deliberate: a green check on a scan with a hole in it would
make this action actively misleading. Drift is a finding; a failed stack is a
report you cannot trust.

So the three outcomes are:

| Situation | `fail-on-drift: true` | `fail-on-drift: false` |
|---|---|---|
| No drift | pass | pass |
| Drift found | **fail** | pass, with a warning |
| A stack could not be checked | **fail** | **fail** |

## Patterns

### Scheduled, with an issue for critical drift only

See
[`examples/workflows/scheduled-drift-check.yml`](../examples/workflows/scheduled-drift-check.yml).
It reuses one open issue rather than filing one a day, because the second
duplicate issue is where people stop reading them.

### On a pull request, as a comment

```yaml
on: pull_request

permissions:
  contents: read
  id-token: write
  pull-requests: write

jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: opentofu/setup-opentofu@v1
      - uses: jetonecloud/crosswind@v0
        id: crosswind
        with:
          path: infra/prod
          role-arn: ${{ vars.CROSSWIND_ROLE_ARN }}
          aws-region: eu-west-1
          formats: markdown,json
          fail-on-drift: false

      - uses: peter-evans/create-or-update-comment@v4
        if: steps.crosswind.outputs.findings != '0'
        with:
          issue-number: ${{ github.event.pull_request.number }}
          body-path: crosswind-reports/crosswind-report.md
```

One caution: a PR from a fork does not get the OIDC token, by design. Such a
run will warn about credentials and report every finding as `unknown`, which
is correct behaviour but worth knowing before you wonder why.

If you do this on PRs, use `peter-evans/create-or-update-comment` with an
`edit-mode: replace` and a marker rather than posting a new comment each
push, or a long-running PR accumulates twenty drift reports.

### Several environments

```yaml
strategy:
  fail-fast: false      # one environment failing must not hide the others
  matrix:
    include:
      - environment: production
        path: infra/prod
        role-arn: arn:aws:iam::111111111111:role/CrosswindReadOnlyRole
      - environment: staging
        path: infra/staging
        role-arn: arn:aws:iam::222222222222:role/CrosswindReadOnlyRole

steps:
  - uses: jetonecloud/crosswind@v0
    with:
      path: ${{ matrix.path }}
      role-arn: ${{ matrix.role-arn }}
      aws-region: eu-west-1
      artifact-name: crosswind-${{ matrix.environment }}
```

`artifact-name` must differ per matrix leg or the uploads collide.
`fail-fast: false` so a broken staging stack doesn't cancel the production
scan.

### Without AWS credentials at all

Drift detection needs only state access, which Terraform's own provider
configuration handles. Omit `role-arn` and attribution is skipped:

```yaml
- uses: jetonecloud/crosswind@v0
  with:
    path: infra/prod
```

Every finding will say `unknown`. The drift report is complete.

## Without the composite action

If you would rather not use it:

```yaml
- run: pipx install crosswind
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: ${{ vars.CROSSWIND_ROLE_ARN }}
    aws-region: eu-west-1
- run: |
    crosswind scan --path infra/prod \
      --format markdown --format json \
      --output-dir reports || code=$?
    cat reports/crosswind-report.md >> "$GITHUB_STEP_SUMMARY"
    exit "${code:-0}"
```

Note the `|| code=$?` — without it, `set -e` ends the step before the summary
is written, which is a mildly annoying thing to debug.

Or the container image, which includes OpenTofu:

```yaml
- run: |
    docker run --rm \
      -v "$PWD:/stacks:ro" -v "$PWD/reports:/out" \
      -e AWS_REGION -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
      -e AWS_SESSION_TOKEN \
      ghcr.io/jetonecloud/crosswind:latest \
      scan --path /stacks --format markdown --output-dir /out
```

## Caching

Don't cache `.terraform/`. Crosswind points `TF_DATA_DIR` at a private temp
directory so it never touches yours, which means a cache of it does nothing
for a Crosswind run.

What is worth caching is the provider download, which is the slow part. Both
setup actions handle that; `actions/cache` on the plugin cache directory with
`TF_PLUGIN_CACHE_DIR` set also works and is honoured, since Crosswind passes
the environment through.

## Troubleshooting

**"Terraform needs to write a provider lock file"** — the stack has no
committed `.terraform.lock.hcl`. Crosswind runs
`init -lockfile=readonly` so it never writes to your tree. Run
`terraform init` locally once and commit the lock file.

**Every finding says `unknown`** — check `role-arn` is set, that the role has
`cloudtrail:LookupEvents`, and that the OIDC trust policy's branch matches
the branch you are running on. The report's `attribution_note` says which.

**Every stack fails to parse** — `terraform_wrapper: false`.

**"Could not assume role"** — the trust policy pins to a single branch by
design. A run on a different branch, or a tag, won't match. Add the ref you
need rather than widening to `*`: for a role that can read state and IAM
policies, the wildcard is the difference between a drift checker and a
credential.
