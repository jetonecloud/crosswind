# Contributing to Crosswind

Thanks for considering a contribution. Crosswind is Apache-2.0 and built in
the open — see [`README.md`](README.md) for what it does and
[`docs/design.md`](docs/design.md) for how it is put together and why.

Two of the most useful contributions need no Python at all: adding a severity
rule to [`severity.yml`](src/crosswind/data/severity.yml), or adding a
CloudTrail mapping to [`cloudtrail.yml`](src/crosswind/data/cloudtrail.yml).
Both are data files, and both are deliberately data files so that the people
who know which drift matters don't have to read the engine to say so.

## Ground rules

1. **Read-only, no exceptions.** Any code that could invoke a Terraform write
   subcommand, or that writes to the user's working tree, state or lock file,
   will be rejected. All Terraform execution goes through
   `core/terraform.py`; there is no second route and
   [`tests/test_safety.py`](tests/test_safety.py) enforces that structurally.
   If you find yourself wanting to add `subprocess` to another module, that's
   a sign the design needs discussing first.
2. **A stack that could not be scanned is never reported as clean.** This is
   the invariant the whole tool rests on. A team that sees "no drift" every
   morning stops looking, and a stack that has been silently failing for a
   month is exactly where the drift will be. Every failure path must produce
   a `FAILED` result with the error attached.
3. **Never guess a person.** Attribution without a CloudTrail event is
   `unknown`, with a machine-readable reason. `Attribution.unknown()` is the
   only constructor that omits an event, and it forces `actor` to `None`. A
   confident wrong name outlives the report it appeared in.
4. **Never log or print a sensitive value.** Redaction happens once, at the
   parser boundary, so renderers cannot leak. If you add a renderer, it gets
   this for free; if you add a field to `Finding`, make sure what goes into
   it has been through `redact.scrub`.
5. **No number you cannot defend.** A cost estimate needs an unambiguous
   price and a `basis` sentence someone can check with a calculator. If you
   can't write the sentence, the estimate should be `None`. A figure that
   turns out to be wrong costs more credibility than the figure was worth.
6. **Avoid false positives over false negatives — except for failures.** A
   noisy check gets muted and then the real finding is missed too. But a
   stack we couldn't read is always reported, because silence there is the
   one unrecoverable error.
7. **Plain language.** Findings and recommendations should read like
   something you'd say to a colleague on a call, not an API dump.
8. **License hygiene.** Don't copy GPL/AGPL code into this repo. If you're
   porting logic from another open-source project, confirm the licence is
   compatible (Apache-2.0/MIT with attribution) and add it to
   [`NOTICE`](NOTICE).

## Development setup

```sh
git clone https://github.com/jetonecloud/crosswind.git
cd crosswind
uv sync --all-extras --dev
uv run pytest -m "not e2e"
```

- Python 3.11+, managed with `uv` and `pyproject.toml`.
- Lint and format with **Ruff**: `uv run ruff check . && uv run ruff format .`
- Type-check with **mypy** in strict mode: `uv run mypy`
- Tests with **pytest**. AWS is mocked with `botocore`'s `Stubber`, which
  validates requests against the real service model — so a wrong parameter
  fails in CI rather than in someone's account.

### Running the end-to-end tests

These create real drift using the `local` and `null` providers. No cloud
account needed, but you do need a binary:

```sh
uv run pytest tests/test_e2e.py                      # whatever is on PATH
CROSSWIND_TEST_BINARY=tofu uv run pytest tests/test_e2e.py
```

CI runs them against OpenTofu and two Terraform versions. If you only have
one locally, that's fine — the matrix will catch the rest.

### Seeing it work on something real

```sh
cd examples/stacks
tofu init && tofu apply -auto-approve
echo "changed by hand" > out/notes.txt
crosswind scan --path . --no-attribution
```

## Adding a severity rule

Edit [`src/crosswind/data/severity.yml`](src/crosswind/data/severity.yml). A
rule needs an `id`, a `severity`, a `reason` written for the person reading
the report, the resource `types` and attribute `paths` it matches, and a
`recommend` with its own reason.

Rules are evaluated in **file order and the first match wins**, so put the
specific one above the general one. `default` stays last.

```yaml
  - id: my-new-rule
    severity: high
    reason: >
      Say what the risk is, not what the rule matched. This sentence appears
      in the report.
    types: ["aws_thing"]
    paths: ["important_attribute"]
    when: became_public          # optional, from the closed vocabulary
    recommend: revert
    recommend_reason: >
      What a person should do. Crosswind never does it for them.
```

`when` must come from the vocabulary in
[`core/severity.py`](src/crosswind/core/severity.py) — `any_change`,
`became_public`, `widened_cidr`, `encryption_disabled`, `logging_disabled`,
`iam_widened`, `became_larger`, `became_smaller`,
`deletion_protection_removed`. **The vocabulary is closed on purpose.**
Crosswind loads `.crosswind.yml` from the repository it is scanning, so an
expression language there would be a sandbox escape in a YAML file. Adding a
new predicate is a small Python change plus tests; please open an issue first
so we can talk about whether it generalises.

Add a test to `tests/test_severity.py` asserting your rule fires on the
drift it's meant to catch, and — more importantly — that it *doesn't* fire on
something similar. A predicate that can't tell should return `False` so the
finding falls through to a less specific rule rather than inventing a
critical.

## Adding a CloudTrail mapping

Edit [`src/crosswind/data/cloudtrail.yml`](src/crosswind/data/cloudtrail.yml).
This is how `unknown (no CloudTrail mapping for this resource type yet)`
becomes a name, and it is the highest-value contribution per line of diff.

```yaml
  aws_thing:
    resource_type: AWS::Service::Thing     # CloudTrail's own ResourceType
    lookup_attributes: [name, id, arn]     # tried in order; first non-empty wins
    global: false                          # true only for IAM/Route53/CloudFront/etc
    events:
      - UpdateThing
      - TagResource
    attribute_events:                      # optional, and much stronger evidence
      "size": [UpdateThing]
      "tags*": [TagResource, UntagResource]
```

Things to get right:

- **Key on the Terraform resource type**, never the provider name. Terraform
  and OpenTofu report different registry hosts for byte-identical providers.
- **`global: true` only for services that log to `us-east-1`** regardless of
  where the resource is: IAM, Route 53, CloudFront, STS, Organizations,
  Shield, global WAF. Getting this wrong is the single most common cause of
  a real change attributing to `unknown` — we look in an empty region.
- **`lookup_attributes` must name an attribute that is actually in the
  state** and that CloudTrail would know the resource by. If the prior state
  has none of them, Crosswind reports `no_lookup_value` rather than looking
  up a guess.
- **`attribute_events` is worth the effort.** An event that changes the
  attribute that actually drifted is the difference between `medium` and
  `high` confidence.

`tests/test_attribution.py` has a test asserting every mapped type has at
least one event and one lookup attribute, so a malformed entry fails CI.

## Adding an output format

Add a module under [`core/report/`](src/crosswind/core/report/) with a
`render_<name>(report: Report) -> str`, and register it in `RENDERERS` and
`EXTENSIONS`. A renderer must be a **pure function of the `Report`** — no
I/O, no filesystem, no clock. That is what makes the cross-format tests
possible.

The tests in `tests/test_report.py` that are parametrised over `FORMATS` will
immediately apply to your format, including that a failed stack is visible in
it and that no seeded secret appears. Several of them will fail until you
handle those cases, which is the point.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/):
`<type>: <summary>`, then a body explaining *why*. Common types: `feat`,
`fix`, `docs`, `chore`, `ci`, `test`, `refactor`.

Write the body for someone reading `git log` in a year, and say what you
tried that didn't work — that's usually the valuable part.

```
fix: look up IAM events in us-east-1 rather than the resource's region

IAM, Route 53 and CloudFront log to us-east-1 whatever region the resource
appears to live in, so every IAM finding was attributing to "unknown" after
searching an empty regional trail. The mapping file now carries a `global`
flag per resource type and the lookup is routed on it.
```

Prefer one commit per logical change, but a single well-described commit for
a batch of related work is fine.

## Pull requests

1. Open an issue first for anything beyond a small fix, so we can discuss
   the approach before you spend time on it.
2. Keep PRs focused — one rule, one mapping, one fix.
3. Include tests. CI (lint, mypy, pytest on three Python versions, e2e on
   three binaries) must pass.
4. Say what your change reads, and from where, so a reviewer can verify it
   stays read-only.
5. By submitting a PR you agree your contribution is licensed under
   Apache-2.0.

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Please read
it before participating.

## Bugs vs. security issues

- Functional bugs: open a GitHub issue.
- Anything that could write to infrastructure, leak a secret, or report a
  failed stack as clean: follow [`SECURITY.md`](SECURITY.md) instead. Please
  don't open a public issue for those.
