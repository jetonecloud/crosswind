---
name: Feature request
about: Something Crosswind should do and doesn't
labels: enhancement
---

## What you're trying to do

The problem, rather than the solution — it often turns out there's a simpler
answer than the one that brought you here.

## What you'd want it to do

## Have you checked whether it's a data file change?

Two of the most commonly requested things need no code:

- **A resource type attributing to `unknown`** → add a mapping to
  [`cloudtrail.yml`](../../src/crosswind/data/cloudtrail.yml). See
  [docs/attribution.md](../../docs/attribution.md#adding-a-resource-type).
- **A finding scored wrong** → add or override a rule in
  [`severity.yml`](../../src/crosswind/data/severity.yml). See
  [docs/severity-rules.md](../../docs/severity-rules.md).

Both make excellent first PRs and we'd rather have the mapping than the
issue.

## Out of scope for v1

These are deliberate omissions rather than oversights, so an issue asking for
one will probably be closed with a link to this list: auto-remediation, a
watch mode or server, a dashboard, Slack integration, hosted scanning, clouds
other than AWS for attribution, and discovery of resources Terraform doesn't
manage.

That last one is the most requested. It isn't in v1 because doing it badly
produces a long list of things that are fine, which is worse than not doing
it.
