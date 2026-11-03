---
name: Bug report
about: Something doesn't work the way it should
labels: bug
---

**Please do not report security issues here.** Anything that could write to
infrastructure, leak a secret, or report a failed stack as clean goes to
security@jetonecloud.com — see [SECURITY.md](../../SECURITY.md).

## What happened

## What you expected

## Steps to reproduce

```sh
crosswind scan --path ... 
```

## Output

Paste the terminal output. **Check it first** — it names your resources, and
a stack error can quote your configuration.

```
```

## Versions

- `crosswind version`:
- `terraform version` or `tofu version`:
- OS and Python version:
- Installed via: pipx / uv / pip / Docker / checkout

## Anything else

If a stack was reported as "could not check", the error text in the report is
the useful part. If a finding was scored wrong, the `severity_rule` in the
JSON tells us which rule to look at. If attribution said `unknown`, the
`reason` field says why.
