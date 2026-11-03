## What this changes

## Why

What problem this solves. If you tried something that didn't work first,
that's usually the valuable part of the description.

## What it reads, and from where

So a reviewer can verify the change stays read-only. "Nothing new" is a
perfectly good answer.

## Checklist

- [ ] `uv run ruff check . && uv run ruff format --check .`
- [ ] `uv run mypy`
- [ ] `uv run pytest -m "not e2e"`
- [ ] `uv run pytest tests/test_e2e.py` if the change touches Terraform
      invocation or plan parsing
- [ ] Tests added for the new behaviour, including a case where it should
      *not* fire
- [ ] No new `subprocess` import — all Terraform execution goes through
      `core/terraform.py`
- [ ] A failed stack still cannot be reported as clean
- [ ] No sensitive value can reach a report, a log, or an error message
- [ ] Any new cost figure carries a `basis` sentence someone can check
- [ ] `CHANGELOG.md` updated under `[Unreleased]`

## Notes for the reviewer
