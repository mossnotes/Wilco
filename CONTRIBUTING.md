# Contributing

Follow the [README](README.md#quick-start) to install Python 3.14, uv, and the locked dependencies. Work on a branch and keep changes focused on one problem.

## Checks

```sh
uv sync --locked
uv run pytest -q
git diff --check
```

External services are mocked in tests. Use synthetic identities and credentials; tests must not send Telegram messages, call paid models, or operate real accounts. Add regression coverage when changing behavior, especially task cancellation, credential isolation, and input ownership.

When changing dependencies, update `pyproject.toml` and regenerate `uv.lock` with `uv lock`. Commit both files. Update `.env.example` and the README when configuration or setup changes.

## Pull requests

Explain the problem, the resulting behavior, and which checks passed. Include screenshots for visible Vault changes. Keep local `.env` files, databases, browser state, screenshots, and temporary output out of commits.

The project currently runs as a single process. Changes that introduce multiple workers must account for task ownership, pending input, profile revocation, and coordination locks as well as database access.
