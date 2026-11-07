# Contributing

Issues and pull requests are welcome. For a larger change, open an issue first.

## Set up and test

```bash
uv sync --locked --extra dev
uv run ruff check .
uv run mypy scanfuse
uv run pytest tests/
```

## Rules

* Keep a change small and add a test that fails without it.
* Scanner files are untrusted input. A parser must not execute, fetch or trust anything in them.
* A new fixture must come from a public source with a license that allows redistribution, or be made by you. Remove hostnames, IP addresses and credentials first. Never add files from a real client engagement.
* Security problems: see [SECURITY.md](SECURITY.md), do not open a public issue.
