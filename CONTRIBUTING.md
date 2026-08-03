# Contributing

Thank you for helping make repository understanding more verifiable.

## Setup

```bash
cd /path/to/repolocus
uv sync --all-extras
uv run ruff check .
uv run pytest --cov=repolocus --cov-report=term-missing
```

Pull requests should be focused, include tests for behavior changes, update user-facing docs,
and include a Developer Certificate of Origin sign-off (`git commit -s`). Do not add a network
call, repository write, executable tool, new telemetry field, or broader file-read scope without
an architecture decision record and explicit maintainer review.

Parser fixtures must be small, redistributable, and include the expected symbols, imports, and
line ranges. Security fixes should include a regression test without publishing live secrets.

Use conventional commit-style subjects where practical (`feat:`, `fix:`, `docs:`, `test:`).
Maintainers squash only when it preserves contributor attribution and DCO sign-offs.

## Releasing

Before the first release, configure a protected GitHub environment named `pypi` and register
the PyPI Trusted Publisher (or pending publisher) with these exact claims:

- owner: `Henry-Yolky`;
- repository: `RepoLocus`;
- workflow: `release.yml`;
- environment: `pypi`.

Require a maintainer approval on the `pypi` environment. Do not add a long-lived PyPI token to
GitHub secrets. The release workflow accepts version tags such as `v0.1.0` only when the tag
matches `pyproject.toml` and its commit belongs to `main`; it then tests, builds, publishes with
OIDC, and creates the GitHub Release with checksums, an SBOM, and the standalone Codex Skill.
