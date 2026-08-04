# Changelog

All notable changes are recorded here. The format follows Keep a Changelog, and versions use
Semantic Versioning while the project is in alpha.

## [0.1.2] - 2026-08-04

### Changed

- Precompiled reusable regular expressions in the Markdown and configuration parsers, avoiding
  repeated regular-expression cache lookups for every source line.

## [0.1.1] - 2026-08-03

### Changed

- Release tags must point to commits on `main`'s first-parent history, preventing tags on merged
  pull-request heads from producing incomplete generated release notes.
- Documented the repeatable version-bump, merge, tag, approval, and immutable-tag release flow.

## [0.1.0] - 2026-08-03

### Added

- Read-only repository scanning with ignore, binary, size, symlink, and secret boundaries.
- Python AST plus conservative JavaScript/TypeScript, Go, Rust, Java, C/C++, docs, and config
  parsing.
- Versioned SQLite/FTS5 indexing with content-hash parser-fact reuse.
- Deterministic `PROJECT_MAP.md` and restricted Mermaid architecture generation.
- Source-backed extractive answers, in-memory follow-ups, and citation-validated model answers.
- Ollama, OpenAI-compatible, and Anthropic providers with redacted previews and explicit consent.
- Root-confined FastAPI service, multi-stage Docker image, cross-platform CI, SBOM, vulnerability
  and license checks.
- Local-only Codex Skill with guarded `doctor`, `scan`, `ask`, `map`, and `diagram` adapters.
- Tag-gated release automation for PyPI Trusted Publishing and verifiable GitHub Release assets.
- Reproducible retrieval evaluation and 1k/10k/100k synthetic scan benchmark harness.

### Security

- Repository configuration cannot choose models, network endpoints, telemetry, or credentials.
- Cloud preview and upload use one immutable evidence bundle.
- Non-loopback Ollama endpoints require consent; API cloud use requires an operator flag.
- Remote provider endpoints require HTTPS, prompts are redacted immediately before transport,
  and plain HTTP remains available only for loopback services.
- The Codex Skill isolates runtime discovery and execution from the untrusted target repository.
- POSIX cache files use private permissions; Windows ACL status is reported as unverified until
  native inspection is available. Untrusted display controls are escaped, and model output with
  unsafe controls or unsupported links is withheld.

### Known limitations

- Multi-language parsing beyond Python is heuristic, not a complete semantic call graph.
- The checked-in evaluation is a small regression set, not the planned 100-question release set.
- The public-repository Web Demo, Tree-sitter adapters, GitHub Action, IDE, and MCP integrations
  remain future milestones.
