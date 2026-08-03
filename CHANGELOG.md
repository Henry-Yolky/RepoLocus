# Changelog

All notable changes are recorded here. The format follows Keep a Changelog, and versions use
Semantic Versioning while the project is in alpha.

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
- Reproducible retrieval evaluation and 1k/10k/100k synthetic scan benchmark harness.

### Security

- Repository configuration cannot choose models, network endpoints, telemetry, or credentials.
- Cloud preview and upload use one immutable evidence bundle.
- Non-loopback Ollama endpoints require consent; API cloud use requires an operator flag.
- Cache files use private permissions, untrusted display controls are escaped, and model output
  with unsafe controls or unsupported links is withheld.

### Known limitations

- Multi-language parsing beyond Python is heuristic, not a complete semantic call graph.
- The checked-in evaluation is a small regression set, not the planned 100-question release set.
- The public-repository Web Demo, Tree-sitter adapters, GitHub Action, IDE, and MCP integrations
  remain future milestones.
