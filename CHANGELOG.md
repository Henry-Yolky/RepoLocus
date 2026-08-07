# Changelog

All notable changes are recorded here. The format follows Keep a Changelog, and versions use
Semantic Versioning while the project is in alpha.

## [Unreleased]

## [0.1.5] - 2026-08-07

### Added

- Added distinct retrieval-visible `content_generation` and diagnostic `scan_revision` counters,
  a `status` command, and explicit `auto`, `always`, `never`, and `rebuild` refresh behavior.
- Added deterministic component fingerprints and parser cache identities so scanner, parser,
  term-index, and retrieval changes invalidate only the facts they affect.
- Added a parser finalizer with normalized ranges, bounded fields and collections, transactional
  repository budgets, and hard resource ceilings around parser output.
- Added a fixed six-repository, 18-qrel synthetic retrieval gate with graded citations, a citation
  recall gate, explicit no-answer truth, per-repository metrics, provenance, fixture and qrel
  digests, and `must_not_return` checks.
- Added state-machine, race, cross-process, parser-boundary, proxy-route, and workflow-policy tests.

### Changed

- `refresh=auto` now performs no database write on an exact cache hit; `always` securely rereads
  every candidate while reusing compatible parser facts, and `rebuild` reparses every source file.
- Python 3.10 configuration now uses `tomli`, while Python 3.11 and newer use `tomllib`; the
  previous partial TOML implementation has been removed.
- The bundled Skill now requires a RepoLocus `>=0.1.5,<0.2.0` runtime so its parser budgets,
  component fingerprints, and refresh semantics cannot silently fall back to v0.1.4 behavior.
- CI now covers Python 3.10 through the supported latest Python 3.14, runs the external retrieval
  gate, pins every third-party Action to a full commit SHA, and uses exact uv and Hatchling
  versions. The existing required `package` check now fails instead of becoming skipped when any
  prerequisite gate fails.

### Security

- Generated Markdown uses descriptor-relative no-replace publication on POSIX. Replacements use
  atomic name exchange and retain the previous document as an explicitly reported `.rollback`
  recovery file rather than risking a cleanup race. Windows uses 128-bit handle identity,
  pre/post content hashes, recoverable replacement, and handle-bound deletion.
- HTTP providers ignore ambient proxy variables by default. Environment or explicit proxy use
  requires an explicit user policy, appears credential-free in previews, and is cryptographically
  bound to remembered consent without persisting proxy credentials.
- Privacy consent state v4 invalidates earlier grants and uses an operating-system cross-process
  lock on Windows as well as POSIX so concurrent grant/revoke updates cannot be lost.
- Release wheel, sdist, Skill ZIP, CycloneDX SBOM, and checksums receive GitHub/Sigstore build
  provenance; a separate clean job verifies checksums and every attestation, installs the wheel,
  and runs the security doctor before PyPI publication.

## [0.1.4] - 2026-08-04

### Changed

- `refresh=auto` now performs an identity-bound delta scan; the evidence path uses a metadata-only
  manifest so unchanged files avoid source reads and parser-fact materialization, while changed
  files are securely read, hashed, and parsed.
- The public `RepoLocusService.scan()` result is metadata-only for unchanged files; callers that
  need source text and parser facts should use `map()`, `diagram()`, or retrieval evidence.
- The bundled Skill now requires a RepoLocus `>=0.1.4,<0.2.0` runtime so older security and
  analysis policies cannot pass adapter preflight.
- CJK retrieval uses position-spread bounded n-gram coverage, and answerable retrieval metrics are
  aggregated separately from no-answer classification metrics and query-type breakdowns.
- Generated-output detection is extension-independent, nested generated documents use correct
  relative source links, and generated CLI files require a Markdown suffix.
- Added repository-wide limits for entries/files, bytes, depth, chunks, symbols, and scan time.

### Security

- Invalidated older analysis facts and path-only index/consent identities; repository replacement,
  stale parser caches, and incomplete upgrades now fail closed.
- Unified scanner and transport secret rules, count prompt redactions in previews, and scan the
  final serialized request before transport.
- Stream provider responses under byte, media-type, HTTP phase-timeout, elapsed-deadline, and
  JSON-structure limits; read repository configuration once through a pinned, no-follow
  descriptor chain.
- Force low-level scanner and repository-config reads into binary mode on Windows so raw-byte
  size, hashes, secret checks, and Ctrl-Z handling remain consistent across platforms.

## [0.1.3] - 2026-08-04

### Added

- Added a deterministic lexical term index that splits camel/snake identifiers and paths, emits
  CJK bigrams/trigrams, and accepts bounded user-owned synonyms through
  `REPOLOCUS_QUERY_SYNONYMS`.
- Expanded retrieval evaluation with recall@k, MRR, nDCG@k, any/all-path coverage, citation
  recall, no-answer precision/accuracy, per-language summaries, and rank/recall thresholds.

### Changed

- `map`, `diagram`, and `ask` now default to compatible committed snapshots with explicit
  `auto|always|never` refresh modes. CLI follow-ups pin the initial index generation and fail
  closed if it changes.
- Index rows now track `source`/`generated` provenance and stale state; retrieval excludes
  generated and stale facts, while generation compare-and-swap prevents an old scan from
  overwriting a newer commit.
- Model output now pairs every material claim with the same citation and an exact source quote.
  Validation checks citation addresses and quote substrings only, and accepted output remains
  `needs_review`.
- Mermaid output now records one concrete import witness for every rendered edge.
- The Codex Skill now requires a preinstalled compatible runtime or pre-synchronized trusted
  checkout and runs offline/no-sync, failing closed rather than installing dependencies.
- Windows scans now use path-backed identity metadata so ordinary files are not falsely reported
  as having changed between directory enumeration and opening.

### Security

- Bound remembered cloud consent to the canonical repository, provider, scheme, host, effective
  port, and complete request path. Legacy v1 family-only grants now fail closed and require fresh
  consent.
- Added model, canonical endpoint, and exact serialized payload byte counts to cloud previews;
  providers send the same immutable request body that was previewed.
- Added default random Bearer authentication, Host validation, request-body and concurrency
  limits, and `Cache-Control: no-store` to the self-hosted API.
- Added a short-lived, single-use `preview_id -> approve` cloud API flow that sends the frozen
  evidence snapshot without rescanning. API clients cannot create persistent cloud grants.
- Required non-loopback API listeners to provide explicit remote opt-in, an allowed Host, and TLS
  certificate/key files.

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
