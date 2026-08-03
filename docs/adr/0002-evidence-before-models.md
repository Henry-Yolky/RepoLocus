# ADR 0002: Produce and validate evidence before model explanation

- Status: Accepted
- Date: 2026-08-03

## Context

Model-only repository summaries are difficult to reproduce and can cite nonexistent files or
infer dynamic behavior from insufficient source. Exact symbols, full-text matches, imports, and
line ranges can be derived locally and tested independently.

## Decision

Scanning, indexing, retrieval, project maps, and Mermaid generation are deterministic. Optional
providers receive a bounded evidence set. Their structured citations must fall inside that set;
otherwise RepoLocus returns the extractive fallback.

## Consequences

Users always receive something inspectable when no model is configured. Narrative quality may
be less fluent, but unsupported confidence is not treated as a successful answer.
