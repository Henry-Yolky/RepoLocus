# ADR 0001: Keep the MVP read-only and local-first

- Status: Accepted
- Date: 2026-08-03

## Context

Repository understanding already involves untrusted input, broad file discovery, model
uncertainty, and possible source disclosure. Adding command execution or code mutation would
also require sandboxing, patch evaluation, rollback, and long-running task controls before the
core evidence workflow has been validated.

## Decision

The MVP scans and indexes within one canonical root, writes only explicitly requested generated
documentation, and never executes repository commands. Deterministic extraction and local
answers work without a model. Cloud calls require explicit consent and show their selected
context.

## Consequences

RepoLocus is not a coding agent. The smaller permission surface is easier to test and explain.
Future write or execution features require a new ADR and must not silently broaden existing
commands.
