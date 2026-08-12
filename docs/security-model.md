# Security model

## Protected assets

RepoLocus protects source text outside the selected root, excluded secrets within the root,
cloud credentials, locally indexed content, and the user's expectation that analysis is
read-only.

## Threats addressed

| Threat | Control |
|---|---|
| Symlink or path traversal reads outside the repository | Canonical-root validation and no symlink following |
| Build, hook, or README-triggered command execution | Scanner and providers expose no command execution interface |
| Target-repository runtime or module shadowing through the Codex Skill | Target paths are canonicalized; target-local interpreters and executables are rejected; child Python runs isolated from a trusted directory |
| Accidental key indexing | Sensitive-name rules, content secret detection, binary/size limits |
| Prompt injection in source | Source is delimited as untrusted data and providers have no tools |
| Unapproved cloud upload | Per-call flag or endpoint-bound repository/provider grant; API cloud sends require a single-use approved preview |
| Ambient or changed HTTP proxy route bypasses consent | Proxy discovery is disabled by default; the exact direct/proxy route is frozen into the preview and consent identity without persisting credentials |
| Excessive cloud disclosure | Retrieval limit, context budget, immutable request preview, and redaction |
| Cleartext remote-provider traffic | HTTP is limited to loopback; non-loopback endpoints require HTTPS |
| Unauthenticated source API access | Random Bearer token, Host allowlist, request-body and concurrency limits, and no-store responses |
| Fabricated citation addresses or quotes | Every material claim requires the same citation on an immediately following exact `Evidence quote`; the address and quote substring are validated against retrieved ranges |
| Generated or uncertain old facts reused as evidence | The scanner excludes recognized RepoLocus output; queries admit only non-stale `source` provenance, and incomplete scans retain uncertain facts as excluded `stale` rows |
| Older concurrent scan overwrites a new index | Monotonic generation compare-and-swap rejects stale commits |
| Generated-output symlink or replacement race | Descriptor-relative or handle-validated same-directory atomic writes attest parent and target identities and fail closed on races; ambiguous post-commit objects are preserved under reported recovery names rather than deleted |
| Mermaid links or directives | Deterministic restricted grammar; model output is never diagram source |
| Index committed to Git | Cache defaults outside the repository; `.repolocus/` is ignored |
| Diff invokes untrusted repository code | Snapshot projection and comparison are pure reads; Git, hooks, builds, tests, and target executables remain outside the core interface |
| Fork pull request receives write token or secrets | The opt-in PR-context Action is artifact-only by default, documents a caller job with only `contents: read`, persists no checkout credentials, and refuses comment mode for fork events |
| Analysis-policy drift looks like a code change | Snapshot schema and component fingerprints are compared first and incompatible comparisons are labeled degraded |

## Non-goals and residual risk

RepoLocus is not a malware scanner, a data-loss-prevention system, a compiler, or a sandbox. A
secret embedded in an ordinary source expression may evade pattern matching. A user can
reconfigure Ollama to a remote host, in which case RepoLocus requires the same explicit consent
boundary used for cloud providers. Static analysis cannot reliably reconstruct
reflection, runtime code generation, dependency injection, or dynamic imports. A process with
the user's operating-system permissions can read the local index. SQLCipher and operating-system
keychain integration are future options, not current claims.

Citation validation is deliberately structural. It verifies that a cited address is within the
retrieved evidence and that the paired quote occurs in that cited source range. It does not prove
that the quote logically supports the model's claim; accepted model text therefore keeps
`needs_review` confidence.

The default `refresh=auto` query path performs a bounded incremental refresh before reading
evidence and writes nothing on an exact cache hit. `refresh=always` rereads all candidate content,
`refresh=rebuild` reparses it, and `refresh=never` is the explicit committed-snapshot mode.
Follow-up sessions pin the retrieval-visible content generation; a diagnostic-only scan revision
does not invalidate the evidence. Metadata reuse is permitted only for the same repository
identity and compatible component fingerprints; changed files are reopened, hashed, and reparsed.

Remembered-consent state v4 binds the current root-directory and Git-marker identity, canonical
path, provider, complete destination endpoint, and exact credential-free direct/proxy route
identity. Proxy credentials are excluded from the digest, state file, and preview. It does not
carry forward legacy v1-v3 grants. A replaced repository or changed endpoint, proxy policy, or
route therefore requires a new explicit grant; credential rotation on the same route does not.
Model names are displayed in previews but are not part of the grant identity.

The self-hosted API accepts only paths below its configured `--root`, binds to loopback by
default, and rejects cloud models by default. It authenticates every request with a random Bearer
token unless the operator supplies one, validates the Host header, bounds request bodies and
concurrent work, and marks `/v1/` responses `no-store`. Cloud-backed calls additionally require
the server-side `--allow-cloud-api` option and a short-lived, single-use
`preview_id -> approve` exchange. Approval consumes the immutable evidence and serialized request
body prepared by the preview; it does not scan again. API clients cannot record persistent cloud
consent.

A non-loopback listener is refused unless the operator supplies `--allow-remote`, at least one
allowed Host, and a TLS certificate/key pair. Preview state is intentionally bounded and
process-local; the built-in `repolocus serve` path runs one worker. This remains a self-hosted
single-operator API, not the public Web Demo architecture.

Architecture snapshots are metadata artifacts, not source archives: they contain paths, digests,
bounded symbol/range data, dependency witnesses, repository identity, generation, schema, and
analysis fingerprints, but no source bodies or retrieval chunks. Paths and symbol names may still
be sensitive metadata, so callers should apply the same access controls used for repository build
artifacts. Snapshot integrity detects accidental or malicious edits; it is not a signature or an
authorization mechanism.

The PR-context GitHub Action is deliberately artifact-first. A composite Action cannot set its
caller's job permissions, so the documented workflow explicitly grants only `contents: read`;
checkout credentials are not persisted, target repository code is never run, and no cloud provider
is used. Commenting is an explicit trusted-context mode requiring a separate same-repository job,
`pull-requests: write`, and a token. Fork pull requests never receive that capability, and the
Action does not use `pull_request_target` to analyze untrusted head code with repository secrets.
