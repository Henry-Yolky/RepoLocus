# Security model

## Protected assets

RepoLocus protects source text outside the selected root, excluded secrets within the root,
cloud credentials, locally indexed content, and the user's expectation that analysis is
read-only.

## Threats addressed in v0.1

| Threat | Control |
|---|---|
| Symlink or path traversal reads outside the repository | Canonical-root validation and no symlink following |
| Build, hook, or README-triggered command execution | Scanner and providers expose no command execution interface |
| Target-repository runtime or module shadowing through the Codex Skill | Target paths are canonicalized; target-local interpreters and executables are rejected; child Python runs isolated from a trusted directory |
| Accidental key indexing | Sensitive-name rules, content secret detection, binary/size limits |
| Prompt injection in source | Source is delimited as untrusted data and providers have no tools |
| Unapproved cloud upload | Per-call flag or endpoint-bound repository/provider grant; API cloud sends require a single-use approved preview |
| Excessive cloud disclosure | Retrieval limit, context budget, immutable request preview, and redaction |
| Cleartext remote-provider traffic | HTTP is limited to loopback; non-loopback endpoints require HTTPS |
| Unauthenticated source API access | Random Bearer token, Host allowlist, request-body and concurrency limits, and no-store responses |
| Fabricated citation addresses or quotes | Every material claim requires the same citation on an immediately following exact `Evidence quote`; the address and quote substring are validated against retrieved ranges |
| Generated or uncertain old facts reused as evidence | The scanner excludes recognized RepoLocus output; queries admit only non-stale `source` provenance, and incomplete scans retain uncertain facts as excluded `stale` rows |
| Older concurrent scan overwrites a new index | Monotonic generation compare-and-swap rejects stale commits |
| Mermaid links or directives | Deterministic restricted grammar; model output is never diagram source |
| Index committed to Git | Cache defaults outside the repository; `.repolocus/` is ignored |

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

The default `refresh=auto` query path reads the last compatible committed snapshot without
rescanning. This makes one operation internally reproducible but does not promise that the
snapshot reflects an uncommitted filesystem change made afterward. Use `refresh=always` when a
new scan is required; `refresh=never` fails closed if no compatible snapshot exists. Follow-up
sessions additionally pin the original generation and stop if another scan changes it.

Remembered-consent state v2 binds a canonical repository and provider to the destination scheme,
host, effective port, and complete request path. It deliberately does not carry forward legacy v1
family-only grants because no safe endpoint can be inferred during migration. A changed endpoint
therefore requires a new explicit grant. Model names are displayed in previews but are not part of
the grant identity.

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
