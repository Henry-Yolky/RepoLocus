# Security model

## Protected assets

DevPilot protects source text outside the selected root, excluded secrets within the root,
cloud credentials, locally indexed content, and the user's expectation that analysis is
read-only.

## Threats addressed in v0.1

| Threat | Control |
|---|---|
| Symlink or path traversal reads outside the repository | Canonical-root validation and no symlink following |
| Build, hook, or README-triggered command execution | Scanner and providers expose no command execution interface |
| Accidental key indexing | Sensitive-name rules, content secret detection, binary/size limits |
| Prompt injection in source | Source is delimited as untrusted data and providers have no tools |
| Unapproved cloud upload | Per-call flag or remembered repository/provider grant |
| Excessive cloud disclosure | Retrieval limit, context budget, preview, and redaction |
| Fabricated source citations | Structured citation markers validated against retrieved ranges |
| Mermaid links or directives | Deterministic restricted grammar; model output is never diagram source |
| Index committed to Git | Cache defaults outside the repository; `.devpilot/` is ignored |

## Non-goals and residual risk

DevPilot is not a malware scanner, a data-loss-prevention system, a compiler, or a sandbox. A
secret embedded in an ordinary source expression may evade pattern matching. A user can
reconfigure Ollama to a remote host, in which case DevPilot requires the same explicit consent
boundary used for cloud providers. Static analysis cannot reliably reconstruct
reflection, runtime code generation, dependency injection, or dynamic imports. A process with
the user's operating-system permissions can read the local index. SQLCipher and operating-system
keychain integration are future options, not current claims.

The self-hosted API accepts only paths below its configured `--root`, binds to loopback by
default, and rejects cloud models by default. `--allow-remote` only acknowledges network
exposure; it does not add authentication. A non-loopback deployment needs an operator-provided
authentication and authorization gateway. Cloud-backed API calls additionally require the
server-side `--allow-cloud-api` option. This is not the public Web Demo architecture.
