# Privacy

RepoLocus is local-first. Telemetry is disabled and there is no RepoLocus-operated service in
v0.1.

## Data stored locally

The scanner stores file hashes, paths, extracted text chunks, symbols, imports, and line ranges
in a SQLite database under the operating-system user cache directory. It does not store Git
author names, email addresses, or commit messages. `repolocus clean` removes an index, and
`repolocus clean --all` removes all RepoLocus indexes after confirmation.

Per-repository cloud-provider grants are stored separately in the operating-system user state
directory. `repolocus privacy status` displays them and `repolocus privacy revoke` deletes them.

## Network access

`local` mode has no network access. Ollama defaults to `http://127.0.0.1:11434`; only a loopback
Ollama URL is treated as local. Plain HTTP is accepted only for loopback endpoints; every
non-loopback Ollama, OpenAI-compatible, or Anthropic endpoint must use HTTPS. A non-loopback
Ollama endpoint and every cloud provider are disabled until the user either passes
`--allow-cloud` for one call or records a repository/provider grant. Before every approved
remote CLI call, RepoLocus displays the exact redacted source content and ranges, fragment count,
estimated tokens, redaction count, and credential-free direct/proxy route that will be used,
including calls covered by a remembered grant. Ambient proxy variables are ignored by default;
environment discovery or an explicit proxy URL requires a user-selected proxy policy. The frozen
credential-free route identity is part of consent, while proxy credentials are excluded from that
identity and are never persisted or displayed. Rotating credentials on an unchanged route does not
require fresh consent.
System and user prompts are redacted again immediately before transport, and the final
serialized JSON body is scanned fail-closed before a network client is created. Provider responses
are read with byte, content-type, JSON-depth, per-HTTP-phase timeout, and elapsed-deadline checks
between streamed chunks. A blocking HTTP phase is bounded by the configured HTTPX phase timeout;
the elapsed deadline is cooperative rather than an operating-system-level interrupt. The
self-hosted API has no interactive confirmation UI; cloud access is operator-disabled by default
and should remain so unless a trusted front end provides an equivalent review step.

Only retrieved fragments needed for the question are sent. API credentials are read from
environment variables and are never written to repository or consent configuration.

Provider retention and training rules are governed by the selected provider and account. Users
must confirm they have authority to send the selected repository content.

## Exclusions

Common credential filenames, `.env` variants, private keys, binary files, oversized files, and
files with high-confidence secret patterns are not indexed. These safeguards reduce risk but
are not a guarantee that arbitrary source contains no confidential information. Always inspect
`repolocus privacy preview` before sending sensitive repositories to a cloud model.

## Pre-rename alpha data

RepoLocus does not import configuration, indexes, environment-variable settings, or remembered
cloud consent from pre-rename DevPilot alpha builds. Requiring fresh configuration and consent
prevents old network destinations or grants from silently carrying over. The legacy
`.devpilot/` directory remains excluded from scans, and recognized generated Markdown outputs can
still be safely replaced, but `repolocus clean --all` and `repolocus privacy revoke` operate only on
RepoLocus state. Inspect and explicitly remove obsolete operating-system config, cache, and state
directories named `devpilot` if they are no longer needed.
