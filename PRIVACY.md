# Privacy

DevPilot is local-first. Telemetry is disabled and there is no DevPilot-operated service in
v0.1.

## Data stored locally

The scanner stores file hashes, paths, extracted text chunks, symbols, imports, and line ranges
in a SQLite database under the operating-system user cache directory. It does not store Git
author names, email addresses, or commit messages. `devpilot clean` removes an index, and
`devpilot clean --all` removes all DevPilot indexes after confirmation.

Per-repository cloud-provider grants are stored separately in the operating-system user state
directory. `devpilot privacy status` displays them and `devpilot privacy revoke` deletes them.

## Network access

`local` mode has no network access. Ollama defaults to `http://127.0.0.1:11434`; only a loopback
Ollama URL is treated as local. A non-loopback Ollama endpoint and every cloud provider are
disabled until the user either passes `--allow-cloud` for one call or records a
repository/provider grant. Before every approved remote CLI call, DevPilot displays the exact
redacted source content and ranges, fragment count, estimated tokens, and redaction count that
will be sent, including calls covered by a remembered grant. The self-hosted API has no
interactive confirmation UI; cloud access is operator-disabled by default and should remain so
unless a trusted front end provides an equivalent review step.

Only retrieved fragments needed for the question are sent. API credentials are read from
environment variables and are never written to repository or consent configuration.

Provider retention and training rules are governed by the selected provider and account. Users
must confirm they have authority to send the selected repository content.

## Exclusions

Common credential filenames, `.env` variants, private keys, binary files, oversized files, and
files with high-confidence secret patterns are not indexed. These safeguards reduce risk but
are not a guarantee that arbitrary source contains no confidential information. Always inspect
`devpilot privacy preview` before sending sensitive repositories to a cloud model.
