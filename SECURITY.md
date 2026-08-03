# Security policy

## Supported versions

Until a stable release, only the latest tagged minor version receives security fixes.

## Reporting a vulnerability

Do not publish exploit details for a suspected path-boundary bypass, credential disclosure,
cloud call without consent, or arbitrary command execution. If the canonical GitHub repository
has private vulnerability reporting enabled, use its **Security → Report a vulnerability**
flow. Otherwise open a detail-free issue requesting a private maintainer contact, or use the
private security contact published by the package distributor. Include the affected version,
operating system, reproduction, and whether any source left the machine only in that private
channel. A release must not advertise a private-reporting address that has not been configured.

## Security boundary

RepoLocus treats repository data as untrusted, never executes repository commands, does not
follow symlinks, checks canonical paths, excludes sensitive and binary files, validates
model-provided citations, and generates Mermaid from a restricted deterministic form. Cloud
providers require explicit consent. See [docs/security-model.md](docs/security-model.md) for
threats and non-goals.
