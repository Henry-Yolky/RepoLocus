# Governance

DevPilot begins with a lightweight maintainer model.

- The Lead Maintainer owns roadmap and release decisions.
- Core Reviewers approve scanner, parser, index, retrieval, and provider changes.
- DX Maintainers own CLI, documentation, installation, and error quality.
- Triage Maintainers reproduce and label reports.
- The Security Contact handles private reports and release security.
- The Release Manager builds, signs, documents, and may roll back releases.

Routine decisions happen in issues and pull requests. A compatibility break, new network or
write permission, major dependency, data-format change, or security-boundary change requires a
public RFC or ADR. The Lead Maintainer resolves deadlock after documenting alternatives and
trade-offs. Maintainers are added based on sustained, high-quality participation and may step
down or be removed after prolonged inactivity or conduct violations.
