# Model support

| Provider string | Network | Credential | Status |
|---|---|---|---|
| `local` or `extractive` | None | None | Supported; deterministic evidence output |
| `ollama/MODEL` | Loopback by default; configurable | None | Supported; non-loopback requires explicit consent |
| `openai/MODEL` | Cloud or compatible gateway | `OPENAI_API_KEY` | Supported; explicit consent |
| `anthropic/MODEL` | Cloud | `ANTHROPIC_API_KEY` | Supported; explicit consent |

Provider adapters share a small contract and receive already-selected evidence. They cannot
execute tools or expand the repository read scope. Cloud consent is enforced outside the
adapter and remembered per canonical repository path and provider family.

Environment configuration:

- `DEVPILOT_MODEL`
- `DEVPILOT_OLLAMA_BASE_URL`
- `DEVPILOT_OPENAI_BASE_URL`
- `DEVPILOT_ANTHROPIC_BASE_URL`
- `DEVPILOT_REQUEST_TIMEOUT`
- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`

Model output is not treated as evidence. A citation must point into one of the retrieved source
ranges or the narrative is withheld in favor of the deterministic evidence response.

Repository-controlled configuration cannot select a model or network endpoint. Those choices
must come from user configuration, environment variables, or an explicit command-line model.
