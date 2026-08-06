# Model support

| Provider string | Network | Credential | Status |
|---|---|---|---|
| `local` or `extractive` | None | None | Supported; deterministic evidence output |
| `ollama/MODEL` | Loopback by default; configurable | None | Supported; non-loopback requires HTTPS and explicit consent |
| `openai/MODEL` | Cloud or compatible gateway | `OPENAI_API_KEY` | Supported; explicit consent |
| `anthropic/MODEL` | Cloud | `ANTHROPIC_API_KEY` | Supported; explicit consent |

Provider adapters share a small contract and receive already-selected evidence. They cannot
execute tools or expand the repository read scope. Cloud consent is enforced outside the adapter
and remembered per canonical repository, provider family, complete endpoint, and exact
direct/proxy route identity.

Environment configuration:

- `REPOLOCUS_MODEL`
- `REPOLOCUS_OLLAMA_BASE_URL`
- `REPOLOCUS_OPENAI_BASE_URL`
- `REPOLOCUS_ANTHROPIC_BASE_URL`
- `REPOLOCUS_REQUEST_TIMEOUT`
- `REPOLOCUS_PROXY_MODE` (`disabled`, `environment`, or `explicit`)
- `REPOLOCUS_PROXY_URL` (required only for `explicit` mode)
- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`

Plain HTTP endpoints are accepted only on loopback addresses such as `localhost`, `127.0.0.1`,
or `::1`. Every non-loopback Ollama, OpenAI-compatible, or Anthropic endpoint must use HTTPS.
Prompts sent through HTTP providers are redacted immediately before transport.
HTTPX environment proxy discovery is disabled unless `REPOLOCUS_PROXY_MODE=environment` is
selected. Explicit and environment proxy routes are shown without credentials in the cloud
preview, frozen for the request, and bound to remembered consent. Loopback endpoints stay direct.

Model output is not treated as evidence. A citation must point into one of the retrieved source
ranges or the narrative is withheld in favor of the deterministic evidence response.

Repository-controlled configuration cannot select a model or network endpoint. Those choices
must come from user configuration, environment variables, or an explicit command-line model.
