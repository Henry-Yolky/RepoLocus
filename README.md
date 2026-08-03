# DevPilot

> Understand an unfamiliar codebase with a project map, a reproducible architecture graph,
> and answers backed by file-and-line evidence.

DevPilot is a read-only, local-first repository understanding tool. It scans source without
executing repository commands, builds a local SQLite/FTS index, writes a stable
`PROJECT_MAP.md`, generates validated Mermaid, and retrieves evidence for code questions.
It works without an LLM; Ollama and explicitly approved cloud providers can add a narrative
answer on top of the same evidence.

> **Alpha:** this repository implements the CLI-first v0.1 baseline. Static dependency and
> call relationships are approximations, and the hosted public-repository Web Demo described
> in the roadmap is not part of this release.

## Quick start

DevPilot requires Python 3.10 or newer.

```bash
pipx install devpilot-codebase
cd your-repository
devpilot scan
devpilot map
devpilot ask "Where is configuration validated?"
devpilot diagram
```

For a development checkout:

```bash
cd /path/to/devpilot
uv sync --all-extras
uv run devpilot doctor --security
uv run pytest
```

The default `local` answer mode does not make a network request. A local model is explicit:

```bash
devpilot ask "How does a request reach the core loop?" --model ollama/qwen3-coder
```

Every remote CLI call first prints the exact redacted source fragments selected for that send,
including calls covered by a remembered grant. Use `--allow-cloud` for one call, or add
`--remember-consent` to remember that provider for the current repository:

```bash
export OPENAI_API_KEY=...
devpilot ask "Where is configuration validated?" \
  --model openai/gpt-4.1-mini --allow-cloud
```

## What it produces

`devpilot map` writes a deterministic `PROJECT_MAP.md` with:

- repository purpose and onboarding files;
- layout, entry points, modules, static dependency flow, configuration, and tests;
- a suggested reading order;
- source links and `Confirmed`, `Inferred`, or `Needs review` labels.

`devpilot diagram` writes `ARCHITECTURE.md`. The Mermaid source is constructed from a small,
validated AST-like subset, not accepted directly from a model. A source-evidence table remains
next to the graph.

`devpilot ask` combines exact symbols, SQLite FTS5, and dependency-neighbor evidence. If no
model is selected, the answer is an extractive evidence bundle. If a model is selected, its
citations are checked against the retrieved file and line ranges before display.

## Commands

| Command | Purpose |
|---|---|
| `devpilot scan [PATH]` | Securely scan and incrementally update the local index |
| `devpilot map [PATH]` | Generate `PROJECT_MAP.md` or print it with `--stdout` |
| `devpilot ask QUESTION [PATH]` | Retrieve source-backed evidence and optionally use a model |
| `devpilot diagram [PATH]` | Generate validated Mermaid in `ARCHITECTURE.md` |
| `devpilot privacy status` | Show remembered per-repository provider consent |
| `devpilot privacy preview QUESTION` | Show fragments a question would send |
| `devpilot privacy revoke` | Forget cloud-provider consent |
| `devpilot doctor --security` | Check runtime, FTS5, cache permissions, and local-model reachability |
| `devpilot clean` | Remove the current repository index after confirmation |
| `devpilot serve` | Start the optional self-hosted FastAPI service |

Every command accepts `--help`. Use `--json` on automation-friendly commands where available.
Add `--follow-up` to `ask` for a non-persistent in-memory question session; entering a blank line
ends it. Follow-up context is never written to the repository or consent state.

Install the API extra with `pipx install 'devpilot-codebase[api]'`, then constrain the server to
one repository tree:

```bash
devpilot serve --root /path/to/allowed/repositories
```

The default bind address is loopback and cloud requests are disabled. A non-loopback bind
requires `--allow-remote`; put an authentication and authorization gateway in front of it.
Cloud-backed API questions additionally require the operator-only `--allow-cloud-api` flag.

The Docker image is dependency-locked and also defaults to container loopback. For a local-only
published port, explicitly bind Uvicorn inside the container while limiting the host publish to
`127.0.0.1`:

```bash
docker build -t devpilot .
docker run --rm -p 127.0.0.1:8765:8765 -v "$PWD:/workspace:ro" devpilot \
  serve --root /workspace --host 0.0.0.0 --allow-remote
```

The source mount is read-only and API cloud access remains disabled in this example.

## Security and privacy boundary

- Repository files are treated as untrusted data, including READMEs and comments.
- DevPilot never runs build scripts, tests, Git hooks, or repository commands while scanning.
- Symlinks, binary files, oversized files, build directories, `.env` files, common private-key
  names, and likely credential-bearing files are excluded.
- Canonical path checks prevent reads outside the requested repository root.
- Indexes live in the operating-system user cache and consent records in the user state
  directory, outside the scanned repository. Both are permission-hardened; telemetry is absent.
- Loopback Ollama is local by default. A non-loopback Ollama endpoint is treated like a cloud
  provider and requires per-call or remembered per-repository consent. Selected, redacted source
  fragments are shown by the CLI before every approved remote send.
- `map` and `diagram` are the only normal commands that write in the repository, and only to
  the output path requested by the user.

See [PRIVACY.md](PRIVACY.md), [SECURITY.md](SECURITY.md), and
[docs/architecture.md](docs/architecture.md) for the detailed model.

## Supported languages

The scanner identifies many common text formats. v0.1 extracts the strongest symbols and
imports for Python, JavaScript/TypeScript, Go, Rust, Java, and C/C++. Python uses the standard
AST; other languages currently use conservative parser plugins and are explicitly static
approximations. Tree-sitter adapters and language-specific semantic resolution remain on the
roadmap.

| Capability | Python | JS/TS | Go | Rust | Java | C/C++ | Docs/config |
|---|---:|---:|---:|---:|---:|---:|---:|
| Safe indexing | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Symbols/imports | AST | Heuristic | Heuristic | Heuristic | Heuristic | Heuristic | No |
| Source citations | Yes | Yes | Yes | Yes | Yes | Yes | File chunks |
| Full call graph | No | No | No | No | No | No | No |

## Model support

Provider strings use `family/model`, for example `ollama/qwen3-coder`,
`openai/gpt-4.1-mini`, or `anthropic/claude-sonnet-4-5`. OpenAI-compatible gateways can be set
with `DEVPILOT_OPENAI_BASE_URL`. See [MODEL_SUPPORT.md](MODEL_SUPPORT.md).

## Why this is not another coding agent

DevPilot does not edit business code, execute commands, create commits, or open pull requests.
Its job is narrower: establish a durable map and auditable evidence before a developer or a
coding tool changes anything. That boundary reduces both prompt-injection impact and the cost
of evaluating autonomous behavior.

## Development

```bash
uv sync --all-extras
uv run ruff check .
uv run pytest --cov=devpilot --cov-report=term-missing
uv run python scripts/evaluate_retrieval.py evaluation/questions.json .
uv build
```

Architecture decisions live in [`docs/adr/`](docs/adr/). Contributions are welcome; start with
[CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md), and the issue templates.

## Roadmap and limits

The repository includes a reproducible synthetic scan harness under `benchmarks/` and a small
source-citation regression set under `evaluation/`; neither substitutes for the planned
multi-repository, 100-question release evaluation. The next milestones are Tree-sitter adapters,
stronger graph resolution, a public-repository-only Web Demo, and an opt-in GitHub Action. The project will not
claim a complete dynamic call graph from static source. See [ROADMAP.md](ROADMAP.md) for scope.

On the recorded Jetson Orin NX synthetic fixture, 10,000 small Python files scanned in 7.60 s
cold, 2.69 s warm, and 2.68 s after one file changed. These are scanner/index timings, not model
latency, and are not a claim about arbitrary repositories. The exact fixture procedure and
machine metadata are in [benchmarks/](benchmarks/README.md).

DevPilot is licensed under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The installable distribution is named `devpilot-codebase`; the command and product name remain
`devpilot` / DevPilot.
