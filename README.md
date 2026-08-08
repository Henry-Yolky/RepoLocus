# RepoLocus

> Understand an unfamiliar codebase with a project map, a reproducible architecture graph,
> and answers backed by file-and-line evidence.

RepoLocus is a read-only, local-first repository understanding tool. It scans source without
executing repository commands, builds a local SQLite/FTS index, writes a stable
`PROJECT_MAP.md`, generates validated Mermaid, and retrieves evidence for code questions.
It works without an LLM; Ollama and explicitly approved cloud providers can add a narrative
answer on top of the same evidence.

> **Alpha:** this repository implements the CLI-first v0.2 baseline. Static dependency and
> call relationships are approximations, and the hosted public-repository Web Demo described
> in the roadmap is not part of this release.

## Quick start

RepoLocus requires Python 3.10 or newer.

For a tagged version that is available on PyPI:

```bash
pipx install repolocus
```

If that version has not been published to PyPI yet, install from a source checkout instead:

```bash
git clone https://github.com/Henry-Yolky/RepoLocus.git
pipx install ./RepoLocus
```

Then run RepoLocus inside the repository you want to inspect:

```bash
cd your-repository
repolocus scan
repolocus map
repolocus ask "Where is configuration validated?"
repolocus diagram
```

For a development checkout:

```bash
cd /path/to/repolocus
uv sync --all-extras
uv run repolocus doctor --security
uv run pytest
```

The default `local` answer mode does not make a network request. A local model is explicit:

```bash
repolocus ask "How does a request reach the core loop?" --model ollama/qwen3-coder
```

Every remote CLI call first prints the model, canonical destination endpoint, exact serialized
payload size, credential-free transport route, and redacted source fragments selected for that
send, including calls covered by a remembered grant. Ambient `HTTP_PROXY`, `HTTPS_PROXY`, and
`ALL_PROXY` variables are ignored by default. Select `--proxy-mode environment` to opt in to
environment discovery, or provide `--proxy-mode explicit --proxy-url URL`; loopback providers
remain direct. Use `--allow-cloud` for one call, or add `--remember-consent` to remember that exact
provider endpoint and transport route for the current repository:

```bash
export OPENAI_API_KEY=...
repolocus ask "Where is configuration validated?" \
  --model openai/gpt-4.1-mini --allow-cloud
```

Remembered-consent format v4 binds a grant to the current repository identity, canonical path,
provider, complete destination endpoint, and exact credential-free direct/proxy route identity.
Proxy credentials are excluded from both that identity and the consent file or preview. Replacing
the directory or its Git marker, or changing an endpoint, proxy mode, or proxy route therefore
requires fresh consent; rotating credentials for the same route does not. Legacy v1-v3 grants are
intentionally ignored after upgrade.

## What it produces

`repolocus map` writes a deterministic `PROJECT_MAP.md` with:

- repository purpose and onboarding files;
- layout, entry points, modules, static dependency flow, configuration, and tests;
- a suggested reading order;
- source links and `Confirmed`, `Inferred`, or `Needs review` labels.

`repolocus diagram` writes `ARCHITECTURE.md`. The Mermaid source is constructed from a small,
validated AST-like subset, not accepted directly from a model. The evidence tables keep a
representative source for each node and one concrete import witness for every rendered edge.

On POSIX, replacing an existing output preserves its previous contents in a reported hidden
`.rollback` file. Remove that recovery file manually only when other repository writers are
quiescent. New documents use atomic create-if-absent publication and do not leave a recovery file.

`repolocus ask` combines exact symbols, SQLite FTS5/BM25, a deterministic term index, and
dependency-neighbor evidence. The term index splits camelCase, snake_case, and path components,
and adds bigrams and trigrams for contiguous CJK text. Users can add explicit retrieval synonyms
with bounded JSON in `REPOLOCUS_QUERY_SYNONYMS`, for example
`{"configuration":["config","settings"]}`; repository-controlled configuration cannot set them.

If no model is selected, the answer is an extractive evidence bundle. For a model answer, every
material claim must be followed immediately by an `Evidence quote` containing an exact source
substring and the same citation. Validation checks only that the citation address is inside the
retrieved evidence and that the quote occurs there; it does not prove that the quote semantically
supports the claim. A model answer that passes these checks is still labeled `needs_review`.

## Commands

| Command | Purpose |
|---|---|
| `repolocus scan [PATH]` | Securely scan and incrementally update the local index |
| `repolocus status [PATH]` | Show content generation, scan revision, and component fingerprints |
| `repolocus map [PATH]` | Generate `PROJECT_MAP.md` or print it with `--stdout` |
| `repolocus ask QUESTION [PATH]` | Retrieve source-backed evidence and optionally use a model |
| `repolocus diagram [PATH]` | Generate validated Mermaid in `ARCHITECTURE.md` |
| `repolocus privacy status` | Show remembered per-repository/provider/endpoint consent |
| `repolocus privacy preview QUESTION` | Show fragments a question would send |
| `repolocus privacy revoke` | Forget cloud-provider consent |
| `repolocus doctor --security` | Check runtime, FTS5, cache permissions, and local-model reachability |
| `repolocus clean` | Remove the current repository index after confirmation |
| `repolocus serve` | Start the optional self-hosted FastAPI service |

Every command accepts `--help`. Use `--json` on automation-friendly commands where available.
`map`, `diagram`, and `ask` default to `--refresh auto`: they perform a bounded incremental refresh
before querying, while an exact cache hit reads no source content and writes no SQLite transaction.
`--refresh always` securely rereads and hashes every candidate but can reuse compatible parser
facts; `--refresh rebuild` reparses every source file. Use `--refresh never` only when explicitly
pinning the last compatible committed snapshot. `repolocus status` reports the retrieval-visible
content generation separately from the diagnostic scan revision.
The Python `RepoLocusService.scan()` result keeps unchanged files metadata-only (including cached
fact counts). `map()`, `diagram()`, and `evidence()` also consume bounded index projections; use
the `RepositoryIndex` query methods when a caller explicitly needs stored facts. The
`RepoLocusService.evidence()` compatibility API returns an evidence list, while
`evidence_result()` returns the structured intent, confidence, rejection reason, fusion hits, and
suppression diagnostics alongside the same evidence.

Add `--follow-up` to `ask` for a non-persistent in-memory question session; entering a blank line
ends it. The first answer pins the content generation, and every follow-up uses that exact
generation with refresh disabled. The session fails closed if retrieval-visible facts change, but
a diagnostics-only scan revision does not invalidate the evidence snapshot.
Follow-up context is never written to the repository or consent state.

## Agent Skill

The repository ships a local-only Codex Skill at
[`skills/repolocus-analyze-repo`](https://github.com/Henry-Yolky/RepoLocus/tree/main/skills/repolocus-analyze-repo).
Its adapter exposes `doctor`,
`scan`, `ask`, `map`, and `diagram` while forcing extractive local answers and sending generated
documents to stdout instead of writing them into the target repository.

GitHub Releases provide the Skill separately as `repolocus-analyze-repo-VERSION.zip`. Extract that
archive as `$CODEX_HOME/skills/repolocus-analyze-repo`, where `CODEX_HOME` defaults to
`~/.codex`. From a source checkout, install RepoLocus and copy the Skill with:

```bash
pipx install .
export CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
mkdir -p "$CODEX_HOME/skills"
cp -R skills/repolocus-analyze-repo "$CODEX_HOME/skills/"
```

PowerShell equivalent:

```powershell
pipx install .
if (-not $env:CODEX_HOME) { $env:CODEX_HOME = Join-Path $HOME ".codex" }
New-Item -ItemType Directory -Force (Join-Path $env:CODEX_HOME "skills") | Out-Null
Copy-Item -Recurse -Force "skills/repolocus-analyze-repo" (Join-Path $env:CODEX_HOME "skills")
```

Restart Codex after copying the directory, or reload its Skill registry when the host provides
that action. Then invoke the Skill as `$repolocus-analyze-repo`. It intentionally exposes no
cloud-consent flags; an agent cannot silently send repository content to a remote provider
through this path. The Skill archive contains the adapter, not a RepoLocus runtime. A compatible
`>=0.2.0,<0.3.0` installed runtime or pre-synchronized trusted source checkout must already exist; adapter
operations stay offline and fail closed instead of downloading or synchronizing dependencies.

## Self-hosted API

Install the API extra with `pipx install 'repolocus[api]'`, then constrain the server to
one repository tree:

```bash
repolocus serve --root /path/to/allowed/repositories
```

The default bind address is loopback and cloud requests are disabled. On each start RepoLocus uses
a random Bearer token, printed once to stderr; set `REPOLOCUS_API_TOKEN` to supply a stable token.
Every request requires `Authorization: Bearer TOKEN` and an allowed `Host` header. Request bodies
and concurrent work are bounded, and `/v1/` responses use `Cache-Control: no-store`.

Cloud-backed API questions additionally require the operator-only `--allow-cloud-api` flag and a
two-stage request. `POST /v1/ask/preview` returns a short-lived, single-use `preview_id`; approving
it with `POST /v1/ask/previews/{preview_id}/approve` sends the exact frozen evidence and serialized
request body from that preview without rescanning. API clients cannot create persistent cloud
grants, even when the operator enables cloud requests.

A non-loopback bind requires all of `--allow-remote`, at least one `--allowed-host`, and a TLS
certificate/key pair supplied with `--ssl-certfile` and `--ssl-keyfile`. The built-in preview store
is process-local, so the two-stage flow assumes the single-worker server started by `repolocus
serve`.

The Docker image is dependency-locked and also defaults to container loopback. For a local-only
published port, explicitly bind Uvicorn inside the container while limiting the host publish to
`127.0.0.1`:

```bash
docker build -t repolocus .
docker run --rm -p 127.0.0.1:8765:8765 \
  -e REPOLOCUS_API_TOKEN="$REPOLOCUS_API_TOKEN" \
  -v "$PWD:/workspace:ro" -v "/path/to/tls:/run/repolocus-tls:ro" repolocus \
  serve --root /workspace --host 0.0.0.0 --allow-remote --allowed-host localhost \
  --ssl-certfile /run/repolocus-tls/server.crt \
  --ssl-keyfile /run/repolocus-tls/server.key
```

The source mount is read-only and API cloud access remains disabled in this example.

## Security and privacy boundary

- Repository files are treated as untrusted data, including READMEs and comments.
- RepoLocus never runs build scripts, tests, Git hooks, or repository commands while scanning.
- Symlinks, binary files, oversized files, build directories, `.env` files, common private-key
  names, and likely credential-bearing files are excluded.
- Canonical path checks prevent reads outside the requested repository root.
- Indexes live in the operating-system user cache and consent records in the user state
  directory, outside the scanned repository. POSIX permissions are hardened. On Windows,
  `doctor --security` reports ACL verification as unavailable until native ACL inspection is
  implemented, instead of claiming an unverified success. Telemetry is absent.
- Loopback Ollama is local by default. A non-loopback Ollama endpoint is treated like a cloud
  provider and requires per-call or remembered per-repository-and-endpoint consent. Selected,
  redacted source fragments and the exact destination and payload size are shown by the CLI before
  every approved remote send.
- Plain HTTP provider endpoints are limited to loopback addresses. Every non-loopback endpoint
  requires HTTPS, and provider prompts are redacted again immediately before transport.
- `map` and `diagram` are the only normal commands that write in the repository, and only to
  the output path requested by the user. Their same-directory atomic writer rejects symlinked
  components. POSIX uses descriptor-relative traversal plus atomic name exchange; Windows uses
  reparse-point and identity checks before and after its handle-backed replacement and fails when
  it detects a race. If post-commit identity becomes ambiguous, RepoLocus reports and preserves
  the recoverable temporary or backup name instead of deleting an unverified object.

See [PRIVACY.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/PRIVACY.md),
[SECURITY.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/SECURITY.md), and
[docs/architecture.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/docs/architecture.md)
for the detailed model.

## Supported languages

The scanner identifies many common text formats. Python uses the standard AST. Installing the
`treesitter` extra adds native syntax ranges for C, C++, JavaScript, TypeScript, and Rust while
retaining deterministic heuristic fallback; Go, Java, documentation, and configuration parsing
remain conservative static approximations. Dependency extraction stays lexical and never executes
project code or build metadata.

| Capability | Python | JS/TS | Go | Rust | Java | C/C++ | Docs/config |
|---|---:|---:|---:|---:|---:|---:|---:|
| Safe indexing | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Symbols/imports | AST | Tree-sitter*/heuristic | Heuristic | Tree-sitter*/heuristic | Heuristic | Tree-sitter*/heuristic | Heuristic |
| Source citations | Yes | Yes | Yes | Yes | Yes | Yes | File chunks |
| Full call graph | No | No | No | No | No | No | No |

\* Tree-sitter is enabled only when the optional `treesitter` extra is installed.

## Model support

Provider strings use `family/model`, for example `ollama/qwen3-coder`,
`openai/gpt-4.1-mini`, or `anthropic/claude-sonnet-4-5`. OpenAI-compatible gateways can be set
with `REPOLOCUS_OPENAI_BASE_URL`. See
[MODEL_SUPPORT.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/MODEL_SUPPORT.md).

## Why this is not another coding agent

RepoLocus does not edit business code, execute commands, create commits, or open pull requests.
Its job is narrower: establish a durable map and auditable evidence before a developer or a
coding tool changes anything. That boundary reduces both prompt-injection impact and the cost
of evaluating autonomous behavior.

## Development

```bash
uv sync --all-extras
uv run ruff check .
uv run pytest --cov=repolocus --cov-report=term-missing
uv run python scripts/evaluate_retrieval.py evaluation/questions.dataset .
uv run python scripts/evaluate_external_repositories.py evaluation
uv build
```

The retrieval report includes per-case recall@k, reciprocal rank, nDCG@k, expected-path coverage,
and citation recall, plus aggregate macro recall, MRR, mean nDCG, any/all-path rates,
no-answer precision/recall/F1/accuracy, `must_not_return` violations, and per-language,
per-repository, and per-query-type breakdowns. Answerable retrieval and no-answer classification
are aggregated separately. The self dataset remains a smoke test; the fixed six-repository,
102-qrel reviewed fixture set is the v0.2 CI/release gate, including citation recall >= 1.0 and
explicit minimum answerable, no-answer, citation, and query-type coverage.

Architecture decisions live in
[`docs/adr/`](https://github.com/Henry-Yolky/RepoLocus/tree/main/docs/adr). Contributions are
welcome; start with
[CONTRIBUTING.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/CONTRIBUTING.md),
[CHANGELOG.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/CHANGELOG.md), and the
[issue templates](https://github.com/Henry-Yolky/RepoLocus/issues/new/choose).

## Roadmap and limits

The repository includes reproducible synthetic scan and indexed-workflow gates under
`benchmarks/`, a self-retrieval smoke set, and a fixed multi-repository release gate under
`evaluation/`. Fixture source, revision, license, tree digest, qrel digest, and review status are
recorded for all 102 qrels. v0.2 adds optional Tree-sitter adapters, an indexed
resolved dependency graph, projection-only map/diagram reads, and structured RRF retrieval. The
next milestones include a public-repository-only Web Demo and an opt-in GitHub Action. The
project will not claim a complete dynamic call graph from static source. See
[ROADMAP.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/ROADMAP.md) for scope.

On the recorded Jetson Orin NX synthetic fixture, 10,000 small Python files scanned in 7.54 s
cold, 2.70 s warm, and 2.69 s after one file changed. These are scanner/index timings, not model
latency, and are not a claim about arbitrary repositories. The exact fixture procedure and
machine metadata are in
[benchmarks/](https://github.com/Henry-Yolky/RepoLocus/blob/main/benchmarks/README.md).

RepoLocus is licensed under Apache-2.0. See
[LICENSE](https://github.com/Henry-Yolky/RepoLocus/blob/main/LICENSE) and
[NOTICE](https://github.com/Henry-Yolky/RepoLocus/blob/main/NOTICE).

The installable distribution and command are both named `repolocus`; the product name is
RepoLocus.
