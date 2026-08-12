# Reproducible public smoke/regression benchmark

This protocol is a public, reproducible **smoke/regression suite** for RepoLocus. The
six repositories are RepoLocus-authored synthetic fixtures distributed in this
repository. They are not third-party, independent, or production repositories. The
quality results test deterministic regressions on those fixtures and **must not be
extrapolated** to other repositories.

“Public” means that any third party can inspect and rerun the same pinned protocol. It
does not mean that the fixtures were created by third parties.

## Pinned protocol

[`public-benchmark-manifest.json`](public-benchmark-manifest.json) pins every input by
repository-relative path and LF-normalized SHA-256 (`sha256-lf-v1`):

- the fixture/qrel manifest, evaluation runner, and retrieval-metrics runner;
- the v0.2 performance gate manifest and performance runner;
- the unified report runner and JSON Schema; and
- the canonical clean-checkout argument vectors for generating and validating reports.

The report builder imports and executes the hash-pinned Python runners. Run it only from
a trusted RepoLocus source tree (for example, a verified release tag or trusted checkout).
The manifest pins the listed protocol files and detects their drift; it does not establish
trust in an otherwise untrusted checkout or claim to pin every file in the Git revision.

The fixture and qrel provenance is public and fixed as follows. `Tree SHA-256` covers
the fixture's regular files and paths using the evaluator's deterministic tree-hash
algorithm. `Qrels SHA-256` covers the reviewed JSONL qrels file bytes.

| Fixture | Revision | License | Source | Tree SHA-256 | Qrels SHA-256 | Qrels |
|---|---|---|---|---|---|---:|
| `python-small` | `fixture-v4` | Apache-2.0 | RepoLocus-authored synthetic external repository fixture | `52b4bf4cac3311a5eedd16b6bcc17132b5edbbe8586536ee789e78aa6273e624` | `a5daa32634795bc691c16b8fa709ff5604018cd14c3789f901887f82f33128a0` | 17 |
| `cpp-cmake` | `fixture-v4` | Apache-2.0 | RepoLocus-authored synthetic external repository fixture | `7185d1283b111d3c69cfed39394a32cdf4badbeb994755bf49a49f4fef2ba7fe` | `90e1985e4343c0cad698e6b3664505264afe90f5f00cff7136766f20dc70858e` | 17 |
| `rust-cli` | `fixture-v4` | Apache-2.0 | RepoLocus-authored synthetic external repository fixture | `12ea2330dafc6bf2496e7899f2695fc3d098f330ca98a78d238696025148aa88` | `2d48d82dae91b8cc4a2cc076b830c4413ad5e36b89cc8052d02c3df45cb1b714` | 17 |
| `go-service` | `fixture-v4` | Apache-2.0 | RepoLocus-authored synthetic external repository fixture | `b0ca058d6e92b28e6012049428829b4377ac54d15e6f752bbf6ade11e4e134a5` | `25265969549c69dd8b49f4293572c6d2949b5369dfacf34f23e4dbd2f3a51d0d` | 17 |
| `typescript-web` | `fixture-v4` | Apache-2.0 | RepoLocus-authored synthetic external repository fixture | `f13f5ab375511c565f889465a901c4c86950559789c9c517e1fa27da00648ce4` | `518a69fa12f7af51227626e19e8c3a1c9aaaf7393b65a00f066756104dab7bd7` | 17 |
| `java-gradle` | `fixture-v4` | Apache-2.0 | RepoLocus-authored synthetic external repository fixture | `ce898b7c3a0ad37d72df2ffac903bc52267d16175d770c31d1120a93dfb37a9f` | `1270bf60a61f4e36f1610e26a3d1064de50b8ab82c68312b7f7ba053cbd03771` | 17 |

The evaluator additionally verifies the reviewed qrel provenance ledger pinned by
`evaluation/external-manifest.json`. A provenance, license, revision, file, qrel, or
runner hash mismatch fails closed before the unified report is written. Every serialized
outcome must match exactly one pinned `fixture`/`case_id`, and all per-case metrics are
independently recomputed from the pinned qrel truth and serialized retrieval evidence.

## Reproduce from a clean checkout

Use Python 3.10 or newer and install the locked development environment:

```console
uv sync --all-extras --locked
```

The tracked `benchmarks/results/.gitignore` ensures that the output directory exists
in a clean checkout while generated reports stay out of Git. The commands below are
the protocol's **canonical clean-checkout reproduction vectors**: start from a trusted
RepoLocus checkout containing this manifest (normally its verified release tag), leave
every tracked protocol input unchanged, install the locked environment, and run the
vectors from the repository root in order. The manifest stores these vectors as data
and the report runner rejects drift in them or in any hash-pinned protocol file.

CI transports the evaluation and performance reports between jobs as downloaded
artifacts, so its final report step may pass equivalent downloaded input paths instead
of `benchmarks/results/public-evaluation.json` and
`benchmarks/results/public-performance.json`. That path substitution is transport
only: the reports must still come from the pinned upstream vectors and pass the same
fixture, revision, license, manifest, gate, and provenance validation. The canonical
vectors embedded in the public report remain the clean-checkout commands below. The CI
artifact includes both transported input reports, the manifest, the schema, and the
generated JSON/Markdown report so the substitution is auditable.

This verifier has a deliberate trust boundary. Run it only from a trusted RepoLocus
checkout whose listed protocol files match the manifest, normally the verified release
tag associated with a published report. To recompute metrics and gates it loads and
executes the hash-pinned evaluation, retrieval, and performance Python modules from that
source tree. The hash checks detect drift from the manifest; they are not a sandbox for
arbitrary Python, and the manifest does not pin the Git commit or every file in the
checkout. Treat downloaded evaluation/performance reports as data, and never execute a
verifier or protocol modules supplied only by an untrusted result bundle.

Generate the quality input report directly from the pinned fixtures and reviewed
qrels:

```console
uv run python scripts/evaluate_external_repositories.py evaluation --output benchmarks/results/public-evaluation.json
```

Generate the resource, latency, and index-cost input report from the pinned 1,000-file
v0.2 synthetic fixture manifest:

```console
uv run python benchmarks/benchmark_v020.py --manifest benchmarks/v0.2-gates.json --output benchmarks/results/public-performance.json
```

Validate both inputs and generate canonical JSON plus a human-readable Markdown
report:

```console
uv run python scripts/public_benchmark_report.py --manifest benchmarks/public-benchmark-manifest.json --evaluation-report benchmarks/results/public-evaluation.json --performance-report benchmarks/results/public-performance.json --json-output benchmarks/results/public-report.json --markdown-output benchmarks/results/public-report.md
```

Finally, prove that the generated reports are byte-for-byte current:

```console
uv run python scripts/public_benchmark_report.py --manifest benchmarks/public-benchmark-manifest.json --evaluation-report benchmarks/results/public-evaluation.json --performance-report benchmarks/results/public-performance.json --json-output benchmarks/results/public-report.json --markdown-output benchmarks/results/public-report.md --check
```

Do not copy commands from this document into automation without also validating them
against the manifest. The runner rejects altered command vectors and protocol files.

## Unified report

The canonical JSON conforms to
[`public-benchmark-report.schema.json`](public-benchmark-report.schema.json). The
report contains these measurement families together so no single favorable number is
presented without the other costs and safeguards:

- **Accuracy:** hit rate, macro recall at `k`, mean reciprocal rank, and citation
  recall over the reviewed synthetic qrels.
- **No-answer behavior:** accuracy, precision, recall, and F1 for queries whose
  reviewed answer is no evidence.
- **Safety:** duplicate-evidence and must-not-return violation rates.
- **Query latency:** isolated-worker wall time in seconds for symbol, dependency, and
  retrieval queries.
- **Peak memory:** peak resident-set bytes for every indexed operation. Linux reports
  `ru_maxrss` converted to bytes, macOS reports its byte value, and Windows reports
  peak working-set bytes.
- **Index cost:** scan wall/CPU seconds, peak RSS, issued SQLite statement count,
  database bytes, and WAL bytes.

Quality results are deterministic for the recorded implementation digest and pinned
fixture/qrel protocol. Timing, CPU, and peak RSS
depend on the host, operating system, filesystem, load, and Python build; the report
therefore records the environment and should only be compared on equivalent hardware
and protocol revisions. Passing both embedded gates means **reproducible
smoke/regression verdict**, not production-repository quality.

## Competitor policy

RepoWiki, DeepWiki, and Sourcebot are explicitly reported as `N/A`. This protocol has
not pinned an equivalent public input, revision, runner, environment, and metric
definition for any of them. No marketing number or differently measured result is
substituted. A future comparison may be populated only after an equivalent public
protocol is reproducible by third parties; until then, protocol and metric fields
remain `null`.
