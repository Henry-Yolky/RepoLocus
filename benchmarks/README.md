# Reproducible scan benchmark

`benchmark_scan.py` creates a temporary, deterministic Python repository and measures cold,
warm, and one-file-change scans. It never executes fixture code. Its index cache lives beside
the temporary fixture, so the default run removes both instead of leaving an orphan user-cache
entry; `--keep` reports both paths for inspection.

```bash
uv run python benchmarks/benchmark_scan.py --files 1000
uv run python benchmarks/benchmark_scan.py --files 10000
uv run python benchmarks/benchmark_scan.py --files 100000
```

Report the generated JSON together with CPU, storage, operating system, Python version, and
RepoLocus commit. Synthetic results are scanner/index measurements, not model latency or evidence
quality. Do not publish a “60 seconds” claim without naming the fixture and hardware.

## Recorded baseline

The checked-in 2026-08-03 Jetson Orin NX result for 10,000 small Python files measured 7.54 s
cold, 2.70 s warm, and 2.69 s after one file changed. See
[`results/2026-08-03-jetson-orin-nx-10000.json`](results/2026-08-03-jetson-orin-nx-10000.json)
for the device, script hash, byte count, and update counters. This synthetic fixture is much
simpler than a large production repository, so the result is a regression baseline rather than
a universal performance promise.

## v0.2 indexed-workflow gate

`benchmark_v020.py` generates a deterministic import graph and measures scan, project map,
Mermaid diagram, symbol query, dependency-neighbor query, and fused retrieval. Every operation
is isolated in a fresh worker with an operation-level timeout and records wall time, CPU time,
process peak RSS, application-issued SQLite statement count, database bytes, and WAL bytes.
Absolute ceilings and relative SQLite-query regression limits live in the versioned manifest
rather than being selected by the current CI run. Each checked-in baseline records the benchmark
script hash and a deterministic digest of the measured RepoLocus implementation.

```bash
uv run python benchmarks/benchmark_v020.py --manifest benchmarks/v0.2-gates.json
```

`v0.2-gates.json` contains 1,000 files, 5,000 symbols, and at least 5 MB of source for the
repeatable pull-request gate. The release workflow additionally runs `v0.2-scale-gates.json`,
which fixes the acceptance scale at 100,000 files, 500,000 symbols, at least 99,000 dependency
edges, and at least 512 MB of source. Use
`benchmark_scan.py` for the separately documented cold/warm/incremental scanner profiles.
