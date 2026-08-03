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
DevPilot commit. Synthetic results are scanner/index measurements, not model latency or evidence
quality. Do not publish a “60 seconds” claim without naming the fixture and hardware.

## Recorded baseline

The checked-in 2026-08-03 Jetson Orin NX result for 10,000 small Python files measured 7.52 s
cold, 2.69 s warm, and 2.69 s after one file changed. See
[`results/2026-08-03-jetson-orin-nx-10000.json`](results/2026-08-03-jetson-orin-nx-10000.json)
for the device, script hash, byte count, and update counters. This synthetic fixture is much
simpler than a large production repository, so the result is a regression baseline rather than
a universal performance promise.
