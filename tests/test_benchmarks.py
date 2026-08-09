from __future__ import annotations

import hashlib
import importlib.util
import json
import math
from pathlib import Path
from types import ModuleType

import pytest

_METRICS = (
    "wall_seconds",
    "cpu_seconds",
    "peak_rss_bytes",
    "sqlite_query_count",
    "database_bytes",
    "wal_bytes",
)


def _benchmark_module() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "benchmarks" / "benchmark_v020.py"
    spec = importlib.util.spec_from_file_location("repolocus_benchmark_v020", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _repository() -> Path:
    return Path(__file__).resolve().parents[1]


def _measurement(operation: str, **overrides: object) -> dict[str, object]:
    measurement: dict[str, object] = {
        "name": operation,
        "wall_seconds": 1.0,
        "cpu_seconds": 1.0,
        "peak_rss_bytes": 1_000,
        "sqlite_query_count": 2,
        "database_bytes": 2_000,
        "wal_bytes": 0,
        "worker_pid": 123,
    }
    measurement.update(overrides)
    return measurement


def _thresholds(benchmark: ModuleType) -> dict[str, object]:
    limits = {
        "maximum_wall_seconds": 10,
        "maximum_cpu_seconds": 10,
        "maximum_peak_rss_bytes": 10_000,
        "maximum_sqlite_query_count": 10,
        "maximum_database_bytes": 10_000,
        "maximum_wal_bytes": 10_000,
        "baseline_sqlite_query_count": 2,
        "maximum_query_regression_ratio": 1.1,
    }
    return {operation: dict(limits) for operation in benchmark._OPERATIONS}


def test_v020_versioned_manifests_fix_scale_and_baseline_provenance() -> None:
    benchmark = _benchmark_module()
    script = _repository() / "benchmarks" / "benchmark_v020.py"
    script_sha256 = benchmark._script_sha256()
    expected_scales = {
        "v0.2-gates.json": (1_000, 5_000, 990, 5_000_000),
        "v0.2-scale-gates.json": (100_000, 500_000, 99_000, 512_000_000),
    }

    for name, (files, symbols, dependencies, source_bytes) in expected_scales.items():
        manifest = json.loads((script.parent / name).read_text(encoding="utf-8"))
        assert manifest["version"] == 1
        assert manifest["files"] == files
        assert manifest["minimum_symbols"] == symbols
        assert manifest["minimum_dependencies"] == dependencies
        assert manifest["minimum_source_bytes"] == source_bytes
        baseline = manifest["baseline"]
        assert baseline["benchmark_script_sha256"] == script_sha256
        assert baseline["implementation_sha256"] == benchmark._implementation_sha256()
        assert baseline["date"]
        assert baseline["python"]
        assert baseline["platform"]
        assert baseline["repolocus_version"] == "0.2.0"
        assert baseline["hardware"]["cpu_visible_to_process"] > 0
        assert set(baseline["operations"]) == set(benchmark._OPERATIONS)
        assert set(manifest["thresholds"]) == set(benchmark._OPERATIONS)

        for operation in benchmark._OPERATIONS:
            measurement = baseline["operations"][operation]
            limits = manifest["thresholds"][operation]
            for metric in _METRICS:
                value = measurement[metric]
                maximum = limits[f"maximum_{metric}"]
                assert not isinstance(value, bool)
                assert isinstance(value, (int, float)) and math.isfinite(value) and value >= 0
                assert maximum >= value
            assert limits["baseline_sqlite_query_count"] == measurement["sqlite_query_count"]
            relative_query_limit = max(
                1,
                int(
                    limits["baseline_sqlite_query_count"] * limits["maximum_query_regression_ratio"]
                ),
            )
            assert relative_query_limit < limits["maximum_sqlite_query_count"]


def test_v020_provenance_hash_normalizes_checkout_line_endings() -> None:
    benchmark = _benchmark_module()
    lf = b"first\nsecond\n"
    crlf = b"first\r\nsecond\r\n"

    assert benchmark._canonical_bytes(lf) == benchmark._canonical_bytes(crlf)
    assert (
        hashlib.sha256(benchmark._canonical_bytes(lf)).hexdigest()
        == hashlib.sha256(benchmark._canonical_bytes(crlf)).hexdigest()
    )


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_v020_benchmark_rejects_nonfinite_manifest_numbers(tmp_path: Path, constant: str) -> None:
    benchmark = _benchmark_module()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(f'{{"version": 1, "files": {constant}}}', encoding="utf-8")

    with pytest.raises(ValueError, match="non-finite number"):
        benchmark.run_benchmark(manifest)


def test_v020_fixture_entry_limit_includes_directories() -> None:
    benchmark = _benchmark_module()

    assert benchmark._fixture_entry_limit(60) == 62
    assert benchmark._fixture_entry_limit(100_000) == 101_001


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ('{"version": true}', "version is invalid"),
        ('{"version": 1, "version": 1}', "duplicate key"),
    ],
)
def test_v020_benchmark_rejects_ambiguous_manifest_json(
    tmp_path: Path, payload: str, message: str
) -> None:
    benchmark = _benchmark_module()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(payload, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        benchmark.run_benchmark(manifest)


@pytest.mark.parametrize(
    ("metric", "value"),
    [
        ("wall_seconds", "NaN"),
        ("cpu_seconds", -1.0),
        ("sqlite_query_count", 1.5),
        ("worker_pid", 0),
    ],
)
def test_v020_gate_rejects_invalid_worker_measurements(metric: str, value: object) -> None:
    benchmark = _benchmark_module()
    measurements = {operation: _measurement(operation) for operation in benchmark._OPERATIONS}
    measurements["scan"][metric] = value

    with pytest.raises(ValueError, match="scan"):
        benchmark._gate(measurements, _thresholds(benchmark))


def test_v020_gate_reports_absolute_and_relative_regressions() -> None:
    benchmark = _benchmark_module()
    measurements = {operation: _measurement(operation) for operation in benchmark._OPERATIONS}
    measurements["scan"]["wall_seconds"] = 11.0
    measurements["retrieval"]["sqlite_query_count"] = 3

    passed, violations = benchmark._gate(measurements, _thresholds(benchmark))

    assert passed is False
    assert any("scan.wall_seconds" in violation for violation in violations)
    assert any("retrieval.sqlite_query_count" in violation for violation in violations)


def test_v020_worker_timeout_removes_stale_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    benchmark = _benchmark_module()
    output = tmp_path / "worker.json"
    output.write_text("stale", encoding="utf-8")

    def timeout(*args: object, **kwargs: object) -> None:
        raise benchmark.subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(benchmark.subprocess, "run", timeout)

    with pytest.raises(RuntimeError, match="worker scan exceeded"):
        benchmark._run_worker(
            "scan",
            tmp_path,
            tmp_path,
            output,
            fixture_files=1,
            generation=0,
            maximum_wall_seconds=5,
            scan_deadline_seconds=5,
        )
    assert not output.exists()


def test_v020_worker_rejects_mismatched_operation_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    benchmark = _benchmark_module()
    output = tmp_path / "worker.json"

    def completed(*args: object, **kwargs: object) -> object:
        output.write_text(json.dumps({"measurement": _measurement("diagram")}), encoding="utf-8")
        return benchmark.subprocess.CompletedProcess(args[0], 0, "", "")

    monkeypatch.setattr(benchmark.subprocess, "run", completed)

    with pytest.raises(RuntimeError, match="mismatched operation name"):
        benchmark._run_worker(
            "map",
            tmp_path,
            tmp_path,
            output,
            fixture_files=1,
            generation=0,
            maximum_wall_seconds=5,
            scan_deadline_seconds=5,
        )


@pytest.mark.parametrize(
    ("operation", "assertion"),
    [
        ("map", {"indexed_files": 0, "symbols": 0}),
        ("diagram", {"valid_mermaid": False, "group": "wrong"}),
        ("symbol_query", {"path": "wrong.py", "symbol": "wrong"}),
        (
            "dependency_query",
            {"source_path": "wrong.py", "target_path": "wrong.py", "direction": "dependent of"},
        ),
        (
            "retrieval",
            {
                "path": "wrong.py",
                "symbol": "wrong",
                "citation": "wrong.py:1",
                "intent": "natural_language",
            },
        ),
    ],
)
def test_v020_worker_report_rejects_wrong_operation_evidence(
    operation: str, assertion: dict[str, object]
) -> None:
    benchmark = _benchmark_module()
    report = {"measurement": _measurement(operation), "assertion": assertion}

    with pytest.raises(RuntimeError, match="invalid report"):
        benchmark._validate_worker_report(operation, report, fixture_files=60)


def test_v020_cli_returns_failure_for_gate_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    benchmark = _benchmark_module()
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        benchmark,
        "run_benchmark",
        lambda _path: {"gate": {"passed": False, "violations": ["regression"]}},
    )
    monkeypatch.setattr(benchmark.sys, "argv", ["benchmark_v020.py", "--manifest", str(manifest)])

    assert benchmark.main() == 1


def test_v020_benchmark_covers_every_versioned_operation(tmp_path: Path) -> None:
    benchmark = _benchmark_module()
    operation_limits = {
        "maximum_wall_seconds": 30,
        "maximum_cpu_seconds": 30,
        "maximum_peak_rss_bytes": 2_147_483_648,
        "maximum_sqlite_query_count": 1_000_000,
        "maximum_database_bytes": 268_435_456,
        "maximum_wal_bytes": 268_435_456,
        "baseline_sqlite_query_count": 1_000_000,
        "maximum_query_regression_ratio": 1.1,
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "files": 60,
                "scan_deadline_seconds": 30,
                "minimum_symbols": 300,
                "minimum_dependencies": 59,
                "minimum_source_bytes": 250_000,
                "thresholds": {operation: operation_limits for operation in benchmark._OPERATIONS},
            }
        ),
        encoding="utf-8",
    )

    report = benchmark.run_benchmark(manifest)

    assert report["files"] == 60
    assert report["symbols"] == 300
    assert report["dependencies"] >= 59
    assert report["gate"] == {"passed": True, "violations": []}
    assert set(report["operations"]) == set(benchmark._OPERATIONS)
    worker_pids = {measurement["worker_pid"] for measurement in report["operations"].values()}
    assert len(worker_pids) == len(benchmark._OPERATIONS)
    for measurement in report["operations"].values():
        assert measurement["wall_seconds"] >= 0
        assert measurement["cpu_seconds"] >= 0
        assert measurement["peak_rss_bytes"] > 0
        assert measurement["sqlite_query_count"] >= 0
        assert measurement["database_bytes"] > 0
        assert measurement["wal_bytes"] >= 0
