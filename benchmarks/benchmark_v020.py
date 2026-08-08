#!/usr/bin/env python3
"""Run the versioned v0.2 scan, projection, graph, and retrieval benchmark gate."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from repolocus import __version__
from repolocus.config import Settings
from repolocus.core import RepoLocusService
from repolocus.generators import MermaidGenerator, ProjectMapGenerator, validate_mermaid
from repolocus.index import RepositoryIndex
from repolocus.retrieval import RetrievalEngine

_OPERATIONS = (
    "scan",
    "map",
    "diagram",
    "symbol_query",
    "dependency_query",
    "retrieval",
)
_METRICS = (
    "wall_seconds",
    "cpu_seconds",
    "peak_rss_bytes",
    "sqlite_query_count",
    "database_bytes",
    "wal_bytes",
)
_INTEGER_METRICS = frozenset(
    {"peak_rss_bytes", "sqlite_query_count", "database_bytes", "wal_bytes", "worker_pid"}
)
_FIXTURE_FILES_PER_SHARD = 100
_FIXTURE_DOCSTRING_PADDING = " " * 900
_FIXTURE_MAX_BYTES_PER_FILE = 6_000


def _canonical_bytes(payload: bytes) -> bytes:
    """Normalize text checkout line endings before computing provenance hashes."""

    return payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _script_sha256() -> str:
    return hashlib.sha256(_canonical_bytes(Path(__file__).read_bytes())).hexdigest()


def _implementation_sha256() -> str:
    repository = Path(__file__).resolve().parents[1]
    paths = [repository / "pyproject.toml", repository / "uv.lock"]
    paths.extend(sorted((repository / "src" / "repolocus").rglob("*.py")))
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(repository).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        payload = _canonical_bytes(path.read_bytes())
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _populate(root: Path, count: int) -> None:
    for number in range(count):
        shard_number = number // _FIXTURE_FILES_PER_SHARD
        shard = root / "src" / f"group_{shard_number:04d}"
        shard.mkdir(parents=True, exist_ok=True)
        functions: list[str] = []
        for offset in range(5):
            body = f"    return value + {number + offset}\n"
            if offset == 0 and number % 100:
                previous_number = number - 1
                body = (
                    f"    from .module_{previous_number:06d} "
                    f"import function_{previous_number:06d}_0\n"
                    f"    return function_{previous_number:06d}_0(value) + {number}\n"
                )
            functions.append(
                f"def function_{number:06d}_{offset}(value: int) -> int:\n"
                f'    """Return fixture value {offset} for module {number}. '
                f'{_FIXTURE_DOCSTRING_PADDING}"""\n' + body
            )
        (shard / f"module_{number:06d}.py").write_text(
            "".join(functions),
            encoding="utf-8",
        )


def _fixture_entry_limit(files: int) -> int:
    """Return the exact scanner entry budget for the generated fixture tree."""

    shard_directories = (files + _FIXTURE_FILES_PER_SHARD - 1) // _FIXTURE_FILES_PER_SHARD
    return files + shard_directories + 1  # files, shard directories, and ``src``


def _peak_rss_bytes() -> int:
    if sys.platform == "win32":  # pragma: no cover - exercised by Windows CI

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        process = ctypes.windll.kernel32.GetCurrentProcess()  # type: ignore[attr-defined]
        succeeded = ctypes.windll.psapi.GetProcessMemoryInfo(  # type: ignore[attr-defined]
            process, ctypes.byref(counters), counters.cb
        )
        if not succeeded:
            raise OSError("GetProcessMemoryInfo failed")
        return int(counters.PeakWorkingSetSize)

    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def _storage_bytes(index_path: Path) -> tuple[int, int]:
    database = index_path.stat().st_size if index_path.is_file() else 0
    wal = Path(f"{index_path}-wal")
    return database, wal.stat().st_size if wal.is_file() else 0


def _traced(index: RepositoryIndex, action: Callable[[], Any]) -> tuple[Any, int]:
    queries = 0

    def record(statement: str) -> None:
        nonlocal queries
        # SQLite exposes FTS5 shadow-table reads as trace lines prefixed with
        # ``--``. They are virtual-table implementation detail, not separate
        # application-issued queries and would make the count corpus-dependent.
        if not statement.lstrip().startswith("--"):
            queries += 1

    index._connection.set_trace_callback(record)
    try:
        return action(), queries
    finally:
        index._connection.set_trace_callback(None)


def _measure(
    name: str,
    action: Callable[[], tuple[Any, int, Path, tuple[int, int] | None]],
) -> tuple[dict[str, int | float | str], Any]:
    cpu_started = time.process_time()
    wall_started = time.perf_counter()
    payload, queries, index_path, storage = action()
    wall_seconds = time.perf_counter() - wall_started
    cpu_seconds = time.process_time() - cpu_started
    database_bytes, wal_bytes = storage or _storage_bytes(index_path)
    return (
        {
            "name": name,
            "wall_seconds": round(wall_seconds, 6),
            "cpu_seconds": round(cpu_seconds, 6),
            "peak_rss_bytes": _peak_rss_bytes(),
            "sqlite_query_count": queries,
            "database_bytes": database_bytes,
            "wal_bytes": wal_bytes,
            "worker_pid": os.getpid(),
        },
        payload,
    )


def _positive_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"benchmark JSON contains non-finite number: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError(f"benchmark JSON contains duplicate key: {key}")
        output[key] = value
    return output


def _load_json(path: Path) -> object:
    return json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=_reject_json_constant,
        object_pairs_hook=_reject_duplicate_keys,
    )


def _nonnegative_finite_number(value: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or value < 0
    ):
        raise ValueError(f"{field} must be a finite non-negative number")
    return float(value)


def _nonnegative_integer(value: object, field: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "positive" if positive else "non-negative"
        raise ValueError(f"{field} must be a {qualifier} integer")
    return value


def _metric_value(metric: str, value: object, field: str) -> int | float:
    if metric in _INTEGER_METRICS:
        return _nonnegative_integer(value, field)
    return _nonnegative_finite_number(value, field)


def _validate_measurement(operation: str, measurement: object) -> Mapping[str, object]:
    if not isinstance(measurement, Mapping):
        raise ValueError(f"benchmark worker {operation} measurement must be an object")
    if measurement.get("name") != operation:
        raise ValueError(f"benchmark worker {operation} returned a mismatched operation name")
    for metric in _METRICS:
        _metric_value(metric, measurement.get(metric), f"{operation}.{metric}")
    _nonnegative_integer(measurement.get("worker_pid"), f"{operation}.worker_pid", positive=True)
    return measurement


def _validate_thresholds(thresholds: Mapping[str, object]) -> None:
    for operation in _OPERATIONS:
        raw_limits = thresholds.get(operation)
        if not isinstance(raw_limits, Mapping):
            raise ValueError(f"benchmark thresholds are missing {operation}")
        for metric in _METRICS:
            _metric_value(
                metric,
                raw_limits.get(f"maximum_{metric}"),
                f"maximum_{metric} threshold for {operation}",
            )
        baseline_queries = raw_limits.get("baseline_sqlite_query_count")
        maximum_ratio = raw_limits.get("maximum_query_regression_ratio")
        if (
            isinstance(baseline_queries, bool)
            or not isinstance(baseline_queries, int)
            or baseline_queries < 0
            or isinstance(maximum_ratio, bool)
            or not isinstance(maximum_ratio, (int, float))
            or not math.isfinite(float(maximum_ratio))
            or maximum_ratio < 1
        ):
            raise ValueError(f"invalid relative query threshold for {operation}")


def _gate(
    measurements: Mapping[str, Mapping[str, object]],
    thresholds: Mapping[str, object],
) -> tuple[bool, list[str]]:
    _validate_thresholds(thresholds)
    violations: list[str] = []
    for operation in _OPERATIONS:
        raw_limits = thresholds.get(operation)
        if not isinstance(raw_limits, Mapping):  # pragma: no cover - validated above
            raise RuntimeError(f"benchmark thresholds are missing {operation}")
        measurement = _validate_measurement(operation, measurements.get(operation))
        for metric in _METRICS:
            maximum = raw_limits.get(f"maximum_{metric}")
            validated_maximum = _metric_value(
                metric, maximum, f"maximum_{metric} threshold for {operation}"
            )
            value = _metric_value(metric, measurement.get(metric), f"{operation}.{metric}")
            if value > validated_maximum:
                violations.append(f"{operation}.{metric}={measurement[metric]} exceeds {maximum}")
        baseline_queries = raw_limits.get("baseline_sqlite_query_count")
        maximum_ratio = raw_limits.get("maximum_query_regression_ratio")
        if not isinstance(baseline_queries, int) or isinstance(  # pragma: no cover - validated
            baseline_queries, bool
        ):
            raise RuntimeError(f"invalid query baseline for {operation}")
        if not isinstance(maximum_ratio, (int, float)) or isinstance(  # pragma: no cover
            maximum_ratio, bool
        ):
            raise RuntimeError(f"invalid query ratio for {operation}")
        allowed_queries = max(1, int(baseline_queries * float(maximum_ratio)))
        measured_queries = _nonnegative_integer(
            measurement.get("sqlite_query_count"), f"{operation}.sqlite_query_count"
        )
        if measured_queries > allowed_queries:
            violations.append(
                f"{operation}.sqlite_query_count={measured_queries} "
                f"regressed beyond baseline {baseline_queries} x {maximum_ratio}"
            )
    return not violations, violations


def _worker_report(
    operation: str,
    repository: Path,
    cache: Path,
    *,
    fixture_files: int,
    generation: int,
    scan_deadline_seconds: int,
) -> dict[str, object]:
    if operation == "scan":
        service = RepoLocusService(
            Settings(
                model="local",
                max_repository_bytes=fixture_files * _FIXTURE_MAX_BYTES_PER_FILE,
                max_repository_chunks=fixture_files * 5,
                max_repository_dependencies=fixture_files,
                max_repository_files=_fixture_entry_limit(fixture_files),
                max_repository_symbols=fixture_files * 5,
                max_scan_seconds=scan_deadline_seconds,
            )
        )

        def scan_action() -> tuple[object, int, Path, tuple[int, int]]:
            result = service.scanner.scan(repository, refresh_mode="rebuild")
            with RepositoryIndex.open(repository, cache_dir=cache) as index:
                update, queries = _traced(index, lambda: index.update(result))
                return update, queries, index.db_path, _storage_bytes(index.db_path)

        measurement, update = _measure("scan", scan_action)
        with RepositoryIndex.open(repository, cache_dir=cache) as index:
            fact_row = index._connection.execute(
                "SELECT (SELECT count(*) FROM symbols) AS symbols, "
                "(SELECT count(*) FROM dependencies) AS dependencies"
            ).fetchone()
        return {
            "measurement": measurement,
            "generation": int(update.content_generation),
            "symbols": int(fact_row["symbols"]),
            "dependencies": int(fact_row["dependencies"]),
        }

    with RepositoryIndex.open(repository, cache_dir=cache) as index:

        def invoke(action: Callable[[], Any]) -> tuple[Any, int, Path, tuple[int, int]]:
            payload, queries = _traced(index, action)
            return payload, queries, index.db_path, _storage_bytes(index.db_path)

        if operation == "map":

            def project_map() -> str:
                with index.repository_view(expected_generation=generation) as view:
                    return ProjectMapGenerator().generate_view(view)

            measurement, document = _measure(operation, lambda: invoke(project_map))
            if not document.startswith("# Project Map"):
                raise RuntimeError("project map benchmark produced invalid output")
            area = re.search(
                r"`src` is a module area with (?P<files>\d+) indexed files "
                r"and (?P<symbols>\d+) extracted symbols",
                document,
            )
            if area is None:
                raise RuntimeError("project map benchmark omitted the fixture area summary")
            assertion = {
                "indexed_files": int(area.group("files")),
                "symbols": int(area.group("symbols")),
            }
        elif operation == "diagram":

            def diagram() -> str:
                with index.repository_view(expected_generation=generation) as view:
                    return MermaidGenerator().generate_view(view)

            measurement, document = _measure(operation, lambda: invoke(diagram))
            if "```mermaid" not in document:
                raise RuntimeError("diagram benchmark produced invalid output")
            mermaid = document.split("```mermaid\n", 1)[1].split("\n```", 1)[0]
            valid_mermaid, _detail = validate_mermaid(mermaid)
            assertion = {
                "valid_mermaid": valid_mermaid,
                "group": "group_0000" if "group_0000" in document else "",
            }
        elif operation == "symbol_query":
            measurement, hits = _measure(
                operation,
                lambda: invoke(lambda: index.find_symbol_chunks("function_000050_0", limit=8)),
            )
            if not hits:
                raise RuntimeError("symbol benchmark returned no evidence")
            assertion = {
                "path": hits[0].chunk.path,
                "symbol": hits[0].symbol_name,
            }
        elif operation == "dependency_query":
            measurement, hits = _measure(
                operation,
                lambda: invoke(
                    lambda: index.dependency_neighbors(
                        ["src/group_0000/module_000050.py"],
                        limit=8,
                        direction="dependency of",
                    )
                ),
            )
            if not hits:
                raise RuntimeError("dependency benchmark returned no evidence")
            assertion = {
                "source_path": hits[0].seed_path,
                "target_path": hits[0].chunk.path,
                "direction": hits[0].direction,
            }
        elif operation == "retrieval":
            retrieval = RetrievalEngine(index)
            measurement, result = _measure(
                operation,
                lambda: invoke(
                    lambda: retrieval.search_result("Where is function_000050_0 defined?", limit=8)
                ),
            )
            if not result.evidence:
                raise RuntimeError("retrieval benchmark returned no evidence")
            assertion = {
                "path": result.evidence[0].path,
                "symbol": result.evidence[0].symbol,
                "citation": result.evidence[0].citation,
                "intent": result.intent,
            }
        else:  # pragma: no cover - argparse and parent invariant
            raise ValueError(f"unknown benchmark operation: {operation}")
    return {"measurement": measurement, "assertion": assertion}


def _validate_worker_report(
    operation: str,
    report: object,
    *,
    fixture_files: int,
) -> dict[str, object]:
    if not isinstance(report, dict):
        raise RuntimeError(f"benchmark worker {operation} returned an invalid report")
    try:
        _validate_measurement(operation, report.get("measurement"))
        if operation == "scan":
            _nonnegative_integer(report.get("generation"), "scan.generation")
            _nonnegative_integer(report.get("symbols"), "scan.symbols")
            _nonnegative_integer(report.get("dependencies"), "scan.dependencies")
        else:
            expected_assertions = {
                "map": {"indexed_files": fixture_files, "symbols": fixture_files * 5},
                "diagram": {"valid_mermaid": True, "group": "group_0000"},
                "symbol_query": {
                    "path": "src/group_0000/module_000050.py",
                    "symbol": "function_000050_0",
                },
                "dependency_query": {
                    "source_path": "src/group_0000/module_000050.py",
                    "target_path": "src/group_0000/module_000049.py",
                    "direction": "dependency of",
                },
                "retrieval": {
                    "path": "src/group_0000/module_000050.py",
                    "symbol": "function_000050_0",
                    "citation": "src/group_0000/module_000050.py:1-4",
                    "intent": "definition",
                },
            }
            if report.get("assertion") != expected_assertions[operation]:
                raise ValueError(f"{operation}.assertion does not prove the expected result")
    except ValueError as exc:
        raise RuntimeError(
            f"benchmark worker {operation} returned an invalid report: {exc}"
        ) from exc
    return report


def _run_worker(
    operation: str,
    repository: Path,
    cache: Path,
    output: Path,
    *,
    fixture_files: int,
    generation: int,
    maximum_wall_seconds: int | float,
    scan_deadline_seconds: int,
) -> dict[str, object]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        operation,
        "--repository",
        str(repository),
        "--cache",
        str(cache),
        "--worker-output",
        str(output),
        "--generation",
        str(generation),
        "--fixture-files",
        str(fixture_files),
        "--scan-deadline-seconds",
        str(scan_deadline_seconds),
    ]
    wall_limit = _nonnegative_finite_number(
        maximum_wall_seconds, f"maximum wall threshold for {operation}"
    )
    timeout_seconds = wall_limit + max(30.0, wall_limit * 0.1)
    output.unlink(missing_ok=True)
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"benchmark worker {operation} exceeded its {timeout_seconds:g}s timeout"
        ) from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"benchmark worker {operation} failed: {detail}")
    if not output.is_file():
        raise RuntimeError(f"benchmark worker {operation} did not write a report")
    return _validate_worker_report(
        operation,
        _load_json(output),
        fixture_files=fixture_files,
    )


def run_benchmark(manifest_path: Path) -> dict[str, object]:
    manifest = _load_json(manifest_path)
    if (
        not isinstance(manifest, dict)
        or isinstance(manifest.get("version"), bool)
        or manifest.get("version") != 1
    ):
        raise ValueError("benchmark manifest version is invalid")
    files = _positive_integer(manifest.get("files"), "files")
    scan_deadline_seconds = _positive_integer(
        manifest.get("scan_deadline_seconds"), "scan_deadline_seconds"
    )
    minimum_symbols = _positive_integer(manifest.get("minimum_symbols"), "minimum_symbols")
    minimum_dependencies = _positive_integer(
        manifest.get("minimum_dependencies"), "minimum_dependencies"
    )
    minimum_source_bytes = _positive_integer(
        manifest.get("minimum_source_bytes"), "minimum_source_bytes"
    )
    thresholds = manifest.get("thresholds")
    if not isinstance(thresholds, Mapping):
        raise ValueError("benchmark thresholds must be an object")
    _validate_thresholds(thresholds)

    def maximum_wall_seconds(operation: str) -> float:
        limits = thresholds[operation]
        if not isinstance(limits, Mapping):  # pragma: no cover - validated above
            raise RuntimeError(f"benchmark thresholds are missing {operation}")
        return _nonnegative_finite_number(
            limits["maximum_wall_seconds"], f"maximum wall threshold for {operation}"
        )

    with tempfile.TemporaryDirectory(prefix="repolocus-v020-benchmark-") as directory:
        temporary = Path(directory)
        repository = temporary / "repository"
        cache = temporary / "cache"
        repository.mkdir()
        cache.mkdir()
        _populate(repository, files)
        source_bytes = sum(path.stat().st_size for path in repository.rglob("*") if path.is_file())
        if source_bytes < minimum_source_bytes:
            raise RuntimeError(
                "benchmark fixture did not reach its declared source scale: "
                f"source_bytes={source_bytes}, minimum_source_bytes={minimum_source_bytes}"
            )
        worker_output = temporary / "worker.json"
        scan_report = _run_worker(
            "scan",
            repository,
            cache,
            worker_output,
            fixture_files=files,
            generation=0,
            maximum_wall_seconds=maximum_wall_seconds("scan"),
            scan_deadline_seconds=scan_deadline_seconds,
        )
        generation = int(scan_report["generation"])
        symbol_count = int(scan_report["symbols"])
        dependency_count = int(scan_report["dependencies"])
        if symbol_count < minimum_symbols or dependency_count < minimum_dependencies:
            raise RuntimeError(
                "benchmark fixture did not reach its declared fact scale: "
                f"symbols={symbol_count}, dependencies={dependency_count}"
            )
        measurements: dict[str, Mapping[str, object]] = {
            "scan": scan_report["measurement"]  # type: ignore[dict-item]
        }
        for operation in _OPERATIONS[1:]:
            operation_report = _run_worker(
                operation,
                repository,
                cache,
                worker_output,
                fixture_files=files,
                generation=generation,
                maximum_wall_seconds=maximum_wall_seconds(operation),
                scan_deadline_seconds=scan_deadline_seconds,
            )
            measurements[operation] = operation_report["measurement"]  # type: ignore[assignment]

        passed, violations = _gate(measurements, thresholds)
        return {
            "benchmark": "v0.2-indexed-workflows-v1",
            "benchmark_script_sha256": _script_sha256(),
            "implementation_sha256": _implementation_sha256(),
            "repolocus_version": __version__,
            "manifest": manifest_path.name,
            "files": files,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
            "source_bytes": source_bytes,
            "symbols": symbol_count,
            "dependencies": dependency_count,
            "operations": measurements,
            "gate": {"passed": passed, "violations": violations},
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("benchmarks/v0.2-gates.json"),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--worker", choices=_OPERATIONS, help=argparse.SUPPRESS)
    parser.add_argument("--repository", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--cache", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--worker-output", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--generation", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--fixture-files", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--scan-deadline-seconds", type=int, default=120, help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.worker is not None:
        if (
            arguments.repository is None
            or arguments.cache is None
            or arguments.worker_output is None
        ):
            parser.error("benchmark worker paths are required")
        generation = arguments.generation
        if isinstance(generation, bool) or generation < 0:
            parser.error("--generation must be non-negative")
        fixture_files = _positive_integer(arguments.fixture_files, "fixture files")
        scan_deadline_seconds = _positive_integer(arguments.scan_deadline_seconds, "scan deadline")
        report = _worker_report(
            arguments.worker,
            arguments.repository.resolve(strict=True),
            arguments.cache.resolve(strict=True),
            fixture_files=fixture_files,
            generation=generation,
            scan_deadline_seconds=scan_deadline_seconds,
        )
        arguments.worker_output.write_text(
            json.dumps(report, ensure_ascii=True, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return 0
    report = run_benchmark(arguments.manifest.resolve(strict=True))
    encoded = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    gate = report["gate"]
    if not isinstance(gate, Mapping):  # pragma: no cover - report invariant
        raise RuntimeError("benchmark gate report is invalid")
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
