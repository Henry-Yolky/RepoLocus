#!/usr/bin/env python3
"""Build and validate the reproducible public benchmark summary.

The runner combines the existing external-evaluation and indexed-workflow
reports.  It does not execute either benchmark and it never treats the bundled
synthetic fixtures as evidence of production-repository quality.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import shlex
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath

_SCHEMA_VERSION = 1
_BENCHMARK_ID = "repolocus-public-benchmark-v1"
_HASH_ALGORITHM = "sha256-lf-v1"
_OPERATIONS = (
    "scan",
    "map",
    "diagram",
    "symbol_query",
    "dependency_query",
    "retrieval",
)
_QUERY_OPERATIONS = ("symbol_query", "dependency_query", "retrieval")
_MEASUREMENT_FIELDS = (
    "wall_seconds",
    "cpu_seconds",
    "peak_rss_bytes",
    "sqlite_query_count",
    "database_bytes",
    "wal_bytes",
)
_INTEGER_MEASUREMENTS = frozenset(
    {"peak_rss_bytes", "sqlite_query_count", "database_bytes", "wal_bytes"}
)
_QUALITY_RATES = (
    "any_expected_path_rate",
    "macro_recall_at_k",
    "mrr",
    "citation_recall",
    "no_answer_accuracy",
    "no_answer_precision",
    "no_answer_recall",
    "no_answer_f1",
    "duplicate_evidence_rate",
    "must_not_return_violation_rate",
)
_BOOTSTRAP_RATES = (
    "any_expected_path_rate",
    "macro_recall_at_k",
    "mrr",
    "citation_recall",
    "no_answer_f1",
)
_ARTIFACT_IDS = frozenset(
    {
        "evaluation_manifest",
        "evaluation_metrics_runner",
        "evaluation_runner",
        "performance_manifest",
        "performance_runner",
        "report_runner",
        "report_schema",
    }
)
_COMPARISON_SYSTEMS = ("RepoWiki", "DeepWiki", "Sourcebot")
_COMMAND_IDS = ("evaluation", "performance", "report", "check")


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _canonical_bytes(payload: bytes) -> bytes:
    """Normalize checkout line endings for cross-platform protocol hashes."""

    return payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(_canonical_bytes(path.read_bytes())).hexdigest()


def _raw_sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _load_protocol_module(
    path: Path,
    name: str,
    *,
    injected_modules: Mapping[str, object] | None = None,
):  # type: ignore[no-untyped-def]
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise ValueError(f"could not load pinned protocol module: {path}")
    module = importlib.util.module_from_spec(specification)
    script_directory = str(path.parent)
    inserted = script_directory not in sys.path
    if inserted:
        sys.path.insert(0, script_directory)
    missing = object()
    previous_modules: dict[str, object] = {}
    for module_name, injected_module in (injected_modules or {}).items():
        previous_modules[module_name] = sys.modules.get(module_name, missing)
        sys.modules[module_name] = injected_module  # type: ignore[assignment]
    try:
        specification.loader.exec_module(module)
    finally:
        for module_name, previous in previous_modules.items():
            if previous is missing:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = previous  # type: ignore[assignment]
        if inserted:
            sys.path.remove(script_directory)
    return module


def _same_json_value(left: object, right: object) -> bool:
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False
    )


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    return value


def _sequence(value: object, field: str) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{field} must be an array")
    return value


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value:
        raise ValueError(f"{field} must be a non-empty single-line string")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be boolean")
    return value


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field} must be an integer >= {minimum}")
    return value


def _number(value: object, field: str, *, rate: bool = False) -> int | float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or value < 0
        or (rate and value > 1)
    ):
        qualifier = "a rate from 0 through 1" if rate else "a finite non-negative number"
        raise ValueError(f"{field} must be {qualifier}")
    return value


def _sha256(value: object, field: str) -> str:
    digest = _string(value, field)
    if len(digest) != 64:
        raise ValueError(f"{field} must be a SHA-256 digest")
    try:
        bytes.fromhex(digest)
    except ValueError as exc:
        raise ValueError(f"{field} must be a SHA-256 digest") from exc
    return digest.lower()


def _exact_keys(value: Mapping[str, object], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ValueError(f"{field} fields must be exactly {sorted(expected)}; got {sorted(actual)}")


def _relative_file(root: Path, value: object, field: str) -> tuple[str, Path]:
    raw = _string(value, field)
    pure = PurePosixPath(raw)
    windows_path = PureWindowsPath(raw)
    if (
        "\\" in raw
        or pure.is_absolute()
        or bool(windows_path.drive)
        or bool(windows_path.root)
        or ".." in pure.parts
        or pure.as_posix() != raw
    ):
        raise ValueError(f"{field} must be a normalized repository-relative path")
    candidate = root.joinpath(*pure.parts)
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"{field} must identify a regular repository file")
    candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    return raw, candidate


def _relative_directory(root: Path, value: object, field: str) -> tuple[str, Path]:
    raw = _string(value, field)
    pure = PurePosixPath(raw)
    windows_path = PureWindowsPath(raw)
    if (
        "\\" in raw
        or pure.is_absolute()
        or bool(windows_path.drive)
        or bool(windows_path.root)
        or ".." in pure.parts
        or pure.as_posix() != raw
    ):
        raise ValueError(f"{field} must be a normalized repository-relative path")
    candidate = root.joinpath(*pure.parts)
    if candidate.is_symlink() or not candidate.is_dir():
        raise ValueError(f"{field} must identify a regular repository directory")
    candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    return raw, candidate


def _validate_artifacts(
    root: Path,
    value: object,
) -> dict[str, dict[str, str]]:
    artifacts = _mapping(value, "manifest.artifacts")
    if set(artifacts) != _ARTIFACT_IDS:
        raise ValueError(f"manifest.artifacts must contain exactly {sorted(_ARTIFACT_IDS)}")
    validated: dict[str, dict[str, str]] = {}
    for artifact_id in sorted(_ARTIFACT_IDS):
        artifact = _mapping(artifacts[artifact_id], f"manifest.artifacts.{artifact_id}")
        _exact_keys(artifact, {"path", "sha256"}, f"manifest.artifacts.{artifact_id}")
        relative, path = _relative_file(
            root,
            artifact.get("path"),
            f"manifest.artifacts.{artifact_id}.path",
        )
        expected = _sha256(
            artifact.get("sha256"),
            f"manifest.artifacts.{artifact_id}.sha256",
        )
        actual = _sha256_file(path)
        if actual != expected:
            raise ValueError(
                f"public benchmark protocol drifted: {relative} has {actual}, expected {expected}"
            )
        validated[artifact_id] = {"path": relative, "sha256": expected}
    return validated


def _expected_commands(artifacts: Mapping[str, Mapping[str, str]]) -> dict[str, list[str]]:
    evaluation_output = "benchmarks/results/public-evaluation.json"
    performance_output = "benchmarks/results/public-performance.json"
    json_output = "benchmarks/results/public-report.json"
    markdown_output = "benchmarks/results/public-report.md"
    report_base = [
        "uv",
        "run",
        "python",
        artifacts["report_runner"]["path"],
        "--manifest",
        "benchmarks/public-benchmark-manifest.json",
        "--evaluation-report",
        evaluation_output,
        "--performance-report",
        performance_output,
        "--json-output",
        json_output,
        "--markdown-output",
        markdown_output,
    ]
    return {
        "evaluation": [
            "uv",
            "run",
            "python",
            artifacts["evaluation_runner"]["path"],
            "evaluation",
            "--output",
            evaluation_output,
        ],
        "performance": [
            "uv",
            "run",
            "python",
            artifacts["performance_runner"]["path"],
            "--manifest",
            artifacts["performance_manifest"]["path"],
            "--output",
            performance_output,
        ],
        "report": report_base,
        "check": [*report_base, "--check"],
    }


def _validate_commands(
    value: object,
    artifacts: Mapping[str, Mapping[str, str]],
) -> tuple[dict[str, object], ...]:
    commands = _sequence(value, "manifest.commands")
    expected = _expected_commands(artifacts)
    if len(commands) != len(_COMMAND_IDS):
        raise ValueError(
            "manifest.commands must contain evaluation, performance, report, and check"
        )
    validated: list[dict[str, object]] = []
    for index, command_id in enumerate(_COMMAND_IDS):
        command = _mapping(commands[index], f"manifest.commands[{index}]")
        _exact_keys(command, {"id", "argv"}, f"manifest.commands[{index}]")
        if command.get("id") != command_id:
            raise ValueError(f"manifest.commands[{index}].id must be {command_id!r}")
        argv = [
            _string(item, f"manifest.commands[{index}].argv")
            for item in _sequence(command.get("argv"), f"manifest.commands[{index}].argv")
        ]
        if argv != expected[command_id]:
            raise ValueError(f"manifest command {command_id} does not match the public protocol")
        validated.append({"id": command_id, "argv": argv})
    return tuple(validated)


def _validate_comparisons(value: object) -> tuple[dict[str, object], ...]:
    comparisons = _sequence(value, "manifest.comparisons")
    if len(comparisons) != len(_COMPARISON_SYSTEMS):
        raise ValueError("manifest.comparisons must list RepoWiki, DeepWiki, and Sourcebot")
    validated: list[dict[str, object]] = []
    for index, system in enumerate(_COMPARISON_SYSTEMS):
        comparison = _mapping(comparisons[index], f"manifest.comparisons[{index}]")
        _exact_keys(
            comparison,
            {"system", "status", "protocol", "metrics", "reason"},
            f"manifest.comparisons[{index}]",
        )
        if comparison.get("system") != system or comparison.get("status") != "N/A":
            raise ValueError(f"{system} must be explicitly marked N/A")
        if comparison.get("protocol") is not None or comparison.get("metrics") is not None:
            raise ValueError(f"{system} cannot report metrics without a pinned equivalent protocol")
        reason = _string(comparison.get("reason"), f"manifest.comparisons[{index}].reason")
        if "equivalent public protocol" not in reason.casefold():
            raise ValueError(
                f"{system} N/A reason must name the missing equivalent public protocol"
            )
        validated.append(
            {
                "system": system,
                "status": "N/A",
                "protocol": None,
                "metrics": None,
                "reason": reason,
            }
        )
    return tuple(validated)


def load_public_manifest(
    manifest_path: Path,
    *,
    repository_root: Path | None = None,
) -> dict[str, object]:
    """Load the strict, hash-pinned public benchmark protocol."""

    root = (repository_root or _repository_root()).resolve(strict=True)
    manifest_path = manifest_path.resolve(strict=True)
    manifest_path.relative_to(root)
    raw = _mapping(_load_json(manifest_path), "manifest")
    _exact_keys(
        raw,
        {
            "schema_version",
            "benchmark_id",
            "hash_algorithm",
            "subject",
            "scope",
            "artifacts",
            "commands",
            "comparisons",
        },
        "manifest",
    )
    if raw.get("schema_version") != _SCHEMA_VERSION:
        raise ValueError("public benchmark manifest schema_version is unsupported")
    if raw.get("benchmark_id") != _BENCHMARK_ID:
        raise ValueError("public benchmark manifest benchmark_id is unsupported")
    if raw.get("hash_algorithm") != _HASH_ALGORITHM:
        raise ValueError("public benchmark manifest hash_algorithm is unsupported")
    subject = _mapping(raw.get("subject"), "manifest.subject")
    _exact_keys(subject, {"name"}, "manifest.subject")
    if subject.get("name") != "RepoLocus":
        raise ValueError("public benchmark subject must be RepoLocus")
    scope = _mapping(raw.get("scope"), "manifest.scope")
    _exact_keys(
        scope,
        {"classification", "cross_repository_quality_claim", "note"},
        "manifest.scope",
    )
    if scope.get("classification") != "smoke":
        raise ValueError("RepoLocus public benchmark result must be classified as smoke")
    if _boolean(
        scope.get("cross_repository_quality_claim"),
        "manifest.scope.cross_repository_quality_claim",
    ):
        raise ValueError("synthetic fixtures cannot support a cross-repository quality claim")
    note = _string(scope.get("note"), "manifest.scope.note")
    if "smoke" not in note.casefold():
        raise ValueError("manifest.scope.note must clearly identify the result as smoke")
    artifacts = _validate_artifacts(root, raw.get("artifacts"))
    commands = _validate_commands(raw.get("commands"), artifacts)
    comparisons = _validate_comparisons(raw.get("comparisons"))
    return {
        "schema_version": _SCHEMA_VERSION,
        "benchmark_id": _BENCHMARK_ID,
        "hash_algorithm": _HASH_ALGORITHM,
        "subject": {"name": "RepoLocus"},
        "scope": {
            "classification": "smoke",
            "cross_repository_quality_claim": False,
            "note": note,
        },
        "artifacts": artifacts,
        "commands": commands,
        "comparisons": comparisons,
    }


def _pinned_evaluation_cases(
    evaluation_manifest_path: Path,
    evaluation_manifest: Mapping[str, object],
    evaluation_module,  # type: ignore[no-untyped-def]
) -> tuple[
    list[Mapping[str, object]],
    dict[str, Path],
    dict[str, dict[str, int]],
    dict[str, object],
]:
    """Load the exact qrel inventory without running retrieval against the fixtures."""

    evaluation_root = evaluation_manifest_path.parent.resolve(strict=True)
    raw_fixtures = _sequence(evaluation_manifest.get("fixtures"), "evaluation manifest fixtures")
    review_artifacts, review_report, reviewed_no_answer_intents = (
        evaluation_module._load_review_provenance(evaluation_root, evaluation_manifest)
    )
    cases: list[Mapping[str, object]] = []
    fixture_truth: dict[str, dict[str, int]] = {}
    fixture_roots: dict[str, Path] = {}
    seen_fixture_ids: set[str] = set()
    seen_roots: set[Path] = set()
    seen_qrel_paths: set[Path] = set()
    seen_tree_hashes: set[str] = set()
    seen_qrel_hashes: set[str] = set()
    for index, item in enumerate(raw_fixtures):
        fixture = _mapping(item, f"evaluation manifest fixtures[{index}]")
        fixture_id = _string(fixture.get("id"), f"evaluation fixture {index}.id")
        if fixture_id in seen_fixture_ids:
            raise ValueError(f"duplicate evaluation fixture id: {fixture_id}")
        seen_fixture_ids.add(fixture_id)
        revision = _string(fixture.get("revision"), f"{fixture_id}.revision")
        _, fixture_root = _relative_directory(
            evaluation_root, fixture.get("path"), f"{fixture_id}.path"
        )
        _, qrel_path = _relative_file(evaluation_root, fixture.get("qrels"), f"{fixture_id}.qrels")
        resolved_root = fixture_root.resolve(strict=True)
        resolved_qrels = qrel_path.resolve(strict=True)
        if resolved_root in seen_roots or resolved_qrels in seen_qrel_paths:
            raise ValueError("evaluation fixture roots and qrel paths must be unique")
        seen_roots.add(resolved_root)
        seen_qrel_paths.add(resolved_qrels)
        fixture_roots[fixture_id] = resolved_root

        expected_tree = _sha256(fixture.get("tree_sha256"), f"{fixture_id}.tree_sha256")
        expected_qrels = _sha256(fixture.get("qrels_sha256"), f"{fixture_id}.qrels_sha256")
        actual_tree = evaluation_module.fixture_tree_sha256(resolved_root)
        actual_qrels = _raw_sha256_file(resolved_qrels)
        if actual_tree != expected_tree:
            raise ValueError(f"pinned evaluation fixture checksum mismatch: {fixture_id}")
        if actual_qrels != expected_qrels:
            raise ValueError(f"pinned evaluation qrel checksum mismatch: {fixture_id}")
        if actual_tree in seen_tree_hashes or actual_qrels in seen_qrel_hashes:
            raise ValueError("evaluation fixture tree and qrel hashes must be unique")
        seen_tree_hashes.add(actual_tree)
        seen_qrel_hashes.add(actual_qrels)

        review = review_artifacts.pop(fixture_id, None)
        if (
            review is None
            or review.get("fixture_revision") != revision
            or review.get("tree_sha256") != actual_tree
            or review.get("qrels_sha256") != actual_qrels
        ):
            raise ValueError(f"review provenance does not cover pinned qrels: {fixture_id}")
        fixture_cases = evaluation_module._load_qrels(
            resolved_qrels,
            fixture=fixture_id,
            revision=revision,
        )
        expected_count = _integer(
            fixture.get("qrels_count"), f"{fixture_id}.qrels_count", minimum=1
        )
        if len(fixture_cases) != expected_count:
            raise ValueError(f"pinned evaluation qrel count mismatch: {fixture_id}")
        evaluation_module._validate_case_sources(resolved_root, fixture_cases)
        fixture_truth[fixture_id] = {
            "qrels": len(fixture_cases),
            "must_not_return_qrels": sum(bool(case["must_not_return"]) for case in fixture_cases),
        }
        cases.extend(fixture_cases)
    if review_artifacts:
        raise ValueError("review provenance contains undeclared evaluation fixtures")
    family_counts, families_by_type, fixtures_by_type = evaluation_module._case_family_report(
        cases,
        reviewed_no_answer_intents=reviewed_no_answer_intents,
    )
    for fixture_id, truth in fixture_truth.items():
        truth["case_families"] = family_counts[fixture_id]
    truth_summary = {
        "qrels": len(cases),
        "reviewed_qrels": len(cases),
        "case_families": sum(family_counts.values()),
        "case_families_by_query_type": dict(sorted(families_by_type.items())),
        "query_type_fixture_counts": dict(sorted(fixtures_by_type.items())),
        "query_types": sorted(families_by_type),
        "runtime_intents": sorted(evaluation_module._RUNTIME_INTENTS),
        "corpus_coverage": evaluation_module._corpus_coverage(cases),
        "answerable_qrels": sum(bool(case["answerable"]) for case in cases),
        "no_answer_qrels": sum(not bool(case["answerable"]) for case in cases),
        "citation_qrels": sum(bool(case["relevant"]) for case in cases),
        "must_not_return_qrels": sum(bool(case["must_not_return"]) for case in cases),
    }
    return (
        cases,
        fixture_roots,
        fixture_truth,
        {
            "review": review_report,
            "summary": truth_summary,
        },
    )


def _evaluation_fixtures(
    evaluation_report: Mapping[str, object],
    evaluation_manifest: Mapping[str, object],
    fixture_truth: Mapping[str, Mapping[str, int]],
) -> list[dict[str, object]]:
    manifest_fixtures = _sequence(
        evaluation_manifest.get("fixtures"), "evaluation manifest fixtures"
    )
    expected: dict[str, Mapping[str, object]] = {}
    for index, item in enumerate(manifest_fixtures):
        fixture = _mapping(item, f"evaluation manifest fixtures[{index}]")
        fixture_id = _string(fixture.get("id"), f"evaluation manifest fixtures[{index}].id")
        if fixture_id in expected:
            raise ValueError(f"duplicate evaluation fixture id: {fixture_id}")
        expected[fixture_id] = fixture
    report_fixtures = _sequence(evaluation_report.get("fixtures"), "evaluation report fixtures")
    if len(report_fixtures) != len(expected):
        raise ValueError("evaluation report fixture count does not match its manifest")
    output: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, item in enumerate(report_fixtures):
        fixture = _mapping(item, f"evaluation report fixtures[{index}]")
        fixture_id = _string(fixture.get("id"), f"evaluation report fixtures[{index}].id")
        if fixture_id in seen or fixture_id not in expected:
            raise ValueError(f"unexpected or duplicate evaluation fixture: {fixture_id}")
        seen.add(fixture_id)
        pinned = expected[fixture_id]
        provenance_fields = (
            "source",
            "license",
            "revision",
            "tree_sha256",
            "qrels_sha256",
        )
        for field in provenance_fields:
            if fixture.get(field) != pinned.get(field):
                raise ValueError(f"evaluation fixture provenance drifted: {fixture_id}.{field}")
        if fixture.get("qrels") != pinned.get("qrels_count"):
            raise ValueError(f"evaluation fixture qrel count drifted: {fixture_id}")
        truth = fixture_truth[fixture_id]
        for field in ("qrels", "case_families", "must_not_return_qrels"):
            if fixture.get(field) != truth[field]:
                raise ValueError(f"evaluation fixture truth drifted: {fixture_id}.{field}")
        output.append(
            {
                "id": fixture_id,
                "fixture_path": _string(pinned.get("path"), f"{fixture_id}.path"),
                "qrels_path": _string(pinned.get("qrels"), f"{fixture_id}.qrels"),
                "source": _string(fixture.get("source"), f"{fixture_id}.source"),
                "license": _string(fixture.get("license"), f"{fixture_id}.license"),
                "revision": _string(fixture.get("revision"), f"{fixture_id}.revision"),
                "tree_sha256": _sha256(fixture.get("tree_sha256"), f"{fixture_id}.tree_sha256"),
                "qrels_sha256": _sha256(fixture.get("qrels_sha256"), f"{fixture_id}.qrels_sha256"),
                "qrels": truth["qrels"],
                "case_families": truth["case_families"],
                "must_not_return_qrels": truth["must_not_return_qrels"],
            }
        )
    return sorted(output, key=lambda fixture: str(fixture["id"]))


def _quality_summary(evaluation_report: Mapping[str, object]) -> dict[str, object]:
    metrics = _mapping(evaluation_report.get("metrics"), "evaluation report metrics")
    rates = {
        name: _number(metrics.get(name), f"evaluation metrics.{name}", rate=True)
        for name in _QUALITY_RATES
    }
    bootstrap = _mapping(evaluation_report.get("bootstrap"), "evaluation report bootstrap")
    intervals = _mapping(bootstrap.get("intervals"), "evaluation report bootstrap.intervals")
    selected_intervals: dict[str, list[int | float]] = {}
    for metric in _BOOTSTRAP_RATES:
        interval = _sequence(intervals.get(metric), f"bootstrap interval {metric}")
        if len(interval) != 2:
            raise ValueError(f"bootstrap interval {metric} must have two bounds")
        lower = _number(interval[0], f"bootstrap interval {metric}[0]", rate=True)
        upper = _number(interval[1], f"bootstrap interval {metric}[1]", rate=True)
        if lower > upper:
            raise ValueError(f"bootstrap interval {metric} is reversed")
        selected_intervals[metric] = [lower, upper]
    gate = _mapping(evaluation_report.get("gate"), "evaluation report gate")
    return {
        "fixture_count": _integer(
            evaluation_report.get("fixture_count"), "evaluation fixture_count", minimum=1
        ),
        "qrels": _integer(evaluation_report.get("qrels"), "evaluation qrels", minimum=1),
        "case_families": _integer(
            evaluation_report.get("case_families"), "evaluation case_families", minimum=1
        ),
        "answerable_qrels": _integer(
            evaluation_report.get("answerable_qrels"), "evaluation answerable_qrels", minimum=1
        ),
        "no_answer_qrels": _integer(
            evaluation_report.get("no_answer_qrels"), "evaluation no_answer_qrels", minimum=1
        ),
        "citation_qrels": _integer(
            evaluation_report.get("citation_qrels"), "evaluation citation_qrels", minimum=1
        ),
        "must_not_return_qrels": _integer(
            evaluation_report.get("must_not_return_qrels"),
            "evaluation must_not_return_qrels",
        ),
        "accuracy": {
            "hit_rate": rates["any_expected_path_rate"],
            "macro_recall_at_k": rates["macro_recall_at_k"],
            "mrr": rates["mrr"],
            "citation_recall": rates["citation_recall"],
        },
        "no_answer": {
            "accuracy": rates["no_answer_accuracy"],
            "precision": rates["no_answer_precision"],
            "recall": rates["no_answer_recall"],
            "f1": rates["no_answer_f1"],
        },
        "safety": {
            "duplicate_evidence_rate": rates["duplicate_evidence_rate"],
            "must_not_return_violation_rate": rates["must_not_return_violation_rate"],
        },
        "bootstrap": {
            "confidence": _number(
                bootstrap.get("confidence"), "evaluation bootstrap.confidence", rate=True
            ),
            "samples": _integer(
                bootstrap.get("samples"), "evaluation bootstrap.samples", minimum=1
            ),
            "cluster_unit": _string(
                bootstrap.get("cluster_unit"), "evaluation bootstrap.cluster_unit"
            ),
            "intervals": selected_intervals,
        },
        "gate_passed": _boolean(gate.get("passed"), "evaluation gate.passed"),
    }


def _measurement(value: object, operation: str) -> dict[str, int | float]:
    measurement = _mapping(value, f"performance operation {operation}")
    if measurement.get("name") != operation:
        raise ValueError(f"performance operation {operation} has a mismatched name")
    output: dict[str, int | float] = {}
    for field in _MEASUREMENT_FIELDS:
        raw = measurement.get(field)
        if field in _INTEGER_MEASUREMENTS:
            output[field] = _integer(raw, f"performance {operation}.{field}")
        else:
            output[field] = _number(raw, f"performance {operation}.{field}")
    return output


def _performance_summary(performance_report: Mapping[str, object]) -> dict[str, object]:
    operations = _mapping(performance_report.get("operations"), "performance report operations")
    if set(operations) != set(_OPERATIONS):
        raise ValueError(f"performance operations must be exactly {list(_OPERATIONS)}")
    validated = {
        operation: _measurement(operations[operation], operation) for operation in _OPERATIONS
    }
    scan = validated["scan"]
    gate = _mapping(performance_report.get("gate"), "performance report gate")
    return {
        "environment": {
            "python": _string(performance_report.get("python"), "performance python"),
            "platform": _string(performance_report.get("platform"), "performance platform"),
            "machine": _string(performance_report.get("machine"), "performance machine"),
            "cpu_count": _integer(
                performance_report.get("cpu_count"), "performance cpu_count", minimum=1
            ),
        },
        "fixture": {
            "manifest": _string(performance_report.get("manifest"), "performance manifest"),
            "files": _integer(performance_report.get("files"), "performance files", minimum=1),
            "source_bytes": _integer(
                performance_report.get("source_bytes"),
                "performance source_bytes",
                minimum=1,
            ),
            "symbols": _integer(
                performance_report.get("symbols"), "performance symbols", minimum=1
            ),
            "dependencies": _integer(
                performance_report.get("dependencies"),
                "performance dependencies",
                minimum=1,
            ),
        },
        "query_latency_seconds": {
            operation: validated[operation]["wall_seconds"] for operation in _QUERY_OPERATIONS
        },
        "peak_rss_bytes": {
            operation: validated[operation]["peak_rss_bytes"] for operation in _OPERATIONS
        },
        "index_cost": {field: scan[field] for field in _MEASUREMENT_FIELDS},
        "operations": validated,
        "gate_passed": _boolean(gate.get("passed"), "performance gate.passed"),
    }


def build_public_report(
    manifest_path: Path,
    evaluation_report_path: Path,
    performance_report_path: Path,
    *,
    repository_root: Path | None = None,
) -> dict[str, object]:
    """Validate pinned inputs and build the deterministic public summary."""

    root = (repository_root or _repository_root()).resolve(strict=True)
    manifest_path = manifest_path.resolve(strict=True)
    manifest = load_public_manifest(manifest_path, repository_root=root)
    artifacts = _mapping(manifest["artifacts"], "manifest artifacts")
    evaluation_manifest_artifact = _mapping(
        artifacts["evaluation_manifest"], "evaluation manifest artifact"
    )
    performance_manifest_artifact = _mapping(
        artifacts["performance_manifest"], "performance manifest artifact"
    )
    performance_runner_artifact = _mapping(
        artifacts["performance_runner"], "performance runner artifact"
    )
    evaluation_runner_artifact = _mapping(
        artifacts["evaluation_runner"], "evaluation runner artifact"
    )
    evaluation_metrics_runner_artifact = _mapping(
        artifacts["evaluation_metrics_runner"], "evaluation metrics runner artifact"
    )
    evaluation_manifest_path = root / _string(
        evaluation_manifest_artifact["path"], "evaluation manifest path"
    )
    evaluation_manifest = _mapping(_load_json(evaluation_manifest_path), "evaluation manifest")
    evaluation_report_path = evaluation_report_path.resolve(strict=True)
    performance_report_path = performance_report_path.resolve(strict=True)
    evaluation_report = _mapping(_load_json(evaluation_report_path), "evaluation report")
    performance_report = _mapping(_load_json(performance_report_path), "performance report")
    if evaluation_report.get("manifest") != Path(evaluation_manifest_path).name:
        raise ValueError("evaluation report was produced from a different manifest")
    if (
        performance_report.get("manifest")
        != Path(_string(performance_manifest_artifact["path"], "performance manifest path")).name
    ):
        raise ValueError("performance report was produced from a different manifest")
    if performance_report.get("benchmark") != "v0.2-indexed-workflows-v1":
        raise ValueError("performance report benchmark identity is unsupported")
    if performance_report.get("benchmark_script_sha256") != performance_runner_artifact["sha256"]:
        raise ValueError("performance report runner hash does not match the pinned protocol")
    if evaluation_report.get("evaluation_script_sha256") != evaluation_runner_artifact["sha256"]:
        raise ValueError("evaluation report runner hash does not match the pinned protocol")
    if (
        evaluation_report.get("evaluation_metrics_script_sha256")
        != evaluation_metrics_runner_artifact["sha256"]
    ):
        raise ValueError("evaluation report metrics runner hash does not match the pinned protocol")
    for field in ("repolocus_version", "implementation_sha256"):
        if evaluation_report.get(field) != performance_report.get(field):
            raise ValueError(f"evaluation and performance reports use different {field}")

    retrieval_module = _load_protocol_module(
        root
        / _string(evaluation_metrics_runner_artifact["path"], "evaluation metrics runner path"),
        "repolocus_public_retrieval_protocol",
    )
    evaluation_runner_path = root / _string(
        evaluation_runner_artifact["path"], "evaluation runner path"
    )
    evaluation_module = _load_protocol_module(
        evaluation_runner_path,
        "repolocus_public_evaluation_protocol",
        injected_modules={"evaluate_retrieval": retrieval_module},
    )
    cases, fixture_roots, fixture_truth, pinned_truth = _pinned_evaluation_cases(
        evaluation_manifest_path,
        evaluation_manifest,
        evaluation_module,
    )
    top_k = _integer(evaluation_report.get("top_k"), "evaluation report top_k", minimum=1)
    if top_k != evaluation_module.default_limit():
        raise ValueError("evaluation report top_k does not match the pinned public protocol")
    raw_outcomes = _sequence(evaluation_report.get("outcomes"), "evaluation report outcomes")
    outcomes = retrieval_module.validate_outcomes_against_qrels(
        cases,
        raw_outcomes,
        limit=top_k,
        fixture_roots=fixture_roots,
    )
    truth_summary = _mapping(pinned_truth["summary"], "pinned evaluation truth summary")
    for field, expected in truth_summary.items():
        if not _same_json_value(evaluation_report.get(field), expected):
            raise ValueError(f"evaluation report {field} does not match the pinned qrels")
    recomputed_metrics = retrieval_module.summarize_outcomes(outcomes)
    if not _same_json_value(evaluation_report.get("metrics"), recomputed_metrics):
        raise ValueError("evaluation metrics do not match the serialized outcomes")
    recomputed_bootstrap = evaluation_module._bootstrap_report(outcomes)
    if not _same_json_value(evaluation_report.get("bootstrap"), recomputed_bootstrap):
        raise ValueError("evaluation bootstrap does not match the serialized outcomes")
    recomputed_evaluation_gate = evaluation_module._gate_report(
        evaluation_report,
        evaluation_module.default_thresholds(),
    )
    if not _same_json_value(evaluation_report.get("gate"), recomputed_evaluation_gate):
        raise ValueError("evaluation gate does not match recomputed pinned thresholds")

    performance_manifest_path = root / _string(
        performance_manifest_artifact["path"], "performance manifest path"
    )
    performance_manifest = _mapping(_load_json(performance_manifest_path), "performance manifest")
    performance_module = _load_protocol_module(
        root / _string(performance_runner_artifact["path"], "performance runner path"),
        "repolocus_public_performance_protocol",
    )
    if (
        performance_report.get("implementation_sha256")
        != performance_module._implementation_sha256()
    ):
        raise ValueError("benchmark reports do not match the current pinned implementation")
    if performance_report.get("repolocus_version") != performance_module.__version__:
        raise ValueError("benchmark reports do not match the current RepoLocus version")
    raw_operations = _mapping(performance_report.get("operations"), "performance operations")
    raw_thresholds = _mapping(performance_manifest.get("thresholds"), "performance thresholds")
    recomputed_passed, recomputed_violations = performance_module._gate(
        raw_operations, raw_thresholds
    )
    recomputed_performance_gate = {
        "passed": recomputed_passed,
        "violations": recomputed_violations,
    }
    if not _same_json_value(performance_report.get("gate"), recomputed_performance_gate):
        raise ValueError("performance gate does not match recomputed pinned thresholds")
    fixtures = _evaluation_fixtures(evaluation_report, evaluation_manifest, fixture_truth)
    if evaluation_report.get("fixture_count") != len(fixtures):
        raise ValueError("evaluation fixture_count does not match fixture provenance")
    if evaluation_report.get("qrels") != sum(int(fixture["qrels"]) for fixture in fixtures):
        raise ValueError("evaluation qrel total does not match fixture provenance")
    reported_review = _mapping(
        evaluation_report.get("review_provenance"), "evaluation report review_provenance"
    )
    if not _same_json_value(reported_review, pinned_truth["review"]):
        raise ValueError("evaluation review provenance does not match its pinned manifest")
    quality = _quality_summary(evaluation_report)
    performance = _performance_summary(performance_report)
    if not quality["gate_passed"] or not performance["gate_passed"]:
        raise ValueError("public benchmark inputs must pass both pinned gates")
    scope = _mapping(manifest["scope"], "manifest scope")
    relative_manifest = manifest_path.relative_to(root).as_posix()
    report = {
        "schema_version": _SCHEMA_VERSION,
        "benchmark_id": _BENCHMARK_ID,
        "subject": {
            "name": "RepoLocus",
            "version": _string(
                performance_report.get("repolocus_version"), "performance repolocus_version"
            ),
            "implementation_sha256": _sha256(
                performance_report.get("implementation_sha256"),
                "performance implementation_sha256",
            ),
            "result_classification": "smoke",
            "cross_repository_quality_claim": False,
            "note": scope["note"],
        },
        "protocol": {
            "manifest": relative_manifest,
            "manifest_sha256": _sha256_file(manifest_path),
            "hash_algorithm": _HASH_ALGORITHM,
            "evaluation_manifest": evaluation_manifest_artifact["path"],
            "evaluation_manifest_sha256": evaluation_manifest_artifact["sha256"],
            "evaluation_runner": evaluation_runner_artifact["path"],
            "evaluation_runner_sha256": evaluation_runner_artifact["sha256"],
            "evaluation_metrics_runner": evaluation_metrics_runner_artifact["path"],
            "evaluation_metrics_runner_sha256": evaluation_metrics_runner_artifact["sha256"],
            "performance_manifest": performance_manifest_artifact["path"],
            "performance_manifest_sha256": performance_manifest_artifact["sha256"],
            "reproduction_commands": list(manifest["commands"]),
        },
        "fixtures": fixtures,
        "quality": quality,
        "performance": performance,
        "comparisons": list(manifest["comparisons"]),
        "validation": {
            "evaluation_report_sha256": _sha256_file(evaluation_report_path),
            "performance_report_sha256": _sha256_file(performance_report_path),
            "evaluation_gate_passed": quality["gate_passed"],
            "performance_gate_passed": performance["gate_passed"],
        },
    }
    validate_public_report(report)
    return report


def validate_public_report(value: object) -> None:
    """Validate the stable public-report schema without an optional dependency."""

    report = _mapping(value, "public report")
    _exact_keys(
        report,
        {
            "schema_version",
            "benchmark_id",
            "subject",
            "protocol",
            "fixtures",
            "quality",
            "performance",
            "comparisons",
            "validation",
        },
        "public report",
    )
    if (
        report.get("schema_version") != _SCHEMA_VERSION
        or report.get("benchmark_id") != _BENCHMARK_ID
    ):
        raise ValueError("public report schema identity is unsupported")
    subject = _mapping(report.get("subject"), "public report subject")
    _exact_keys(
        subject,
        {
            "name",
            "version",
            "implementation_sha256",
            "result_classification",
            "cross_repository_quality_claim",
            "note",
        },
        "public report subject",
    )
    if (
        subject.get("name") != "RepoLocus"
        or subject.get("result_classification") != "smoke"
        or subject.get("cross_repository_quality_claim") is not False
    ):
        raise ValueError("public report must describe RepoLocus smoke results only")
    _string(subject.get("version"), "public report subject.version")
    _sha256(subject.get("implementation_sha256"), "public report subject.implementation_sha256")
    note = _string(subject.get("note"), "public report subject.note")
    if "smoke" not in note.casefold():
        raise ValueError("public report subject.note must identify the result as smoke")

    protocol = _mapping(report.get("protocol"), "public report protocol")
    _exact_keys(
        protocol,
        {
            "manifest",
            "manifest_sha256",
            "hash_algorithm",
            "evaluation_manifest",
            "evaluation_manifest_sha256",
            "evaluation_runner",
            "evaluation_runner_sha256",
            "evaluation_metrics_runner",
            "evaluation_metrics_runner_sha256",
            "performance_manifest",
            "performance_manifest_sha256",
            "reproduction_commands",
        },
        "public report protocol",
    )
    for field in (
        "manifest",
        "evaluation_manifest",
        "evaluation_runner",
        "evaluation_metrics_runner",
        "performance_manifest",
    ):
        _string(protocol.get(field), f"public report protocol.{field}")
    if protocol.get("evaluation_runner") != "scripts/evaluate_external_repositories.py":
        raise ValueError("public report evaluation runner is unsupported")
    if protocol.get("evaluation_metrics_runner") != "scripts/evaluate_retrieval.py":
        raise ValueError("public report evaluation metrics runner is unsupported")
    for field in (
        "manifest_sha256",
        "evaluation_manifest_sha256",
        "evaluation_runner_sha256",
        "evaluation_metrics_runner_sha256",
        "performance_manifest_sha256",
    ):
        _sha256(protocol.get(field), f"public report protocol.{field}")
    if protocol.get("hash_algorithm") != _HASH_ALGORITHM:
        raise ValueError("public report hash_algorithm is unsupported")
    commands = _sequence(
        protocol.get("reproduction_commands"),
        "public report protocol.reproduction_commands",
    )
    if len(commands) != len(_COMMAND_IDS):
        raise ValueError("public report must include all four reproduction commands")
    expected_commands = _expected_commands(
        {
            "evaluation_runner": {"path": "scripts/evaluate_external_repositories.py"},
            "performance_runner": {"path": "benchmarks/benchmark_v020.py"},
            "performance_manifest": {"path": "benchmarks/v0.2-gates.json"},
            "report_runner": {"path": "scripts/public_benchmark_report.py"},
        }
    )
    for index, command_id in enumerate(_COMMAND_IDS):
        command = _mapping(commands[index], f"public report command {index}")
        _exact_keys(command, {"id", "argv"}, f"public report command {index}")
        if command.get("id") != command_id:
            raise ValueError(f"public report command {index} must be {command_id}")
        argv = _sequence(command.get("argv"), f"public report command {command_id}.argv")
        validated_argv = [
            _string(argument, f"public report command {command_id}.argv[{position}]")
            for position, argument in enumerate(argv)
        ]
        if validated_argv != expected_commands[command_id]:
            raise ValueError(f"public report reproduction command {command_id} drifted")

    fixtures = _sequence(report.get("fixtures"), "public report fixtures")
    if not fixtures:
        raise ValueError("public report fixtures cannot be empty")
    fixture_ids: set[str] = set()
    qrel_total = 0
    for index, item in enumerate(fixtures):
        fixture = _mapping(item, f"public report fixtures[{index}]")
        _exact_keys(
            fixture,
            {
                "id",
                "fixture_path",
                "qrels_path",
                "source",
                "license",
                "revision",
                "tree_sha256",
                "qrels_sha256",
                "qrels",
                "case_families",
                "must_not_return_qrels",
            },
            f"public report fixtures[{index}]",
        )
        fixture_id = _string(fixture.get("id"), f"public report fixtures[{index}].id")
        if fixture_id in fixture_ids:
            raise ValueError(f"duplicate public report fixture id: {fixture_id}")
        fixture_ids.add(fixture_id)
        for field in (
            "fixture_path",
            "qrels_path",
            "source",
            "license",
            "revision",
        ):
            _string(fixture.get(field), f"public report fixture {fixture_id}.{field}")
        _sha256(fixture.get("tree_sha256"), f"public report fixture {fixture_id}.tree_sha256")
        _sha256(
            fixture.get("qrels_sha256"),
            f"public report fixture {fixture_id}.qrels_sha256",
        )
        qrel_total += _integer(
            fixture.get("qrels"), f"public report fixture {fixture_id}.qrels", minimum=1
        )
        _integer(
            fixture.get("case_families"),
            f"public report fixture {fixture_id}.case_families",
            minimum=1,
        )
        _integer(
            fixture.get("must_not_return_qrels"),
            f"public report fixture {fixture_id}.must_not_return_qrels",
        )

    quality = _mapping(report.get("quality"), "public report quality")
    _exact_keys(
        quality,
        {
            "fixture_count",
            "qrels",
            "case_families",
            "answerable_qrels",
            "no_answer_qrels",
            "citation_qrels",
            "must_not_return_qrels",
            "accuracy",
            "no_answer",
            "safety",
            "bootstrap",
            "gate_passed",
        },
        "public report quality",
    )
    fixture_count = _integer(
        quality.get("fixture_count"), "public report quality.fixture_count", minimum=1
    )
    if fixture_count != len(fixtures):
        raise ValueError("public report fixture_count does not match fixtures")
    quality_qrels = _integer(quality.get("qrels"), "public report quality.qrels", minimum=1)
    if quality_qrels != qrel_total:
        raise ValueError("public report qrel total does not match fixtures")
    for field in (
        "case_families",
        "answerable_qrels",
        "no_answer_qrels",
        "citation_qrels",
    ):
        _integer(quality.get(field), f"public report quality.{field}", minimum=1)
    _integer(
        quality.get("must_not_return_qrels"),
        "public report quality.must_not_return_qrels",
    )
    if quality.get("answerable_qrels") + quality.get("no_answer_qrels") != quality_qrels:
        raise ValueError("public report answerable and no-answer qrels do not sum to qrels")
    rate_groups = {
        "accuracy": ("hit_rate", "macro_recall_at_k", "mrr", "citation_recall"),
        "no_answer": ("accuracy", "precision", "recall", "f1"),
        "safety": ("duplicate_evidence_rate", "must_not_return_violation_rate"),
    }
    for group_name, fields in rate_groups.items():
        group = _mapping(quality.get(group_name), f"public report quality.{group_name}")
        _exact_keys(group, set(fields), f"public report quality.{group_name}")
        for field in fields:
            _number(
                group.get(field),
                f"public report quality.{group_name}.{field}",
                rate=True,
            )
    bootstrap = _mapping(quality.get("bootstrap"), "public report quality.bootstrap")
    _exact_keys(
        bootstrap,
        {"confidence", "samples", "cluster_unit", "intervals"},
        "public report quality.bootstrap",
    )
    _number(
        bootstrap.get("confidence"),
        "public report quality.bootstrap.confidence",
        rate=True,
    )
    _integer(
        bootstrap.get("samples"),
        "public report quality.bootstrap.samples",
        minimum=1,
    )
    _string(
        bootstrap.get("cluster_unit"),
        "public report quality.bootstrap.cluster_unit",
    )
    intervals = _mapping(bootstrap.get("intervals"), "public report quality.bootstrap.intervals")
    _exact_keys(intervals, set(_BOOTSTRAP_RATES), "public report quality.bootstrap.intervals")
    for metric in _BOOTSTRAP_RATES:
        interval = _sequence(
            intervals.get(metric),
            f"public report quality.bootstrap.intervals.{metric}",
        )
        if len(interval) != 2:
            raise ValueError(f"public report bootstrap interval {metric} needs two bounds")
        lower = _number(interval[0], f"public report bootstrap {metric}[0]", rate=True)
        upper = _number(interval[1], f"public report bootstrap {metric}[1]", rate=True)
        if lower > upper:
            raise ValueError(f"public report bootstrap interval {metric} is reversed")
    quality_gate = _boolean(quality.get("gate_passed"), "public report quality.gate_passed")

    performance = _mapping(report.get("performance"), "public report performance")
    _exact_keys(
        performance,
        {
            "environment",
            "fixture",
            "query_latency_seconds",
            "peak_rss_bytes",
            "index_cost",
            "operations",
            "gate_passed",
        },
        "public report performance",
    )
    environment = _mapping(performance.get("environment"), "public report performance.environment")
    _exact_keys(
        environment,
        {"python", "platform", "machine", "cpu_count"},
        "public report performance.environment",
    )
    for field in ("python", "platform", "machine"):
        _string(environment.get(field), f"public report performance.environment.{field}")
    _integer(
        environment.get("cpu_count"),
        "public report performance.environment.cpu_count",
        minimum=1,
    )
    performance_fixture = _mapping(performance.get("fixture"), "public report performance.fixture")
    _exact_keys(
        performance_fixture,
        {"manifest", "files", "source_bytes", "symbols", "dependencies"},
        "public report performance.fixture",
    )
    _string(
        performance_fixture.get("manifest"),
        "public report performance.fixture.manifest",
    )
    for field in ("files", "source_bytes", "symbols", "dependencies"):
        _integer(
            performance_fixture.get(field),
            f"public report performance.fixture.{field}",
            minimum=1,
        )
    query_latency = _mapping(
        performance.get("query_latency_seconds"),
        "public report performance.query_latency_seconds",
    )
    _exact_keys(
        query_latency,
        set(_QUERY_OPERATIONS),
        "public report performance.query_latency_seconds",
    )
    for operation in _QUERY_OPERATIONS:
        _number(
            query_latency.get(operation),
            f"public report performance.query_latency_seconds.{operation}",
        )
    peak_rss = _mapping(
        performance.get("peak_rss_bytes"), "public report performance.peak_rss_bytes"
    )
    _exact_keys(peak_rss, set(_OPERATIONS), "public report performance.peak_rss_bytes")
    for operation in _OPERATIONS:
        _integer(
            peak_rss.get(operation),
            f"public report performance.peak_rss_bytes.{operation}",
        )
    operations = _mapping(performance.get("operations"), "public report performance.operations")
    _exact_keys(operations, set(_OPERATIONS), "public report performance.operations")
    validated_operations: dict[str, dict[str, int | float]] = {}
    for operation in _OPERATIONS:
        measurement = _mapping(
            operations.get(operation),
            f"public report performance.operations.{operation}",
        )
        _exact_keys(
            measurement,
            set(_MEASUREMENT_FIELDS),
            f"public report performance.operations.{operation}",
        )
        validated_measurement: dict[str, int | float] = {}
        for field in _MEASUREMENT_FIELDS:
            if field in _INTEGER_MEASUREMENTS:
                validated_measurement[field] = _integer(
                    measurement.get(field),
                    f"public report performance.operations.{operation}.{field}",
                )
            else:
                validated_measurement[field] = _number(
                    measurement.get(field),
                    f"public report performance.operations.{operation}.{field}",
                )
        validated_operations[operation] = validated_measurement
    index_cost = _mapping(performance.get("index_cost"), "public report performance.index_cost")
    _exact_keys(index_cost, set(_MEASUREMENT_FIELDS), "public report performance.index_cost")
    if dict(index_cost) != validated_operations["scan"]:
        raise ValueError("public report index_cost must equal the scan operation")
    for operation in _QUERY_OPERATIONS:
        if query_latency.get(operation) != validated_operations[operation]["wall_seconds"]:
            raise ValueError(f"public report query latency drifted for {operation}")
    for operation in _OPERATIONS:
        if peak_rss.get(operation) != validated_operations[operation]["peak_rss_bytes"]:
            raise ValueError(f"public report peak RSS drifted for {operation}")
    performance_gate = _boolean(
        performance.get("gate_passed"), "public report performance.gate_passed"
    )

    _validate_comparisons(report.get("comparisons"))
    validation = _mapping(report.get("validation"), "public report validation")
    _exact_keys(
        validation,
        {
            "evaluation_report_sha256",
            "performance_report_sha256",
            "evaluation_gate_passed",
            "performance_gate_passed",
        },
        "public report validation",
    )
    _sha256(validation.get("evaluation_report_sha256"), "evaluation report digest")
    _sha256(validation.get("performance_report_sha256"), "performance report digest")
    if (
        _boolean(validation.get("evaluation_gate_passed"), "evaluation gate verdict")
        != quality_gate
    ):
        raise ValueError("public report evaluation gate verdict is inconsistent")
    if (
        _boolean(validation.get("performance_gate_passed"), "performance gate verdict")
        != performance_gate
    ):
        raise ValueError("public report performance gate verdict is inconsistent")


def canonical_json(report: Mapping[str, object]) -> str:
    validate_public_report(report)
    return json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True, allow_nan=False) + "\n"


def _markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _format_rate(value: object) -> str:
    return f"{float(value):.6f}"


def _format_seconds(value: object) -> str:
    return f"{float(value):.6f}"


def render_markdown(report: Mapping[str, object]) -> str:
    """Render the public report with stable headings, ordering, and precision."""

    validate_public_report(report)
    subject = _mapping(report["subject"], "subject")
    protocol = _mapping(report["protocol"], "protocol")
    quality = _mapping(report["quality"], "quality")
    accuracy = _mapping(quality["accuracy"], "quality.accuracy")
    no_answer = _mapping(quality["no_answer"], "quality.no_answer")
    safety = _mapping(quality["safety"], "quality.safety")
    performance = _mapping(report["performance"], "performance")
    environment = _mapping(performance["environment"], "performance.environment")
    fixture = _mapping(performance["fixture"], "performance.fixture")
    query_latency = _mapping(
        performance["query_latency_seconds"], "performance.query_latency_seconds"
    )
    peak_rss = _mapping(performance["peak_rss_bytes"], "performance.peak_rss_bytes")
    index_cost = _mapping(performance["index_cost"], "performance.index_cost")
    lines = [
        "# RepoLocus public benchmark report",
        "",
        "> **SMOKE ONLY.** " + _markdown_cell(subject["note"]),
        "> This report makes no cross-repository quality claim.",
        "",
        "## Subject and protocol",
        "",
        f"- RepoLocus version: `{_markdown_cell(subject['version'])}`",
        f"- Implementation SHA-256: `{_markdown_cell(subject['implementation_sha256'])}`",
        f"- Protocol manifest: `{_markdown_cell(protocol['manifest'])}`",
        f"- Protocol manifest SHA-256: `{_markdown_cell(protocol['manifest_sha256'])}`",
        f"- Hash algorithm: `{_markdown_cell(protocol['hash_algorithm'])}`",
        "",
        "## Fixture and qrel provenance",
        "",
        "| Fixture | Revision | License | Source | Fixture SHA-256 | Qrels SHA-256 | Qrels |",
        "|---|---|---|---|---|---|---:|",
    ]
    for item in _sequence(report["fixtures"], "fixtures"):
        provenance = _mapping(item, "fixture")
        lines.append(
            "| "
            + " | ".join(
                _markdown_cell(provenance[field])
                for field in (
                    "id",
                    "revision",
                    "license",
                    "source",
                    "tree_sha256",
                    "qrels_sha256",
                    "qrels",
                )
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Quality smoke metrics",
            "",
            "| Metric | Value |",
            "|---|---:|",
            f"| Reviewed qrels | {quality['qrels']} |",
            f"| Answerable qrels | {quality['answerable_qrels']} |",
            f"| No-answer qrels | {quality['no_answer_qrels']} |",
            f"| Hit rate | {_format_rate(accuracy['hit_rate'])} |",
            f"| Macro recall@k | {_format_rate(accuracy['macro_recall_at_k'])} |",
            f"| MRR | {_format_rate(accuracy['mrr'])} |",
            f"| Citation recall | {_format_rate(accuracy['citation_recall'])} |",
            f"| No-answer accuracy | {_format_rate(no_answer['accuracy'])} |",
            f"| No-answer precision | {_format_rate(no_answer['precision'])} |",
            f"| No-answer recall | {_format_rate(no_answer['recall'])} |",
            f"| No-answer F1 | {_format_rate(no_answer['f1'])} |",
            f"| Duplicate evidence rate | {_format_rate(safety['duplicate_evidence_rate'])} |",
            "| Must-not-return violation rate | "
            f"{_format_rate(safety['must_not_return_violation_rate'])} |",
            f"| Evaluation gate passed | `{str(quality['gate_passed']).lower()}` |",
            "",
            "## Resource and latency smoke metrics",
            "",
            f"Performance fixture: `{_markdown_cell(fixture['manifest'])}` with "
            f"{fixture['files']} files, {fixture['symbols']} symbols, "
            f"{fixture['dependencies']} dependencies, and {fixture['source_bytes']} source bytes.",
            "",
            "Environment: "
            f"Python `{_markdown_cell(environment['python'])}`, "
            f"platform `{_markdown_cell(environment['platform'])}`, "
            f"machine `{_markdown_cell(environment['machine'])}`, "
            f"{environment['cpu_count']} visible CPUs.",
            "",
            "| Query | Wall seconds |",
            "|---|---:|",
        ]
    )
    for operation in _QUERY_OPERATIONS:
        lines.append(f"| {operation} | {_format_seconds(query_latency[operation])} |")
    lines.extend(
        [
            "",
            "Peak resident memory by isolated operation:",
            "",
            "| Operation | Peak RSS bytes |",
            "|---|---:|",
        ]
    )
    for operation in _OPERATIONS:
        lines.append(f"| {operation} | {peak_rss[operation]} |")
    lines.extend(
        [
            "",
            "Index cost:",
            "",
            f"- Wall seconds: {_format_seconds(index_cost['wall_seconds'])}",
            f"- CPU seconds: {_format_seconds(index_cost['cpu_seconds'])}",
            f"- Peak RSS bytes: {index_cost['peak_rss_bytes']}",
            f"- SQLite statements: {index_cost['sqlite_query_count']}",
            f"- Database bytes: {index_cost['database_bytes']}",
            f"- WAL bytes: {index_cost['wal_bytes']}",
            f"- Performance gate passed: `{str(performance['gate_passed']).lower()}`",
            "",
            "## Competitor comparison",
            "",
            "| System | Status | Public equivalent protocol | Metrics | Reason |",
            "|---|---|---|---|---|",
        ]
    )
    for item in _sequence(report["comparisons"], "comparisons"):
        comparison = _mapping(item, "comparison")
        lines.append(
            "| "
            + " | ".join(
                (
                    _markdown_cell(comparison["system"]),
                    "N/A",
                    "N/A",
                    "N/A",
                    _markdown_cell(comparison["reason"]),
                )
            )
            + " |"
        )
    lines.extend(["", "## Reproduction", ""])
    for command in _sequence(protocol["reproduction_commands"], "reproduction commands"):
        command_data = _mapping(command, "reproduction command")
        argv = [
            _string(item, "reproduction argv")
            for item in _sequence(command_data["argv"], "reproduction argv")
        ]
        lines.extend(
            [
                f"### {_markdown_cell(command_data['id'])}",
                "",
                "```console",
                shlex.join(argv),
                "```",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def write_or_check_outputs(
    report: Mapping[str, object],
    json_output: Path,
    markdown_output: Path,
    *,
    check: bool,
) -> None:
    json_text = canonical_json(report)
    markdown_text = render_markdown(report)
    if json_output.resolve() == markdown_output.resolve():
        raise ValueError("JSON and Markdown outputs must be different paths")
    if check:
        for path, expected in ((json_output, json_text), (markdown_output, markdown_text)):
            if not path.is_file() or path.read_text(encoding="utf-8") != expected:
                raise ValueError(f"public benchmark output is missing or stale: {path}")
        return
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json_text, encoding="utf-8", newline="\n")
    markdown_output.write_text(markdown_text, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("benchmarks/public-benchmark-manifest.json"),
    )
    parser.add_argument("--evaluation-report", type=Path, required=True)
    parser.add_argument("--performance-report", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify that existing JSON and Markdown outputs are byte-for-byte current",
    )
    arguments = parser.parse_args()
    try:
        report = build_public_report(
            arguments.manifest,
            arguments.evaluation_report,
            arguments.performance_report,
        )
        write_or_check_outputs(
            report,
            arguments.json_output,
            arguments.markdown_output,
            check=arguments.check,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(
        "public benchmark outputs are current"
        if arguments.check
        else "public benchmark outputs written"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
