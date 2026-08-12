from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import sys
from functools import lru_cache
from pathlib import Path
from types import ModuleType

import pytest

_OPERATIONS = (
    "scan",
    "map",
    "diagram",
    "symbol_query",
    "dependency_query",
    "retrieval",
)
_COMMAND_IDS = ("evaluation", "performance", "report", "check")


def _repository() -> Path:
    return Path(__file__).resolve().parents[1]


def _report_module() -> ModuleType:
    scripts = str(_repository() / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    path = _repository() / "scripts" / "public_benchmark_report.py"
    spec = importlib.util.spec_from_file_location("repolocus_public_benchmark", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _script_module(filename: str, name: str) -> ModuleType:
    scripts = str(_repository() / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    path = _repository() / "scripts" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@lru_cache(maxsize=1)
def _benchmark_module() -> ModuleType:
    path = _repository() / "benchmarks" / "benchmark_v020.py"
    spec = importlib.util.spec_from_file_location(
        "repolocus_test_public_performance_protocol", path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _external_manifest() -> dict[str, object]:
    return json.loads(
        (_repository() / "evaluation" / "external-manifest.json").read_text(encoding="utf-8")
    )


@lru_cache(maxsize=1)
def _pinned_evaluation_truth() -> dict[str, object]:
    evaluation_module = _script_module(
        "evaluate_external_repositories.py", "repolocus_test_public_truth_protocol"
    )
    evaluation_root = _repository() / "evaluation"
    manifest = _external_manifest()
    review_artifacts, review_report, reviewed_no_answer_intents = (
        evaluation_module._load_review_provenance(evaluation_root, manifest)
    )
    cases: list[dict[str, object]] = []
    fixture_roots: dict[str, Path] = {}
    fixtures: list[dict[str, object]] = []
    for fixture in manifest["fixtures"]:
        fixture_id = fixture["id"]
        revision = fixture["revision"]
        root = (evaluation_root / fixture["path"]).resolve(strict=True)
        qrels = (evaluation_root / fixture["qrels"]).resolve(strict=True)
        assert evaluation_module.fixture_tree_sha256(root) == fixture["tree_sha256"]
        assert evaluation_module._sha256_file(qrels) == fixture["qrels_sha256"]
        review = review_artifacts.pop(fixture_id)
        assert review["fixture_revision"] == revision
        fixture_cases = evaluation_module._load_qrels(
            qrels,
            fixture=fixture_id,
            revision=revision,
        )
        evaluation_module._validate_case_sources(root, fixture_cases)
        assert len(fixture_cases) == fixture["qrels_count"]
        cases.extend(fixture_cases)
        fixture_roots[fixture_id] = root
        fixtures.append(
            {
                "id": fixture_id,
                "revision": revision,
                "source": fixture["source"],
                "license": fixture["license"],
                "tree_sha256": fixture["tree_sha256"],
                "qrels_sha256": fixture["qrels_sha256"],
                "qrels": len(fixture_cases),
                "must_not_return_qrels": sum(
                    bool(case["must_not_return"]) for case in fixture_cases
                ),
                "dependency_expectations": sum(
                    case.get("expected_dependency") is not None for case in fixture_cases
                ),
                "content_generation": 1,
                "scan_revision": 1,
            }
        )
    assert not review_artifacts
    family_counts, families_by_type, fixtures_by_type = evaluation_module._case_family_report(
        cases,
        reviewed_no_answer_intents=reviewed_no_answer_intents,
    )
    for fixture in fixtures:
        fixture["case_families"] = family_counts[fixture["id"]]
    return {
        "cases": cases,
        "fixture_roots": fixture_roots,
        "fixtures": fixtures,
        "review_provenance": review_report,
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


def _evaluation_outcomes() -> list[dict[str, object]]:
    retrieval_module = _script_module(
        "evaluate_retrieval.py", "repolocus_test_public_outcome_protocol"
    )
    truth = _pinned_evaluation_truth()
    fixture_roots = truth["fixture_roots"]
    outcomes: list[dict[str, object]] = []
    for case in truth["cases"]:
        fixture = case["fixture"]
        evidence = []
        for relevant in case["relevant"]:
            path = relevant["path"]
            start = relevant["start"]
            end = relevant["end"]
            source = fixture_roots[fixture] / path
            content = "".join(
                source.read_text(encoding="utf-8").splitlines(keepends=True)[start - 1 : end]
            )
            graph_reason = {
                "direct_dependency": "dependency of pinned-source",
                "reverse_dependency": "dependent of pinned-source",
            }.get(case["query_type"], "pinned test evidence")
            evidence.append(
                {
                    "path": path,
                    "start_line": start,
                    "end_line": end,
                    "citation": f"{path}:{start}" + (f"-{end}" if end != start else ""),
                    "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    "symbol": "",
                    "generation": 1,
                    "reason": graph_reason,
                }
            )
        graph_retriever = {
            "direct_dependency": "outbound_dependency",
            "reverse_dependency": "reverse_dependency",
        }.get(case["query_type"])
        hits = (
            [
                {
                    "chunk_id": 1,
                    "retriever": graph_retriever,
                    "rank": 1,
                    "raw_score": 1.0,
                    "features": {},
                }
            ]
            if graph_retriever is not None
            else []
        )
        placeholder = {field: None for field in retrieval_module._OUTCOME_FIELDS}
        placeholder.update(
            {
                "fixture": fixture,
                "case_id": case["case_id"],
                "intent": case["expected_intent"],
                "confidence": 1.0 if evidence else 0.0,
                "rejected_reason": None if evidence else "no_candidates",
                "returned_evidence": evidence,
                "retrieval_hits": hits,
                "suppressed": [],
            }
        )
        outcomes.append(
            retrieval_module._canonical_outcome_from_serialized_evidence(
                case,
                placeholder,
                limit=5,
                fixture_root=fixture_roots[fixture],
            )
        )
    return outcomes


@lru_cache(maxsize=1)
def _base_evaluation_report() -> dict[str, object]:
    retrieval_module = _script_module(
        "evaluate_retrieval.py", "repolocus_test_public_retrieval_protocol"
    )
    evaluation_module = _script_module(
        "evaluate_external_repositories.py", "repolocus_test_public_evaluation_protocol"
    )
    public_manifest = json.loads(
        (_repository() / "benchmarks" / "public-benchmark-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    benchmark_module = _benchmark_module()
    truth = _pinned_evaluation_truth()
    outcomes = _evaluation_outcomes()
    metrics = retrieval_module.summarize_outcomes(outcomes)
    report = {
        "manifest": "external-manifest.json",
        "evaluation_script_sha256": public_manifest["artifacts"]["evaluation_runner"]["sha256"],
        "evaluation_metrics_script_sha256": public_manifest["artifacts"][
            "evaluation_metrics_runner"
        ]["sha256"],
        "implementation_sha256": benchmark_module._implementation_sha256(),
        "repolocus_version": benchmark_module.__version__,
        "review_provenance": truth["review_provenance"],
        "fixtures": truth["fixtures"],
        "fixture_count": len(truth["fixtures"]),
        "qrels": truth["qrels"],
        "reviewed_qrels": truth["reviewed_qrels"],
        "case_families": truth["case_families"],
        "case_families_by_query_type": truth["case_families_by_query_type"],
        "query_type_fixture_counts": truth["query_type_fixture_counts"],
        "query_types": truth["query_types"],
        "runtime_intents": truth["runtime_intents"],
        "corpus_coverage": truth["corpus_coverage"],
        "answerable_qrels": truth["answerable_qrels"],
        "no_answer_qrels": truth["no_answer_qrels"],
        "citation_qrels": truth["citation_qrels"],
        "must_not_return_qrels": truth["must_not_return_qrels"],
        "top_k": 5,
        "metrics": metrics,
        "bootstrap": evaluation_module._bootstrap_report(outcomes),
        "outcomes": outcomes,
    }
    report["gate"] = evaluation_module._gate_report(report, evaluation_module.default_thresholds())
    return report


def _evaluation_report() -> dict[str, object]:
    return copy.deepcopy(_base_evaluation_report())


def _measurement(operation: str, index: int) -> dict[str, object]:
    return {
        "name": operation,
        "wall_seconds": round(0.1 + index / 100, 6),
        "cpu_seconds": round(0.08 + index / 100, 6),
        "peak_rss_bytes": 10_000 + index,
        "sqlite_query_count": 1,
        "database_bytes": 20_000,
        "wal_bytes": 0,
        "worker_pid": 100 + index,
    }


def _performance_report() -> dict[str, object]:
    manifest = json.loads(
        (_repository() / "benchmarks" / "public-benchmark-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    benchmark_module = _benchmark_module()
    operations = {
        operation: _measurement(operation, index) for index, operation in enumerate(_OPERATIONS)
    }
    performance_manifest = json.loads(
        (_repository() / "benchmarks" / "v0.2-gates.json").read_text(encoding="utf-8")
    )
    passed, violations = benchmark_module._gate(
        operations,
        performance_manifest["thresholds"],
    )
    return {
        "benchmark": "v0.2-indexed-workflows-v1",
        "benchmark_script_sha256": manifest["artifacts"]["performance_runner"]["sha256"],
        "implementation_sha256": benchmark_module._implementation_sha256(),
        "repolocus_version": benchmark_module.__version__,
        "manifest": "v0.2-gates.json",
        "files": 1_000,
        "python": "3.12.3",
        "platform": "Linux-test-x86_64",
        "machine": "x86_64",
        "cpu_count": 8,
        "source_bytes": 5_141_250,
        "symbols": 5_000,
        "dependencies": 990,
        "operations": operations,
        "gate": {"passed": passed, "violations": violations},
    }


def _build_report(
    tmp_path: Path,
    *,
    evaluation: dict[str, object] | None = None,
    performance: dict[str, object] | None = None,
) -> tuple[ModuleType, dict[str, object], Path, Path]:
    module = _report_module()
    evaluation_path = tmp_path / "evaluation.json"
    performance_path = tmp_path / "performance.json"
    _write_json(evaluation_path, evaluation or _evaluation_report())
    _write_json(performance_path, performance or _performance_report())
    report = module.build_public_report(
        _repository() / "benchmarks" / "public-benchmark-manifest.json",
        evaluation_path,
        performance_path,
        repository_root=_repository(),
    )
    return module, report, evaluation_path, performance_path


def test_manifest_pins_public_protocol_and_clean_output_directory() -> None:
    module = _report_module()
    manifest = module.load_public_manifest(
        _repository() / "benchmarks" / "public-benchmark-manifest.json",
        repository_root=_repository(),
    )

    assert manifest["scope"] == {
        "classification": "smoke",
        "cross_repository_quality_claim": False,
        "note": (
            "Public, reproducible RepoLocus-authored synthetic smoke/regression suite "
            "only; quality results must not be extrapolated to independent or "
            "production repositories."
        ),
    }
    assert set(manifest["artifacts"]) == {
        "evaluation_manifest",
        "evaluation_metrics_runner",
        "evaluation_runner",
        "performance_manifest",
        "performance_runner",
        "report_runner",
        "report_schema",
    }
    assert [command["id"] for command in manifest["commands"]] == [
        "evaluation",
        "performance",
        "report",
        "check",
    ]
    assert all(item["status"] == "N/A" for item in manifest["comparisons"])
    assert all(item["protocol"] is None for item in manifest["comparisons"])
    assert all(item["metrics"] is None for item in manifest["comparisons"])
    assert (_repository() / "benchmarks" / "results" / ".gitignore").is_file()


def test_report_unifies_provenance_quality_and_performance(tmp_path: Path) -> None:
    module, report, evaluation_path, performance_path = _build_report(tmp_path)

    assert report["schema_version"] == 1
    assert report["benchmark_id"] == "repolocus-public-benchmark-v1"
    assert report["subject"]["result_classification"] == "smoke"
    assert report["subject"]["cross_repository_quality_claim"] is False
    assert [fixture["id"] for fixture in report["fixtures"]] == sorted(
        fixture["id"] for fixture in report["fixtures"]
    )
    assert report["quality"]["qrels"] == 102
    assert report["quality"]["accuracy"]["hit_rate"] == 1.0
    assert report["quality"]["no_answer"]["f1"] == 1.0
    assert report["quality"]["safety"]["must_not_return_violation_rate"] == 0.0
    performance = report["performance"]
    assert performance["query_latency_seconds"]["retrieval"] == 0.15
    assert performance["peak_rss_bytes"]["scan"] == 10_000
    assert performance["index_cost"] == performance["operations"]["scan"]
    assert report["validation"] == {
        "evaluation_report_sha256": module._sha256_file(evaluation_path),
        "performance_report_sha256": module._sha256_file(performance_path),
        "evaluation_gate_passed": True,
        "performance_gate_passed": True,
    }


def test_json_and_markdown_are_deterministic_and_explicitly_smoke_only(
    tmp_path: Path,
) -> None:
    module, report, _, _ = _build_report(tmp_path)

    assert module.canonical_json(report) == module.canonical_json(copy.deepcopy(report))
    markdown = module.render_markdown(report)
    assert markdown == module.render_markdown(copy.deepcopy(report))
    assert "**SMOKE ONLY.**" in markdown
    assert "no cross-repository quality claim" in markdown
    assert "## Quality smoke metrics" in markdown
    assert "## Resource and latency smoke metrics" in markdown
    assert "RepoWiki | N/A | N/A | N/A" in markdown
    assert "DeepWiki | N/A | N/A | N/A" in markdown
    assert "Sourcebot | N/A | N/A | N/A" in markdown
    assert "scripts/evaluate_external_repositories.py evaluation" in markdown
    assert "benchmarks/benchmark_v020.py --manifest benchmarks/v0.2-gates.json" in markdown


def test_write_and_check_detect_stale_output(tmp_path: Path) -> None:
    module, report, _, _ = _build_report(tmp_path)
    json_output = tmp_path / "outputs" / "report.json"
    markdown_output = tmp_path / "outputs" / "report.md"

    module.write_or_check_outputs(report, json_output, markdown_output, check=False)
    module.write_or_check_outputs(report, json_output, markdown_output, check=True)
    markdown_output.write_text("stale\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing or stale"):
        module.write_or_check_outputs(report, json_output, markdown_output, check=True)


def test_report_rejects_fixture_provenance_drift(tmp_path: Path) -> None:
    evaluation = _evaluation_report()
    evaluation["fixtures"][0]["license"] = "unknown"

    with pytest.raises(ValueError, match="fixture provenance drifted"):
        _build_report(tmp_path, evaluation=evaluation)


def test_report_rejects_scale_artifact_outside_pinned_public_protocol(
    tmp_path: Path,
) -> None:
    performance = _performance_report()
    performance["manifest"] = "v0.2-scale-gates.json"

    with pytest.raises(ValueError, match="different manifest"):
        _build_report(tmp_path, performance=performance)


def test_report_rejects_evaluation_metrics_forged_independently_of_outcomes(
    tmp_path: Path,
) -> None:
    evaluation = _evaluation_report()
    evaluation["metrics"]["any_expected_path_rate"] = 0.0

    with pytest.raises(ValueError, match="metrics do not match the serialized outcomes"):
        _build_report(tmp_path, evaluation=evaluation)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "missing pinned qrels"),
        ("duplicate", "outcome is duplicated"),
        ("unknown", "not in the pinned qrel inventory"),
        ("wrong_truth", "field question does not match"),
        ("forged_metric", "field recall_at_k does not match"),
    ],
)
def test_report_binds_every_outcome_to_pinned_qrel_truth(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    evaluation = _evaluation_report()
    if mutation == "missing":
        evaluation["outcomes"].pop()
    elif mutation == "duplicate":
        evaluation["outcomes"].append(copy.deepcopy(evaluation["outcomes"][0]))
    elif mutation == "unknown":
        evaluation["outcomes"][0]["case_id"] = "unknown-case"
    elif mutation == "wrong_truth":
        evaluation["outcomes"][0]["question"] = "forged question"
    else:
        evaluation["outcomes"][0]["recall_at_k"] = 0.0

    with pytest.raises(ValueError, match=message):
        _build_report(tmp_path, evaluation=evaluation)


def test_report_rejects_serialized_evidence_content_forgery(tmp_path: Path) -> None:
    evaluation = _evaluation_report()
    outcome = next(item for item in evaluation["outcomes"] if item["returned_evidence"])
    outcome["returned_evidence"][0]["content_sha256"] = "0" * 64

    with pytest.raises(ValueError, match="does not match the pinned fixture content"):
        _build_report(tmp_path, evaluation=evaluation)


def test_qrel_loader_rejects_pinned_qrel_drift(tmp_path: Path) -> None:
    evaluation_root = tmp_path / "evaluation"
    shutil.copytree(_repository() / "evaluation", evaluation_root)
    qrels = evaluation_root / "qrels" / "python-small.jsonl"
    qrels.write_text(
        qrels.read_text(encoding="utf-8").replace("local path", "changed path", 1),
        encoding="utf-8",
    )
    manifest_path = evaluation_root / "external-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report_module = _report_module()
    evaluation_module = _script_module(
        "evaluate_external_repositories.py", "repolocus_test_public_drift_protocol"
    )

    with pytest.raises(ValueError, match="pinned evaluation qrel checksum mismatch"):
        report_module._pinned_evaluation_cases(
            manifest_path,
            manifest,
            evaluation_module,
        )


def test_report_rejects_evaluation_gate_forged_independently_of_metrics(
    tmp_path: Path,
) -> None:
    evaluation = _evaluation_report()
    evaluation["gate"]["passed"] = False

    with pytest.raises(ValueError, match="gate does not match recomputed pinned thresholds"):
        _build_report(tmp_path, evaluation=evaluation)


def test_report_rejects_performance_measurement_with_forged_passing_gate(
    tmp_path: Path,
) -> None:
    performance = _performance_report()
    performance["operations"]["scan"]["wall_seconds"] = 99_999.0

    with pytest.raises(ValueError, match="performance gate does not match recomputed"):
        _build_report(tmp_path, performance=performance)


@pytest.mark.parametrize("field", ["repolocus_version", "implementation_sha256"])
def test_report_rejects_cross_protocol_subject_mismatch(tmp_path: Path, field: str) -> None:
    evaluation = _evaluation_report()
    evaluation[field] = "0.2.0" if field == "repolocus_version" else "2" * 64

    with pytest.raises(ValueError, match=rf"different {field}"):
        _build_report(tmp_path, evaluation=evaluation)


@pytest.mark.parametrize(
    ("report_name", "field"),
    [
        ("evaluation", "evaluation_script_sha256"),
        ("performance", "benchmark_script_sha256"),
    ],
)
def test_report_rejects_runner_hash_mismatch(
    tmp_path: Path,
    report_name: str,
    field: str,
) -> None:
    evaluation = _evaluation_report()
    performance = _performance_report()
    report = evaluation if report_name == "evaluation" else performance
    report[field] = "2" * 64

    with pytest.raises(ValueError, match=rf"{report_name} report runner hash"):
        _build_report(tmp_path, evaluation=evaluation, performance=performance)


def test_report_rejects_metrics_runner_hash_mismatch(tmp_path: Path) -> None:
    evaluation = _evaluation_report()
    evaluation["evaluation_metrics_script_sha256"] = "2" * 64

    with pytest.raises(ValueError, match="evaluation report metrics runner hash"):
        _build_report(tmp_path, evaluation=evaluation)


def test_report_injects_pinned_metrics_module_when_loading_evaluator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation = _evaluation_report()
    performance = _performance_report()
    fake = ModuleType("evaluate_retrieval")
    monkeypatch.setitem(sys.modules, "evaluate_retrieval", fake)

    _, report, _, _ = _build_report(
        tmp_path,
        evaluation=evaluation,
        performance=performance,
    )

    assert report["quality"]["gate_passed"] is True


def test_report_rejects_competitor_metrics_without_equivalent_protocol(
    tmp_path: Path,
) -> None:
    module, report, _, _ = _build_report(tmp_path)
    report["comparisons"][0]["metrics"] = {"hit_rate": 1.0}

    with pytest.raises(ValueError, match="without a pinned equivalent protocol"):
        module.validate_public_report(report)


def test_report_validator_rejects_cross_field_drift(tmp_path: Path) -> None:
    module, report, _, _ = _build_report(tmp_path)
    report["performance"]["query_latency_seconds"]["retrieval"] = 999.0

    with pytest.raises(ValueError, match="query latency drifted"):
        module.validate_public_report(report)


def test_report_validator_rejects_mutated_reproduction_argv(tmp_path: Path) -> None:
    module, report, _, _ = _build_report(tmp_path)
    report["protocol"]["reproduction_commands"][0]["argv"] = ["not-the-pinned-command"]

    with pytest.raises(ValueError, match="reproduction command"):
        module.validate_public_report(report)


def test_json_schema_is_strict_and_matches_report_identity(tmp_path: Path) -> None:
    module, report, _, _ = _build_report(tmp_path)
    schema = json.loads(
        (_repository() / "benchmarks" / "public-benchmark-report.schema.json").read_text(
            encoding="utf-8"
        )
    )

    module.validate_public_report(report)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == 1
    assert schema["properties"]["benchmark_id"]["const"] == "repolocus-public-benchmark-v1"
    assert (
        schema["properties"]["subject"]["properties"]["cross_repository_quality_claim"]["const"]
        is False
    )
    assert schema["properties"]["comparisons"]["minItems"] == 3
    protocol_properties = schema["properties"]["protocol"]["properties"]
    assert protocol_properties["evaluation_metrics_runner"] == {
        "const": "scripts/evaluate_retrieval.py"
    }
    assert protocol_properties["evaluation_metrics_runner_sha256"] == {"$ref": "#/$defs/sha256"}
    manifest = json.loads(
        (_repository() / "benchmarks" / "public-benchmark-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    for command_id, expected in zip(_COMMAND_IDS, manifest["commands"], strict=True):
        argv_schema = schema["$defs"][f"{command_id}_command"]["properties"]["argv"]
        assert argv_schema["minItems"] == len(expected["argv"])
        assert argv_schema["maxItems"] == len(expected["argv"])
        assert argv_schema["items"] is False
        assert [item["const"] for item in argv_schema["prefixItems"]] == expected["argv"]
