from __future__ import annotations

import importlib.util
import json
import random
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from repolocus.config import Settings
from repolocus.core import RepoLocusService
from repolocus.index import RepositoryIndex
from repolocus.models import Evidence
from repolocus.retrieval import RetrievalEngine, RetrievalHit, RetrievalResult


def _evaluation_script() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_retrieval.py"
    spec = importlib.util.spec_from_file_location("repolocus_evaluate_retrieval", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _external_evaluation_script() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_external_repositories.py"
    spec = importlib.util.spec_from_file_location("repolocus_external_evaluation", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    scripts = str(path.parent)
    sys.path.insert(0, scripts)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(scripts)
    return module


def _copy_external_evaluation(tmp_path: Path) -> Path:
    source = Path(__file__).resolve().parents[1] / "evaluation"
    destination = tmp_path / "evaluation"
    shutil.copytree(source, destination)
    return destination


def test_evaluation_reports_complete_ranked_and_no_answer_metrics() -> None:
    class FakeRetrieval:
        def search(self, question: str, limit: int) -> list[Evidence]:
            fixtures = {
                "multi": [
                    Evidence("b.py", 1, 1, "b", 3),
                    Evidence("irrelevant.py", 1, 1, "x", 2),
                    Evidence("a.py", 1, 3, "a\nvalue\nz", 1),
                ],
                "none": [],
                "miss": [],
                "spurious": [Evidence("irrelevant.py", 1, 1, "x", 1)],
            }
            return fixtures[question][:limit]

    cases = [
        {
            "question": "multi",
            "expected_paths": ["a.py", "b.py"],
            "expected_citations": ["a.py:2"],
            "language": "en",
        },
        {"question": "none", "expected_paths": [], "language": "zh"},
        {"question": "miss", "expected_paths": ["missing.py"], "language": "en"},
        {"question": "spurious", "expected_paths": [], "language": "zh"},
    ]

    outcomes, metrics = _evaluation_script().evaluate_cases(FakeRetrieval(), cases, limit=5)

    assert outcomes[0]["all_expected_paths"] is True
    assert outcomes[0]["citation_recall"] == 1.0
    assert outcomes[1]["recall_at_k"] is None
    assert outcomes[1]["reciprocal_rank"] is None
    assert outcomes[1]["ndcg_at_k"] is None
    assert metrics["cases"] == 4
    assert metrics["answerable_cases"] == 2
    assert metrics["no_answer_cases"] == 2
    assert metrics["macro_recall_at_k"] == 0.5
    assert metrics["mrr"] == 0.5
    assert metrics["all_expected_paths_rate"] == 0.5
    assert metrics["no_answer_precision"] == 0.5
    assert metrics["no_answer_recall"] == 0.5
    assert metrics["no_answer_f1"] == 0.5
    assert metrics["no_answer_accuracy"] == 0.5
    assert metrics["by_language"]["en"]["cases"] == 2  # type: ignore[index]
    assert metrics["by_language"]["zh"]["answerable_cases"] == 0  # type: ignore[index]
    assert metrics["by_language"]["zh"]["macro_recall_at_k"] is None  # type: ignore[index]
    assert metrics["by_repository"]["unspecified"]["cases"] == 4  # type: ignore[index]
    assert metrics["by_query_type"]["unspecified"]["cases"] == 4  # type: ignore[index]


def test_correct_no_answer_padding_cannot_inflate_answerable_metrics() -> None:
    class FakeRetrieval:
        def search(self, question: str, limit: int) -> list[Evidence]:
            if question == "hit":
                return [Evidence("answer.py", 1, 1, "answer", 1)][:limit]
            return []

    answerable = [
        {"question": "hit", "expected_paths": ["answer.py"]},
        {"question": "miss", "expected_paths": ["missing.py"]},
    ]
    negatives = [
        {"question": f"meaningful absent question {index}", "expected_paths": []}
        for index in range(100)
    ]
    evaluation = _evaluation_script()

    _, baseline = evaluation.evaluate_cases(FakeRetrieval(), answerable, limit=5)
    _, padded = evaluation.evaluate_cases(FakeRetrieval(), answerable + negatives, limit=5)

    for metric in (
        "macro_recall_at_k",
        "mrr",
        "mean_ndcg_at_k",
        "any_expected_path_rate",
        "all_expected_paths_rate",
    ):
        assert padded[metric] == baseline[metric]
    assert padded["answerable_cases"] == 2
    assert padded["no_answer_cases"] == 100


def test_no_answer_only_cases_do_not_report_retrieval_quality() -> None:
    class EmptyRetrieval:
        def search(self, question: str, limit: int) -> list[Evidence]:
            return []

    _, metrics = _evaluation_script().evaluate_cases(
        EmptyRetrieval(),
        [{"question": "meaningful but absent", "expected_paths": [], "language": "en"}],
        limit=5,
    )

    assert metrics["answerable_cases"] == 0
    assert metrics["macro_recall_at_k"] is None
    assert metrics["mrr"] is None
    assert metrics["mean_ndcg_at_k"] is None
    assert metrics["any_expected_path_rate"] is None
    assert metrics["all_expected_paths_rate"] is None
    assert metrics["no_answer_recall"] == 1.0


def test_spurious_answers_report_zero_no_answer_precision_and_f1() -> None:
    class SpuriousRetrieval:
        def search(self, question: str, limit: int) -> list[Evidence]:
            return [Evidence("wrong.py", 1, 1, "wrong", 1)][:limit]

    _, metrics = _evaluation_script().evaluate_cases(
        SpuriousRetrieval(),
        [{"question": "meaningful but absent", "expected_paths": [], "language": "en"}],
        limit=5,
    )

    assert metrics["no_answer_precision"] == 0.0
    assert metrics["no_answer_recall"] == 0.0
    assert metrics["no_answer_f1"] == 0.0


def test_ndcg_penalizes_missing_relevant_results_up_to_cutoff() -> None:
    evaluation = _evaluation_script()

    assert evaluation._ndcg(["a.py"], {"a.py", "b.py"}, 5) == pytest.approx(0.613147)


def test_evaluation_uses_structured_results_without_hiding_duplicate_ranges() -> None:
    duplicate = Evidence("answer.py", 1, 3, "answer\nvalue\nend", 1, generation=7)

    class StructuredRetrieval:
        def search_result(self, question: str, limit: int) -> RetrievalResult:
            assert question == "Where is answer defined?"
            assert limit == 5
            return RetrievalResult(
                evidence=(duplicate, duplicate),
                confidence=0.5,
                rejected_reason=None,
                intent="definition",
                hits=(
                    RetrievalHit(
                        chunk_id=1,
                        retriever="symbol_exact",
                        rank=1,
                        raw_score=None,
                        features={"rrf_weight": 3.2},
                    ),
                ),
                suppressed=((2, "overlapping_range"),),
            )

    outcomes, metrics = _evaluation_script().evaluate_cases(
        StructuredRetrieval(),
        [
            {
                "question": "Where is answer defined?",
                "query_type": "definition",
                "expected_intent": "definition",
                "relevant": [{"path": "answer.py", "start": 2, "end": 2, "grade": 3}],
                "answerable": True,
            }
        ],
        limit=5,
    )

    outcome = outcomes[0]
    assert outcome["returned_paths"] == ["answer.py"]
    assert len(outcome["returned_evidence"]) == 2  # type: ignore[arg-type]
    assert outcome["duplicate_evidence_rate"] == 0.5
    assert outcome["path_diversity"] == 0.5
    assert outcome["maximum_line_iou"] == 1.0
    assert outcome["intent"] == "definition"
    assert outcome["intent_match"] is True
    assert outcome["retrieval_hits"][0]["retriever"] == "symbol_exact"  # type: ignore[index]
    assert outcome["suppressed"] == [{"chunk_id": 2, "reason": "overlapping_range"}]
    assert metrics["duplicate_evidence_rate"] == 0.5
    assert metrics["mean_path_diversity"] == 0.5
    assert metrics["maximum_line_iou"] == 1.0
    assert metrics["intent_accuracy"] == 1.0


def test_evaluation_rejects_results_beyond_the_top_k_contract() -> None:
    class OverLimitRetrieval:
        def search(self, question: str, limit: int) -> list[Evidence]:
            return [Evidence(f"{number}.py", 1, 1, "value", 1) for number in range(limit + 1)]

    with pytest.raises(ValueError, match="more evidence than the requested limit"):
        _evaluation_script().evaluate_cases(
            OverLimitRetrieval(),
            [{"question": "target", "expected_paths": ["5.py"]}],
            limit=5,
        )


def test_dependency_path_hit_without_graph_evidence_fails_grounding_metric() -> None:
    class LexicalOnlyRetrieval:
        def search_result(self, question: str, limit: int) -> RetrievalResult:
            return RetrievalResult(
                evidence=(Evidence("dependency.py", 1, 2, "target", 1),),
                confidence=0.5,
                rejected_reason=None,
                intent="dependency",
                hits=(
                    RetrievalHit(
                        chunk_id=1,
                        retriever="full_text",
                        rank=1,
                        raw_score=1.0,
                        features={},
                    ),
                ),
            )

    outcomes, metrics = _evaluation_script().evaluate_cases(
        LexicalOnlyRetrieval(),
        [
            {
                "question": "Which dependency does caller import?",
                "query_type": "direct_dependency",
                "expected_intent": "dependency",
                "expected_paths": ["dependency.py"],
            }
        ],
        limit=5,
    )

    assert outcomes[0]["any_expected_path"] is True
    assert outcomes[0]["graph_grounded"] is False
    assert metrics["graph_grounded_rate"] == 0.0


def test_repository_question_set_keeps_top_five_path_hit_rate(
    isolated_user_dirs: Path,
) -> None:
    repository = Path(__file__).resolve().parents[1]
    cases = json.loads(
        (repository / "evaluation" / "questions.dataset").read_text(encoding="utf-8")
    )
    RepoLocusService(Settings(model="local")).scan(repository)

    with RepositoryIndex.open(repository) as index:
        retrieval = RetrievalEngine(index)
        outcomes, metrics = _evaluation_script().evaluate_cases(retrieval, cases, limit=5)

    assert len(cases) >= 10
    assert metrics["any_expected_path_rate"] >= 0.9  # type: ignore[operator]
    assert metrics["macro_recall_at_k"] >= 0.8  # type: ignore[operator]
    assert metrics["mrr"] >= 0.7  # type: ignore[operator]
    assert metrics["no_answer_f1"] == 1.0
    assert metrics["citation_recall"] == 1.0
    assert metrics["by_language"]["zh"]["macro_recall_at_k"] == 1.0  # type: ignore[index]
    assert metrics["by_query_type"]["identifier"]["answerable_cases"] >= 1  # type: ignore[index,operator]
    assert all(outcome["language"] in {"en", "zh"} for outcome in outcomes)


@pytest.mark.parametrize(
    "relevant",
    [
        [{"path": "source.py", "end": 1, "grade": 3}],
        [{"path": "source.py", "start": 1, "grade": 3}],
        [{"path": "source.py", "start": 0, "end": 1, "grade": 3}],
        [{"path": "source.py", "start": 2, "end": 1, "grade": 3}],
        [{"path": "source.py", "start": 1, "end": 3, "grade": 3}],
    ],
)
def test_external_qrels_require_explicit_valid_source_ranges(
    tmp_path: Path, relevant: list[dict[str, object]]
) -> None:
    (tmp_path / "source.py").write_text("first\nsecond\n", encoding="utf-8")
    case = {"answerable": True, "relevant": relevant, "must_not_return": []}

    with pytest.raises(ValueError, match="range"):
        _external_evaluation_script()._validate_case_sources(tmp_path, [case])


@pytest.mark.parametrize(
    "forbidden, message",
    [(["missing.py"], "does not exist"), (["source.py"], "overlap")],
)
def test_external_qrels_validate_must_not_return_paths(
    tmp_path: Path, forbidden: list[str], message: str
) -> None:
    (tmp_path / "source.py").write_text("answer\n", encoding="utf-8")
    case = {
        "answerable": True,
        "relevant": [{"path": "source.py", "start": 1, "end": 1, "grade": 3}],
        "must_not_return": forbidden,
    }

    with pytest.raises(ValueError, match=message):
        _external_evaluation_script()._validate_case_sources(tmp_path, [case])


@pytest.mark.parametrize(
    "forbidden",
    [
        "tests/./decoy.py",
        "tests//decoy.py",
        "tests\\decoy.py",
        "C:/tests/decoy.py",
        "C:tests/decoy.py",
    ],
)
def test_external_qrels_reject_noncanonical_must_not_return_paths(
    tmp_path: Path, forbidden: str
) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "decoy.py").write_text("decoy\n", encoding="utf-8")
    if sys.platform != "win32":
        windows_drive = tmp_path / "C:tests"
        windows_drive.mkdir()
        (windows_drive / "decoy.py").write_text("decoy\n", encoding="utf-8")
    case = {"answerable": False, "relevant": [], "must_not_return": [forbidden]}

    with pytest.raises(ValueError, match="repository-relative"):
        _external_evaluation_script()._validate_case_sources(tmp_path, [case])


def test_case_family_cannot_split_identical_reviewed_truth() -> None:
    cases = [
        {
            "fixture": "fixture",
            "case_id": f"case-{number}",
            "case_family": family,
            "query_type": "definition",
            "answerable": True,
            "relevant": [{"path": "source.py", "start": 1, "end": 1, "grade": 3}],
            "must_not_return": [f"decoy-{number}.py"],
        }
        for number, family in enumerate(("family-a", "family-b"), 1)
    ]

    with pytest.raises(ValueError, match="must share a case family"):
        _external_evaluation_script()._case_family_report(cases)


def test_external_qrels_reject_unknown_relevant_fields(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text("answer\n", encoding="utf-8")
    case = {
        "answerable": True,
        "relevant": [
            {
                "path": "source.py",
                "start": 1,
                "end": 1,
                "grade": 3,
                "note": "mechanical-family-split",
            }
        ],
        "must_not_return": [],
    }

    with pytest.raises(ValueError, match="contain exactly"):
        _external_evaluation_script()._validate_case_sources(tmp_path, [case])


def test_case_family_signature_ignores_unreviewed_relevant_metadata() -> None:
    cases = [
        {
            "fixture": "fixture",
            "case_id": f"case-{number}",
            "case_family": family,
            "query_type": "definition",
            "answerable": True,
            "relevant": [
                {
                    "path": "source.py",
                    "start": 1,
                    "end": 1,
                    "grade": 3,
                    "note": f"variant-{number}",
                }
            ],
            "must_not_return": [],
        }
        for number, family in enumerate(("family-a", "family-b"), 1)
    ]

    with pytest.raises(ValueError, match="must share a case family"):
        _external_evaluation_script()._case_family_report(cases)


def test_external_qrels_reject_duplicate_relevant_ranges(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text("answer\n", encoding="utf-8")
    case = {
        "answerable": True,
        "relevant": [
            {"path": "source.py", "start": 1, "end": 1, "grade": 3},
            {"path": "source.py", "start": 1, "end": 1, "grade": 1},
        ],
        "must_not_return": [],
    }

    with pytest.raises(ValueError, match="source range is duplicated"):
        _external_evaluation_script()._validate_case_sources(tmp_path, [case])


def test_case_family_signature_normalizes_duplicate_relevant_ranges() -> None:
    canonical = {"path": "source.py", "start": 1, "end": 1, "grade": 3}
    redundant = {"path": "source.py", "start": 1, "end": 1, "grade": 1}
    cases = [
        {
            "fixture": "fixture",
            "case_id": "case-1",
            "case_family": "family-a",
            "query_type": "definition",
            "answerable": True,
            "relevant": [canonical],
            "must_not_return": [],
        },
        {
            "fixture": "fixture",
            "case_id": "case-2",
            "case_family": "family-b",
            "query_type": "definition",
            "answerable": True,
            "relevant": [canonical, redundant],
            "must_not_return": [],
        },
    ]

    with pytest.raises(ValueError, match="must share a case family"):
        _external_evaluation_script()._case_family_report(cases)


@pytest.mark.parametrize(
    "ranges",
    [
        [(1, 2), (3, 4)],
        [(1, 4), (2, 3)],
    ],
)
def test_external_qrels_reject_split_or_overlapping_relevant_ranges(
    tmp_path: Path, ranges: list[tuple[int, int]]
) -> None:
    (tmp_path / "source.py").write_text("one\ntwo\nthree\nfour\n", encoding="utf-8")
    case = {
        "answerable": True,
        "relevant": [
            {"path": "source.py", "start": start, "end": end, "grade": 3} for start, end in ranges
        ],
        "must_not_return": [],
    }

    with pytest.raises(ValueError, match="overlap or be adjacent"):
        _external_evaluation_script()._validate_case_sources(tmp_path, [case])


def test_case_family_signature_normalizes_split_relevant_ranges() -> None:
    cases = [
        {
            "fixture": "fixture",
            "case_id": "case-1",
            "case_family": "family-a",
            "query_type": "definition",
            "answerable": True,
            "relevant": [{"path": "source.py", "start": 1, "end": 4, "grade": 3}],
            "must_not_return": [],
        },
        {
            "fixture": "fixture",
            "case_id": "case-2",
            "case_family": "family-b",
            "query_type": "definition",
            "answerable": True,
            "relevant": [
                {"path": "source.py", "start": 1, "end": 2, "grade": 3},
                {"path": "source.py", "start": 3, "end": 4, "grade": 1},
            ],
            "must_not_return": [],
        },
    ]

    with pytest.raises(ValueError, match="must share a case family"):
        _external_evaluation_script()._case_family_report(cases)


def test_no_answer_families_require_unique_reviewed_canonical_intents() -> None:
    cases = [
        {
            "fixture": "fixture",
            "case_id": f"case-{number}",
            "case_family": family,
            "query_type": "hard_negative",
            "answerable": False,
            "relevant": [],
            "must_not_return": [],
        }
        for number, family in enumerate(("family-a", "family-b"), 1)
    ]
    reviewed = {
        ("fixture", "family-a"): "absent-identifier",
        ("fixture", "family-b"): "absent-identifier",
    }

    with pytest.raises(ValueError, match="must share a case family"):
        _external_evaluation_script()._case_family_report(
            cases,
            reviewed_no_answer_intents=reviewed,
        )


def test_no_answer_family_must_exist_in_review_ledger() -> None:
    cases = [
        {
            "fixture": "fixture",
            "case_id": "case-1",
            "case_family": "family-a",
            "query_type": "hard_negative",
            "answerable": False,
            "relevant": [],
            "must_not_return": [],
        }
    ]

    with pytest.raises(ValueError, match="lacks reviewed canonical intent"):
        _external_evaluation_script()._case_family_report(cases)


def test_external_json_loader_rejects_duplicate_object_keys() -> None:
    with pytest.raises(ValueError, match="duplicate JSON key"):
        _external_evaluation_script()._load_json(
            '{"review_id":"visible","review_id":"effective"}',
            source="fixture.json",
        )


def test_external_qrels_reject_citation_truth_overrides(tmp_path: Path) -> None:
    qrels = tmp_path / "qrels.jsonl"
    qrels.write_text(
        json.dumps(
            {
                "case_id": "case-1",
                "case_family": "family-1",
                "question": "Where is source?",
                "language": "en",
                "query_type": "definition",
                "answerable": True,
                "relevant": [{"path": "source.py", "start": 1, "end": 1, "grade": 3}],
                "must_not_return": [],
                "expected_citations": ["source.py:2"],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="external evaluation schema"):
        _external_evaluation_script()._load_qrels(
            qrels,
            fixture="fixture",
            revision="fixture-v1",
        )


def test_clustered_bootstrap_never_splits_a_case_family() -> None:
    outcomes = [
        {"fixture": "one", "case_family": "shared", "case_id": "a"},
        {"fixture": "one", "case_family": "shared", "case_id": "b"},
        {"fixture": "one", "case_family": "single", "case_id": "c"},
        {"fixture": "two", "case_family": "other", "case_id": "d"},
    ]

    sample = _external_evaluation_script()._clustered_resample(outcomes, random.Random(7))
    sampled_ids = [item["case_id"] for item in sample]

    assert sampled_ids.count("a") == sampled_ids.count("b")


def test_clustered_bootstrap_weights_case_families_instead_of_case_padding() -> None:
    outcomes: list[dict[str, object]] = []
    for fixture_number in range(6):
        fixture = f"fixture-{fixture_number}"
        for family_number in range(12):
            family = f"family-{family_number}"
            value = 1.0 if family_number == 0 else 0.2
            repetitions = 1_000 if family_number == 0 else 1
            outcomes.extend(
                {
                    "fixture": fixture,
                    "case_family": family,
                    "answerable": True,
                    "predicted_no_answer": False,
                    "any_expected_path": value,
                    "recall_at_k": value,
                    "reciprocal_rank": value,
                    "citation_recall": value,
                    "duplicate_evidence_rate": 0.0,
                    "path_diversity": 1.0,
                    "intent_match": True,
                    "must_not_return": [],
                    "must_not_return_violations": [],
                }
                for _ in range(repetitions)
            )
    evaluation = _external_evaluation_script()
    evaluation._BOOTSTRAP_SAMPLES = 400

    report = evaluation._bootstrap_report(outcomes)

    assert report["weighting"] == "equal fixture/case-family clusters"
    assert report["intervals"]["mrr"][1] < 0.6


def test_bootstrap_reports_no_answer_f1_instead_of_majority_accuracy() -> None:
    outcomes = [
        {
            "fixture": "fixture",
            "case_family": f"answer-{number}",
            "answerable": True,
            "predicted_no_answer": False,
            "any_expected_path": 1.0,
            "recall_at_k": 1.0,
            "reciprocal_rank": 1.0,
            "citation_recall": 1.0,
            "must_not_return": [],
            "must_not_return_violations": [],
        }
        for number in range(9)
    ]
    outcomes.append(
        {
            "fixture": "fixture",
            "case_family": "no-answer",
            "answerable": False,
            "predicted_no_answer": False,
            "any_expected_path": None,
            "recall_at_k": None,
            "reciprocal_rank": None,
            "citation_recall": None,
            "must_not_return": [],
            "must_not_return_violations": [],
        }
    )
    evaluation = _external_evaluation_script()
    evaluation._BOOTSTRAP_SAMPLES = 50

    report = evaluation._bootstrap_report(outcomes)

    assert evaluation._no_answer_f1(outcomes) == 0.0
    assert "no_answer_f1" in report["intervals"]
    assert "no_answer_accuracy" not in report["intervals"]


def test_release_gate_uses_bootstrap_lower_and_upper_bounds() -> None:
    thresholds = {
        "minimum_hit_rate": 0.90,
        "minimum_macro_recall": 0.80,
        "minimum_mrr": 0.75,
        "minimum_citation_recall": 1.0,
        "minimum_no_answer_f1": 0.80,
        "maximum_must_not_return_rate": 0.0,
        "maximum_duplicate_evidence_rate": 1.0,
        "maximum_line_iou": 1.0,
        "minimum_intent_accuracy": 0.0,
        "minimum_graph_grounded_rate": 0.0,
        "minimum_mean_path_diversity": 0.0,
        "minimum_slice_hit_rate": 0.0,
        "minimum_slice_mrr": 0.0,
        "minimum_slice_no_answer_f1": 0.0,
        "minimum_qrels": 100,
        "minimum_answerable_qrels": 60,
        "minimum_no_answer_qrels": 20,
        "minimum_citation_qrels": 60,
    }
    report = {
        "bootstrap": {
            "intervals": {
                "any_expected_path_rate": [0.89, 1.0],
                "macro_recall_at_k": [0.90, 1.0],
                "mrr": [0.80, 1.0],
                "citation_recall": [1.0, 1.0],
                "no_answer_f1": [0.90, 1.0],
                "must_not_return_violation_rate": [0.0, 0.0],
                "duplicate_evidence_rate": [0.0, 0.0],
                "intent_accuracy": [1.0, 1.0],
                "graph_grounded_rate": [1.0, 1.0],
                "mean_path_diversity": [1.0, 1.0],
            }
        },
        "metrics": {
            "maximum_line_iou": 0.0,
            "by_query_type": {
                "definition": {
                    "answerable_cases": 1,
                    "no_answer_cases": 1,
                    "any_expected_path_rate": 1.0,
                    "mrr": 1.0,
                    "no_answer_f1": 1.0,
                }
            },
            "by_intent": {
                "definition": {
                    "answerable_cases": 1,
                    "no_answer_cases": 1,
                    "any_expected_path_rate": 1.0,
                    "mrr": 1.0,
                    "no_answer_f1": 1.0,
                }
            },
        },
        "qrels": 100,
        "answerable_qrels": 60,
        "no_answer_qrels": 20,
        "citation_qrels": 60,
    }

    lower_failure = _external_evaluation_script()._gate_report(report, thresholds)
    report["bootstrap"]["intervals"]["any_expected_path_rate"] = [0.9, 1.0]
    report["bootstrap"]["intervals"]["must_not_return_violation_rate"] = [0.0, 0.01]
    upper_failure = _external_evaluation_script()._gate_report(report, thresholds)

    assert lower_failure["passed"] is False
    assert lower_failure["observed"]["minimum_hit_rate"]["bound"] == "lower"
    assert upper_failure["passed"] is False
    assert upper_failure["observed"]["maximum_must_not_return_rate"]["bound"] == "upper"

    thresholds["minimum_hit_rate"] = float("nan")
    with pytest.raises(ValueError, match="finite number"):
        _external_evaluation_script()._gate_report(report, thresholds)


@pytest.mark.parametrize(
    "argument",
    [
        "--minimum-hit-rate=-inf",
        "--maximum-must-not-return-rate=nan",
        "--minimum-qrels=-1",
        "--limit=0",
    ],
)
def test_external_gate_rejects_non_finite_and_out_of_range_thresholds(argument: str) -> None:
    repository = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            str(repository / "scripts" / "evaluate_external_repositories.py"),
            str(repository / "evaluation"),
            argument,
        ],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 2
    assert "error:" in result.stderr


def test_review_provenance_checksum_detects_drift(tmp_path: Path) -> None:
    evaluation_root = _copy_external_evaluation(tmp_path)
    provenance = evaluation_root / "qrels" / "review-provenance.json"
    provenance.write_text(
        provenance.read_text(encoding="utf-8").replace("Manual", "Changed", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="review provenance checksum mismatch"):
        _external_evaluation_script().evaluate_suite(evaluation_root)


@pytest.mark.parametrize("duplicate", ["id", "root", "qrel_path", "tree_hash", "qrel_hash"])
def test_external_gate_rejects_duplicate_fixture_identity(tmp_path: Path, duplicate: str) -> None:
    evaluation_root = _copy_external_evaluation(tmp_path)
    manifest_path = evaluation_root / "external-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    first, second = manifest["fixtures"][:2]
    if duplicate == "id":
        second["id"] = first["id"]
    elif duplicate == "root":
        second["path"] = first["path"]
    elif duplicate == "qrel_path":
        second["qrels"] = first["qrels"]
    elif duplicate == "tree_hash":
        second_root = evaluation_root / second["path"]
        shutil.rmtree(second_root)
        shutil.copytree(evaluation_root / first["path"], second_root)
        second["tree_sha256"] = first["tree_sha256"]
    else:
        shutil.copyfile(evaluation_root / first["qrels"], evaluation_root / second["qrels"])
        second["qrels_sha256"] = first["qrels_sha256"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="unique"):
        _external_evaluation_script().evaluate_suite(evaluation_root)


def test_json_loader_rejects_non_finite_numbers() -> None:
    with pytest.raises(ValueError, match="invalid JSON"):
        _external_evaluation_script()._load_json('{"threshold": NaN}', source="test")


def test_external_multi_repository_release_gate_is_reproducible() -> None:
    repository = Path(__file__).resolve().parents[1]
    command = [
        sys.executable,
        str(repository / "scripts" / "evaluate_external_repositories.py"),
        str(repository / "evaluation"),
    ]
    results = [
        subprocess.run(
            command,
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        for _ in range(2)
    ]

    assert all(result.returncode == 0 for result in results), "\n".join(
        result.stderr or result.stdout for result in results
    )
    assert results[0].stdout.isascii()
    assert results[0].stdout == results[1].stdout
    reports = [json.loads(result.stdout) for result in results]
    assert reports[0] == reports[1]
    report = reports[0]
    metrics = report["metrics"]
    assert report["bootstrap"]["samples"] == 2000
    assert report["bootstrap"]["confidence"] == 0.95
    assert report["bootstrap"]["cluster_unit"] == "fixture/case_family"
    assert report["bootstrap"]["fixture_clusters"] == 6
    assert report["bootstrap"]["family_clusters"] == 82
    assert set(report["bootstrap"]["intervals"]) == {
        "any_expected_path_rate",
        "macro_recall_at_k",
        "mrr",
        "citation_recall",
        "duplicate_evidence_rate",
        "graph_grounded_rate",
        "intent_accuracy",
        "mean_path_diversity",
        "no_answer_f1",
        "must_not_return_violation_rate",
    }
    assert report["manifest"] == "external-manifest.json"
    assert report["fixture_count"] == 6
    assert report["qrels"] == 102
    assert report["reviewed_qrels"] == 102
    assert report["case_families"] == 82
    assert report["answerable_qrels"] == 72
    assert report["no_answer_qrels"] == 30
    assert report["citation_qrels"] == 72
    assert report["must_not_return_qrels"] == 33
    assert report["review_provenance"]["review_id"] == "v0.2.0-qrels-r3"
    assert len(report["review_provenance"]["sha256"]) == 64
    assert set(report["query_types"]) == {
        "ambiguous_dependency",
        "architecture",
        "configuration",
        "definition",
        "direct_dependency",
        "entry_point",
        "exact_symbol",
        "expanded_symbol",
        "hard_negative",
        "partial_symbol",
        "path",
        "reverse_dependency",
    }
    assert report["gate"]["passed"] is True
    assert report["gate"]["basis"] == (
        "95% equal-weight fixture/case-family clustered bootstrap bounds, "
        "v0.2 semantic slices, and observed counts"
    )
    assert report["gate"]["thresholds"] == {
        "maximum_duplicate_evidence_rate": 0.0,
        "maximum_line_iou": 0.79,
        "maximum_must_not_return_rate": 0.0,
        "minimum_answerable_qrels": 60,
        "minimum_citation_recall": 1.0,
        "minimum_citation_qrels": 60,
        "minimum_graph_grounded_rate": 1.0,
        "minimum_hit_rate": 0.9,
        "minimum_intent_accuracy": 1.0,
        "minimum_macro_recall": 0.8,
        "minimum_mean_path_diversity": 0.5,
        "minimum_mrr": 0.75,
        "minimum_no_answer_f1": 0.8,
        "minimum_no_answer_qrels": 20,
        "minimum_qrels": 100,
        "minimum_slice_hit_rate": 0.5,
        "minimum_slice_mrr": 0.5,
        "minimum_slice_no_answer_f1": 0.75,
    }
    assert all(item["passed"] for item in report["gate"]["observed"].values())
    assert metrics["any_expected_path_rate"] >= 0.90
    assert metrics["macro_recall_at_k"] >= 0.80
    assert metrics["mrr"] >= 0.75
    assert metrics["citation_recall"] >= 1.0
    assert metrics["no_answer_f1"] >= 0.80
    assert metrics["must_not_return_violation_rate"] == 0.0
    assert set(metrics["by_repository"]) == {
        "cpp-cmake",
        "go-service",
        "java-gradle",
        "python-small",
        "rust-cli",
        "typescript-web",
    }
    assert all(bucket["cases"] == 17 for bucket in metrics["by_repository"].values())
    assert all(fixture["revision"] == "fixture-v4" for fixture in report["fixtures"])
    assert all(fixture["must_not_return_qrels"] >= 5 for fixture in report["fixtures"])
    assert all(fixture["case_families"] >= 12 for fixture in report["fixtures"])
    assert all(fixture["content_generation"] == 1 for fixture in report["fixtures"])
    assert all(fixture["scan_revision"] == 1 for fixture in report["fixtures"])
    assert all(outcome["qrel_line"] for outcome in report["outcomes"])
    assert all(outcome["case_id"] for outcome in report["outcomes"])
    assert all(outcome["case_family"] for outcome in report["outcomes"])


def test_external_fixture_bytes_are_lf_pinned_for_cross_platform_git_checkouts() -> None:
    repository = Path(__file__).resolve().parents[1]
    attributes = (repository / ".gitattributes").read_text(encoding="utf-8").splitlines()

    assert "evaluation/repos/** text eol=lf" in attributes
    assert "evaluation/qrels/** text eol=lf" in attributes
    assert "evaluation/external-manifest.json text eol=lf" in attributes
