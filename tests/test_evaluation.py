from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from repolocus.config import Settings
from repolocus.core import RepoLocusService
from repolocus.index import RepositoryIndex
from repolocus.models import Evidence
from repolocus.retrieval import RetrievalEngine


def _evaluation_script() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_retrieval.py"
    spec = importlib.util.spec_from_file_location("repolocus_evaluate_retrieval", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
