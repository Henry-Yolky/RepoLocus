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
    ]

    outcomes, metrics = _evaluation_script().evaluate_cases(FakeRetrieval(), cases, limit=5)

    assert outcomes[0]["all_expected_paths"] is True
    assert outcomes[0]["citation_recall"] == 1.0
    assert metrics["macro_recall_at_k"] == 0.666667
    assert metrics["all_expected_paths_rate"] == 0.666667
    assert metrics["no_answer_precision"] == 0.5
    assert metrics["no_answer_accuracy"] == 1.0
    assert metrics["by_language"]["en"]["cases"] == 2  # type: ignore[index]


def test_ndcg_penalizes_missing_relevant_results_up_to_cutoff() -> None:
    evaluation = _evaluation_script()

    assert evaluation._ndcg(["a.py"], {"a.py", "b.py"}, 5) == pytest.approx(0.613147)


def test_repository_question_set_keeps_top_five_path_hit_rate(
    isolated_user_dirs: Path,
) -> None:
    repository = Path(__file__).resolve().parents[1]
    cases = json.loads((repository / "evaluation" / "questions.json").read_text(encoding="utf-8"))
    RepoLocusService(Settings(model="local")).scan(repository)

    answerable = [case for case in cases if case["expected_paths"]]
    passed = 0
    with RepositoryIndex.open(repository) as index:
        retrieval = RetrievalEngine(index)
        for case in answerable:
            returned = {item.path for item in retrieval.search(case["question"], limit=5)}
            if returned.intersection(case["expected_paths"]):
                passed += 1

    assert len(cases) >= 10
    assert passed / len(answerable) >= 0.9
