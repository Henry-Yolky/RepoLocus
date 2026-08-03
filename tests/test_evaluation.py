from __future__ import annotations

import json
from pathlib import Path

from repolocus.config import Settings
from repolocus.core import RepoLocusService
from repolocus.index import RepositoryIndex
from repolocus.retrieval import RetrievalEngine


def test_repository_question_set_keeps_top_five_path_hit_rate(
    isolated_user_dirs: Path,
) -> None:
    repository = Path(__file__).resolve().parents[1]
    cases = json.loads((repository / "evaluation" / "questions.json").read_text(encoding="utf-8"))
    RepoLocusService(Settings(model="local")).scan(repository)

    passed = 0
    with RepositoryIndex.open(repository) as index:
        retrieval = RetrievalEngine(index)
        for case in cases:
            returned = {item.path for item in retrieval.search(case["question"], limit=5)}
            if returned.intersection(case["expected_paths"]):
                passed += 1

    assert len(cases) >= 10
    assert passed / len(cases) >= 0.9
