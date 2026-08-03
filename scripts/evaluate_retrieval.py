#!/usr/bin/env python3
"""Run a small, source-citation retrieval evaluation against a repository."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from repolocus.config import Settings
from repolocus.core import RepoLocusService
from repolocus.index import RepositoryIndex
from repolocus.retrieval import RetrievalEngine


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("questions", type=Path)
    parser.add_argument("repository", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--minimum-hit-rate", type=float, default=0.9)
    arguments = parser.parse_args()

    questions = json.loads(arguments.questions.read_text(encoding="utf-8"))
    if not isinstance(questions, list) or not questions:
        raise ValueError("evaluation file must contain a non-empty JSON list")
    repository = arguments.repository.resolve(strict=True)
    operation = RepoLocusService(Settings(model="local")).scan(repository)
    outcomes: list[dict[str, object]] = []
    with RepositoryIndex.open(repository) as index:
        retrieval = RetrievalEngine(index)
        for case in questions:
            question = str(case["question"])
            expected = {str(path) for path in case["expected_paths"]}
            evidence = retrieval.search(question, limit=arguments.limit)
            returned = [item.path for item in evidence]
            outcomes.append(
                {
                    "question": question,
                    "passed": bool(expected.intersection(returned)),
                    "expected_paths": sorted(expected),
                    "returned_citations": [item.citation for item in evidence],
                }
            )
    passed = sum(bool(outcome["passed"]) for outcome in outcomes)
    hit_rate = passed / len(outcomes)
    report = {
        "repository": str(repository),
        "questions": len(outcomes),
        "passed": passed,
        "top_k": arguments.limit,
        "path_hit_rate": round(hit_rate, 6),
        "scan": operation.to_dict(),
        "outcomes": outcomes,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if hit_rate >= arguments.minimum_hit_rate else 1


if __name__ == "__main__":
    raise SystemExit(main())
