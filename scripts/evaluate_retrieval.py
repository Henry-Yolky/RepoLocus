#!/usr/bin/env python3
"""Run a source-citation retrieval evaluation against one or more question sets."""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

from repolocus.config import Settings
from repolocus.core import RepoLocusService
from repolocus.index import RepositoryIndex
from repolocus.retrieval import RetrievalEngine

_CITATION = re.compile(r"^(.+):([1-9]\d*)(?:-([1-9]\d*))?$")


class EvidenceLike(Protocol):
    path: str
    start_line: int
    end_line: int
    citation: str


class RetrievalLike(Protocol):
    def search(self, question: str, limit: int) -> list[EvidenceLike]: ...


def _unique_paths(evidence: Iterable[EvidenceLike]) -> list[str]:
    paths: list[str] = []
    for item in evidence:
        path = str(item.path)
        if path not in paths:
            paths.append(path)
    return paths


def _ndcg(returned: Sequence[str], expected: set[str], cutoff: int) -> float:
    if not expected:
        return 1.0 if not returned else 0.0
    dcg = sum(1.0 / math.log2(rank + 2) for rank, path in enumerate(returned) if path in expected)
    ideal = sum(1.0 / math.log2(rank + 2) for rank in range(min(len(expected), cutoff)))
    return dcg / ideal if ideal else 0.0


def _citation_range(value: str) -> tuple[str, int, int]:
    match = _CITATION.fullmatch(value)
    if match is None:
        raise ValueError(f"invalid expected citation: {value!r}")
    start = int(match.group(2))
    return match.group(1), start, int(match.group(3) or start)


def _citation_recall(evidence: Sequence[EvidenceLike], expected: Sequence[str]) -> float | None:
    if not expected:
        return None
    returned = [
        (
            str(item.path),
            int(item.start_line),
            int(item.end_line),
        )
        for item in evidence
    ]
    matches = 0
    for citation in expected:
        path, start, end = _citation_range(citation)
        if any(
            returned_path == path and returned_start <= start and end <= returned_end
            for returned_path, returned_start, returned_end in returned
        ):
            matches += 1
    return matches / len(expected)


def evaluate_cases(
    retrieval: RetrievalLike,
    cases: Sequence[Mapping[str, Any]],
    *,
    limit: int,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Evaluate ranked path recall, ranking quality, citations, and no-answer behavior."""

    if limit <= 0:
        raise ValueError("evaluation limit must be positive")
    outcomes: list[dict[str, object]] = []
    language_metrics: dict[str, list[tuple[float, float, float]]] = defaultdict(list)
    language_case_counts: dict[str, int] = defaultdict(int)
    query_type_metrics: dict[str, list[tuple[float, float, float]]] = defaultdict(list)
    query_type_case_counts: dict[str, int] = defaultdict(int)
    no_answer_true_positive = 0
    no_answer_false_positive = 0
    no_answer_false_negative = 0
    no_answer_true_negative = 0
    citation_scores: list[float] = []
    for case in cases:
        question = str(case["question"])
        raw_expected = case.get("expected_paths", [])
        if not isinstance(raw_expected, list):
            raise ValueError("expected_paths must be a JSON list")
        expected = {str(path) for path in raw_expected}
        evidence = retrieval.search(question, limit=limit)
        returned = _unique_paths(evidence)
        answerable = bool(expected)
        predicted_no_answer = not returned
        relevant_ranks = [rank for rank, path in enumerate(returned, 1) if path in expected]
        recall = len(expected.intersection(returned)) / len(expected) if answerable else None
        reciprocal_rank = (
            (1.0 / relevant_ranks[0] if relevant_ranks else 0.0) if answerable else None
        )
        ndcg = _ndcg(returned, expected, limit) if answerable else None
        expected_citations = case.get("expected_citations", [])
        if not isinstance(expected_citations, list):
            raise ValueError("expected_citations must be a JSON list")
        citation_recall = _citation_recall(evidence, [str(item) for item in expected_citations])
        if citation_recall is not None:
            citation_scores.append(citation_recall)
        if not answerable and predicted_no_answer:
            no_answer_true_positive += 1
        elif answerable and predicted_no_answer:
            no_answer_false_positive += 1
        elif not answerable:
            no_answer_false_negative += 1
        else:
            no_answer_true_negative += 1
        language = str(case.get("language", "unspecified"))
        language_case_counts[language] += 1
        query_type = str(case.get("query_type", "unspecified"))
        query_type_case_counts[query_type] += 1
        if answerable:
            if recall is None or reciprocal_rank is None or ndcg is None:  # pragma: no cover
                raise RuntimeError("answerable metric invariant violated")
            language_metrics[language].append((recall, reciprocal_rank, ndcg))
            query_type_metrics[query_type].append((recall, reciprocal_rank, ndcg))
        outcomes.append(
            {
                "question": question,
                "language": language,
                "query_type": query_type,
                "answerable": answerable,
                "predicted_no_answer": predicted_no_answer,
                "any_expected_path": bool(expected.intersection(returned)) if answerable else None,
                "all_expected_paths": expected.issubset(returned) if answerable else None,
                "recall_at_k": round(recall, 6) if recall is not None else None,
                "reciprocal_rank": (
                    round(reciprocal_rank, 6) if reciprocal_rank is not None else None
                ),
                "ndcg_at_k": round(ndcg, 6) if ndcg is not None else None,
                "citation_recall": (
                    round(citation_recall, 6) if citation_recall is not None else None
                ),
                "expected_paths": sorted(expected),
                "returned_paths": returned,
                "returned_citations": [str(item.citation) for item in evidence],
            }
        )

    answerable = [outcome for outcome in outcomes if outcome["answerable"]]
    no_answer_cases = len(outcomes) - len(answerable)
    no_answer_precision_denominator = no_answer_true_positive + no_answer_false_positive
    no_answer_recall_denominator = no_answer_true_positive + no_answer_false_negative
    no_answer_precision = (
        no_answer_true_positive / no_answer_precision_denominator
        if no_answer_precision_denominator
        else 0.0
        if no_answer_cases
        else None
    )
    no_answer_recall = (
        no_answer_true_positive / no_answer_recall_denominator
        if no_answer_recall_denominator
        else None
    )
    no_answer_f1 = (
        2 * no_answer_precision * no_answer_recall / (no_answer_precision + no_answer_recall)
        if no_answer_precision is not None
        and no_answer_recall is not None
        and no_answer_precision + no_answer_recall > 0
        else 0.0
        if no_answer_precision is not None and no_answer_recall is not None
        else None
    )

    def answerable_average(field: str) -> float | None:
        if not answerable:
            return None
        return round(sum(float(outcome[field]) for outcome in answerable) / len(answerable), 6)

    def bucket_summary(
        counts: Mapping[str, int],
        values: Mapping[str, list[tuple[float, float, float]]],
    ) -> dict[str, dict[str, int | float | None]]:
        summary: dict[str, dict[str, int | float | None]] = {}
        for label in sorted(counts):
            answerable_values = values[label]
            answerable_count = len(answerable_values)
            summary[label] = {
                "cases": counts[label],
                "answerable_cases": answerable_count,
                "no_answer_cases": counts[label] - answerable_count,
                "macro_recall_at_k": (
                    round(sum(item[0] for item in answerable_values) / answerable_count, 6)
                    if answerable_values
                    else None
                ),
                "mrr": (
                    round(sum(item[1] for item in answerable_values) / answerable_count, 6)
                    if answerable_values
                    else None
                ),
                "mean_ndcg_at_k": (
                    round(sum(item[2] for item in answerable_values) / answerable_count, 6)
                    if answerable_values
                    else None
                ),
            }
        return summary

    metrics: dict[str, object] = {
        "cases": len(outcomes),
        "answerable_cases": len(answerable),
        "no_answer_cases": no_answer_cases,
        "macro_recall_at_k": answerable_average("recall_at_k"),
        "mrr": answerable_average("reciprocal_rank"),
        "mean_ndcg_at_k": answerable_average("ndcg_at_k"),
        "any_expected_path_rate": answerable_average("any_expected_path"),
        "all_expected_paths_rate": answerable_average("all_expected_paths"),
        # Compatibility alias retained for reports produced by v0.1.3.
        "answerable_all_paths_rate": answerable_average("all_expected_paths"),
        "citation_recall": round(sum(citation_scores) / len(citation_scores), 6)
        if citation_scores
        else None,
        "no_answer_precision": (
            round(no_answer_precision, 6) if no_answer_precision is not None else None
        ),
        "no_answer_recall": round(no_answer_recall, 6) if no_answer_recall is not None else None,
        "no_answer_f1": round(no_answer_f1, 6) if no_answer_f1 is not None else None,
        "no_answer_accuracy": round(
            (no_answer_true_positive + no_answer_true_negative) / len(outcomes), 6
        )
        if outcomes
        else None,
        "by_language": bucket_summary(language_case_counts, language_metrics),
        "by_query_type": bucket_summary(query_type_case_counts, query_type_metrics),
    }
    return outcomes, metrics


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("questions", type=Path)
    parser.add_argument("repository", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--minimum-hit-rate", type=float, default=0.9)
    parser.add_argument("--minimum-macro-recall", type=float, default=0.0)
    parser.add_argument("--minimum-mrr", type=float, default=0.0)
    arguments = parser.parse_args()

    questions = json.loads(arguments.questions.read_text(encoding="utf-8"))
    if not isinstance(questions, list) or not questions:
        raise ValueError("evaluation file must contain a non-empty JSON list")
    repository = arguments.repository.resolve(strict=True)
    operation = RepoLocusService(Settings(model="local")).scan(repository)
    with RepositoryIndex.open(repository) as index:
        retrieval = RetrievalEngine(index)
        outcomes, metrics = evaluate_cases(retrieval, questions, limit=arguments.limit)
    if not metrics["answerable_cases"]:
        raise ValueError("evaluation file must contain at least one answerable case")
    hit_rate = float(metrics["any_expected_path_rate"])
    report = {
        "repository": str(repository),
        "questions": len(outcomes),
        "top_k": arguments.limit,
        # Compatibility alias retained for existing automation. New consumers
        # should use the complete metrics object below.
        "path_hit_rate": round(hit_rate, 6),
        "metrics": metrics,
        "scan": operation.to_dict(),
        "outcomes": outcomes,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    passed_thresholds = (
        hit_rate >= arguments.minimum_hit_rate
        and float(metrics["macro_recall_at_k"]) >= arguments.minimum_macro_recall
        and float(metrics["mrr"]) >= arguments.minimum_mrr
    )
    return 0 if passed_thresholds else 1


if __name__ == "__main__":
    raise SystemExit(main())
