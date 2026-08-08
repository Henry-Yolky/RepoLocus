#!/usr/bin/env python3
"""Run a source-citation retrieval evaluation against one or more question sets."""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter
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
    content: str
    citation: str


class RetrievalLike(Protocol):
    def search(self, question: str, limit: int) -> list[EvidenceLike]: ...


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _unit_interval(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a finite number from 0 to 1") from exc
    if not math.isfinite(parsed) or not 0.0 <= parsed <= 1.0:
        raise argparse.ArgumentTypeError("must be a finite number from 0 to 1")
    return parsed


def _unique_paths(evidence: Iterable[EvidenceLike]) -> list[str]:
    paths: list[str] = []
    for item in evidence:
        path = str(item.path)
        if path not in paths:
            paths.append(path)
    return paths


def _ndcg(returned: Sequence[str], expected: set[str] | Mapping[str, int], cutoff: int) -> float:
    grades = {path: 1 for path in expected} if isinstance(expected, set) else dict(expected)
    if not grades:
        return 1.0 if not returned else 0.0
    dcg = sum(
        (2 ** grades[path] - 1) / math.log2(rank + 2)
        for rank, path in enumerate(returned[:cutoff])
        if path in grades
    )
    ideal = sum(
        (2**grade - 1) / math.log2(rank + 2)
        for rank, grade in enumerate(sorted(grades.values(), reverse=True)[:cutoff])
    )
    return dcg / ideal if ideal else 0.0


def _line_iou(first: EvidenceLike, second: EvidenceLike) -> float:
    if str(first.path) != str(second.path):
        return 0.0
    first_start, first_end = int(first.start_line), int(first.end_line)
    second_start, second_end = int(second.start_line), int(second.end_line)
    intersection = max(0, min(first_end, second_end) - max(first_start, second_start) + 1)
    union = max(first_end, second_end) - min(first_start, second_start) + 1
    return intersection / union if union else 0.0


def _evidence_diagnostics(evidence: Sequence[EvidenceLike]) -> tuple[int, float | None, float]:
    seen_ranges: set[tuple[str, int, int]] = set()
    seen_content: set[str] = set()
    duplicates = 0
    for item in evidence:
        identity = (str(item.path), int(item.start_line), int(item.end_line))
        content = str(getattr(item, "content", ""))
        if identity in seen_ranges or (bool(content) and content in seen_content):
            duplicates += 1
        seen_ranges.add(identity)
        if content:
            seen_content.add(content)
    path_diversity = (
        len({str(item.path) for item in evidence}) / len(evidence) if evidence else None
    )
    maximum_iou = max(
        (
            _line_iou(first, second)
            for index, first in enumerate(evidence)
            for second in evidence[index + 1 :]
        ),
        default=0.0,
    )
    return duplicates, path_diversity, maximum_iou


def _retrieve(
    retrieval: RetrievalLike,
    question: str,
    *,
    limit: int,
) -> tuple[list[EvidenceLike], dict[str, object]]:
    search_result = getattr(retrieval, "search_result", None)
    if not callable(search_result):
        evidence = list(retrieval.search(question, limit=limit))
        diagnostics: dict[str, object] = {
            "confidence": None,
            "rejected_reason": None,
            "intent": None,
            "retrieval_hits": [],
            "suppressed": [],
        }
    else:
        result = search_result(question, limit=limit)
        raw_evidence = getattr(result, "evidence", None)
        if not isinstance(raw_evidence, Sequence):
            raise ValueError("structured retrieval result evidence must be a sequence")
        evidence = list(raw_evidence)
        confidence = getattr(result, "confidence", None)
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(float(confidence))
            or not 0.0 <= float(confidence) <= 1.0
        ):
            raise ValueError("structured retrieval confidence must be from 0 to 1")
        intent = getattr(result, "intent", None)
        if not isinstance(intent, str) or not intent:
            raise ValueError("structured retrieval intent must be a non-empty string")
        rejected_reason = getattr(result, "rejected_reason", None)
        if evidence and rejected_reason is not None:
            raise ValueError("structured retrieval cannot reject accepted evidence")
        if not evidence and (not isinstance(rejected_reason, str) or not rejected_reason):
            raise ValueError("structured no-answer results require a stable rejected reason")
        retrieval_hits: list[dict[str, object]] = []
        for hit in getattr(result, "hits", ()):
            features = getattr(hit, "features", None)
            if not isinstance(features, Mapping):
                raise ValueError("structured retrieval hit features must be a mapping")
            retrieval_hits.append(
                {
                    "chunk_id": int(hit.chunk_id),
                    "retriever": str(hit.retriever),
                    "rank": int(hit.rank),
                    "raw_score": hit.raw_score,
                    "features": dict(features),
                }
            )
        suppressed: list[dict[str, object]] = []
        for item in getattr(result, "suppressed", ()):
            if not isinstance(item, Sequence) or len(item) != 2:
                raise ValueError("structured retrieval suppression entries must be pairs")
            suppressed.append({"chunk_id": int(item[0]), "reason": str(item[1])})
        diagnostics = {
            "confidence": round(float(confidence), 6),
            "rejected_reason": rejected_reason,
            "intent": intent,
            "retrieval_hits": retrieval_hits,
            "suppressed": suppressed,
        }
    if len(evidence) > limit:
        raise ValueError("retrieval returned more evidence than the requested limit")
    return evidence, diagnostics


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
    for case in cases:
        question = str(case["question"])
        relevant = case.get("relevant")
        grades: dict[str, int] = {}
        derived_citations: list[str] = []
        if relevant is not None:
            if not isinstance(relevant, list):
                raise ValueError("relevant must be a JSON list")
            raw_expected = []
            for item in relevant:
                if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
                    raise ValueError("each relevant item must contain a path")
                path = str(item["path"])
                grade = item.get("grade", 1)
                if isinstance(grade, bool) or not isinstance(grade, int) or not 1 <= grade <= 3:
                    raise ValueError("relevance grade must be an integer from 1 to 3")
                grades[path] = max(grades.get(path, 0), grade)
                raw_expected.append(path)
                start = item.get("start")
                end = item.get("end", start)
                if start is not None:
                    if (
                        isinstance(start, bool)
                        or isinstance(end, bool)
                        or not isinstance(start, int)
                        or not isinstance(end, int)
                        or not 1 <= start <= end
                    ):
                        raise ValueError("relevant citation ranges must be positive and ordered")
                    suffix = f"-{end}" if end != start else ""
                    derived_citations.append(f"{path}:{start}{suffix}")
        else:
            raw_expected = case.get("expected_paths", [])
        if not isinstance(raw_expected, list):
            raise ValueError("expected_paths must be a JSON list")
        expected = {str(path) for path in raw_expected}
        if not grades:
            grades = {path: 1 for path in expected}
        explicit_answerable = case.get("answerable", bool(expected))
        if not isinstance(explicit_answerable, bool):
            raise ValueError("answerable must be true or false")
        if explicit_answerable != bool(expected):
            raise ValueError("answerable must agree with the presence of relevant paths")
        evidence, diagnostics = _retrieve(retrieval, question, limit=limit)
        returned = _unique_paths(evidence)
        duplicate_count, path_diversity, maximum_line_iou = _evidence_diagnostics(evidence)
        answerable = explicit_answerable
        predicted_no_answer = not returned
        relevant_ranks = [rank for rank, path in enumerate(returned, 1) if path in expected]
        recall = len(expected.intersection(returned)) / len(expected) if answerable else None
        reciprocal_rank = (
            (1.0 / relevant_ranks[0] if relevant_ranks else 0.0) if answerable else None
        )
        ndcg = _ndcg(returned, grades, limit) if answerable else None
        expected_citations = case.get("expected_citations", derived_citations)
        if not isinstance(expected_citations, list):
            raise ValueError("expected_citations must be a JSON list")
        citation_recall = _citation_recall(evidence, [str(item) for item in expected_citations])
        raw_must_not_return = case.get("must_not_return", [])
        if not isinstance(raw_must_not_return, list):
            raise ValueError("must_not_return must be a JSON list")
        forbidden = {str(path) for path in raw_must_not_return}
        forbidden_returned = sorted(forbidden.intersection(returned))
        language = str(case.get("language", "unspecified"))
        query_type = str(case.get("query_type", "unspecified"))
        expected_intent = case.get("expected_intent")
        if expected_intent is not None and (
            not isinstance(expected_intent, str) or not expected_intent
        ):
            raise ValueError("expected_intent must be a non-empty string")
        actual_intent = diagnostics["intent"]
        if expected_intent is not None and actual_intent is None:
            raise ValueError("intent qrels require the structured retrieval API")
        intent_match = actual_intent == expected_intent if expected_intent is not None else None
        required_graph_retriever = {
            "direct_dependency": "outbound_dependency",
            "reverse_dependency": "reverse_dependency",
        }.get(query_type)
        graph_grounded: bool | None = None
        if required_graph_retriever is not None:
            retriever_present = any(
                hit["retriever"] == required_graph_retriever
                for hit in diagnostics["retrieval_hits"]  # type: ignore[union-attr]
            )
            graph_reason = "dependency of" if query_type == "direct_dependency" else "dependent of"
            relevant_graph_evidence = any(
                str(item.path) in expected and graph_reason in str(getattr(item, "reason", ""))
                for item in evidence
            )
            graph_grounded = retriever_present and relevant_graph_evidence
        outcomes.append(
            {
                "question": question,
                "case_id": case.get("case_id"),
                "case_family": case.get("case_family"),
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
                "duplicate_evidence_count": duplicate_count,
                "duplicate_evidence_rate": round(duplicate_count / len(evidence), 6)
                if evidence
                else 0.0,
                "path_diversity": round(path_diversity, 6) if path_diversity is not None else None,
                "maximum_line_iou": round(maximum_line_iou, 6),
                "expected_intent": expected_intent,
                "intent": actual_intent,
                "intent_match": intent_match,
                "graph_grounded": graph_grounded,
                "confidence": diagnostics["confidence"],
                "rejected_reason": diagnostics["rejected_reason"],
                "retrieval_hits": diagnostics["retrieval_hits"],
                "suppressed": diagnostics["suppressed"],
                "expected_paths": sorted(expected),
                "returned_paths": returned,
                "returned_citations": [str(item.citation) for item in evidence],
                "returned_evidence": [
                    {
                        "path": str(item.path),
                        "start_line": int(item.start_line),
                        "end_line": int(item.end_line),
                        "citation": str(item.citation),
                        "symbol": str(getattr(item, "symbol", "")),
                        "generation": int(getattr(item, "generation", 0)),
                        "reason": str(getattr(item, "reason", "")),
                    }
                    for item in evidence
                ],
                "must_not_return": sorted(forbidden),
                "must_not_return_violations": forbidden_returned,
                "fixture": case.get("fixture"),
                "fixture_revision": case.get("fixture_revision"),
                "qrel_line": case.get("qrel_line"),
            }
        )

    def average(items: Sequence[Mapping[str, object]], field: str) -> float | None:
        values = [float(item[field]) for item in items if item.get(field) is not None]
        return round(sum(values) / len(values), 6) if values else None

    def summarize(items: Sequence[Mapping[str, object]]) -> dict[str, object]:
        answerable = [item for item in items if bool(item["answerable"])]
        no_answer = [item for item in items if not bool(item["answerable"])]
        true_positive = sum(bool(item["predicted_no_answer"]) for item in no_answer)
        false_positive = sum(bool(item["predicted_no_answer"]) for item in answerable)
        true_negative = len(answerable) - false_positive
        precision_denominator = true_positive + false_positive
        no_answer_precision = (
            true_positive / precision_denominator
            if precision_denominator
            else 0.0
            if no_answer
            else None
        )
        no_answer_recall = true_positive / len(no_answer) if no_answer else None
        no_answer_f1 = (
            2 * no_answer_precision * no_answer_recall / (no_answer_precision + no_answer_recall)
            if no_answer_precision is not None
            and no_answer_recall is not None
            and no_answer_precision + no_answer_recall > 0
            else 0.0
            if no_answer_precision is not None and no_answer_recall is not None
            else None
        )
        citations = [
            float(item["citation_recall"])
            for item in items
            if item.get("citation_recall") is not None
        ]
        constrained = [item for item in items if item.get("must_not_return")]
        violations = sum(bool(item["must_not_return_violations"]) for item in constrained)
        evidence_count = sum(len(item["returned_evidence"]) for item in items)  # type: ignore[arg-type]
        duplicate_count = sum(int(item["duplicate_evidence_count"]) for item in items)
        intent_cases = [item for item in items if item.get("intent_match") is not None]
        graph_cases = [item for item in items if item.get("graph_grounded") is not None]
        return {
            "cases": len(items),
            "answerable_cases": len(answerable),
            "no_answer_cases": len(no_answer),
            "macro_recall_at_k": average(answerable, "recall_at_k"),
            "mrr": average(answerable, "reciprocal_rank"),
            "mean_ndcg_at_k": average(answerable, "ndcg_at_k"),
            "any_expected_path_rate": average(answerable, "any_expected_path"),
            "all_expected_paths_rate": average(answerable, "all_expected_paths"),
            "citation_recall": round(sum(citations) / len(citations), 6) if citations else None,
            "citation_cases": len(citations),
            "must_not_return_cases": len(constrained),
            "must_not_return_violations": violations,
            "must_not_return_violation_rate": round(violations / len(constrained), 6)
            if constrained
            else 0.0,
            "no_answer_precision": round(no_answer_precision, 6)
            if no_answer_precision is not None
            else None,
            "no_answer_recall": round(no_answer_recall, 6)
            if no_answer_recall is not None
            else None,
            "no_answer_f1": round(no_answer_f1, 6) if no_answer_f1 is not None else None,
            "no_answer_accuracy": round((true_positive + true_negative) / len(items), 6)
            if items
            else None,
            "returned_evidence": evidence_count,
            "duplicate_evidence": duplicate_count,
            "duplicate_evidence_rate": round(duplicate_count / evidence_count, 6)
            if evidence_count
            else 0.0,
            "mean_path_diversity": average(items, "path_diversity"),
            "maximum_line_iou": max(
                (float(item["maximum_line_iou"]) for item in items), default=0.0
            ),
            "intent_cases": len(intent_cases),
            "intent_matches": sum(bool(item["intent_match"]) for item in intent_cases),
            "intent_accuracy": average(intent_cases, "intent_match"),
            "graph_cases": len(graph_cases),
            "graph_grounded": sum(bool(item["graph_grounded"]) for item in graph_cases),
            "graph_grounded_rate": average(graph_cases, "graph_grounded"),
        }

    def bucket_summary(field: str) -> dict[str, dict[str, object]]:
        def label(item: Mapping[str, object]) -> str:
            value = item.get(field)
            return str(value) if value is not None else "unspecified"

        labels = sorted({label(item) for item in outcomes})
        return {
            bucket: summarize([item for item in outcomes if label(item) == bucket])
            for bucket in labels
        }

    metrics = summarize(outcomes)
    # Compatibility alias retained for reports produced by v0.1.3.
    metrics["answerable_all_paths_rate"] = metrics["all_expected_paths_rate"]
    metrics["by_language"] = bucket_summary("language")
    metrics["by_repository"] = bucket_summary("fixture")
    metrics["by_query_type"] = bucket_summary("query_type")
    metrics["by_intent"] = bucket_summary("expected_intent")
    metrics["intent_counts"] = dict(
        sorted(Counter(str(item["intent"]) for item in outcomes if item.get("intent")).items())
    )
    metrics["rejected_reason_counts"] = dict(
        sorted(
            Counter(
                str(item["rejected_reason"]) for item in outcomes if item.get("rejected_reason")
            ).items()
        )
    )
    metrics["retriever_hit_counts"] = dict(
        sorted(
            Counter(
                str(hit["retriever"])
                for item in outcomes
                for hit in item["retrieval_hits"]  # type: ignore[union-attr]
            ).items()
        )
    )
    metrics["suppressed_reason_counts"] = dict(
        sorted(
            Counter(
                str(suppressed["reason"])
                for item in outcomes
                for suppressed in item["suppressed"]  # type: ignore[union-attr]
            ).items()
        )
    )
    return outcomes, metrics


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("questions", type=Path)
    parser.add_argument("repository", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--limit", type=_positive_integer, default=5)
    parser.add_argument("--minimum-hit-rate", type=_unit_interval, default=0.9)
    parser.add_argument("--minimum-macro-recall", type=_unit_interval, default=0.0)
    parser.add_argument("--minimum-mrr", type=_unit_interval, default=0.0)
    parser.add_argument("--minimum-no-answer-f1", type=_unit_interval, default=0.0)
    parser.add_argument("--maximum-must-not-return-rate", type=_unit_interval, default=0.0)
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
        and float(metrics["no_answer_f1"] or 0.0) >= arguments.minimum_no_answer_f1
        and float(metrics["must_not_return_violation_rate"])
        <= arguments.maximum_must_not_return_rate
    )
    return 0 if passed_thresholds else 1


if __name__ == "__main__":
    raise SystemExit(main())
