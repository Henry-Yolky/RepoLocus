#!/usr/bin/env python3
"""Run the versioned multi-repository retrieval release gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import stat
from collections import defaultdict
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from pathlib import Path, PurePosixPath, PureWindowsPath
from tempfile import TemporaryDirectory
from typing import Any

from evaluate_retrieval import evaluate_cases

from repolocus.config import Settings
from repolocus.core import RepoLocusService
from repolocus.index import RepositoryIndex
from repolocus.retrieval import RetrievalEngine, classify_query_intent

_REQUIRED_QUERY_TYPES = frozenset(
    {
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
)
_RUNTIME_INTENTS = frozenset(
    {
        "architecture",
        "configuration",
        "definition",
        "dependency",
        "identifier",
        "natural_language",
        "path",
        "references",
    }
)
_QUERY_TYPE_INTENTS = {
    "ambiguous_dependency": "dependency",
    "architecture": "architecture",
    "configuration": "configuration",
    "definition": "definition",
    "direct_dependency": "dependency",
    "entry_point": "natural_language",
    "exact_symbol": "identifier",
    "expanded_symbol": "identifier",
    "partial_symbol": "identifier",
    "path": "path",
    "reverse_dependency": "references",
}
_BOOTSTRAP_SEED = 2_020_020
_BOOTSTRAP_SAMPLES = 2_000
_SHA256 = re.compile(r"[0-9a-f]{64}")
_CANONICAL_INTENT = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_QREL_REQUIRED_FIELDS = frozenset(
    {
        "case_id",
        "case_family",
        "question",
        "language",
        "query_type",
        "answerable",
        "relevant",
        "must_not_return",
    }
)
_QREL_OPTIONAL_FIELDS = frozenset({"expected_dependency", "expected_intent"})
_RELEVANT_FIELDS = frozenset({"path", "start", "end", "grade"})
_DEPENDENCY_EXPECTATION_FIELDS = frozenset(
    {"source_path", "raw_target", "line", "confidence", "candidates"}
)
_RATE_THRESHOLDS = frozenset(
    {
        "minimum_hit_rate",
        "minimum_macro_recall",
        "minimum_mrr",
        "minimum_citation_recall",
        "minimum_no_answer_f1",
        "maximum_must_not_return_rate",
        "maximum_duplicate_evidence_rate",
        "maximum_line_iou",
        "minimum_intent_accuracy",
        "minimum_graph_grounded_rate",
        "minimum_mean_path_diversity",
        "minimum_slice_hit_rate",
        "minimum_slice_mrr",
        "minimum_slice_no_answer_f1",
    }
)
_COUNT_THRESHOLDS = frozenset(
    {
        "minimum_qrels",
        "minimum_answerable_qrels",
        "minimum_no_answer_qrels",
        "minimum_citation_qrels",
    }
)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key is not allowed: {key}")
        document[key] = value
    return document


def _load_json(text: str, *, source: str) -> Any:
    try:
        return json.loads(
            text,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"invalid JSON in {source}: {exc}") from exc


def _positive_integer(value: object, field: str, *, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field} must be an integer >= {minimum}")
    return value


def _positive_cli_integer(value: str) -> int:
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


def _validated_thresholds(
    thresholds: Mapping[str, object],
) -> dict[str, int | float]:
    if set(thresholds) != _RATE_THRESHOLDS | _COUNT_THRESHOLDS:
        raise ValueError("external evaluation thresholds are incomplete")
    validated: dict[str, int | float] = {}
    for field in _RATE_THRESHOLDS:
        value = thresholds[field]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0.0 <= value <= 1.0
        ):
            raise ValueError(f"{field} must be a finite number from 0 to 1")
        validated[field] = value
    for field in _COUNT_THRESHOLDS:
        validated[field] = _positive_integer(thresholds[field], field)
    return validated


def _percentile_interval(values: Sequence[float]) -> list[float] | None:
    if not values:
        return None
    ordered = sorted(values)
    lower = ordered[int((len(ordered) - 1) * 0.025)]
    upper = ordered[int((len(ordered) - 1) * 0.975)]
    return [round(lower, 6), round(upper, 6)]


def _clustered_resample(
    outcomes: Sequence[Mapping[str, object]], randomizer: random.Random
) -> list[Mapping[str, object]]:
    clusters: dict[str, dict[str, list[Mapping[str, object]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for outcome in outcomes:
        fixture = str(outcome.get("fixture", ""))
        family = str(outcome.get("case_family", ""))
        if not fixture or not family:
            raise ValueError("bootstrap outcomes require fixture and case_family")
        clusters[fixture][family].append(outcome)

    fixture_names = sorted(clusters)
    sampled: list[Mapping[str, object]] = []
    for _ in fixture_names:
        fixture = randomizer.choice(fixture_names)
        families = sorted(clusters[fixture])
        for _ in families:
            family = randomizer.choice(families)
            cluster = clusters[fixture][family]
            weight = 1.0 / (len(families) * len(cluster))
            sampled.extend(dict(item, _cluster_weight=weight) for item in cluster)
    return sampled


def _mean(outcomes: Sequence[Mapping[str, object]], field: str) -> float | None:
    values = [
        (float(item[field]), float(item.get("_cluster_weight", 1.0)))
        for item in outcomes
        if item.get(field) is not None
    ]
    weight = sum(item_weight for _value, item_weight in values)
    return sum(value * item_weight for value, item_weight in values) / weight if weight else None


def _no_answer_f1(outcomes: Sequence[Mapping[str, object]]) -> float | None:
    true_positive = sum(
        float(item.get("_cluster_weight", 1.0))
        for item in outcomes
        if not bool(item["answerable"]) and bool(item["predicted_no_answer"])
    )
    false_positive = sum(
        float(item.get("_cluster_weight", 1.0))
        for item in outcomes
        if bool(item["answerable"]) and bool(item["predicted_no_answer"])
    )
    false_negative = sum(
        float(item.get("_cluster_weight", 1.0))
        for item in outcomes
        if not bool(item["answerable"]) and not bool(item["predicted_no_answer"])
    )
    no_answer_cases = true_positive + false_negative
    if not no_answer_cases:
        return None
    precision_denominator = true_positive + false_positive
    precision = true_positive / precision_denominator if precision_denominator else 0.0
    recall = true_positive / no_answer_cases
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def _must_not_return_rate(outcomes: Sequence[Mapping[str, object]]) -> float | None:
    constrained = [item for item in outcomes if item.get("must_not_return")]
    if not constrained:
        return None
    denominator = sum(float(item.get("_cluster_weight", 1.0)) for item in constrained)
    violations = sum(
        float(item.get("_cluster_weight", 1.0))
        for item in constrained
        if item.get("must_not_return_violations")
    )
    return violations / denominator if denominator else None


def _bootstrap_report(outcomes: list[dict[str, object]]) -> dict[str, object]:
    randomizer = random.Random(_BOOTSTRAP_SEED)
    sampled_metrics: dict[str, list[float]] = defaultdict(list)
    metric_functions = {
        "any_expected_path_rate": lambda sample: _mean(sample, "any_expected_path"),
        "macro_recall_at_k": lambda sample: _mean(sample, "recall_at_k"),
        "mrr": lambda sample: _mean(sample, "reciprocal_rank"),
        "citation_recall": lambda sample: _mean(sample, "citation_recall"),
        "duplicate_evidence_rate": lambda sample: _mean(sample, "duplicate_evidence_rate"),
        "intent_accuracy": lambda sample: _mean(sample, "intent_match"),
        "graph_grounded_rate": lambda sample: _mean(sample, "graph_grounded"),
        "mean_path_diversity": lambda sample: _mean(sample, "path_diversity"),
        "no_answer_f1": _no_answer_f1,
        "must_not_return_violation_rate": _must_not_return_rate,
    }
    for _ in range(_BOOTSTRAP_SAMPLES):
        sample = _clustered_resample(outcomes, randomizer)
        for name, calculate in metric_functions.items():
            value = calculate(sample)
            if value is not None:
                sampled_metrics[name].append(value)

    fixture_count = len({str(item["fixture"]) for item in outcomes})
    family_count = len({(str(item["fixture"]), str(item["case_family"])) for item in outcomes})
    return {
        "confidence": 0.95,
        "samples": _BOOTSTRAP_SAMPLES,
        "seed": _BOOTSTRAP_SEED,
        "cluster_unit": "fixture/case_family",
        "weighting": "equal fixture/case-family clusters",
        "fixture_clusters": fixture_count,
        "family_clusters": family_count,
        "intervals": {
            name: _percentile_interval(sampled_metrics[name]) for name in metric_functions
        },
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65_536), b""):
            digest.update(block)
    return digest.hexdigest()


def fixture_tree_sha256(root: Path) -> str:
    """Hash every regular fixture file with a path-delimited deterministic manifest."""

    digest = hashlib.sha256()
    files = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())
    for path in files:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"fixture must not contain links: {path}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"fixture must contain only regular files: {path}")
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_sha256_file(path).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _load_qrels(path: Path, *, fixture: str, revision: str) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw_line.strip():
            continue
        try:
            case = _load_json(raw_line, source=f"{path}:{line_number}")
        except ValueError as exc:
            raise ValueError(f"invalid qrel JSON at {path}:{line_number}") from exc
        if not isinstance(case, dict):
            raise ValueError(f"qrel must be an object at {path}:{line_number}")
        fields = set(case)
        if not _QREL_REQUIRED_FIELDS.issubset(fields) or not fields.issubset(
            _QREL_REQUIRED_FIELDS | _QREL_OPTIONAL_FIELDS
        ):
            raise ValueError(
                f"qrel fields must match the external evaluation schema at {path}:{line_number}"
            )
        for field in ("case_id", "case_family", "question", "language", "query_type"):
            value = case.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"qrel {field} must be a non-empty string at {path}:{line_number}")
        query_type = str(case["query_type"])
        if query_type not in _REQUIRED_QUERY_TYPES:
            raise ValueError(f"unsupported external qrel query type: {query_type}")
        expected_intent = case.get("expected_intent")
        fixed_intent = _QUERY_TYPE_INTENTS.get(query_type)
        if fixed_intent is not None:
            if expected_intent is not None and expected_intent != fixed_intent:
                raise ValueError(f"qrel intent conflicts with query type at {path}:{line_number}")
            expected_intent = fixed_intent
        if not isinstance(expected_intent, str) or expected_intent not in _RUNTIME_INTENTS:
            raise ValueError(f"qrel expected_intent is invalid at {path}:{line_number}")
        classified_intent = classify_query_intent(str(case["question"]))
        if classified_intent != expected_intent:
            raise ValueError(
                f"qrel question does not express expected intent at {path}:{line_number}: "
                f"expected {expected_intent}, classified {classified_intent}"
            )
        case["expected_intent"] = expected_intent
        case["fixture"] = fixture
        case["fixture_revision"] = revision
        case["qrel_line"] = line_number
        cases.append(case)
    if not cases:
        raise ValueError(f"qrel file is empty: {path}")
    return cases


def _repository_file(root: Path, value: object, field: str) -> tuple[str, Path]:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} paths must be non-empty strings")
    relative = PurePosixPath(value)
    windows_path = PureWindowsPath(value)
    if (
        "\\" in value
        or relative.is_absolute()
        or bool(windows_path.drive)
        or bool(windows_path.root)
        or ".." in relative.parts
        or "." in relative.parts
        or relative.as_posix() != value
    ):
        raise ValueError(f"{field} path must be repository-relative: {value!r}")
    source = root.joinpath(*relative.parts)
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"{field} path does not exist as a regular file: {source}")
    resolved = source.resolve(strict=True)
    resolved.relative_to(root.resolve(strict=True))
    return relative.as_posix(), resolved


def _validate_case_sources(root: Path, cases: list[dict[str, Any]]) -> None:
    for case in cases:
        answerable = case.get("answerable")
        relevant = case.get("relevant")
        if not isinstance(answerable, bool) or not isinstance(relevant, list):
            raise ValueError("qrel answerable must be boolean and relevant must be a list")
        if answerable != bool(relevant):
            raise ValueError("qrel answerable must agree with relevant source ranges")

        relevant_paths: set[str] = set()
        relevant_ranges: set[tuple[str, int, int]] = set()
        relevant_ranges_by_path: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for item in relevant:
            if not isinstance(item, Mapping) or set(item) != _RELEVANT_FIELDS:
                raise ValueError(
                    "qrel relevant source-range entries must contain exactly "
                    "path, start, end, and grade"
                )
            if not isinstance(item.get("path"), str):
                raise ValueError("qrel relevant paths must be strings")
            relative, source = _repository_file(root, item["path"], "qrel relevant")
            relevant_paths.add(relative)
            start = item.get("start")
            end = item.get("end")
            grade = item.get("grade")
            if (
                isinstance(start, bool)
                or isinstance(end, bool)
                or not isinstance(start, int)
                or not isinstance(end, int)
                or not 1 <= start <= end
            ):
                raise ValueError("qrel relevant ranges must explicitly be positive and ordered")
            if isinstance(grade, bool) or not isinstance(grade, int) or not 1 <= grade <= 3:
                raise ValueError("qrel relevance grade must be an integer from 1 to 3")
            range_key = (relative, start, end)
            if range_key in relevant_ranges:
                raise ValueError(f"qrel relevant source range is duplicated: {range_key}")
            if any(
                start <= existing_end + 1 and existing_start <= end + 1
                for existing_start, existing_end in relevant_ranges_by_path[relative]
            ):
                raise ValueError(
                    f"qrel relevant source ranges must not overlap or be adjacent: {relative}"
                )
            relevant_ranges.add(range_key)
            relevant_ranges_by_path[relative].append((start, end))
            line_count = len(source.read_text(encoding="utf-8").splitlines())
            if end > line_count:
                raise ValueError(f"qrel line range exceeds source: {source}")

        raw_forbidden = case.get("must_not_return")
        if not isinstance(raw_forbidden, list):
            raise ValueError("qrel must_not_return must be a list")
        forbidden: set[str] = set()
        for value in raw_forbidden:
            relative, _ = _repository_file(root, value, "qrel must_not_return")
            if relative in forbidden:
                raise ValueError(f"qrel must_not_return path is duplicated: {relative}")
            forbidden.add(relative)
        case["must_not_return"] = sorted(forbidden)
        overlap = relevant_paths & forbidden
        if overlap:
            raise ValueError(f"qrel relevant and must_not_return paths overlap: {sorted(overlap)}")

        raw_dependency = case.get("expected_dependency")
        if case.get("query_type") != "ambiguous_dependency":
            if raw_dependency is not None:
                raise ValueError("expected_dependency is reserved for ambiguous dependency qrels")
            continue
        if bool(answerable) or not isinstance(raw_dependency, Mapping):
            raise ValueError("ambiguous dependency qrels must be no-answer with an expectation")
        if set(raw_dependency) != _DEPENDENCY_EXPECTATION_FIELDS:
            raise ValueError("expected_dependency fields do not match the qrel schema")
        source_path, source = _repository_file(
            root, raw_dependency.get("source_path"), "expected dependency source"
        )
        raw_target = raw_dependency.get("raw_target")
        line = raw_dependency.get("line")
        confidence = raw_dependency.get("confidence")
        candidates = raw_dependency.get("candidates")
        if (
            not isinstance(raw_target, str)
            or not raw_target
            or isinstance(line, bool)
            or not isinstance(line, int)
            or line <= 0
            or line > len(source.read_text(encoding="utf-8").splitlines())
            or confidence != "ambiguous"
            or not isinstance(candidates, list)
            or len(candidates) < 2
        ):
            raise ValueError("ambiguous expected_dependency is invalid")
        candidate_paths = {
            _repository_file(root, candidate, "expected dependency candidate")[0]
            for candidate in candidates
        }
        if len(candidate_paths) != len(candidates) or candidate_paths != forbidden:
            raise ValueError(
                "ambiguous dependency candidates must be unique and match must_not_return"
            )
        case["expected_dependency"] = {
            "source_path": source_path,
            "raw_target": raw_target,
            "line": line,
            "confidence": confidence,
            "candidates": sorted(candidate_paths),
        }


def _validate_dependency_expectations(
    index: RepositoryIndex, cases: Sequence[Mapping[str, object]]
) -> int:
    expected = [case for case in cases if case.get("expected_dependency") is not None]
    if not expected:
        return 0
    dependencies = {
        (item.source_path, item.raw_target, item.line): item
        for item in index.get_resolved_dependencies()
    }
    for case in expected:
        raw = case["expected_dependency"]
        if not isinstance(raw, Mapping):  # pragma: no cover - validated qrel invariant
            raise RuntimeError("expected dependency qrel invariant violated")
        key = (str(raw["source_path"]), str(raw["raw_target"]), int(raw["line"]))
        dependency = dependencies.get(key)
        if dependency is None:
            raise ValueError(f"expected dependency was not indexed: {key}")
        if dependency.confidence != raw["confidence"] or tuple(dependency.candidates) != tuple(
            raw["candidates"]
        ):
            raise ValueError(f"resolved dependency does not match reviewed qrel: {key}")
        if dependency.target_path is not None:
            raise ValueError(f"ambiguous dependency unexpectedly selected a target: {key}")
    return len(expected)


def _load_review_provenance(
    evaluation_root: Path, manifest: Mapping[str, object]
) -> tuple[
    dict[str, Mapping[str, object]],
    dict[str, object],
    dict[tuple[str, str], str],
]:
    raw = manifest.get("review_provenance")
    if not isinstance(raw, Mapping):
        raise ValueError("external evaluation review_provenance must be an object")
    review_id = raw.get("review_id")
    raw_path = raw.get("path")
    expected_hash = raw.get("sha256")
    if (
        not isinstance(review_id, str)
        or not review_id
        or not isinstance(raw_path, str)
        or not raw_path
        or not isinstance(expected_hash, str)
        or _SHA256.fullmatch(expected_hash) is None
    ):
        raise ValueError("external evaluation review provenance metadata is invalid")
    relative = PurePosixPath(raw_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("review provenance path must stay inside evaluation root")
    candidate = evaluation_root.joinpath(*relative.parts)
    if not candidate.is_file() or candidate.is_symlink():
        raise ValueError("review provenance must be a regular file")
    path = candidate.resolve(strict=True)
    path.relative_to(evaluation_root)
    actual_hash = _sha256_file(path)
    if actual_hash != expected_hash:
        raise ValueError("review provenance checksum mismatch")

    document = _load_json(path.read_text(encoding="utf-8"), source=str(path))
    if not isinstance(document, dict) or document.get("version") != 2:
        raise ValueError("review provenance version is invalid")
    if document.get("review_id") != review_id:
        raise ValueError("review provenance ID mismatch")
    for field in ("reviewed_at", "reviewed_by", "method"):
        value = document.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"review provenance {field} must be non-empty")
    raw_artifacts = document.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise ValueError("review provenance artifacts must be a non-empty list")
    artifacts: dict[str, Mapping[str, object]] = {}
    no_answer_intents: dict[tuple[str, str], str] = {}
    for artifact in raw_artifacts:
        if not isinstance(artifact, Mapping):
            raise ValueError("review provenance artifacts must be objects")
        fixture = artifact.get("fixture")
        if not isinstance(fixture, str) or not fixture or fixture in artifacts:
            raise ValueError("review provenance fixture IDs must be non-empty and unique")
        revision = artifact.get("fixture_revision")
        tree_digest = artifact.get("tree_sha256")
        qrel_digest = artifact.get("qrels_sha256")
        if (
            not isinstance(revision, str)
            or not revision
            or not isinstance(tree_digest, str)
            or _SHA256.fullmatch(tree_digest) is None
            or not isinstance(qrel_digest, str)
            or _SHA256.fullmatch(qrel_digest) is None
        ):
            raise ValueError(f"review provenance artifact is invalid: {fixture}")
        raw_no_answer_families = artifact.get("no_answer_families")
        if not isinstance(raw_no_answer_families, Mapping) or not raw_no_answer_families:
            raise ValueError(f"review provenance no-answer family ledger is missing: {fixture}")
        fixture_intents: set[str] = set()
        for family, canonical_intent in raw_no_answer_families.items():
            if (
                not isinstance(family, str)
                or not family
                or not isinstance(canonical_intent, str)
                or _CANONICAL_INTENT.fullmatch(canonical_intent) is None
                or canonical_intent in fixture_intents
            ):
                raise ValueError(f"review provenance no-answer family ledger is invalid: {fixture}")
            fixture_intents.add(canonical_intent)
            no_answer_intents[(fixture, family)] = canonical_intent
        artifacts[fixture] = artifact
    report = {
        "review_id": review_id,
        "reviewed_at": document["reviewed_at"],
        "reviewed_by": document["reviewed_by"],
        "method": document["method"],
        "sha256": actual_hash,
    }
    return artifacts, report, no_answer_intents


def _case_family_report(
    cases: Sequence[Mapping[str, object]],
    *,
    reviewed_no_answer_intents: Mapping[tuple[str, str], str] | None = None,
) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    no_answer_intents = reviewed_no_answer_intents or {}
    signatures: dict[tuple[str, str], str] = {}
    family_by_signature: dict[tuple[str, str], str] = {}
    cases_by_fixture: dict[str, set[str]] = defaultdict(set)
    families_by_type: dict[str, set[tuple[str, str]]] = defaultdict(set)
    fixtures_by_type: dict[str, set[str]] = defaultdict(set)
    seen_case_ids: set[str] = set()
    used_no_answer_families: set[tuple[str, str]] = set()
    for case in cases:
        fixture = str(case["fixture"])
        case_id = str(case["case_id"])
        family = str(case["case_family"])
        query_type = str(case["query_type"])
        if case_id in seen_case_ids:
            raise ValueError(f"external qrel case IDs must be globally unique: {case_id}")
        seen_case_ids.add(case_id)
        if query_type not in _REQUIRED_QUERY_TYPES:
            raise ValueError(f"unsupported external qrel query type: {query_type}")
        key = (fixture, family)
        path_grades: dict[str, int] = {}
        source_ranges: set[tuple[str, int, int]] = set()
        for item in case["relevant"]:
            path = str(item["path"])
            grade = int(item["grade"])
            path_grades[path] = max(path_grades.get(path, 0), grade)
            source_ranges.add((path, int(item["start"]), int(item["end"])))
        merged_ranges: list[tuple[str, int, int]] = []
        for path, start, end in sorted(source_ranges):
            if merged_ranges and merged_ranges[-1][0] == path and start <= merged_ranges[-1][2] + 1:
                previous_path, previous_start, previous_end = merged_ranges[-1]
                merged_ranges[-1] = (previous_path, previous_start, max(previous_end, end))
            else:
                merged_ranges.append((path, start, end))
        canonical_relevant = [
            {
                "path": path,
                "start": start,
                "end": end,
                "grade": path_grades[path],
            }
            for path, start, end in merged_ranges
        ]
        signature_payload = {
            "query_type": query_type,
            "expected_intent": case.get(
                "expected_intent", _QUERY_TYPE_INTENTS.get(query_type, query_type)
            ),
            "answerable": case["answerable"],
            "relevant": canonical_relevant,
        }
        if case.get("expected_dependency") is not None:
            signature_payload["expected_dependency"] = case["expected_dependency"]
        if not bool(case["answerable"]):
            canonical_intent = no_answer_intents.get(key)
            if canonical_intent is None:
                raise ValueError(
                    f"no-answer case family lacks reviewed canonical intent: {fixture}/{family}"
                )
            signature_payload["canonical_intent"] = canonical_intent
            used_no_answer_families.add(key)
        signature = json.dumps(
            signature_payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        previous = signatures.setdefault(key, signature)
        if previous != signature:
            raise ValueError(f"case family has inconsistent intent or truth: {fixture}/{family}")
        signature_key = (fixture, signature)
        previous_family = family_by_signature.setdefault(signature_key, family)
        if previous_family != family:
            raise ValueError(f"identical qrel intent and truth must share a case family: {fixture}")
        cases_by_fixture[fixture].add(family)
        families_by_type[query_type].add(key)
        fixtures_by_type[query_type].add(fixture)
    unused_no_answer_families = set(no_answer_intents) - used_no_answer_families
    if unused_no_answer_families:
        fixture, family = min(unused_no_answer_families)
        raise ValueError(f"reviewed no-answer family has no qrel: {fixture}/{family}")
    return (
        {fixture: len(families) for fixture, families in cases_by_fixture.items()},
        {query_type: len(families) for query_type, families in families_by_type.items()},
        {query_type: len(fixtures) for query_type, fixtures in fixtures_by_type.items()},
    )


def _corpus_coverage(cases: Sequence[Mapping[str, object]]) -> dict[str, object]:
    ranges_by_fixture: dict[str, set[tuple[str, int, int]]] = defaultdict(set)
    multi_path_families_by_fixture: dict[str, set[str]] = defaultdict(set)
    answerable_intent_families: dict[str, set[tuple[str, str]]] = defaultdict(set)
    no_answer_intent_families: dict[str, set[tuple[str, str]]] = defaultdict(set)
    answerable_intent_fixtures: dict[str, set[str]] = defaultdict(set)
    no_answer_intent_fixtures: dict[str, set[str]] = defaultdict(set)
    ambiguous_families: set[tuple[str, str]] = set()
    for case in cases:
        fixture = str(case["fixture"])
        family = str(case["case_family"])
        intent = str(case["expected_intent"])
        family_key = (fixture, family)
        if bool(case["answerable"]):
            answerable_intent_families[intent].add(family_key)
            answerable_intent_fixtures[intent].add(fixture)
        else:
            no_answer_intent_families[intent].add(family_key)
            no_answer_intent_fixtures[intent].add(fixture)
        paths: set[str] = set()
        for relevant in case["relevant"]:
            path = str(relevant["path"])
            paths.add(path)
            ranges_by_fixture[fixture].add((path, int(relevant["start"]), int(relevant["end"])))
        if len(paths) >= 2:
            multi_path_families_by_fixture[fixture].add(family)
        if case["query_type"] == "ambiguous_dependency":
            ambiguous_families.add(family_key)
    return {
        "distinct_relevant_ranges": sum(len(items) for items in ranges_by_fixture.values()),
        "distinct_relevant_ranges_by_fixture": {
            fixture: len(items) for fixture, items in sorted(ranges_by_fixture.items())
        },
        "multi_path_families": sum(len(items) for items in multi_path_families_by_fixture.values()),
        "multi_path_families_by_fixture": {
            fixture: len(items) for fixture, items in sorted(multi_path_families_by_fixture.items())
        },
        "ambiguous_dependency_families": len(ambiguous_families),
        "answerable_intent_families": {
            intent: len(answerable_intent_families[intent]) for intent in sorted(_RUNTIME_INTENTS)
        },
        "no_answer_intent_families": {
            intent: len(no_answer_intent_families[intent]) for intent in sorted(_RUNTIME_INTENTS)
        },
        "answerable_intent_fixture_counts": {
            intent: len(answerable_intent_fixtures[intent]) for intent in sorted(_RUNTIME_INTENTS)
        },
        "no_answer_intent_fixture_counts": {
            intent: len(no_answer_intent_fixtures[intent]) for intent in sorted(_RUNTIME_INTENTS)
        },
    }


class _RoutedRetrieval:
    def __init__(self, routes: Mapping[str, RetrievalEngine]) -> None:
        self.routes = routes

    def search_result(self, question: str, limit: int):  # type: ignore[no-untyped-def]
        return self.routes[question].search_result(question, limit=limit)


def evaluate_suite(
    evaluation_root: Path,
    *,
    limit: int = 5,
) -> dict[str, object]:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("evaluation limit must be a positive integer")
    evaluation_root = evaluation_root.resolve(strict=True)
    manifest_path = evaluation_root / "external-manifest.json"
    manifest = _load_json(manifest_path.read_text(encoding="utf-8"), source=str(manifest_path))
    if not isinstance(manifest, dict) or manifest.get("version") != 3:
        raise ValueError("external evaluation manifest version is invalid")
    minimum_qrels = _positive_integer(manifest.get("minimum_qrels"), "minimum_qrels")
    if minimum_qrels < 100:
        raise ValueError("external evaluation must require at least 100 reviewed qrels")
    minimum_case_families = _positive_integer(
        manifest.get("minimum_case_families"), "minimum_case_families"
    )
    minimum_case_families_per_fixture = _positive_integer(
        manifest.get("minimum_case_families_per_fixture"),
        "minimum_case_families_per_fixture",
    )
    minimum_must_not_return_qrels = _positive_integer(
        manifest.get("minimum_must_not_return_qrels"),
        "minimum_must_not_return_qrels",
    )
    minimum_must_not_return_qrels_per_fixture = _positive_integer(
        manifest.get("minimum_must_not_return_qrels_per_fixture"),
        "minimum_must_not_return_qrels_per_fixture",
    )
    minimum_query_type_fixtures = _positive_integer(
        manifest.get("minimum_query_type_fixtures"),
        "minimum_query_type_fixtures",
        minimum=2,
    )
    minimum_distinct_relevant_ranges = _positive_integer(
        manifest.get("minimum_distinct_relevant_ranges"),
        "minimum_distinct_relevant_ranges",
    )
    minimum_distinct_relevant_ranges_per_fixture = _positive_integer(
        manifest.get("minimum_distinct_relevant_ranges_per_fixture"),
        "minimum_distinct_relevant_ranges_per_fixture",
    )
    minimum_multi_path_families = _positive_integer(
        manifest.get("minimum_multi_path_families"), "minimum_multi_path_families"
    )
    minimum_multi_path_families_per_fixture = _positive_integer(
        manifest.get("minimum_multi_path_families_per_fixture"),
        "minimum_multi_path_families_per_fixture",
    )
    minimum_ambiguous_dependency_families = _positive_integer(
        manifest.get("minimum_ambiguous_dependency_families"),
        "minimum_ambiguous_dependency_families",
    )
    minimum_runtime_intent_fixtures = _positive_integer(
        manifest.get("minimum_runtime_intent_fixtures"),
        "minimum_runtime_intent_fixtures",
        minimum=2,
    )
    raw_family_minimums = manifest.get("minimum_query_type_families")
    if not isinstance(raw_family_minimums, Mapping) or set(raw_family_minimums) != set(
        _REQUIRED_QUERY_TYPES
    ):
        raise ValueError("minimum_query_type_families must cover every required query type")
    family_minimums = {
        query_type: _positive_integer(
            raw_family_minimums[query_type], f"minimum_query_type_families.{query_type}"
        )
        for query_type in _REQUIRED_QUERY_TYPES
    }
    intent_minimums: dict[str, dict[str, int]] = {}
    for field in (
        "minimum_answerable_intent_families",
        "minimum_no_answer_intent_families",
    ):
        raw_minimums = manifest.get(field)
        if not isinstance(raw_minimums, Mapping) or set(raw_minimums) != set(_RUNTIME_INTENTS):
            raise ValueError(f"{field} must cover every runtime intent")
        intent_minimums[field] = {
            intent: _positive_integer(raw_minimums[intent], f"{field}.{intent}")
            for intent in _RUNTIME_INTENTS
        }
    raw_fixtures = manifest.get("fixtures")
    if not isinstance(raw_fixtures, list) or len(raw_fixtures) < 2:
        raise ValueError("external evaluation must declare multiple fixtures")
    if minimum_query_type_fixtures > len(raw_fixtures):
        raise ValueError("minimum_query_type_fixtures exceeds fixture count")
    if minimum_runtime_intent_fixtures > len(raw_fixtures):
        raise ValueError("minimum_runtime_intent_fixtures exceeds fixture count")
    review_artifacts, review_report, reviewed_no_answer_intents = _load_review_provenance(
        evaluation_root, manifest
    )

    all_cases: list[dict[str, Any]] = []
    routes: dict[str, RetrievalEngine] = {}
    fixture_reports: list[dict[str, object]] = []
    seen_fixture_ids: set[str] = set()
    seen_roots: set[Path] = set()
    seen_qrel_paths: set[Path] = set()
    seen_tree_hashes: set[str] = set()
    seen_qrel_hashes: set[str] = set()
    must_not_by_fixture: dict[str, int] = {}
    with ExitStack() as stack:
        cache_directory = (
            Path(stack.enter_context(TemporaryDirectory(prefix="repolocus-evaluation-")))
            / "indexes"
        )
        scanner = RepoLocusService(Settings(model="local")).scanner
        for entry in raw_fixtures:
            if not isinstance(entry, dict):
                raise ValueError("fixture manifest entries must be objects")
            provenance = [entry.get(field) for field in ("id", "revision", "source", "license")]
            if not all(isinstance(value, str) and value.strip() for value in provenance):
                raise ValueError("fixture provenance fields must not be empty")
            fixture, revision, source, license_name = provenance
            assert all(isinstance(value, str) for value in provenance)
            if fixture in seen_fixture_ids:
                raise ValueError(f"fixture IDs must be unique: {fixture}")
            seen_fixture_ids.add(fixture)

            raw_root = entry.get("path")
            raw_qrels = entry.get("qrels")
            if not isinstance(raw_root, str) or not isinstance(raw_qrels, str):
                raise ValueError(f"fixture paths must be strings: {fixture}")
            root_candidate = evaluation_root.joinpath(*PurePosixPath(raw_root).parts)
            qrels_candidate = evaluation_root.joinpath(*PurePosixPath(raw_qrels).parts)
            if root_candidate.is_symlink() or not root_candidate.is_dir():
                raise ValueError(f"fixture root must be a regular directory: {fixture}")
            if qrels_candidate.is_symlink() or not qrels_candidate.is_file():
                raise ValueError(f"fixture qrels must be a regular file: {fixture}")
            root = root_candidate.resolve(strict=True)
            qrels = qrels_candidate.resolve(strict=True)
            root.relative_to(evaluation_root)
            qrels.relative_to(evaluation_root)
            if root in seen_roots or qrels in seen_qrel_paths:
                raise ValueError(f"fixture roots and qrel paths must be unique: {fixture}")
            seen_roots.add(root)
            seen_qrel_paths.add(qrels)

            actual_tree = fixture_tree_sha256(root)
            actual_qrels = _sha256_file(qrels)
            expected_tree = entry.get("tree_sha256")
            expected_qrels = entry.get("qrels_sha256")
            if (
                not isinstance(expected_tree, str)
                or _SHA256.fullmatch(expected_tree) is None
                or actual_tree != expected_tree
            ):
                raise ValueError(f"fixture checksum mismatch: {fixture}")
            if (
                not isinstance(expected_qrels, str)
                or _SHA256.fullmatch(expected_qrels) is None
                or actual_qrels != expected_qrels
            ):
                raise ValueError(f"qrel checksum mismatch: {fixture}")
            if actual_tree in seen_tree_hashes or actual_qrels in seen_qrel_hashes:
                raise ValueError(f"fixture tree and qrel hashes must be unique: {fixture}")
            seen_tree_hashes.add(actual_tree)
            seen_qrel_hashes.add(actual_qrels)

            review = review_artifacts.pop(fixture, None)
            if (
                review is None
                or review.get("fixture_revision") != revision
                or review.get("tree_sha256") != actual_tree
                or review.get("qrels_sha256") != actual_qrels
            ):
                raise ValueError(f"review provenance does not cover fixture qrels: {fixture}")
            cases = _load_qrels(qrels, fixture=fixture, revision=revision)
            expected_count = _positive_integer(
                entry.get("qrels_count"), f"fixtures.{fixture}.qrels_count"
            )
            if expected_count != len(cases):
                raise ValueError(f"qrel count mismatch: {fixture}")
            _validate_case_sources(root, cases)
            must_not_cases = sum(bool(case["must_not_return"]) for case in cases)
            must_not_by_fixture[fixture] = must_not_cases
            scan = scanner.scan(root, refresh_mode="rebuild")
            index = stack.enter_context(RepositoryIndex.open(root, cache_dir=cache_directory))
            update = index.update(scan)
            dependency_expectations = _validate_dependency_expectations(index, cases)
            retrieval = RetrievalEngine(index)
            for case in cases:
                question = str(case.get("question", ""))
                if not question or question in routes:
                    raise ValueError("external qrel questions must be non-empty and unique")
                routes[question] = retrieval
            all_cases.extend(cases)
            fixture_reports.append(
                {
                    "id": fixture,
                    "revision": revision,
                    "source": source,
                    "license": license_name,
                    "tree_sha256": actual_tree,
                    "qrels_sha256": actual_qrels,
                    "qrels": len(cases),
                    "must_not_return_qrels": must_not_cases,
                    "dependency_expectations": dependency_expectations,
                    "content_generation": update.content_generation,
                    "scan_revision": update.scan_revision,
                }
            )
        if review_artifacts:
            raise ValueError(
                "review provenance contains undeclared fixtures: "
                + ", ".join(sorted(review_artifacts))
            )
        if len(all_cases) < minimum_qrels:
            raise ValueError(
                f"external evaluation has {len(all_cases)} qrels; expected at least {minimum_qrels}"
            )
        family_counts, families_by_type, fixtures_by_type = _case_family_report(
            all_cases,
            reviewed_no_answer_intents=reviewed_no_answer_intents,
        )
        family_count = sum(family_counts.values())
        if family_count < minimum_case_families:
            raise ValueError(
                f"external evaluation has {family_count} case families; "
                f"expected at least {minimum_case_families}"
            )
        for fixture, count in family_counts.items():
            if count < minimum_case_families_per_fixture:
                raise ValueError(f"fixture has too few independent case families: {fixture}")
        for query_type in sorted(_REQUIRED_QUERY_TYPES):
            if families_by_type.get(query_type, 0) < family_minimums[query_type]:
                raise ValueError(f"query type has too few case families: {query_type}")
            if fixtures_by_type.get(query_type, 0) < minimum_query_type_fixtures:
                raise ValueError(f"query type has insufficient fixture distribution: {query_type}")
        corpus_coverage = _corpus_coverage(all_cases)
        if int(corpus_coverage["distinct_relevant_ranges"]) < minimum_distinct_relevant_ranges:
            raise ValueError("external evaluation has too few distinct relevant source ranges")
        for fixture, count in corpus_coverage["distinct_relevant_ranges_by_fixture"].items():
            if int(count) < minimum_distinct_relevant_ranges_per_fixture:
                raise ValueError(f"fixture has too few distinct relevant ranges: {fixture}")
        if int(corpus_coverage["multi_path_families"]) < minimum_multi_path_families:
            raise ValueError("external evaluation has too few multi-path families")
        for fixture in seen_fixture_ids:
            count = corpus_coverage["multi_path_families_by_fixture"].get(fixture, 0)
            if int(count) < minimum_multi_path_families_per_fixture:
                raise ValueError(f"fixture has too few multi-path families: {fixture}")
        if (
            int(corpus_coverage["ambiguous_dependency_families"])
            < minimum_ambiguous_dependency_families
        ):
            raise ValueError("external evaluation has too few ambiguous dependency families")
        for answerability, minimum_field, fixture_field in (
            (
                "answerable",
                "minimum_answerable_intent_families",
                "answerable_intent_fixture_counts",
            ),
            (
                "no-answer",
                "minimum_no_answer_intent_families",
                "no_answer_intent_fixture_counts",
            ),
        ):
            family_field = f"{answerability.replace('-', '_')}_intent_families"
            family_values = corpus_coverage[family_field]
            fixture_values = corpus_coverage[fixture_field]
            for intent in sorted(_RUNTIME_INTENTS):
                if int(family_values[intent]) < intent_minimums[minimum_field][intent]:
                    raise ValueError(
                        f"{answerability} runtime intent has too few families: {intent}"
                    )
                if int(fixture_values[intent]) < minimum_runtime_intent_fixtures:
                    raise ValueError(
                        f"{answerability} runtime intent has insufficient fixture distribution: "
                        f"{intent}"
                    )
        must_not_qrels = sum(must_not_by_fixture.values())
        if must_not_qrels < minimum_must_not_return_qrels:
            raise ValueError("external evaluation has too few must_not_return qrels")
        for fixture, count in must_not_by_fixture.items():
            if count < minimum_must_not_return_qrels_per_fixture:
                raise ValueError(f"fixture has too few must_not_return qrels: {fixture}")

        query_types = set(families_by_type)
        outcomes, metrics = evaluate_cases(_RoutedRetrieval(routes), all_cases, limit=limit)

    for fixture_report in fixture_reports:
        fixture_report["case_families"] = family_counts[str(fixture_report["id"])]
    return {
        "manifest": manifest_path.relative_to(evaluation_root).as_posix(),
        "review_provenance": review_report,
        "fixtures": fixture_reports,
        "fixture_count": len(fixture_reports),
        "qrels": len(all_cases),
        "reviewed_qrels": len(all_cases),
        "case_families": family_count,
        "case_families_by_query_type": dict(sorted(families_by_type.items())),
        "query_type_fixture_counts": dict(sorted(fixtures_by_type.items())),
        "query_types": sorted(query_types),
        "runtime_intents": sorted(_RUNTIME_INTENTS),
        "corpus_coverage": corpus_coverage,
        "answerable_qrels": metrics["answerable_cases"],
        "no_answer_qrels": metrics["no_answer_cases"],
        "citation_qrels": metrics["citation_cases"],
        "must_not_return_qrels": metrics["must_not_return_cases"],
        "top_k": limit,
        "metrics": metrics,
        "bootstrap": _bootstrap_report(outcomes),
        "outcomes": outcomes,
    }


def _gate_report(
    report: Mapping[str, object], thresholds: Mapping[str, object]
) -> dict[str, object]:
    validated_thresholds = _validated_thresholds(thresholds)
    raw_bootstrap = report.get("bootstrap")
    if not isinstance(raw_bootstrap, Mapping) or not isinstance(
        raw_bootstrap.get("intervals"), Mapping
    ):
        raise ValueError("external evaluation bootstrap report is invalid")
    intervals = raw_bootstrap["intervals"]
    assert isinstance(intervals, Mapping)
    quality_specs = {
        "minimum_hit_rate": ("any_expected_path_rate", 0, ">="),
        "minimum_macro_recall": ("macro_recall_at_k", 0, ">="),
        "minimum_mrr": ("mrr", 0, ">="),
        "minimum_citation_recall": ("citation_recall", 0, ">="),
        "minimum_no_answer_f1": ("no_answer_f1", 0, ">="),
        "maximum_must_not_return_rate": ("must_not_return_violation_rate", 1, "<="),
        "maximum_duplicate_evidence_rate": ("duplicate_evidence_rate", 1, "<="),
        "minimum_intent_accuracy": ("intent_accuracy", 0, ">="),
        "minimum_graph_grounded_rate": ("graph_grounded_rate", 0, ">="),
        "minimum_mean_path_diversity": ("mean_path_diversity", 0, ">="),
    }
    observed: dict[str, object] = {}
    passed = True
    for threshold_name, (metric, bound_index, comparison) in quality_specs.items():
        interval = intervals.get(metric)
        bound = (
            float(interval[bound_index])
            if isinstance(interval, list)
            and len(interval) == 2
            and all(isinstance(value, (int, float)) for value in interval)
            else None
        )
        threshold = float(validated_thresholds[threshold_name])
        check_passed = bound is not None and (
            bound >= threshold if comparison == ">=" else bound <= threshold
        )
        observed[threshold_name] = {
            "metric": metric,
            "bound": "lower" if bound_index == 0 else "upper",
            "value": bound,
            "passed": check_passed,
        }
        passed = passed and check_passed

    raw_metrics = report.get("metrics")
    if not isinstance(raw_metrics, Mapping):
        raise ValueError("external evaluation metrics report is invalid")
    maximum_line_iou = raw_metrics.get("maximum_line_iou")
    line_iou_threshold = float(validated_thresholds["maximum_line_iou"])
    line_iou_passed = (
        isinstance(maximum_line_iou, (int, float))
        and not isinstance(maximum_line_iou, bool)
        and float(maximum_line_iou) <= line_iou_threshold
    )
    observed["maximum_line_iou"] = {
        "metric": "maximum_line_iou",
        "bound": "observed maximum",
        "value": maximum_line_iou,
        "passed": line_iou_passed,
    }
    passed = passed and line_iou_passed

    slice_specs = {
        "minimum_slice_hit_rate": ("any_expected_path_rate", "answerable_cases"),
        "minimum_slice_mrr": ("mrr", "answerable_cases"),
        "minimum_slice_no_answer_f1": ("no_answer_f1", "no_answer_cases"),
    }
    for threshold_name, (metric, eligibility) in slice_specs.items():
        values: list[tuple[float, str]] = []
        for grouping in ("by_query_type", "by_intent"):
            raw_buckets = raw_metrics.get(grouping)
            if not isinstance(raw_buckets, Mapping):
                raise ValueError(f"external evaluation {grouping} report is invalid")
            for label, raw_bucket in raw_buckets.items():
                if not isinstance(raw_bucket, Mapping) or not int(raw_bucket.get(eligibility, 0)):
                    continue
                value = raw_bucket.get(metric)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    values.append((float(value), f"{grouping}.{label}"))
        worst_value, worst_slice = min(values, default=(float("-inf"), "missing"))
        threshold = float(validated_thresholds[threshold_name])
        check_passed = bool(values) and worst_value >= threshold
        observed[threshold_name] = {
            "metric": metric,
            "bound": "minimum slice",
            "slice": worst_slice,
            "value": worst_value if values else None,
            "passed": check_passed,
        }
        passed = passed and check_passed

    count_specs = {
        "minimum_qrels": "qrels",
        "minimum_answerable_qrels": "answerable_qrels",
        "minimum_no_answer_qrels": "no_answer_qrels",
        "minimum_citation_qrels": "citation_qrels",
    }
    for threshold_name, report_name in count_specs.items():
        value = int(report[report_name])
        check_passed = value >= int(validated_thresholds[threshold_name])
        observed[threshold_name] = {
            "metric": report_name,
            "bound": "count",
            "value": value,
            "passed": check_passed,
        }
        passed = passed and check_passed
    return {
        "passed": passed,
        "basis": (
            "95% equal-weight fixture/case-family clustered bootstrap bounds, "
            "v0.2 semantic slices, and observed counts"
        ),
        "thresholds": validated_thresholds,
        "observed": observed,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "evaluation_root",
        type=Path,
        nargs="?",
        default=Path("evaluation"),
    )
    parser.add_argument("--limit", type=_positive_cli_integer, default=5)
    parser.add_argument("--minimum-hit-rate", type=_unit_interval, default=0.90)
    parser.add_argument("--minimum-macro-recall", type=_unit_interval, default=0.80)
    parser.add_argument("--minimum-mrr", type=_unit_interval, default=0.75)
    parser.add_argument("--minimum-citation-recall", type=_unit_interval, default=1.0)
    parser.add_argument("--minimum-no-answer-f1", type=_unit_interval, default=0.80)
    parser.add_argument("--maximum-must-not-return-rate", type=_unit_interval, default=0.0)
    parser.add_argument("--maximum-duplicate-evidence-rate", type=_unit_interval, default=0.0)
    parser.add_argument("--maximum-line-iou", type=_unit_interval, default=0.79)
    parser.add_argument("--minimum-intent-accuracy", type=_unit_interval, default=1.0)
    parser.add_argument("--minimum-graph-grounded-rate", type=_unit_interval, default=1.0)
    parser.add_argument("--minimum-mean-path-diversity", type=_unit_interval, default=0.50)
    parser.add_argument("--minimum-slice-hit-rate", type=_unit_interval, default=0.50)
    parser.add_argument("--minimum-slice-mrr", type=_unit_interval, default=0.50)
    parser.add_argument("--minimum-slice-no-answer-f1", type=_unit_interval, default=0.75)
    parser.add_argument("--minimum-qrels", type=_positive_cli_integer, default=100)
    parser.add_argument("--minimum-answerable-qrels", type=_positive_cli_integer, default=60)
    parser.add_argument("--minimum-no-answer-qrels", type=_positive_cli_integer, default=20)
    parser.add_argument("--minimum-citation-qrels", type=_positive_cli_integer, default=60)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    report = evaluate_suite(arguments.evaluation_root.resolve(strict=True), limit=arguments.limit)
    thresholds = {
        "minimum_hit_rate": arguments.minimum_hit_rate,
        "minimum_macro_recall": arguments.minimum_macro_recall,
        "minimum_mrr": arguments.minimum_mrr,
        "minimum_citation_recall": arguments.minimum_citation_recall,
        "minimum_no_answer_f1": arguments.minimum_no_answer_f1,
        "maximum_must_not_return_rate": arguments.maximum_must_not_return_rate,
        "maximum_duplicate_evidence_rate": arguments.maximum_duplicate_evidence_rate,
        "maximum_line_iou": arguments.maximum_line_iou,
        "minimum_intent_accuracy": arguments.minimum_intent_accuracy,
        "minimum_graph_grounded_rate": arguments.minimum_graph_grounded_rate,
        "minimum_mean_path_diversity": arguments.minimum_mean_path_diversity,
        "minimum_slice_hit_rate": arguments.minimum_slice_hit_rate,
        "minimum_slice_mrr": arguments.minimum_slice_mrr,
        "minimum_slice_no_answer_f1": arguments.minimum_slice_no_answer_f1,
        "minimum_qrels": arguments.minimum_qrels,
        "minimum_answerable_qrels": arguments.minimum_answerable_qrels,
        "minimum_no_answer_qrels": arguments.minimum_no_answer_qrels,
        "minimum_citation_qrels": arguments.minimum_citation_qrels,
    }
    report["gate"] = _gate_report(report, thresholds)
    # Keep stdout and persisted reports independent of the host console code page.
    # In particular, Windows runners commonly expose cp1252 even when the qrels
    # contain CJK text. JSON escapes preserve the exact Unicode values while
    # making the serialized release artifact portable ASCII.
    encoded = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if report["gate"]["passed"] else 1  # type: ignore[index]


if __name__ == "__main__":
    raise SystemExit(main())
