#!/usr/bin/env python3
"""Run the versioned multi-repository retrieval release gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
from collections.abc import Mapping
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from evaluate_retrieval import evaluate_cases

from repolocus.config import Settings
from repolocus.core import RepoLocusService
from repolocus.index import RepositoryIndex
from repolocus.retrieval import RetrievalEngine


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
            case = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid qrel JSON at {path}:{line_number}") from exc
        if not isinstance(case, dict):
            raise ValueError(f"qrel must be an object at {path}:{line_number}")
        case["fixture"] = fixture
        case["fixture_revision"] = revision
        case["qrel_line"] = line_number
        cases.append(case)
    if not cases:
        raise ValueError(f"qrel file is empty: {path}")
    return cases


def _validate_case_sources(root: Path, cases: list[dict[str, Any]]) -> None:
    for case in cases:
        for item in case.get("relevant", []):
            if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
                raise ValueError("qrel relevant entries must contain paths")
            relative = Path(str(item["path"]))
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("qrel path must be repository-relative")
            source = root / relative
            if not source.is_file() or source.is_symlink():
                raise ValueError(f"qrel source does not exist as a regular file: {source}")
            line_count = len(source.read_text(encoding="utf-8").splitlines())
            if int(item.get("end", item.get("start", 0))) > line_count:
                raise ValueError(f"qrel line range exceeds source: {source}")


class _RoutedRetrieval:
    def __init__(self, routes: Mapping[str, RetrievalEngine]) -> None:
        self.routes = routes

    def search(self, question: str, limit: int):  # type: ignore[no-untyped-def]
        return self.routes[question].search(question, limit=limit)


def evaluate_suite(
    evaluation_root: Path,
    *,
    limit: int = 5,
) -> dict[str, object]:
    manifest_path = evaluation_root / "external-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("version") != 1:
        raise ValueError("external evaluation manifest version is invalid")
    raw_fixtures = manifest.get("fixtures")
    if not isinstance(raw_fixtures, list) or len(raw_fixtures) < 2:
        raise ValueError("external evaluation must declare multiple fixtures")

    all_cases: list[dict[str, Any]] = []
    routes: dict[str, RetrievalEngine] = {}
    fixture_reports: list[dict[str, object]] = []
    with ExitStack() as stack:
        cache_directory = (
            Path(stack.enter_context(TemporaryDirectory(prefix="repolocus-evaluation-")))
            / "indexes"
        )
        scanner = RepoLocusService(Settings(model="local")).scanner
        for entry in raw_fixtures:
            if not isinstance(entry, dict):
                raise ValueError("fixture manifest entries must be objects")
            fixture = str(entry.get("id", ""))
            revision = str(entry.get("revision", ""))
            source = str(entry.get("source", ""))
            license_name = str(entry.get("license", ""))
            if not fixture or not revision or not source or not license_name:
                raise ValueError("fixture provenance fields must not be empty")
            root = (evaluation_root / str(entry.get("path", ""))).resolve(strict=True)
            qrels = (evaluation_root / str(entry.get("qrels", ""))).resolve(strict=True)
            root.relative_to(evaluation_root.resolve(strict=True))
            qrels.relative_to(evaluation_root.resolve(strict=True))
            actual_tree = fixture_tree_sha256(root)
            actual_qrels = _sha256_file(qrels)
            if actual_tree != entry.get("tree_sha256"):
                raise ValueError(f"fixture checksum mismatch: {fixture}")
            if actual_qrels != entry.get("qrels_sha256"):
                raise ValueError(f"qrel checksum mismatch: {fixture}")
            cases = _load_qrels(qrels, fixture=fixture, revision=revision)
            _validate_case_sources(root, cases)
            scan = scanner.scan(root, refresh_mode="rebuild")
            index = stack.enter_context(RepositoryIndex.open(root, cache_dir=cache_directory))
            update = index.update(scan)
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
                    "content_generation": update.content_generation,
                    "scan_revision": update.scan_revision,
                }
            )
        outcomes, metrics = evaluate_cases(_RoutedRetrieval(routes), all_cases, limit=limit)

    return {
        "manifest": manifest_path.relative_to(evaluation_root).as_posix(),
        "fixtures": fixture_reports,
        "fixture_count": len(fixture_reports),
        "qrels": len(all_cases),
        "answerable_qrels": metrics["answerable_cases"],
        "no_answer_qrels": metrics["no_answer_cases"],
        "citation_qrels": metrics["citation_cases"],
        "top_k": limit,
        "metrics": metrics,
        "outcomes": outcomes,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "evaluation_root",
        type=Path,
        nargs="?",
        default=Path("evaluation"),
    )
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--minimum-hit-rate", type=float, default=0.90)
    parser.add_argument("--minimum-macro-recall", type=float, default=0.80)
    parser.add_argument("--minimum-mrr", type=float, default=0.75)
    parser.add_argument("--minimum-citation-recall", type=float, default=1.0)
    parser.add_argument("--minimum-no-answer-f1", type=float, default=0.80)
    parser.add_argument("--maximum-must-not-return-rate", type=float, default=0.0)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    report = evaluate_suite(arguments.evaluation_root.resolve(strict=True), limit=arguments.limit)
    metrics = report["metrics"]
    if not isinstance(metrics, Mapping):  # pragma: no cover - report invariant
        raise RuntimeError("external evaluation metrics are invalid")
    thresholds = {
        "minimum_hit_rate": arguments.minimum_hit_rate,
        "minimum_macro_recall": arguments.minimum_macro_recall,
        "minimum_mrr": arguments.minimum_mrr,
        "minimum_citation_recall": arguments.minimum_citation_recall,
        "minimum_no_answer_f1": arguments.minimum_no_answer_f1,
        "maximum_must_not_return_rate": arguments.maximum_must_not_return_rate,
    }
    passed = (
        float(metrics["any_expected_path_rate"] or 0.0) >= arguments.minimum_hit_rate
        and float(metrics["macro_recall_at_k"] or 0.0) >= arguments.minimum_macro_recall
        and float(metrics["mrr"] or 0.0) >= arguments.minimum_mrr
        and float(metrics["citation_recall"] or 0.0) >= arguments.minimum_citation_recall
        and float(metrics["no_answer_f1"] or 0.0) >= arguments.minimum_no_answer_f1
        and float(metrics["must_not_return_violation_rate"])
        <= arguments.maximum_must_not_return_rate
    )
    report["gate"] = {"passed": passed, "thresholds": thresholds}
    # Keep stdout and persisted reports independent of the host console code page.
    # In particular, Windows runners commonly expose cp1252 even when the qrels
    # contain CJK text. JSON escapes preserve the exact Unicode values while
    # making the serialized release artifact portable ASCII.
    encoded = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
