"""Generation-pinned, projection-only repository reads."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import TracebackType
from typing import Protocol

from repolocus.analysis import DEPENDENCY_RESOLVER_FINGERPRINT, AnalysisFingerprints
from repolocus.graph import ResolvedDependency
from repolocus.models import ScannedFile, Symbol


@dataclass(frozen=True, slots=True)
class DiagramFile:
    path: str
    first_line: int = 1


@dataclass(frozen=True, slots=True)
class FileSummary:
    path: str
    language: str
    size_bytes: int
    line_count: int
    is_entry_point: bool
    symbol_count: int
    first_line: int = 1


@dataclass(frozen=True, slots=True)
class EntryPoint:
    path: str
    line: int


@dataclass(frozen=True, slots=True)
class AreaSummary:
    area: str
    file_count: int
    symbol_count: int
    languages: tuple[tuple[str, int], ...]
    representative_path: str
    representative_line: int


class RepositoryView(Protocol):
    """Small, read-only projections pinned to one content generation."""

    generation: int
    root: Path
    schema_version: int
    repository_identity: str
    fingerprints: AnalysisFingerprints | None
    dependency_resolver_fingerprint: str | None

    def file_manifest(self) -> Iterable[ScannedFile]: ...

    def symbols(self) -> Iterable[Symbol]: ...

    def diagram_files(self) -> Iterable[DiagramFile]: ...

    def file_summaries(self) -> Iterable[FileSummary]: ...

    def entry_points(self) -> Iterable[EntryPoint]: ...

    def symbols_by_area(self) -> Iterable[AreaSummary]: ...

    def dependencies(self) -> Iterable[ResolvedDependency]: ...

    def read_text_prefix(self, path: str, max_chars: int) -> str: ...

    def stats(self) -> dict[str, object]: ...


def _area(path: str) -> str:
    parts = PurePosixPath(path).parts
    if len(parts) == 1:
        return "(repository root)"
    return parts[0]


class SQLiteRepositoryView:
    """A context-managed RepositoryView backed by one SQLite read snapshot."""

    def __init__(self, index: object, expected_generation: int | None = None) -> None:
        if expected_generation is not None and (
            isinstance(expected_generation, bool)
            or not isinstance(expected_generation, int)
            or expected_generation < 0
        ):
            raise ValueError("expected_generation must be a non-negative integer or None")
        self._index = index
        self._expected_generation = expected_generation
        self._active = False
        self._lifecycle = 0
        self._active_lifecycle: int | None = None
        self._dependency_cursors: list[sqlite3.Cursor] = []
        self._file_summary_cache: tuple[FileSummary, ...] | None = None
        self.generation = 0
        self.root = Path(index.root)
        self.schema_version = 0
        self.repository_identity = ""
        self.fingerprints: AnalysisFingerprints | None = None
        self.dependency_resolver_fingerprint: str | None = None

    def __enter__(self) -> SQLiteRepositoryView:
        if self._active:
            raise RuntimeError("repository view is already active")
        self._index._ensure_open()
        self._index._ensure_repository_identity()
        self._index._lock.acquire()
        try:
            self._file_summary_cache = None
            self._index._connection.execute("BEGIN")
            self.generation = self._index._revision_in_transaction(
                "content_generation", fallback="generation"
            )
            metadata = {
                str(row["key"]): str(row["value"])
                for row in self._index._connection.execute(
                    "SELECT key, value FROM meta "
                    "WHERE key IN ("
                    "'schema_version', 'repository_identity', "
                    "'scan_fingerprint', 'parser_fingerprint', "
                    "'term_index_fingerprint', 'retrieval_fingerprint', "
                    "'dependency_resolver_fingerprint'"
                    ")"
                )
            }
            self.schema_version = int(metadata.get("schema_version", "0"))
            self.repository_identity = metadata.get("repository_identity", "")
            self.fingerprints = AnalysisFingerprints.from_metadata(metadata)
            self.dependency_resolver_fingerprint = metadata.get("dependency_resolver_fingerprint")
            if self.dependency_resolver_fingerprint != DEPENDENCY_RESOLVER_FINGERPRINT:
                from repolocus.index.store import StaleScanError

                raise StaleScanError(
                    "resolved dependency graph is stale; refresh the repository index"
                )
            if (
                self._expected_generation is not None
                and self.generation != self._expected_generation
            ):
                from repolocus.index.store import StaleScanError

                raise StaleScanError(
                    f"expected index generation {self._expected_generation}, "
                    f"but current generation is {self.generation}"
                )
            self._lifecycle += 1
            self._active_lifecycle = self._lifecycle
            self._active = True
            return self
        except BaseException:
            self._index._connection.rollback()
            self._index._lock.release()
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            self._close_dependency_cursors()
            if exc_type is None:
                self._index._connection.commit()
            else:
                self._index._connection.rollback()
        finally:
            self._active = False
            self._active_lifecycle = None
            self._file_summary_cache = None
            self._index._lock.release()

    def _ensure_active(self) -> None:
        if not self._active:
            raise RuntimeError("repository view must be used as a context manager")

    def _ensure_dependency_lifecycle(self, lifecycle: int) -> None:
        self._ensure_active()
        if lifecycle != self._active_lifecycle:
            raise RuntimeError(
                "dependency iterator belongs to a different repository view lifecycle"
            )

    def diagram_files(self) -> tuple[DiagramFile, ...]:
        self._ensure_active()
        rows = self._index._connection.execute(
            """
            SELECT f.path, 1 AS first_line
            FROM files AS f
            WHERE f.provenance = 'source' AND f.stale = 0
            ORDER BY f.path
            """
        ).fetchall()
        return tuple(
            DiagramFile(path=str(row["path"]), first_line=int(row["first_line"])) for row in rows
        )

    def file_manifest(self) -> tuple[ScannedFile, ...]:
        """Return metadata-only files from this view's read transaction."""

        self._ensure_active()
        rows = self._index._connection.execute(
            """
            SELECT path, language, size_bytes, sha256, line_count, is_entry_point,
                   mtime_ns, ctime_ns, provenance, stale
            FROM files
            WHERE provenance = 'source' AND stale = 0
            ORDER BY path
            """
        ).fetchall()
        return tuple(
            ScannedFile(
                path=str(row["path"]),
                language=str(row["language"]),
                size_bytes=int(row["size_bytes"]),
                sha256=str(row["sha256"]),
                line_count=int(row["line_count"]),
                text="",
                is_entry_point=bool(row["is_entry_point"]),
                mtime_ns=int(row["mtime_ns"]),
                ctime_ns=int(row["ctime_ns"]),
                provenance="source",
                stale=False,
                facts_materialized=False,
            )
            for row in rows
        )

    def symbols(self) -> tuple[Symbol, ...]:
        """Return source symbol locations without reading files or chunks."""

        self._ensure_active()
        rows = self._index._connection.execute(
            """
            SELECT s.name, s.kind, s.file_path, s.start_line, s.end_line, s.signature
            FROM symbols AS s
            JOIN files AS f ON f.path = s.file_path
            WHERE f.provenance = 'source' AND f.stale = 0
            ORDER BY s.file_path, s.start_line, s.end_line, s.name, s.kind, s.id
            """
        ).fetchall()
        return tuple(
            Symbol(
                name=str(row["name"]),
                kind=str(row["kind"]),
                path=str(row["file_path"]),
                start_line=int(row["start_line"]),
                end_line=int(row["end_line"]),
                signature=str(row["signature"]),
            )
            for row in rows
        )

    def file_summaries(self) -> tuple[FileSummary, ...]:
        self._ensure_active()
        if self._file_summary_cache is not None:
            return self._file_summary_cache
        rows = self._index._connection.execute(
            """
            WITH symbol_counts AS (
                SELECT file_path, count(*) AS count FROM symbols GROUP BY file_path
            ),
            first_lines AS (
                SELECT file_path, min(start_line) AS line FROM chunks GROUP BY file_path
            )
            SELECT f.path, f.language, f.size_bytes, f.line_count, f.is_entry_point,
                   coalesce(s.count, 0) AS symbol_count,
                   coalesce(l.line, 1) AS first_line
            FROM files AS f
            LEFT JOIN symbol_counts AS s ON s.file_path = f.path
            LEFT JOIN first_lines AS l ON l.file_path = f.path
            WHERE f.provenance = 'source' AND f.stale = 0
            ORDER BY f.path
            """
        ).fetchall()
        self._file_summary_cache = tuple(
            FileSummary(
                path=str(row["path"]),
                language=str(row["language"]),
                size_bytes=int(row["size_bytes"]),
                line_count=int(row["line_count"]),
                is_entry_point=bool(row["is_entry_point"]),
                symbol_count=int(row["symbol_count"]),
                first_line=int(row["first_line"]),
            )
            for row in rows
        )
        return self._file_summary_cache

    def entry_points(self) -> tuple[EntryPoint, ...]:
        self._ensure_active()
        rows = self._index._connection.execute(
            """
            SELECT f.path,
                   coalesce(
                       min(CASE
                           WHEN lower(s.name) = 'main'
                                OR lower(s.name) = '__main__'
                                OR lower(s.name) LIKE '%.main'
                           THEN s.start_line
                       END),
                       1
                   ) AS line
            FROM files AS f
            LEFT JOIN symbols AS s ON s.file_path = f.path
            WHERE f.provenance = 'source' AND f.stale = 0 AND f.is_entry_point = 1
            GROUP BY f.path
            ORDER BY f.path
            """
        ).fetchall()
        return tuple(EntryPoint(str(row["path"]), int(row["line"])) for row in rows)

    def symbols_by_area(self) -> tuple[AreaSummary, ...]:
        summaries = self.file_summaries()
        grouped: dict[str, list[FileSummary]] = defaultdict(list)
        for summary in summaries:
            grouped[_area(summary.path)].append(summary)
        output: list[AreaSummary] = []
        for area, files in sorted(grouped.items()):
            languages = Counter(file.language for file in files)
            representative = min(files, key=lambda item: item.path)
            output.append(
                AreaSummary(
                    area=area,
                    file_count=len(files),
                    symbol_count=sum(file.symbol_count for file in files),
                    languages=tuple(sorted(languages.items())),
                    representative_path=representative.path,
                    representative_line=representative.first_line,
                )
            )
        return tuple(output)

    def dependencies(self) -> Iterator[ResolvedDependency]:
        self._ensure_active()
        lifecycle = self._active_lifecycle
        if lifecycle is None:  # pragma: no cover - guarded by _ensure_active
            raise RuntimeError("repository view has no active lifecycle")
        return self._dependency_iterator(lifecycle)

    def _dependency_iterator(self, lifecycle: int) -> Iterator[ResolvedDependency]:
        rows: sqlite3.Cursor | None = None
        current_row: sqlite3.Row | None = None
        candidates: list[str] = []
        try:
            self._ensure_dependency_lifecycle(lifecycle)
            self._index._ensure_resolved_graph_current()
            rows = self._index._connection.execute(
                """
                SELECT rd.dependency_id, rd.source_path, d.target, rd.target_path,
                       rd.target_symbol, d.kind, rd.witness_line, rd.resolution_kind,
                       candidate.path AS candidate_path
                FROM resolved_dependencies AS rd
                JOIN dependencies AS d ON d.id = rd.dependency_id
                JOIN files AS f ON f.path = rd.source_path
                LEFT JOIN resolved_dependency_candidates AS candidate
                  ON candidate.dependency_id = rd.dependency_id
                WHERE f.provenance = 'source' AND f.stale = 0
                ORDER BY rd.source_path, rd.witness_line, d.target, d.kind,
                         rd.dependency_id, candidate.path
                """
            )
            self._dependency_cursors.append(rows)
            while True:
                self._ensure_dependency_lifecycle(lifecycle)
                row = rows.fetchone()
                self._ensure_dependency_lifecycle(lifecycle)
                if row is None:
                    break
                dependency_id = int(row["dependency_id"])
                if current_row is not None and dependency_id != int(current_row["dependency_id"]):
                    dependency = _resolved_dependency(current_row, candidates)
                    candidates = []
                    current_row = row
                    if row["candidate_path"] is not None:
                        candidates.append(str(row["candidate_path"]))
                    self._ensure_dependency_lifecycle(lifecycle)
                    yield dependency
                    self._ensure_dependency_lifecycle(lifecycle)
                    continue
                current_row = row
                if row["candidate_path"] is not None:
                    candidates.append(str(row["candidate_path"]))
            if current_row is not None:
                self._ensure_dependency_lifecycle(lifecycle)
                yield _resolved_dependency(current_row, candidates)
                self._ensure_dependency_lifecycle(lifecycle)
        finally:
            if rows is not None:
                self._close_dependency_cursor(rows)

    def _close_dependency_cursor(self, cursor: sqlite3.Cursor) -> None:
        try:
            self._dependency_cursors.remove(cursor)
        except ValueError:
            return
        with suppress(sqlite3.ProgrammingError):
            cursor.close()

    def _close_dependency_cursors(self) -> None:
        for cursor in tuple(self._dependency_cursors):
            self._close_dependency_cursor(cursor)

    def read_text_prefix(self, path: str, max_chars: int) -> str:
        self._ensure_active()
        if not isinstance(max_chars, int) or isinstance(max_chars, bool) or max_chars <= 0:
            raise ValueError("max_chars must be a positive integer")
        candidate = PurePosixPath(path)
        if (
            not path
            or "\\" in path
            or candidate.is_absolute()
            or ".." in candidate.parts
            or candidate.as_posix() != path
        ):
            raise ValueError("path must be normalized and repository-relative")
        row = self._index._connection.execute(
            """
            SELECT substr(text, 1, ?) AS prefix FROM files
            WHERE path = ? AND provenance = 'source' AND stale = 0
            """,
            (min(max_chars, 64_000), path),
        ).fetchone()
        return str(row["prefix"]) if row is not None else ""

    def stats(self) -> dict[str, object]:
        self._ensure_active()
        row = self._index._connection.execute(
            """
            SELECT count(*) AS files, coalesce(sum(size_bytes), 0) AS indexed_bytes
            FROM files WHERE provenance = 'source' AND stale = 0
            """
        ).fetchone()
        language_rows = self._index._connection.execute(
            """
            SELECT language, count(*) AS count FROM files
            WHERE provenance = 'source' AND stale = 0
            GROUP BY language ORDER BY language
            """
        ).fetchall()
        metadata = {
            str(item["key"]): str(item["value"])
            for item in self._index._connection.execute(
                "SELECT key, value FROM meta "
                "WHERE key IN ('last_scan_skipped', 'last_scan_warnings')"
            )
        }
        try:
            skipped = json.loads(metadata.get("last_scan_skipped", "{}"))
            warnings = json.loads(metadata.get("last_scan_warnings", "[]"))
        except json.JSONDecodeError:
            skipped, warnings = {}, []
        return {
            "files": int(row["files"]),
            "indexed_bytes": int(row["indexed_bytes"]),
            "languages": {str(item["language"]): int(item["count"]) for item in language_rows},
            "skipped": skipped if isinstance(skipped, dict) else {},
            "warnings": warnings if isinstance(warnings, list) else [],
        }


def _resolved_dependency(row: sqlite3.Row, candidates: Iterable[str]) -> ResolvedDependency:
    return ResolvedDependency(
        source_path=str(row["source_path"]),
        raw_target=str(row["target"]),
        target_path=str(row["target_path"]) if row["target_path"] is not None else None,
        target_symbol=str(row["target_symbol"]) if row["target_symbol"] is not None else None,
        kind=str(row["kind"]),
        line=int(row["witness_line"]),
        confidence=str(row["resolution_kind"]),  # type: ignore[arg-type]
        candidates=tuple(candidates),
    )
