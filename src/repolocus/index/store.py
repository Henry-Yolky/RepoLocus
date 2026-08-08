"""SQLite-backed, incremental repository index.

The database deliberately lives in the user's cache directory instead of the
repository.  Repository contents are data only: this module never invokes Git,
a shell, or any executable found in the indexed tree.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import unicodedata
from collections import defaultdict
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from platformdirs import user_cache_path

from repolocus.analysis import (
    DEFAULT_ANALYSIS_FINGERPRINTS,
    DEPENDENCY_RESOLVER_FINGERPRINT,
    AnalysisFingerprints,
)
from repolocus.graph import ResolvedDependency
from repolocus.models import (
    Chunk,
    Dependency,
    IndexSnapshot,
    IndexUpdate,
    ScannedFile,
    ScanResult,
    Symbol,
)
from repolocus.security.identity import filesystem_identity

if TYPE_CHECKING:
    from repolocus.index.view import SQLiteRepositoryView

SCHEMA_VERSION = 6
INDEX_FORMAT_VERSION = "6"
MAX_RETRIEVAL_LIMIT = 500
_PROVENANCE_SCHEMA_VERSION = 3
_IDENTITY_SCHEMA_VERSION = 4
_FINGERPRINT_SCHEMA_VERSION = 5
# The product rename did not change the SQLite schema. Keep the original format
# magic so existing valid indexes remain recognizable when explicitly opened.
APPLICATION_ID = 0x4456504C  # "DVPL"
_SAFE_SLUG = re.compile(r"[^A-Za-z0-9._-]+")
_V2_REQUIRED_TABLES = frozenset(
    {"meta", "files", "symbols", "dependencies", "chunks", "chunks_fts"}
)
_V5_REQUIRED_TABLES = _V2_REQUIRED_TABLES | {"chunk_terms"}
_REQUIRED_TABLES = _V5_REQUIRED_TABLES | {
    "path_aliases",
    "resolved_dependencies",
    "resolved_dependency_candidates",
    "symbol_terms",
}
_EVIDENCE_TABLE_COLUMNS = {
    "path_aliases": (
        ("alias", "TEXT", 1, 1),
        ("path", "TEXT", 1, 2),
    ),
    "resolved_dependencies": (
        ("dependency_id", "INTEGER", 0, 1),
        ("source_path", "TEXT", 1, 0),
        ("target_path", "TEXT", 0, 0),
        ("target_symbol", "TEXT", 0, 0),
        ("resolution_kind", "TEXT", 1, 0),
        ("confidence", "REAL", 1, 0),
        ("witness_line", "INTEGER", 1, 0),
    ),
    "resolved_dependency_candidates": (
        ("dependency_id", "INTEGER", 1, 1),
        ("path", "TEXT", 1, 2),
    ),
    "symbol_terms": (
        ("term", "TEXT", 1, 1),
        ("symbol_id", "INTEGER", 1, 2),
        ("match_kind", "TEXT", 1, 3),
    ),
}
_EVIDENCE_TABLE_FOREIGN_KEYS = {
    "path_aliases": frozenset({("path", "files", "path", "CASCADE")}),
    "resolved_dependencies": frozenset(
        {
            ("dependency_id", "dependencies", "id", "CASCADE"),
            ("source_path", "files", "path", "CASCADE"),
            ("target_path", "files", "path", "CASCADE"),
        }
    ),
    "resolved_dependency_candidates": frozenset(
        {
            ("dependency_id", "resolved_dependencies", "dependency_id", "CASCADE"),
            ("path", "files", "path", "CASCADE"),
        }
    ),
    "symbol_terms": frozenset({("symbol_id", "symbols", "id", "CASCADE")}),
}
_EVIDENCE_TABLE_SQL_FRAGMENTS = {
    "path_aliases": ("withoutrowid",),
    "resolved_dependencies": (
        "check(resolution_kindin('exact','probable','ambiguous','unresolved'))",
        "check(confidence>=0.0andconfidence<=1.0)",
        "check(witness_line>=1)",
    ),
    "resolved_dependency_candidates": ("withoutrowid",),
    "symbol_terms": (
        "check(match_kindin('exact','casefold','term'))",
        "withoutrowid",
    ),
}
_EVIDENCE_INDEX_SPECS = {
    "path_aliases_path_idx": ("path_aliases", ("path",)),
    "resolved_dependencies_source_idx": ("resolved_dependencies", ("source_path",)),
    "resolved_dependencies_target_idx": ("resolved_dependencies", ("target_path",)),
    "resolved_dependency_candidates_path_idx": (
        "resolved_dependency_candidates",
        ("path",),
    ),
    "symbol_terms_symbol_idx": ("symbol_terms", ("symbol_id",)),
}
_EVIDENCE_SCHEMA_OBJECTS = frozenset({*_EVIDENCE_TABLE_COLUMNS, *_EVIDENCE_INDEX_SPECS})
_OPEN_LOCKS_GUARD = threading.Lock()
_OPEN_LOCKS: dict[str, threading.RLock] = {}
_MAX_SNAPSHOT_WARNINGS = 256
_SQLITE_IN_BATCH_SIZE = 500
_SEARCH_RRF_K = 60


class IndexFormatError(RuntimeError):
    """The cache exists but is not a compatible RepoLocus index."""


class IndexClosedError(RuntimeError):
    """An operation was attempted after an index was closed."""


class StaleScanError(RuntimeError):
    """A scan was based on an index generation that is no longer current."""


@dataclass(frozen=True, slots=True)
class IndexedChunkHit:
    """An internal chunk result with its fused lexical rank."""

    chunk_id: int
    chunk: Chunk
    rank: float


@dataclass(frozen=True, slots=True)
class SymbolChunkHit:
    """A chunk selected through the symbol table."""

    chunk_id: int
    chunk: Chunk
    symbol_name: str
    match: str


@dataclass(frozen=True, slots=True)
class NeighborChunkHit:
    """A representative chunk reached through a dependency edge."""

    chunk_id: int
    chunk: Chunk
    seed_path: str
    direction: str


def _validate_retrieval_limit(limit: object) -> int:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= MAX_RETRIEVAL_LIMIT
    ):
        raise ValueError(f"limit must be an integer between 1 and {MAX_RETRIEVAL_LIMIT}")
    return limit


def _canonical_root(root: Path) -> Path:
    candidate = Path(root).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ValueError(f"repository root does not exist: {candidate}") from exc
    if not resolved.is_dir():
        raise ValueError(f"repository root is not a directory: {resolved}")
    return resolved


def _repository_identity(root: Path) -> str:
    """Return a stable identity for the directory currently mounted at *root*."""

    try:
        metadata = root.lstat()
    except OSError as exc:
        raise IndexFormatError(f"repository root cannot be identified: {root}") from exc
    try:
        return filesystem_identity(metadata)
    except ValueError as exc:
        raise IndexFormatError(
            "the filesystem does not expose a stable repository identity"
        ) from exc


def _root_key(root: Path) -> str:
    canonical = os.path.normcase(str(root))
    return hashlib.sha256(canonical.encode("utf-8", errors="surrogatepass")).hexdigest()


def _open_lock(path: Path) -> threading.RLock:
    key = os.path.normcase(str(path))
    with _OPEN_LOCKS_GUARD:
        return _OPEN_LOCKS.setdefault(key, threading.RLock())


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def cache_root(cache_dir: Path | None = None) -> Path:
    """Return the index cache directory without creating it."""

    if cache_dir is not None:
        return Path(cache_dir).expanduser().resolve(strict=False)
    return (
        Path(user_cache_path("repolocus", appauthor=False, ensure_exists=False)) / "indexes"
    ).resolve(strict=False)


def index_path_for(root: Path, cache_dir: Path | None = None) -> Path:
    """Return the deterministic cache path for *root* without creating it."""

    canonical = _canonical_root(Path(root))
    base = cache_root(cache_dir)
    slug = _SAFE_SLUG.sub("-", canonical.name).strip("-.") or "repository"
    slug = slug[:48]
    database = base / f"{slug}-{_root_key(canonical)[:20]}.sqlite3"
    if _is_within(database, canonical):
        raise ValueError("the index cache must be outside the indexed repository")
    return database


def _query_tokens(
    query: str,
    synonyms: Mapping[str, Sequence[str]] | None = None,
    *,
    maximum: int = 64,
) -> tuple[str, ...]:
    # Lazy imports avoid index <-> retrieval package initialization cycles.
    from repolocus.retrieval.terms import query_terms

    return query_terms(query, synonyms, maximum=maximum)


def _literal_query_tokens(query: str) -> frozenset[str]:
    """Return user-written terms only, excluding configured synonyms."""

    from repolocus.retrieval.terms import literal_query_terms

    return frozenset(literal_query_terms(query))


def _literal_identifier_terms(query: str) -> frozenset[str]:
    """Return identifiers written as complete lexical units by the user."""

    normalized = unicodedata.normalize("NFKC", query)
    identifiers: set[str] = set()
    for match in re.finditer(r"[\w$]+(?:(?:::|\.)[\w$]+)*", normalized):
        identifier = match.group(0).casefold()
        identifiers.add(identifier)
        if "." in identifier or "::" in identifier:
            identifiers.update(part for part in re.split(r"::|\.", identifier) if part)
    return frozenset(identifiers)


def _literal_query_token_groups(query: str) -> tuple[tuple[str, ...], ...]:
    """Return literal groups that expanded terms may not satisfy."""

    from repolocus.retrieval.terms import literal_query_term_groups

    return literal_query_term_groups(query)


def _validate_relative_path(value: str) -> None:
    if not value or "\x00" in value or "\\" in value:
        raise ValueError(f"invalid indexed path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ValueError(
            f"indexed paths must be normalized repository-relative POSIX paths: {value!r}"
        )


def _validate_scanned_file(file: ScannedFile) -> None:
    _validate_relative_path(file.path)
    if file.size_bytes < 0 or file.line_count < 0:
        raise ValueError(f"negative file metadata for {file.path}")
    if file.mtime_ns < 0 or file.ctime_ns < 0:
        raise ValueError(f"negative file timestamp for {file.path}")
    if (
        file.cached_chunk_count < 0
        or file.cached_symbol_count < 0
        or file.cached_dependency_count < 0
    ):
        raise ValueError(f"negative cached fact count for {file.path}")
    if not isinstance(file.facts_materialized, bool):
        raise ValueError(f"invalid fact materialization marker for {file.path}")
    if file.provenance not in {"source", "generated"}:
        raise ValueError(f"invalid provenance for {file.path}")
    if file.stale:
        raise ValueError(f"fresh scan input cannot already be stale: {file.path}")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", file.sha256):
        raise ValueError(f"invalid SHA256 for {file.path}")
    for symbol in file.symbols:
        if symbol.path != file.path:
            raise ValueError(f"symbol path {symbol.path!r} does not match {file.path!r}")
        if (
            symbol.start_line < 1
            or symbol.end_line < symbol.start_line
            or symbol.end_line > file.line_count
        ):
            raise ValueError(f"invalid symbol line range in {file.path}")
    for dependency in file.dependencies:
        if dependency.source_path != file.path:
            raise ValueError(
                f"dependency source {dependency.source_path!r} does not match {file.path!r}"
            )
        if dependency.line < 1 or dependency.line > file.line_count:
            raise ValueError(f"invalid dependency line in {file.path}")
    for chunk in file.chunks:
        if chunk.path != file.path:
            raise ValueError(f"chunk path {chunk.path!r} does not match {file.path!r}")
        if (
            chunk.start_line < 1
            or chunk.end_line < chunk.start_line
            or chunk.end_line > file.line_count
        ):
            raise ValueError(f"invalid chunk line range in {file.path}")
        source_lines = file.text.splitlines(keepends=True)
        source_region = "".join(source_lines[chunk.start_line - 1 : chunk.end_line])
        if chunk.content not in source_region:
            raise ValueError(f"chunk content is not present in source range for {file.path}")


def _validate_scan_path(value: str) -> None:
    if value == ".":
        return
    _validate_relative_path(value)


def _covered_by_incomplete_path(path: str, prefixes: Sequence[str]) -> bool:
    return any(
        prefix == "." or path == prefix or path.startswith(prefix + "/") for prefix in prefixes
    )


def _snapshot_scan_metadata(
    scan: ScanResult,
) -> tuple[tuple[tuple[str, int], ...], tuple[str, ...]]:
    skipped: list[tuple[str, int]] = []
    for reason, count in sorted(scan.stats.skipped.items()):
        if (
            not isinstance(reason, str)
            or not reason
            or len(reason) > 128
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
        ):
            raise ValueError("scan skipped counters must use short names and non-negative integers")
        skipped.append((reason, count))
    warnings: list[str] = []
    for warning in scan.warnings[:_MAX_SNAPSHOT_WARNINGS]:
        if not isinstance(warning, str):
            raise ValueError("scan warnings must be strings")
        warnings.append(warning[:4096])
    omitted = len(scan.warnings) - len(warnings)
    if omitted > 0:
        warnings.append(f"{omitted} additional scan warning(s) omitted from snapshot metadata")
    return tuple(skipped), tuple(warnings)


def _decode_snapshot_state(
    metadata: Mapping[str, str],
) -> tuple[tuple[tuple[str, int], ...], tuple[str, ...], tuple[str, ...]]:
    try:
        skipped_value = json.loads(metadata.get("last_scan_skipped", "{}"))
        warnings_value = json.loads(metadata.get("last_scan_warnings", "[]"))
        incomplete_value = json.loads(metadata.get("last_scan_incomplete", "[]"))
    except json.JSONDecodeError as exc:
        raise IndexFormatError("index snapshot metadata contains invalid JSON") from exc
    if not isinstance(skipped_value, dict) or not isinstance(warnings_value, list):
        raise IndexFormatError("index snapshot metadata has invalid scan summaries")
    if not isinstance(incomplete_value, list):
        raise IndexFormatError("index snapshot metadata has invalid incomplete paths")
    skipped: list[tuple[str, int]] = []
    for reason, count in sorted(skipped_value.items()):
        if (
            not isinstance(reason, str)
            or not reason
            or len(reason) > 128
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
        ):
            raise IndexFormatError("index snapshot metadata has invalid skipped counters")
        skipped.append((reason, count))
    if len(warnings_value) > _MAX_SNAPSHOT_WARNINGS + 1 or any(
        not isinstance(warning, str) or len(warning) > 4096 for warning in warnings_value
    ):
        raise IndexFormatError("index snapshot metadata has invalid warnings")
    incomplete: list[str] = []
    for path in incomplete_value:
        if not isinstance(path, str):
            raise IndexFormatError("index snapshot metadata has invalid incomplete paths")
        try:
            _validate_scan_path(path)
        except ValueError as exc:
            raise IndexFormatError("index snapshot metadata has invalid incomplete paths") from exc
        incomplete.append(path)
    return tuple(skipped), tuple(warnings_value), tuple(incomplete)


def _metadata_fingerprints(metadata: Mapping[str, str]) -> AnalysisFingerprints | None:
    try:
        return AnalysisFingerprints.from_metadata(dict(metadata))
    except ValueError as exc:
        raise IndexFormatError("index component fingerprint metadata is invalid") from exc


def _effective_chunks(file: ScannedFile) -> tuple[Chunk, ...]:
    if file.chunks or not file.text:
        return file.chunks
    from repolocus.parsers.chunking import semantic_chunks

    return semantic_chunks(
        path=file.path,
        text=file.text,
        language=file.language,
        max_lines=160,
        max_chars=16_000,
    )


def _file_fact_digest(file: ScannedFile) -> str:
    """Hash retrieval-visible facts while excluding diagnostic file metadata."""

    chunks = _effective_chunks(file)
    payload = {
        "path": file.path,
        "language": file.language,
        "size_bytes": file.size_bytes,
        "sha256": file.sha256.casefold(),
        "line_count": file.line_count,
        "is_entry_point": file.is_entry_point,
        "provenance": file.provenance,
        "symbols": [
            [item.name, item.kind, item.start_line, item.end_line, item.signature]
            for item in file.symbols
        ],
        "dependencies": [[item.target, item.kind, item.line] for item in file.dependencies],
        "chunks": [
            [
                item.start_line,
                item.end_line,
                item.content,
                item.language,
                item.symbol,
            ]
            for item in chunks
        ],
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class RepositoryIndex:
    """A versioned SQLite/FTS5 index for exactly one canonical repository."""

    def __init__(self, root: Path, database_path: Path) -> None:
        self._root = root
        self._repository_identity = _repository_identity(root)
        self._database_path = database_path
        self._lock = threading.RLock()
        self._closed = False
        database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._harden_path(database_path.parent, 0o700)
        try:
            connection = sqlite3.connect(
                database_path,
                timeout=30.0,
                isolation_level=None,
                check_same_thread=False,
            )
        except sqlite3.Error as exc:
            raise IndexFormatError(f"could not open index {database_path}: {exc}") from exc
        connection.row_factory = sqlite3.Row
        self._connection = connection
        try:
            self._harden_path(database_path, 0o600)
            self._configure()
            self._initialize_or_validate()
        except Exception:
            connection.close()
            self._closed = True
            raise

    @staticmethod
    def _harden_path(path: Path, mode: int) -> None:
        """Restrict plaintext index access where POSIX mode bits are available."""

        if os.name == "nt":
            return
        try:
            path.chmod(mode)
        except OSError as exc:
            raise IndexFormatError(f"could not secure index path {path}: {exc}") from exc

    @classmethod
    def open(cls, root: Path, cache_dir: Path | None = None) -> RepositoryIndex:
        """Open (or create) the deterministic cache for *root*."""

        canonical = _canonical_root(Path(root))
        database_path = index_path_for(canonical, cache_dir)
        with _open_lock(database_path):
            return cls(canonical, database_path)

    @property
    def root(self) -> Path:
        return self._root

    @property
    def db_path(self) -> Path:
        return self._database_path

    @property
    def database_path(self) -> Path:
        return self._database_path

    def _ensure_open(self) -> None:
        if self._closed:
            raise IndexClosedError("repository index is closed")

    def _configure(self) -> None:
        try:
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 30000")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = NORMAL")
        except sqlite3.Error as exc:
            raise IndexFormatError(f"could not configure SQLite index: {exc}") from exc

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._connection.rollback()
            raise
        else:
            self._connection.commit()

    @contextmanager
    def _read_transaction(self) -> Iterator[None]:
        """Pin all reads in one cross-process-consistent SQLite snapshot."""

        self._connection.execute("BEGIN")
        try:
            yield
        except BaseException:
            self._connection.rollback()
            raise
        else:
            self._connection.commit()

    def _initialize_or_validate(self) -> None:
        try:
            application_id = int(self._connection.execute("PRAGMA application_id").fetchone()[0])
            version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
            tables = {
                str(row[0])
                for row in self._connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if version == 0:
                if tables:
                    raise IndexFormatError(
                        f"refusing to overwrite an unversioned database at {self._database_path}"
                    )
                self._create_schema()
            else:
                if application_id != APPLICATION_ID:
                    raise IndexFormatError(
                        f"database at {self._database_path} is not a RepoLocus index"
                    )
                if version == 2:
                    if not _V2_REQUIRED_TABLES.issubset(tables):
                        missing = ", ".join(sorted(_V2_REQUIRED_TABLES - tables))
                        raise IndexFormatError(f"index schema is incomplete; missing: {missing}")
                    self._migrate_v2_to_v3()
                    version = _PROVENANCE_SCHEMA_VERSION
                    tables.add("chunk_terms")
                if version == _PROVENANCE_SCHEMA_VERSION:
                    missing_tables = _V5_REQUIRED_TABLES - tables
                    if missing_tables and (
                        missing_tables != {"chunk_terms"}
                        or not self._is_recognized_legacy_v3_layout()
                    ):
                        missing = ", ".join(sorted(missing_tables))
                        raise IndexFormatError(f"index schema is incomplete; missing: {missing}")
                    self._migrate_v3_to_v4()
                    version = _IDENTITY_SCHEMA_VERSION
                    tables.add("chunk_terms")
                if version == _IDENTITY_SCHEMA_VERSION:
                    if not _V5_REQUIRED_TABLES.issubset(tables):
                        missing = ", ".join(sorted(_V5_REQUIRED_TABLES - tables))
                        raise IndexFormatError(f"index schema is incomplete; missing: {missing}")
                    self._migrate_v4_to_v5()
                    version = _FINGERPRINT_SCHEMA_VERSION
                if version == _FINGERPRINT_SCHEMA_VERSION:
                    if not _V5_REQUIRED_TABLES.issubset(tables):
                        missing = ", ".join(sorted(_V5_REQUIRED_TABLES - tables))
                        raise IndexFormatError(f"index schema is incomplete; missing: {missing}")
                    self._migrate_v5_to_v6()
                    version = SCHEMA_VERSION
                    tables.update(_REQUIRED_TABLES)
                elif version != SCHEMA_VERSION:
                    raise IndexFormatError(
                        f"unsupported index schema {version}; expected {SCHEMA_VERSION}"
                    )
                if not _REQUIRED_TABLES.issubset(tables):
                    missing = ", ".join(sorted(_REQUIRED_TABLES - tables))
                    raise IndexFormatError(f"index schema is incomplete; missing: {missing}")
            metadata = self.get_metadata()
            if metadata.get("repository_root") != str(self._root):
                raise IndexFormatError(
                    "index repository identity does not match the requested root"
                )
            if metadata.get("index_format_version") != INDEX_FORMAT_VERSION:
                raise IndexFormatError("index format version is incompatible")
            if metadata.get("repository_identity") != self._repository_identity:
                self._rebind_repository_identity(self._repository_identity)
        except sqlite3.Error as exc:
            raise IndexFormatError(f"invalid SQLite index at {self._database_path}: {exc}") from exc

    def _migrate_v2_to_v3(self) -> None:
        """Add provenance, freshness, and CAS state without discarding v2 facts."""

        try:
            with self._transaction():
                # Another process may have completed the migration while this
                # connection waited for BEGIN IMMEDIATE.
                current_version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
                if current_version in {
                    _PROVENANCE_SCHEMA_VERSION,
                    _IDENTITY_SCHEMA_VERSION,
                    _FINGERPRINT_SCHEMA_VERSION,
                    SCHEMA_VERSION,
                }:
                    return
                if current_version != 2:
                    raise IndexFormatError(
                        f"unsupported index schema {current_version}; expected 2"
                    )
                self._connection.execute(
                    "ALTER TABLE files ADD COLUMN provenance TEXT NOT NULL DEFAULT 'source' "
                    "CHECK (provenance IN ('source', 'generated'))"
                )
                self._connection.execute(
                    "ALTER TABLE files ADD COLUMN stale INTEGER NOT NULL DEFAULT 0 "
                    "CHECK (stale IN (0, 1))"
                )
                from repolocus.scanner.filters import is_generated_document

                generated_paths = [
                    str(row["path"])
                    for row in self._connection.execute("SELECT path, text FROM files")
                    if is_generated_document(str(row["text"]))
                ]
                self._connection.executemany(
                    "UPDATE files SET provenance = 'generated' WHERE path = ?",
                    ((path,) for path in generated_paths),
                )
                self._connection.execute(
                    "INSERT OR IGNORE INTO meta(key, value) VALUES ('generation', '0')"
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS chunk_terms (
                        term TEXT NOT NULL,
                        chunk_id INTEGER NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
                        PRIMARY KEY (term, chunk_id)
                    ) WITHOUT ROWID
                    """
                )
                self._connection.execute(
                    "CREATE INDEX IF NOT EXISTS chunk_terms_chunk_idx ON chunk_terms(chunk_id)"
                )
                self._rebuild_chunk_terms()
                self._connection.execute("DROP TRIGGER IF EXISTS chunks_after_insert")
                self._connection.execute("DROP TRIGGER IF EXISTS chunks_after_delete")
                self._connection.execute("DROP TRIGGER IF EXISTS chunks_after_update")
                self._connection.execute("DROP TABLE chunks_fts")
                self._connection.execute(
                    """
                    CREATE VIRTUAL TABLE chunks_fts USING fts5(
                        file_path,
                        symbol,
                        content,
                        content = 'chunks',
                        content_rowid = 'id',
                        tokenize = 'unicode61 remove_diacritics 2'
                    )
                    """
                )
                self._create_fts_triggers()
                self._connection.execute("INSERT INTO chunks_fts(chunks_fts) VALUES ('rebuild')")
                self._connection.executemany(
                    """
                    INSERT INTO meta(key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (
                        ("schema_version", str(_PROVENANCE_SCHEMA_VERSION)),
                        ("index_format_version", str(_PROVENANCE_SCHEMA_VERSION)),
                    ),
                )
                self._connection.execute(f"PRAGMA user_version = {_PROVENANCE_SCHEMA_VERSION}")
        except sqlite3.Error as exc:
            raise IndexFormatError(f"could not migrate v2 index: {exc}") from exc

    def _is_recognized_legacy_v3_layout(self) -> bool:
        """Recognize the pre-release v3 layout that retained the v2 search schema."""

        tables = {
            str(row[0])
            for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if not _V2_REQUIRED_TABLES.issubset(tables) or "chunk_terms" in tables:
            return False
        metadata = {
            str(row["key"]): str(row["value"])
            for row in self._connection.execute("SELECT key, value FROM meta")
        }
        if (
            metadata.get("schema_version") != str(_PROVENANCE_SCHEMA_VERSION)
            or metadata.get("index_format_version") != str(_PROVENANCE_SCHEMA_VERSION)
            or metadata.get("repository_root") != str(self._root)
        ):
            return False
        try:
            generation = int(metadata["generation"])
        except (KeyError, TypeError, ValueError):
            return False
        if generation < 0:
            return False
        file_columns = {
            str(row["name"]) for row in self._connection.execute("PRAGMA table_info(files)")
        }
        expected_file_columns = {
            "path",
            "language",
            "size_bytes",
            "sha256",
            "line_count",
            "text",
            "is_entry_point",
            "mtime_ns",
            "ctime_ns",
            "provenance",
            "stale",
        }
        if file_columns != expected_file_columns:
            return False
        fts_columns = tuple(
            str(row["name"]) for row in self._connection.execute("PRAGMA table_info(chunks_fts)")
        )
        if fts_columns != ("path", "symbol", "content"):
            return False
        trigger_names = {
            str(row[0])
            for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'chunks'"
            )
        }
        return {
            "chunks_after_insert",
            "chunks_after_delete",
            "chunks_after_update",
        }.issubset(trigger_names)

    def _replace_legacy_v3_search_layout(self) -> None:
        """Replace the recognized v2-style search schema after facts are invalidated."""

        self._connection.execute("DROP TRIGGER chunks_after_insert")
        self._connection.execute("DROP TRIGGER chunks_after_delete")
        self._connection.execute("DROP TRIGGER chunks_after_update")
        self._connection.execute("DROP TABLE chunks_fts")
        self._connection.execute(
            """
            CREATE TABLE chunk_terms (
                term TEXT NOT NULL,
                chunk_id INTEGER NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
                PRIMARY KEY (term, chunk_id)
            ) WITHOUT ROWID
            """
        )
        self._connection.execute("CREATE INDEX chunk_terms_chunk_idx ON chunk_terms(chunk_id)")
        self._connection.execute(
            """
            CREATE VIRTUAL TABLE chunks_fts USING fts5(
                file_path,
                symbol,
                content,
                content = 'chunks',
                content_rowid = 'id',
                tokenize = 'unicode61 remove_diacritics 2'
            )
            """
        )
        self._create_fts_triggers()
        self._connection.execute("INSERT INTO chunks_fts(chunks_fts) VALUES ('rebuild')")

    def _migrate_v3_to_v4(self) -> None:
        """Invalidate path-only facts before binding the index to this directory."""

        try:
            with self._transaction():
                current_version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
                if current_version in {
                    _IDENTITY_SCHEMA_VERSION,
                    _FINGERPRINT_SCHEMA_VERSION,
                    SCHEMA_VERSION,
                }:
                    return
                if current_version != _PROVENANCE_SCHEMA_VERSION:
                    raise IndexFormatError(
                        f"unsupported index schema {current_version}; "
                        f"expected {_PROVENANCE_SCHEMA_VERSION}"
                    )
                tables = {
                    str(row[0])
                    for row in self._connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                    )
                }
                legacy_search_layout = "chunk_terms" not in tables
                if legacy_search_layout and not self._is_recognized_legacy_v3_layout():
                    raise IndexFormatError("unrecognized legacy v3 index layout")
                generation = self._generation_in_transaction()
                self._clear_repository_facts()
                if legacy_search_layout:
                    self._replace_legacy_v3_search_layout()
                self._connection.executemany(
                    """
                    INSERT INTO meta(key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (
                        ("schema_version", str(_IDENTITY_SCHEMA_VERSION)),
                        ("index_format_version", str(_IDENTITY_SCHEMA_VERSION)),
                        ("analysis_version", ""),
                        ("generation", str(generation + 1)),
                        ("repository_identity", self._repository_identity),
                    ),
                )
                self._connection.execute(f"PRAGMA user_version = {_IDENTITY_SCHEMA_VERSION}")
        except sqlite3.Error as exc:
            raise IndexFormatError(f"could not migrate v3 index: {exc}") from exc

    def _migrate_v4_to_v5(self) -> None:
        """Add dual revisions, component fingerprints, and per-file fact digests."""

        try:
            with self._transaction():
                current_version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
                if current_version in {_FINGERPRINT_SCHEMA_VERSION, SCHEMA_VERSION}:
                    return
                if current_version != _IDENTITY_SCHEMA_VERSION:
                    raise IndexFormatError(
                        f"unsupported index schema {current_version}; "
                        f"expected {_IDENTITY_SCHEMA_VERSION}"
                    )
                generation = self._generation_in_transaction()
                columns = {
                    str(row["name"]) for row in self._connection.execute("PRAGMA table_info(files)")
                }
                if "facts_sha256" not in columns:
                    self._connection.execute(
                        "ALTER TABLE files ADD COLUMN facts_sha256 TEXT NOT NULL DEFAULT ''"
                    )
                for file in self.get_files():
                    self._connection.execute(
                        "UPDATE files SET facts_sha256 = ? WHERE path = ?",
                        (_file_fact_digest(file), file.path),
                    )
                self._connection.executemany(
                    """
                    INSERT INTO meta(key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (
                        ("schema_version", str(_FINGERPRINT_SCHEMA_VERSION)),
                        ("index_format_version", str(_FINGERPRINT_SCHEMA_VERSION)),
                        ("content_generation", str(generation)),
                        ("scan_revision", str(generation)),
                        ("generation", str(generation)),
                        ("scan_fingerprint", ""),
                        ("parser_fingerprint", ""),
                        ("term_index_fingerprint", ""),
                        ("retrieval_fingerprint", ""),
                    ),
                )
                self._connection.execute(f"PRAGMA user_version = {_FINGERPRINT_SCHEMA_VERSION}")
        except sqlite3.Error as exc:
            raise IndexFormatError(f"could not migrate v4 index: {exc}") from exc

    def _migrate_v5_to_v6(self) -> None:
        """Add normalized symbol terms and the persistent resolved graph."""

        try:
            with self._transaction():
                current_version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
                if current_version == SCHEMA_VERSION:
                    return
                if current_version != _FINGERPRINT_SCHEMA_VERSION:
                    raise IndexFormatError(
                        f"unsupported index schema {current_version}; "
                        f"expected {_FINGERPRINT_SCHEMA_VERSION}"
                    )
                existing_schema_objects = {
                    str(row[0])
                    for row in self._connection.execute(
                        "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
                    )
                }
                unexpected = sorted(_EVIDENCE_SCHEMA_OBJECTS & existing_schema_objects)
                if unexpected:
                    self._validate_existing_evidence_schema(existing_schema_objects)
                generation = self._generation_in_transaction()
                has_evidence_facts = bool(
                    self._connection.execute(
                        "SELECT EXISTS(SELECT 1 FROM symbols LIMIT 1) "
                        "OR EXISTS(SELECT 1 FROM dependencies LIMIT 1)"
                    ).fetchone()[0]
                )
                migrated_generation = generation + int(has_evidence_facts)
                for statement in self._evidence_index_schema():
                    self._connection.execute(statement)
                self._rebuild_symbol_terms()
                self._rebuild_resolved_graph()
                self._connection.executemany(
                    """
                    INSERT INTO meta(key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (
                        ("schema_version", str(SCHEMA_VERSION)),
                        ("index_format_version", INDEX_FORMAT_VERSION),
                        ("generation", str(migrated_generation)),
                        ("content_generation", str(migrated_generation)),
                        ("dependency_resolver_fingerprint", DEPENDENCY_RESOLVER_FINGERPRINT),
                    ),
                )
                self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        except sqlite3.Error as exc:
            raise IndexFormatError(f"could not migrate v5 index: {exc}") from exc

    def _generation_in_transaction(self) -> int:
        return self._revision_in_transaction("content_generation", fallback="generation")

    def _revision_in_transaction(self, key: str, *, fallback: str | None = None) -> int:
        row = self._connection.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        if row is None and fallback is not None:
            row = self._connection.execute(
                "SELECT value FROM meta WHERE key = ?", (fallback,)
            ).fetchone()
        try:
            revision = int(row["value"]) if row else 0
        except (TypeError, ValueError) as exc:
            raise IndexFormatError(f"index {key} metadata is invalid") from exc
        if revision < 0:
            raise IndexFormatError(f"index {key} metadata is invalid")
        return revision

    def _clear_repository_facts(self) -> None:
        self._connection.execute("DELETE FROM files")
        self._connection.execute(
            "DELETE FROM meta WHERE key LIKE 'last_scan_%' OR key LIKE 'last_update_%'"
        )

    def _rebind_repository_identity(self, identity: str) -> None:
        """Fail closed when the canonical path now names a different directory."""

        with self._lock, self._transaction():
            metadata = {
                str(row["key"]): str(row["value"])
                for row in self._connection.execute("SELECT key, value FROM meta")
            }
            if metadata.get("repository_identity") == identity:
                return
            generation = self._generation_in_transaction()
            scan_revision = self._revision_in_transaction("scan_revision")
            self._clear_repository_facts()
            self._connection.executemany(
                """
                INSERT INTO meta(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (
                    ("analysis_version", ""),
                    ("generation", str(generation + 1)),
                    ("content_generation", str(generation + 1)),
                    ("scan_revision", str(scan_revision + 1)),
                    ("scan_fingerprint", ""),
                    ("parser_fingerprint", ""),
                    ("term_index_fingerprint", ""),
                    ("retrieval_fingerprint", ""),
                    ("repository_identity", identity),
                ),
            )

    def _ensure_repository_identity(self) -> None:
        identity = _repository_identity(self._root)
        if identity != self._repository_identity:
            self._rebind_repository_identity(identity)
            self._repository_identity = identity

    def _create_fts_triggers(self) -> None:
        for statement in (
            """
            CREATE TRIGGER chunks_after_insert AFTER INSERT ON chunks BEGIN
                INSERT INTO chunks_fts(rowid, file_path, symbol, content)
                VALUES (new.id, new.file_path, new.symbol, new.content);
            END
            """,
            """
            CREATE TRIGGER chunks_after_delete AFTER DELETE ON chunks BEGIN
                INSERT INTO chunks_fts(chunks_fts, rowid, file_path, symbol, content)
                VALUES ('delete', old.id, old.file_path, old.symbol, old.content);
            END
            """,
            """
            CREATE TRIGGER chunks_after_update AFTER UPDATE ON chunks BEGIN
                INSERT INTO chunks_fts(chunks_fts, rowid, file_path, symbol, content)
                VALUES ('delete', old.id, old.file_path, old.symbol, old.content);
                INSERT INTO chunks_fts(rowid, file_path, symbol, content)
                VALUES (new.id, new.file_path, new.symbol, new.content);
            END
            """,
        ):
            self._connection.execute(statement)

    def _validate_existing_evidence_schema(self, existing_objects: set[str]) -> None:
        """Fail closed if a v5 cache contains a partial or malformed v6 schema."""

        missing = sorted(_EVIDENCE_SCHEMA_OBJECTS - existing_objects)
        if missing:
            raise IndexFormatError(
                "v5 index contains an incomplete v6 evidence schema; missing: " + ", ".join(missing)
            )

        for table, expected_columns in _EVIDENCE_TABLE_COLUMNS.items():
            columns = tuple(
                (
                    str(row["name"]),
                    str(row["type"]).upper(),
                    int(row["notnull"]),
                    int(row["pk"]),
                )
                for row in self._connection.execute(f"PRAGMA table_info({table})")  # nosec B608
            )
            if columns != expected_columns:
                raise IndexFormatError(
                    f"v5 index contains an incompatible v6 evidence table: {table}"
                )

            foreign_keys = frozenset(
                (
                    str(row["from"]),
                    str(row["table"]),
                    str(row["to"]),
                    str(row["on_delete"]).upper(),
                )
                for row in self._connection.execute(  # nosec B608
                    f"PRAGMA foreign_key_list({table})"
                )
            )
            if foreign_keys != _EVIDENCE_TABLE_FOREIGN_KEYS[table]:
                raise IndexFormatError(
                    f"v5 index contains incompatible v6 evidence foreign keys: {table}"
                )

            row = self._connection.execute(
                "SELECT type, sql FROM sqlite_master WHERE name = ?",
                (table,),
            ).fetchone()
            if row is None or str(row["type"]) != "table" or row["sql"] is None:
                raise IndexFormatError(
                    f"v5 index contains an incompatible v6 evidence object: {table}"
                )
            normalized_sql = re.sub(r"\s+", "", str(row["sql"]).casefold())
            if any(
                fragment not in normalized_sql for fragment in _EVIDENCE_TABLE_SQL_FRAGMENTS[table]
            ):
                raise IndexFormatError(
                    f"v5 index contains incompatible v6 evidence constraints: {table}"
                )

        for index_name, (table, expected_columns) in _EVIDENCE_INDEX_SPECS.items():
            indexes = {
                str(row["name"]): row
                for row in self._connection.execute(f"PRAGMA index_list({table})")  # nosec B608
            }
            index = indexes.get(index_name)
            if (
                index is None
                or int(index["unique"]) != 0
                or str(index["origin"]) != "c"
                or int(index["partial"]) != 0
            ):
                raise IndexFormatError(
                    f"v5 index contains an incompatible v6 evidence index: {index_name}"
                )
            columns = tuple(
                str(row["name"])
                for row in self._connection.execute(  # nosec B608
                    f"PRAGMA index_info({index_name})"
                )
            )
            if columns != expected_columns:
                raise IndexFormatError(
                    f"v5 index contains an incompatible v6 evidence index: {index_name}"
                )

    @staticmethod
    def _evidence_index_schema() -> tuple[str, ...]:
        return (
            """
            CREATE TABLE IF NOT EXISTS path_aliases (
                alias TEXT NOT NULL,
                path TEXT NOT NULL REFERENCES files(path) ON DELETE CASCADE,
                PRIMARY KEY (alias, path)
            ) WITHOUT ROWID
            """,
            "CREATE INDEX IF NOT EXISTS path_aliases_path_idx ON path_aliases(path)",
            """
            CREATE TABLE IF NOT EXISTS resolved_dependencies (
                dependency_id INTEGER PRIMARY KEY
                    REFERENCES dependencies(id) ON DELETE CASCADE,
                source_path TEXT NOT NULL REFERENCES files(path) ON DELETE CASCADE,
                target_path TEXT REFERENCES files(path) ON DELETE CASCADE,
                target_symbol TEXT,
                resolution_kind TEXT NOT NULL CHECK (
                    resolution_kind IN ('exact', 'probable', 'ambiguous', 'unresolved')
                ),
                confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
                witness_line INTEGER NOT NULL CHECK (witness_line >= 1)
            )
            """,
            "CREATE INDEX IF NOT EXISTS resolved_dependencies_source_idx "
            "ON resolved_dependencies(source_path)",
            "CREATE INDEX IF NOT EXISTS resolved_dependencies_target_idx "
            "ON resolved_dependencies(target_path)",
            """
            CREATE TABLE IF NOT EXISTS resolved_dependency_candidates (
                dependency_id INTEGER NOT NULL
                    REFERENCES resolved_dependencies(dependency_id) ON DELETE CASCADE,
                path TEXT NOT NULL REFERENCES files(path) ON DELETE CASCADE,
                PRIMARY KEY (dependency_id, path)
            ) WITHOUT ROWID
            """,
            "CREATE INDEX IF NOT EXISTS resolved_dependency_candidates_path_idx "
            "ON resolved_dependency_candidates(path)",
            """
            CREATE TABLE IF NOT EXISTS symbol_terms (
                term TEXT NOT NULL,
                symbol_id INTEGER NOT NULL REFERENCES symbols(id) ON DELETE CASCADE,
                match_kind TEXT NOT NULL CHECK (match_kind IN ('exact', 'casefold', 'term')),
                PRIMARY KEY (term, symbol_id, match_kind)
            ) WITHOUT ROWID
            """,
            "CREATE INDEX IF NOT EXISTS symbol_terms_symbol_idx ON symbol_terms(symbol_id)",
        )

    def _create_schema(self) -> None:
        statements = (
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) WITHOUT ROWID
            """,
            """
            CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY,
                language TEXT NOT NULL,
                size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
                sha256 TEXT NOT NULL,
                line_count INTEGER NOT NULL CHECK (line_count >= 0),
                text TEXT NOT NULL,
                is_entry_point INTEGER NOT NULL CHECK (is_entry_point IN (0, 1)),
                mtime_ns INTEGER NOT NULL CHECK (mtime_ns >= 0),
                ctime_ns INTEGER NOT NULL CHECK (ctime_ns >= 0),
                provenance TEXT NOT NULL CHECK (provenance IN ('source', 'generated')),
                stale INTEGER NOT NULL CHECK (stale IN (0, 1)),
                facts_sha256 TEXT NOT NULL
            ) WITHOUT ROWID
            """,
            """
            CREATE TABLE IF NOT EXISTS symbols (
                id INTEGER PRIMARY KEY,
                file_path TEXT NOT NULL REFERENCES files(path) ON DELETE CASCADE,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                start_line INTEGER NOT NULL CHECK (start_line >= 1),
                end_line INTEGER NOT NULL CHECK (end_line >= start_line),
                signature TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS dependencies (
                id INTEGER PRIMARY KEY,
                source_path TEXT NOT NULL REFERENCES files(path) ON DELETE CASCADE,
                target TEXT NOT NULL,
                kind TEXT NOT NULL,
                line INTEGER NOT NULL CHECK (line >= 1)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS chunks (
                id INTEGER PRIMARY KEY,
                file_path TEXT NOT NULL REFERENCES files(path) ON DELETE CASCADE,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                start_line INTEGER NOT NULL CHECK (start_line >= 1),
                end_line INTEGER NOT NULL CHECK (end_line >= start_line),
                content TEXT NOT NULL,
                language TEXT NOT NULL,
                symbol TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                UNIQUE (file_path, ordinal)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS chunk_terms (
                term TEXT NOT NULL,
                chunk_id INTEGER NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
                PRIMARY KEY (term, chunk_id)
            ) WITHOUT ROWID
            """,
            "CREATE INDEX IF NOT EXISTS chunk_terms_chunk_idx ON chunk_terms(chunk_id)",
            "CREATE INDEX IF NOT EXISTS symbols_file_idx ON symbols(file_path, start_line, name)",
            "CREATE INDEX IF NOT EXISTS symbols_name_idx ON symbols(name COLLATE NOCASE)",
            "CREATE INDEX IF NOT EXISTS dependencies_source_idx ON dependencies(source_path, line)",
            "CREATE INDEX IF NOT EXISTS dependencies_target_idx "
            "ON dependencies(target COLLATE NOCASE)",
            "CREATE INDEX IF NOT EXISTS chunks_file_idx ON chunks(file_path, start_line, ordinal)",
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
                file_path,
                symbol,
                content,
                content = 'chunks',
                content_rowid = 'id',
                tokenize = 'unicode61 remove_diacritics 2'
            )
            """,
            """
            CREATE TRIGGER IF NOT EXISTS chunks_after_insert AFTER INSERT ON chunks BEGIN
                INSERT INTO chunks_fts(rowid, file_path, symbol, content)
                VALUES (new.id, new.file_path, new.symbol, new.content);
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS chunks_after_delete AFTER DELETE ON chunks BEGIN
                INSERT INTO chunks_fts(chunks_fts, rowid, file_path, symbol, content)
                VALUES ('delete', old.id, old.file_path, old.symbol, old.content);
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS chunks_after_update AFTER UPDATE ON chunks BEGIN
                INSERT INTO chunks_fts(chunks_fts, rowid, file_path, symbol, content)
                VALUES ('delete', old.id, old.file_path, old.symbol, old.content);
                INSERT INTO chunks_fts(rowid, file_path, symbol, content)
                VALUES (new.id, new.file_path, new.symbol, new.content);
            END
            """,
            *self._evidence_index_schema(),
        )
        try:
            with self._transaction():
                for statement in statements:
                    self._connection.execute(statement)
                self._connection.executemany(
                    "INSERT OR IGNORE INTO meta(key, value) VALUES (?, ?)",
                    (
                        ("repository_root", str(self._root)),
                        ("root_hash", _root_key(self._root)),
                        ("schema_version", str(SCHEMA_VERSION)),
                        ("index_format_version", INDEX_FORMAT_VERSION),
                        ("analysis_version", ""),
                        ("generation", "0"),
                        ("content_generation", "0"),
                        ("scan_revision", "0"),
                        ("scan_fingerprint", ""),
                        ("parser_fingerprint", ""),
                        ("term_index_fingerprint", ""),
                        ("retrieval_fingerprint", ""),
                        ("dependency_resolver_fingerprint", DEPENDENCY_RESOLVER_FINGERPRINT),
                        ("repository_identity", self._repository_identity),
                    ),
                )
                self._connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        except sqlite3.Error as exc:
            raise IndexFormatError(
                "SQLite FTS5 support is required to create a RepoLocus index"
            ) from exc

    def auto_cache_hit(self, scan: ScanResult) -> IndexUpdate | None:
        """Return a no-write update when an ``auto`` scan is an exact cache hit."""

        self._ensure_open()
        self._ensure_repository_identity()
        scan_root = _canonical_root(scan.root)
        if scan_root != self._root:
            raise ValueError(f"scan root {scan_root} does not match index root {self._root}")
        scan_identity = scan.repository_identity or _repository_identity(scan_root)
        if scan_identity != self._repository_identity:
            raise StaleScanError("repository identity changed after the scan started")
        if scan.refresh_mode != "auto" or scan.stats.content_reads or scan.stats.parsed_files:
            return None
        incoming = {file.path: file for file in scan.files}
        if len(incoming) != len(scan.files):
            raise ValueError("duplicate scanned path")
        skipped_summary, warning_summary = _snapshot_scan_metadata(scan)
        incomplete_paths = tuple(sorted(set(scan.temporarily_unreadable)))
        with self._lock, self._read_transaction():
            metadata = self.get_metadata()
            if metadata.get("dependency_resolver_fingerprint") != DEPENDENCY_RESOLVER_FINGERPRINT:
                return None
            current_generation = self._read_revision(metadata, "content_generation", "generation")
            scan_revision = self._read_revision(metadata, "scan_revision")
            if (
                scan.base_generation is not None and scan.base_generation != current_generation
            ) or (scan.base_scan_revision is not None and scan.base_scan_revision != scan_revision):
                return None
            if scan.fingerprints is None or _metadata_fingerprints(metadata) != scan.fingerprints:
                return None
            current_rows = self._connection.execute(
                """
                SELECT path, language, size_bytes, sha256, line_count, is_entry_point,
                       mtime_ns, ctime_ns, provenance, stale
                FROM files ORDER BY path
                """
            ).fetchall()
            if len(current_rows) != len(incoming):
                return None
            for row in current_rows:
                file = incoming.get(str(row["path"]))
                if file is None or (
                    file.language != str(row["language"])
                    or file.size_bytes != int(row["size_bytes"])
                    or file.sha256.casefold() != str(row["sha256"]).casefold()
                    or file.line_count != int(row["line_count"])
                    or file.is_entry_point != bool(row["is_entry_point"])
                    or file.mtime_ns != int(row["mtime_ns"])
                    or file.ctime_ns != int(row["ctime_ns"])
                    or file.provenance != str(row["provenance"])
                    or file.stale != bool(row["stale"])
                ):
                    return None
            previous_skipped, previous_warnings, previous_incomplete = _decode_snapshot_state(
                metadata
            )
            if (
                skipped_summary != previous_skipped
                or warning_summary != previous_warnings
                or incomplete_paths != previous_incomplete
            ):
                return None
        if _repository_identity(self._root) != scan_identity:
            raise StaleScanError("repository identity changed while checking the scan cache")
        return IndexUpdate(
            added=0,
            changed=0,
            unchanged=len(incoming),
            removed=0,
            chunks=0,
            stale=sum(file.stale for file in incoming.values()),
            content_generation=current_generation,
            scan_revision=scan_revision,
        )

    @staticmethod
    def _read_revision(metadata: Mapping[str, str], key: str, fallback: str | None = None) -> int:
        raw = metadata.get(key, metadata.get(fallback, "0") if fallback is not None else "0")
        try:
            revision = int(raw)
        except (TypeError, ValueError) as exc:
            raise IndexFormatError(f"index {key} metadata is invalid") from exc
        if revision < 0:
            raise IndexFormatError(f"index {key} metadata is invalid")
        return revision

    def update(self, scan: ScanResult) -> IndexUpdate:
        """Atomically apply one completed scan and advance only changed fact state."""

        self._ensure_open()
        self._ensure_repository_identity()
        scan_root = _canonical_root(scan.root)
        if scan_root != self._root:
            raise ValueError(f"scan root {scan_root} does not match index root {self._root}")
        scan_identity = scan.repository_identity or _repository_identity(scan_root)
        if scan_identity != self._repository_identity:
            raise StaleScanError("repository identity changed after the scan started")
        incoming: dict[str, ScannedFile] = {}
        incoming_digests: dict[str, str] = {}
        incomplete_paths = tuple(sorted(set(scan.temporarily_unreadable)))
        skipped_summary, warning_summary = _snapshot_scan_metadata(scan)
        if not scan.analysis_version or len(scan.analysis_version) > 256:
            raise ValueError("scan analysis version must be a short non-empty string")
        for name, revision in (
            ("base generation", scan.base_generation),
            ("base scan revision", scan.base_scan_revision),
        ):
            if revision is not None and (
                isinstance(revision, bool) or not isinstance(revision, int) or revision < 0
            ):
                raise ValueError(f"scan {name} must be a non-negative integer or None")
        for path in incomplete_paths:
            _validate_scan_path(path)
        for file in scan.files:
            _validate_scanned_file(file)
            if file.path in incoming:
                raise ValueError(f"duplicate scanned path: {file.path}")
            incoming[file.path] = file
            if file.facts_materialized:
                incoming_digests[file.path] = _file_fact_digest(file)

        with self._lock, self._transaction():
            current_generation = self._revision_in_transaction(
                "content_generation", fallback="generation"
            )
            current_scan_revision = self._revision_in_transaction("scan_revision")
            if scan.base_generation is not None and scan.base_generation != current_generation:
                raise StaleScanError(
                    f"scan content generation {scan.base_generation} is stale; "
                    f"current content generation is {current_generation}"
                )
            if (
                scan.base_scan_revision is not None
                and scan.base_scan_revision != current_scan_revision
            ):
                raise StaleScanError(
                    f"scan revision {scan.base_scan_revision} is stale; "
                    f"current scan revision is {current_scan_revision}"
                )
            if _repository_identity(self._root) != scan_identity:
                raise StaleScanError("repository identity changed while committing the scan")
            metadata_before = {
                str(row["key"]): str(row["value"])
                for row in self._connection.execute("SELECT key, value FROM meta")
            }
            prior_fingerprints = _metadata_fingerprints(metadata_before)
            resolver_changed = (
                metadata_before.get("dependency_resolver_fingerprint")
                != DEPENDENCY_RESOLVER_FINGERPRINT
            )
            committed_fingerprints = (
                scan.fingerprints or prior_fingerprints or DEFAULT_ANALYSIS_FINGERPRINTS
            )
            current = {
                str(row["path"]): {
                    "sha256": str(row["sha256"]).casefold(),
                    "provenance": str(row["provenance"]),
                    "stale": bool(row["stale"]),
                    "facts_sha256": str(row["facts_sha256"]),
                }
                for row in self._connection.execute(
                    "SELECT path, sha256, provenance, stale, facts_sha256 FROM files"
                )
            }
            incoming_paths = set(incoming)
            current_paths = set(current)
            current_resolver_paths = {
                path
                for path, row in current.items()
                if row["provenance"] == "source" and not row["stale"]
            }
            incoming_resolver_paths = {
                path
                for path, file in incoming.items()
                if file.provenance == "source" and not file.stale
            }
            resolver_paths_changed = current_resolver_paths != incoming_resolver_paths
            added = sorted(incoming_paths - current_paths)
            if any(not incoming[path].facts_materialized for path in added):
                raise ValueError("new scanned files must include materialized parser facts")
            absent = current_paths - incoming_paths
            retained_stale = sorted(
                path for path in absent if _covered_by_incomplete_path(path, incomplete_paths)
            )
            removed = sorted(absent - set(retained_stale))
            changed: list[str] = []
            for path in sorted(incoming_paths & current_paths):
                file = incoming[path]
                row = current[path]
                if file.facts_materialized:
                    digest_changed = incoming_digests[path] != row["facts_sha256"]
                else:
                    digest_changed = (
                        file.sha256.casefold() != row["sha256"]
                        or file.provenance != row["provenance"]
                    )
                    if digest_changed:
                        raise ValueError(
                            f"changed scanned file {path!r} must include materialized parser facts"
                        )
                if digest_changed or row["stale"]:
                    changed.append(path)
            changed_set = set(changed)
            unchanged_paths = sorted((incoming_paths & current_paths) - changed_set)
            newly_stale = [path for path in retained_stale if not current[path]["stale"]]
            go_module_aliases_changed = any(
                PurePosixPath(path).name.casefold() == "go.mod"
                for path in {*added, *changed_set, *removed, *newly_stale}
            )
            term_changed = (
                prior_fingerprints is None
                or prior_fingerprints.term_index != committed_fingerprints.term_index
            )
            current_has_chunks = (
                self._connection.execute("SELECT 1 FROM chunks LIMIT 1").fetchone() is not None
            )
            incoming_has_chunks = any(
                bool(_effective_chunks(file))
                if file.facts_materialized
                else file.cached_chunk_count > 0
                for file in incoming.values()
            )
            term_fact_changed = term_changed and (current_has_chunks or incoming_has_chunks)
            current_has_dependencies = (
                self._connection.execute(
                    "SELECT 1 FROM dependencies AS d "
                    "JOIN files AS f ON f.path = d.source_path "
                    "WHERE f.provenance = 'source' AND f.stale = 0 LIMIT 1"
                ).fetchone()
                is not None
            )
            resolver_fact_changed = resolver_changed and current_has_dependencies
            fact_changed = bool(
                added
                or changed
                or removed
                or newly_stale
                or term_fact_changed
                or resolver_fact_changed
            )
            physical_replacements = sorted(
                set(added)
                | changed_set
                | (incoming_paths & current_paths if scan.refresh_mode == "rebuild" else set())
            )
            if any(not incoming[path].facts_materialized for path in physical_replacements):
                raise ValueError("rebuild scans must include materialized parser facts")
            existing_replacements = [
                path for path in physical_replacements if path in current_paths
            ]
            stored_dependency_facts: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
            for offset in range(0, len(existing_replacements), _SQLITE_IN_BATCH_SIZE):
                batch = existing_replacements[offset : offset + _SQLITE_IN_BATCH_SIZE]
                placeholders = ", ".join("?" for _ in batch)
                rows = self._connection.execute(
                    f"""
                    SELECT source_path, target, kind, line
                    FROM dependencies
                    WHERE source_path IN ({placeholders})
                    ORDER BY source_path, target, kind, line, id
                    """,  # nosec B608 -- only generated placeholders are interpolated
                    tuple(batch),
                ).fetchall()
                for row in rows:
                    stored_dependency_facts[str(row["source_path"])].append(
                        (str(row["target"]), str(row["kind"]), int(row["line"]))
                    )
            dependency_replacements = {
                path
                for path in existing_replacements
                if tuple(stored_dependency_facts[path])
                != tuple(
                    sorted(
                        (dependency.target, dependency.kind, dependency.line)
                        for dependency in incoming[path].dependencies
                    )
                )
            }
            inserted_chunks = 0
            for path in removed:
                self._connection.execute("DELETE FROM files WHERE path = ?", (path,))
            for path in physical_replacements:
                if path in current_paths:
                    inserted_chunks += self._replace_file(
                        incoming[path],
                        replace_dependencies=path in dependency_replacements,
                    )
                else:
                    inserted_chunks += self._insert_file(incoming[path])
            for path in unchanged_paths:
                if path in physical_replacements:
                    continue
                file = incoming[path]
                self._connection.execute(
                    "UPDATE files SET mtime_ns = ?, ctime_ns = ?, stale = 0 WHERE path = ?",
                    (file.mtime_ns, file.ctime_ns, path),
                )
            for path in retained_stale:
                self._connection.execute("UPDATE files SET stale = 1 WHERE path = ?", (path,))
            if term_changed:
                self._rebuild_chunk_terms()
                self._rebuild_symbol_terms()
            if resolver_paths_changed or resolver_changed or go_module_aliases_changed:
                self._rebuild_resolved_graph()
            else:
                replaced_dependency_sources = [
                    path
                    for path in dependency_replacements
                    if incoming[path].provenance == "source" and incoming[path].dependencies
                ]
                if replaced_dependency_sources:
                    self._resolve_replaced_dependencies(
                        sorted(replaced_dependency_sources),
                        incoming_resolver_paths,
                    )

            scan_digest = hashlib.sha256()
            for path in sorted(incoming):
                scan_digest.update(path.encode("utf-8", errors="surrogatepass"))
                scan_digest.update(b"\0")
                scan_digest.update(incoming[path].sha256.casefold().encode("ascii"))
                scan_digest.update(b"\0")
            committed_generation = current_generation + int(fact_changed)
            committed_scan_revision = current_scan_revision + 1
            metadata = {
                "last_scan_digest": scan_digest.hexdigest(),
                "last_scan_file_count": str(len(incoming)),
                "last_scan_indexed_bytes": str(sum(file.size_bytes for file in incoming.values())),
                "last_update_added": str(len(added)),
                "last_update_changed": str(len(changed)),
                "last_update_unchanged": str(len(unchanged_paths)),
                "last_update_removed": str(len(removed)),
                "last_update_stale": str(len(retained_stale)),
                "last_scan_skipped": json.dumps(
                    dict(skipped_summary), ensure_ascii=False, sort_keys=True
                ),
                "last_scan_warnings": json.dumps(warning_summary, ensure_ascii=False),
                "last_scan_incomplete": json.dumps(incomplete_paths, ensure_ascii=False),
                "analysis_version": scan.analysis_version,
                "generation": str(committed_generation),
                "content_generation": str(committed_generation),
                "scan_revision": str(committed_scan_revision),
                "dependency_resolver_fingerprint": DEPENDENCY_RESOLVER_FINGERPRINT,
                **committed_fingerprints.metadata(),
            }
            self._connection.executemany(
                """
                INSERT INTO meta(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                sorted(metadata.items()),
            )
            if _repository_identity(self._root) != scan_identity:
                raise StaleScanError("repository identity changed while committing the scan")

        return IndexUpdate(
            added=len(added),
            changed=len(changed),
            unchanged=len(unchanged_paths),
            removed=len(removed),
            chunks=inserted_chunks,
            stale=len(retained_stale),
            content_generation=committed_generation,
            scan_revision=committed_scan_revision,
        )

    def _insert_file(self, file: ScannedFile) -> int:
        self._connection.execute(
            """
            INSERT INTO files(
                path, language, size_bytes, sha256, line_count, text, is_entry_point,
                mtime_ns, ctime_ns, provenance, stale, facts_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file.path,
                file.language,
                file.size_bytes,
                file.sha256.casefold(),
                file.line_count,
                file.text,
                int(file.is_entry_point),
                file.mtime_ns,
                file.ctime_ns,
                file.provenance,
                int(file.stale),
                _file_fact_digest(file),
            ),
        )
        return self._insert_file_facts(file, insert_dependencies=True)

    def _replace_file(self, file: ScannedFile, *, replace_dependencies: bool) -> int:
        """Replace facts in place so graph edges targeting the stable path survive."""

        self._connection.execute(
            """
            UPDATE files
            SET language = ?, size_bytes = ?, sha256 = ?, line_count = ?, text = ?,
                is_entry_point = ?, mtime_ns = ?, ctime_ns = ?, provenance = ?,
                stale = ?, facts_sha256 = ?
            WHERE path = ?
            """,
            (
                file.language,
                file.size_bytes,
                file.sha256.casefold(),
                file.line_count,
                file.text,
                int(file.is_entry_point),
                file.mtime_ns,
                file.ctime_ns,
                file.provenance,
                int(file.stale),
                _file_fact_digest(file),
                file.path,
            ),
        )
        self._connection.execute("DELETE FROM symbols WHERE file_path = ?", (file.path,))
        if replace_dependencies:
            self._connection.execute("DELETE FROM dependencies WHERE source_path = ?", (file.path,))
        self._connection.execute("DELETE FROM chunks WHERE file_path = ?", (file.path,))
        return self._insert_file_facts(file, insert_dependencies=replace_dependencies)

    def _insert_file_facts(self, file: ScannedFile, *, insert_dependencies: bool) -> int:
        self._connection.executemany(
            """
            INSERT INTO symbols(file_path, name, kind, start_line, end_line, signature)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    file.path,
                    symbol.name,
                    symbol.kind,
                    symbol.start_line,
                    symbol.end_line,
                    symbol.signature,
                )
                for symbol in file.symbols
            ),
        )
        self._insert_symbol_terms_for_path(file.path)
        if insert_dependencies:
            self._connection.executemany(
                """
                INSERT INTO dependencies(source_path, target, kind, line)
                VALUES (?, ?, ?, ?)
                """,
                (
                    (file.path, dependency.target, dependency.kind, dependency.line)
                    for dependency in file.dependencies
                ),
            )
        chunks = _effective_chunks(file)
        self._connection.executemany(
            """
            INSERT INTO chunks(
                file_path, ordinal, start_line, end_line, content, language, symbol,
                content_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    file.path,
                    ordinal,
                    chunk.start_line,
                    chunk.end_line,
                    chunk.content,
                    chunk.language,
                    chunk.symbol,
                    hashlib.sha256(chunk.content.encode("utf-8")).hexdigest(),
                )
                for ordinal, chunk in enumerate(chunks)
            ),
        )
        chunk_rows = self._connection.execute(
            """
            SELECT id, file_path, symbol, content FROM chunks
            WHERE file_path = ? ORDER BY ordinal
            """,
            (file.path,),
        ).fetchall()
        self._insert_chunk_terms(chunk_rows)
        return len(chunks)

    def _insert_chunk_terms(self, chunk_rows: Sequence[sqlite3.Row]) -> None:
        from repolocus.retrieval.terms import document_terms

        for row in chunk_rows:
            terms = document_terms(
                str(row["file_path"]),
                str(row["symbol"]),
                str(row["content"]),
            )
            self._connection.executemany(
                "INSERT OR IGNORE INTO chunk_terms(term, chunk_id) VALUES (?, ?)",
                ((term, int(row["id"])) for term in terms),
            )

    def _rebuild_chunk_terms(self) -> None:
        self._connection.execute("DELETE FROM chunk_terms")
        rows = self._connection.execute(
            "SELECT id, file_path, symbol, content FROM chunks ORDER BY id"
        ).fetchall()
        self._insert_chunk_terms(rows)

    def _insert_symbol_terms_for_path(self, path: str) -> None:
        rows = self._connection.execute(
            "SELECT id, name FROM symbols WHERE file_path = ? ORDER BY id", (path,)
        ).fetchall()
        self._insert_symbol_terms(rows)

    def _insert_symbol_terms(self, rows: Sequence[sqlite3.Row]) -> None:
        from repolocus.retrieval.terms import document_terms

        for row in rows:
            name = str(row["name"])
            symbol_id = int(row["id"])
            normalized = name.casefold()
            values = {(name, "exact"), (normalized, "casefold")}
            values.update((term, "term") for term in document_terms(name, maximum=128))
            self._connection.executemany(
                "INSERT OR IGNORE INTO symbol_terms(term, symbol_id, match_kind) VALUES (?, ?, ?)",
                ((term, symbol_id, kind) for term, kind in sorted(values)),
            )

    def _rebuild_symbol_terms(self) -> None:
        self._connection.execute("DELETE FROM symbol_terms")
        rows = self._connection.execute("SELECT id, name FROM symbols ORDER BY id").fetchall()
        self._insert_symbol_terms(rows)

    def _rebuild_resolved_graph(self) -> None:
        from repolocus.graph import build_alias_index

        self._connection.execute("DELETE FROM resolved_dependency_candidates")
        self._connection.execute("DELETE FROM resolved_dependencies")
        self._connection.execute("DELETE FROM path_aliases")
        paths = [
            str(row["path"])
            for row in self._connection.execute(
                "SELECT path FROM files WHERE provenance = 'source' AND stale = 0 ORDER BY path"
            )
        ]
        aliases = build_alias_index(paths, go_modules=self._go_module_roots())
        self._connection.executemany(
            "INSERT INTO path_aliases(alias, path) VALUES (?, ?)",
            ((alias, path) for alias, candidates in aliases.items() for path in candidates),
        )
        dependency_rows = self._connection.execute(
            """
            SELECT d.id, d.source_path, d.target, d.kind, d.line
            FROM dependencies AS d
            JOIN files AS f ON f.path = d.source_path
            WHERE f.provenance = 'source' AND f.stale = 0
            ORDER BY d.source_path, d.line, d.target, d.kind, d.id
            """
        ).fetchall()
        self._insert_resolved_dependencies(dependency_rows, aliases)

    def _resolve_replaced_dependencies(
        self,
        source_paths: Sequence[str],
        resolver_paths: Sequence[str] | set[str],
    ) -> None:
        """Resolve newly inserted dependency rows without rewriting the complete graph."""

        if not source_paths:
            return
        from repolocus.graph import build_alias_index

        aliases = build_alias_index(resolver_paths, go_modules=self._go_module_roots())
        for offset in range(0, len(source_paths), _SQLITE_IN_BATCH_SIZE):
            batch = source_paths[offset : offset + _SQLITE_IN_BATCH_SIZE]
            placeholders = ", ".join("?" for _ in batch)
            dependency_rows = self._connection.execute(
                f"""
                SELECT d.id, d.source_path, d.target, d.kind, d.line
                FROM dependencies AS d
                JOIN files AS f ON f.path = d.source_path
                WHERE f.provenance = 'source' AND f.stale = 0
                  AND d.source_path IN ({placeholders})
                ORDER BY d.source_path, d.line, d.target, d.kind, d.id
                """,  # nosec B608 -- only generated placeholders are interpolated
                tuple(batch),
            ).fetchall()
            self._insert_resolved_dependencies(dependency_rows, aliases)

    def _go_module_roots(self) -> dict[str, str]:
        from repolocus.graph import go_module_roots

        rows = self._connection.execute(
            """
            SELECT path, text
            FROM files
            WHERE provenance = 'source' AND stale = 0
              AND (path = 'go.mod' OR path LIKE '%/go.mod')
            ORDER BY path
            """
        ).fetchall()
        return go_module_roots((str(row["path"]), str(row["text"])) for row in rows)

    def _insert_resolved_dependencies(
        self,
        dependency_rows: Sequence[sqlite3.Row],
        aliases: Mapping[str, tuple[str, ...]],
    ) -> None:
        from repolocus.graph import resolve_dependency

        confidence_scores = {
            "exact": 1.0,
            "probable": 0.7,
            "ambiguous": 0.25,
            "unresolved": 0.0,
        }
        for row in dependency_rows:
            dependency_id = int(row["id"])
            resolved = resolve_dependency(
                Dependency(
                    source_path=str(row["source_path"]),
                    target=str(row["target"]),
                    kind=str(row["kind"]),
                    line=int(row["line"]),
                ),
                aliases,
            )
            self._connection.execute(
                """
                INSERT INTO resolved_dependencies(
                    dependency_id, source_path, target_path, target_symbol,
                    resolution_kind, confidence, witness_line
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dependency_id,
                    resolved.source_path,
                    resolved.target_path,
                    resolved.target_symbol,
                    resolved.confidence,
                    confidence_scores[resolved.confidence],
                    resolved.line,
                ),
            )
            self._connection.executemany(
                "INSERT INTO resolved_dependency_candidates(dependency_id, path) VALUES (?, ?)",
                ((dependency_id, path) for path in resolved.candidates),
            )

    def get_metadata(self) -> dict[str, str]:
        self._ensure_open()
        with self._lock:
            return {
                str(row["key"]): str(row["value"])
                for row in self._connection.execute("SELECT key, value FROM meta ORDER BY key")
            }

    def generation(self) -> int:
        """Deprecated alias for :meth:`content_generation`."""

        return self.content_generation()

    def content_generation(self) -> int:
        """Return the retrieval-visible fact generation."""

        return self._read_revision(self.get_metadata(), "content_generation", "generation")

    def scan_revision(self) -> int:
        """Return the diagnostic completed-scan revision."""

        return self._read_revision(self.get_metadata(), "scan_revision")

    def fingerprints(self) -> AnalysisFingerprints | None:
        """Return committed component identities, if this index has been refreshed."""

        return _metadata_fingerprints(self.get_metadata())

    @contextmanager
    def consistent_read(self) -> Iterator[int]:
        """Hold one SQLite read snapshot and yield its content generation."""

        self._ensure_open()
        self._ensure_repository_identity()
        with self._lock:
            self._connection.execute("BEGIN")
            try:
                generation = self._revision_in_transaction(
                    "content_generation", fallback="generation"
                )
                yield generation
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def repository_view(self, *, expected_generation: int | None = None) -> SQLiteRepositoryView:
        """Return a projection-only view that must be used as a context manager."""

        from repolocus.index.view import SQLiteRepositoryView

        return SQLiteRepositoryView(self, expected_generation)

    def snapshot(self) -> IndexSnapshot:
        """Read full cache facts and their CAS generation from one SQLite snapshot."""

        return self._snapshot(manifest_only=False)

    def manifest_snapshot(self, *, max_files: int | None = None) -> IndexSnapshot:
        """Read only file metadata needed for an incremental scan.

        Text, symbols, dependencies, and chunks stay in SQLite for unchanged
        paths; changed files are read and reparsed by the scanner.
        """

        return self._snapshot(manifest_only=True, max_manifest_files=max_files)

    def _snapshot(
        self,
        *,
        manifest_only: bool,
        max_manifest_files: int | None = None,
    ) -> IndexSnapshot:
        """Read one generation-consistent full or metadata-only snapshot."""

        self._ensure_open()
        self._ensure_repository_identity()
        with self._lock:
            self._connection.execute("BEGIN")
            try:
                metadata = self.get_metadata()
                try:
                    generation = self._read_revision(metadata, "content_generation", "generation")
                    scan_revision = self._read_revision(metadata, "scan_revision")
                except ValueError as exc:
                    raise IndexFormatError("index revision metadata is invalid") from exc
                fingerprints = _metadata_fingerprints(metadata)
                skipped, warnings, incomplete = _decode_snapshot_state(metadata)
                files = tuple(
                    self.get_file_manifest(max_files=max_manifest_files)
                    if manifest_only
                    else self.get_files()
                )
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()
        return IndexSnapshot(
            content_generation=generation,
            scan_revision=scan_revision,
            fingerprints=fingerprints,
            files=files,
            skipped=skipped,
            warnings=warnings,
            temporarily_unreadable=incomplete,
            dependency_resolver_fingerprint=metadata.get("dependency_resolver_fingerprint"),
        )

    def stats(self) -> dict[str, int]:
        self._ensure_open()
        with self._lock:
            row = self._connection.execute(
                """
                SELECT
                    (SELECT count(*) FROM files) AS files,
                    (SELECT count(*) FROM symbols) AS symbols,
                    (SELECT count(*) FROM dependencies) AS dependencies,
                    (SELECT count(*) FROM chunks) AS chunks,
                    coalesce((SELECT sum(size_bytes) FROM files), 0) AS indexed_bytes
                """
            ).fetchone()
        keys = ("files", "symbols", "dependencies", "chunks", "indexed_bytes")
        return {key: int(row[key]) for key in keys}

    def get_stats(self) -> dict[str, int]:
        return self.stats()

    def get_symbols(self, path: str | None = None) -> list[Symbol]:
        self._ensure_open()
        query = "SELECT * FROM symbols"
        parameters: tuple[str, ...] = ()
        if path is not None:
            query += " WHERE file_path = ?"
            parameters = (path,)
        query += " ORDER BY file_path, start_line, end_line, name, kind, id"
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [
            Symbol(
                name=str(row["name"]),
                kind=str(row["kind"]),
                path=str(row["file_path"]),
                start_line=int(row["start_line"]),
                end_line=int(row["end_line"]),
                signature=str(row["signature"]),
            )
            for row in rows
        ]

    def list_symbols(self, path: str | None = None) -> list[Symbol]:
        return self.get_symbols(path)

    def get_dependencies(self, source_path: str | None = None) -> list[Dependency]:
        self._ensure_open()
        query = "SELECT * FROM dependencies"
        parameters: tuple[str, ...] = ()
        if source_path is not None:
            query += " WHERE source_path = ?"
            parameters = (source_path,)
        query += " ORDER BY source_path, line, target, kind, id"
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [
            Dependency(
                source_path=str(row["source_path"]),
                target=str(row["target"]),
                kind=str(row["kind"]),
                line=int(row["line"]),
            )
            for row in rows
        ]

    def list_dependencies(self, source_path: str | None = None) -> list[Dependency]:
        return self.get_dependencies(source_path)

    def get_chunks(self, path: str | None = None) -> list[Chunk]:
        self._ensure_open()
        rows = self._chunk_rows(path)
        return [self._row_to_chunk(row) for row in rows]

    def list_chunks(self, path: str | None = None) -> list[Chunk]:
        return self.get_chunks(path)

    def _chunk_rows(self, path: str | None = None) -> list[sqlite3.Row]:
        query = "SELECT * FROM chunks"
        parameters: tuple[str, ...] = ()
        if path is not None:
            query += " WHERE file_path = ?"
            parameters = (path,)
        query += " ORDER BY file_path, start_line, ordinal, id"
        with self._lock:
            return self._connection.execute(query, parameters).fetchall()

    @staticmethod
    def _row_to_chunk(row: sqlite3.Row) -> Chunk:
        return Chunk(
            path=str(row["file_path"]),
            start_line=int(row["start_line"]),
            end_line=int(row["end_line"]),
            content=str(row["content"]),
            language=str(row["language"]),
            symbol=str(row["symbol"]),
        )

    def get_file_manifest(self, *, max_files: int | None = None) -> list[ScannedFile]:
        """Return bounded per-file metadata without loading source text or parser facts."""

        self._ensure_open()
        if max_files is not None and (
            isinstance(max_files, bool) or not isinstance(max_files, int) or max_files <= 0
        ):
            raise ValueError("max_files must be a positive integer or None")
        query = """
            WITH chunk_counts AS (
                SELECT file_path, count(*) AS count FROM chunks GROUP BY file_path
            ),
            symbol_counts AS (
                SELECT file_path, count(*) AS count FROM symbols GROUP BY file_path
            ),
            dependency_counts AS (
                SELECT source_path, count(*) AS count
                FROM dependencies GROUP BY source_path
            )
            SELECT f.path, f.language, f.size_bytes, f.sha256, f.line_count,
                   f.is_entry_point, f.mtime_ns, f.ctime_ns, f.provenance, f.stale,
                   coalesce(c.count, 0) AS cached_chunk_count,
                   coalesce(s.count, 0) AS cached_symbol_count,
                   coalesce(d.count, 0) AS cached_dependency_count
            FROM files AS f
            LEFT JOIN chunk_counts AS c ON c.file_path = f.path
            LEFT JOIN symbol_counts AS s ON s.file_path = f.path
            LEFT JOIN dependency_counts AS d ON d.source_path = f.path
            ORDER BY f.path
        """
        parameters: tuple[int, ...] = ()
        if max_files is not None:
            query += " LIMIT ?"
            parameters = (max_files,)
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [
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
                provenance=str(row["provenance"]),  # type: ignore[arg-type]
                stale=bool(row["stale"]),
                cached_chunk_count=int(row["cached_chunk_count"]),
                cached_symbol_count=int(row["cached_symbol_count"]),
                cached_dependency_count=int(row["cached_dependency_count"]),
                facts_materialized=False,
            )
            for row in rows
        ]

    def get_files(self) -> list[ScannedFile]:
        self._ensure_open()
        with self._lock:
            file_rows = self._connection.execute("SELECT * FROM files ORDER BY path").fetchall()
            symbols = self.get_symbols()
            dependencies = self.get_dependencies()
            chunks = self.get_chunks()
        symbols_by_path: dict[str, list[Symbol]] = defaultdict(list)
        dependencies_by_path: dict[str, list[Dependency]] = defaultdict(list)
        chunks_by_path: dict[str, list[Chunk]] = defaultdict(list)
        for symbol in symbols:
            symbols_by_path[symbol.path].append(symbol)
        for dependency in dependencies:
            dependencies_by_path[dependency.source_path].append(dependency)
        for chunk in chunks:
            chunks_by_path[chunk.path].append(chunk)
        return [
            ScannedFile(
                path=str(row["path"]),
                language=str(row["language"]),
                size_bytes=int(row["size_bytes"]),
                sha256=str(row["sha256"]),
                line_count=int(row["line_count"]),
                text=str(row["text"]),
                symbols=tuple(symbols_by_path[str(row["path"])]),
                dependencies=tuple(dependencies_by_path[str(row["path"])]),
                chunks=tuple(chunks_by_path[str(row["path"])]),
                is_entry_point=bool(row["is_entry_point"]),
                mtime_ns=int(row["mtime_ns"]),
                ctime_ns=int(row["ctime_ns"]),
                provenance=str(row["provenance"]),  # type: ignore[arg-type]
                stale=bool(row["stale"]),
                cached_chunk_count=len(chunks_by_path[str(row["path"])]),
                cached_symbol_count=len(symbols_by_path[str(row["path"])]),
                cached_dependency_count=len(dependencies_by_path[str(row["path"])]),
                facts_materialized=True,
            )
            for row in file_rows
        ]

    def list_files(self) -> list[ScannedFile]:
        return self.get_files()

    def search_chunks(
        self,
        query: str,
        limit: int = 32,
        *,
        synonyms: Mapping[str, Sequence[str]] | None = None,
    ) -> list[IndexedChunkHit]:
        """Search FTS5 and normalized terms with a limit from 1 through 500."""

        self._ensure_open()
        limit = _validate_retrieval_limit(limit)
        tokens = _query_tokens(query, synonyms)
        if not tokens:
            return []
        stripped_query = query.strip()
        identifier_query = not any(character.isspace() for character in stripped_query) and (
            "_" in stripped_query or re.search(r"[a-z0-9][A-Z]", stripped_query) is not None
        )
        fts_tokens = tokens[:1] if identifier_query else tokens
        expression = " OR ".join(f'"{token}"' for token in fts_tokens)
        literal_groups = _literal_query_token_groups(query)
        from repolocus.retrieval.terms import is_cjk_term

        cjk_groups = [group for group in literal_groups if is_cjk_term(group[0])]
        non_cjk_literals = [group[0] for group in literal_groups if not is_cjk_term(group[0])]
        if identifier_query and non_cjk_literals:
            # A snake_case or camelCase lookup names one concrete identifier.
            # Requiring only two decomposed parts would let
            # ``old_unique_value`` match ``new_unique_value``.
            non_cjk_literals = non_cjk_literals[:1]
        coverage_clauses: list[str] = []
        coverage_parameters: list[str | int] = []
        if non_cjk_literals:
            placeholders = ", ".join("?" for _ in non_cjk_literals)
            coverage_clauses.append(
                "(SELECT count(*) FROM chunk_terms AS required_term "  # nosec B608
                "WHERE required_term.chunk_id = c.id "
                f"AND required_term.term IN ({placeholders})"
                ") >= ?"
            )
            coverage_parameters.extend(non_cjk_literals)
            coverage_parameters.append(min(2, len(non_cjk_literals)))
        for group in cjk_groups:
            placeholders = ", ".join("?" for _ in group)
            coverage_clauses.append(
                "(SELECT count(*) FROM chunk_terms AS required_term "  # nosec B608
                "WHERE required_term.chunk_id = c.id "
                f"AND required_term.term IN ({placeholders})"
                ") >= ?"
            )
            coverage_parameters.extend(group)
            coverage_parameters.append(min(2, len(group)))
        literal_coverage = " AND ".join(coverage_clauses) or "1 = 1"
        with self._lock:
            fts_query_template = """
                SELECT c.*, bm25(chunks_fts, 2.0, 5.0, 1.0) AS fts_rank
                FROM chunks_fts
                JOIN chunks AS c ON c.id = chunks_fts.rowid
                JOIN files AS f ON f.path = c.file_path
                WHERE chunks_fts MATCH ?
                  AND f.provenance = 'source'
                  AND f.stale = 0
                  AND %s
                ORDER BY fts_rank, c.file_path, c.start_line, c.ordinal
                LIMIT ?
                """
            # Only generated SQLite parameter markers are interpolated; every value stays bound.
            fts_query = fts_query_template % literal_coverage  # nosec B608
            fts_rows = self._connection.execute(
                fts_query,
                (expression, *coverage_parameters, limit),
            ).fetchall()
            placeholders = ", ".join("?" for _ in tokens)
            # Only generated SQLite parameter markers are interpolated; every value stays bound.
            term_query_template = """
                SELECT c.*, count(*) AS term_matches
                FROM chunk_terms AS t
                JOIN chunks AS c ON c.id = t.chunk_id
                JOIN files AS f ON f.path = c.file_path
                WHERE t.term IN (%s)
                  AND f.provenance = 'source'
                  AND f.stale = 0
                  AND %s
                GROUP BY c.id
                ORDER BY term_matches DESC, c.file_path, c.start_line, c.ordinal
                LIMIT ?
                """
            term_query = term_query_template % (placeholders, literal_coverage)  # nosec B608
            term_rows = self._connection.execute(
                term_query,
                (*tokens, *coverage_parameters, limit),
            ).fetchall()
        chunks: dict[int, Chunk] = {}
        fused_scores: defaultdict[int, float] = defaultdict(float)
        previous_fts_rank: float | None = None
        dense_rank = 0
        for position, row in enumerate(fts_rows, 1):
            fts_rank = float(row["fts_rank"])
            if previous_fts_rank is None or fts_rank != previous_fts_rank:
                dense_rank = position
                previous_fts_rank = fts_rank
            chunk_id = int(row["id"])
            chunks[chunk_id] = self._row_to_chunk(row)
            fused_scores[chunk_id] += 1.0 / (_SEARCH_RRF_K + dense_rank)

        previous_term_matches: int | None = None
        dense_rank = 0
        for position, row in enumerate(term_rows, 1):
            term_matches = int(row["term_matches"])
            if previous_term_matches is None or term_matches != previous_term_matches:
                dense_rank = position
                previous_term_matches = term_matches
            chunk_id = int(row["id"])
            if chunk_id not in chunks:
                chunks[chunk_id] = self._row_to_chunk(row)
            fused_scores[chunk_id] += 1.0 / (_SEARCH_RRF_K + dense_rank)

        ordered_ids = sorted(
            fused_scores,
            key=lambda chunk_id: (
                -fused_scores[chunk_id],
                chunks[chunk_id].path,
                chunks[chunk_id].start_line,
                chunk_id,
            ),
        )
        return [
            IndexedChunkHit(
                chunk_id=chunk_id,
                chunk=chunks[chunk_id],
                rank=-fused_scores[chunk_id],
            )
            for chunk_id in ordered_ids[:limit]
        ]

    def find_symbol_chunks(
        self,
        query: str,
        limit: int = 32,
        *,
        synonyms: Mapping[str, Sequence[str]] | None = None,
    ) -> list[SymbolChunkHit]:
        """Find symbol chunks with one query and a limit from 1 through 500."""

        self._ensure_open()
        limit = _validate_retrieval_limit(limit)
        tokens = _query_tokens(query, synonyms)
        if not tokens:
            return []
        full = unicodedata.normalize("NFKC", query.strip()).casefold()
        token_set = {token.casefold() for token in tokens}
        literal_tokens = _literal_query_tokens(query)
        expanded_tokens = token_set - literal_tokens
        exact_terms = _literal_identifier_terms(query)
        requested: dict[str, tuple[str, bool]] = {}
        if full:
            requested[full] = ("literal", full in exact_terms)
        for token in sorted(token_set):
            category = "expanded" if token in expanded_tokens else "literal"
            current = requested.get(token)
            if current is None or current[0] != "literal":
                requested[token] = (category, category == "literal" and token in exact_terms)
        request_rows = {
            (term, category, term if allow_exact else "")
            for term, (category, allow_exact) in requested.items()
        }
        alias_count = 0
        for exact_term in sorted(exact_terms):
            normalized_terms = _query_tokens(exact_term, maximum=1)
            if normalized_terms and normalized_terms[0] in token_set:
                request_rows.add((normalized_terms[0], "literal", exact_term))
                alias_count += 1
                if alias_count >= len(token_set):
                    break
        values = ", ".join("(?, ?, ?, ?, ?, ?)" for _ in request_rows)
        parameters: list[str | int] = []
        for term, category, exact_form in sorted(request_rows):
            parameters.extend(
                (
                    term,
                    category,
                    term + "\U0010ffff",
                    int(len(term) >= 4),
                    int(bool(exact_form)),
                    exact_form,
                )
            )
        sql = f"""
            WITH requested(
                term, category, upper_bound, allow_prefix, allow_exact, exact_form
            ) AS (
                VALUES {values}
            ),
            term_matches AS (
                SELECT s.id AS symbol_id, s.file_path, s.name, s.start_line,
                       CASE
                           WHEN r.category = 'literal' AND r.allow_exact = 1
                                AND (
                                    s.name = r.exact_form COLLATE NOCASE
                                    OR (
                                        substr(s.name, -length(r.exact_form))
                                            = r.exact_form COLLATE NOCASE
                                        AND (
                                            substr(
                                                s.name, -(length(r.exact_form) + 1), 1
                                            ) = '.'
                                            OR substr(
                                                s.name, -(length(r.exact_form) + 2), 2
                                            ) = '::'
                                        )
                                    )
                                ) THEN 0
                           WHEN r.category = 'expanded' THEN 1
                           ELSE 3
                       END AS priority
                FROM requested AS r
                JOIN symbol_terms AS st ON st.term = r.term
                JOIN symbols AS s ON s.id = st.symbol_id
                UNION ALL
                SELECT s.id AS symbol_id, s.file_path, s.name, s.start_line,
                       CASE WHEN r.category = 'expanded' THEN 2 ELSE 3 END AS priority
                FROM requested AS r
                JOIN symbol_terms AS st
                  ON st.match_kind = 'term'
                 AND st.term >= r.term
                 AND st.term < r.upper_bound
                 AND st.term != r.term
                JOIN symbols AS s ON s.id = st.symbol_id
                WHERE r.allow_prefix = 1
            ),
            matched_symbols AS (
                SELECT m.symbol_id, m.file_path, m.name, m.start_line,
                       min(m.priority) AS priority
                FROM term_matches AS m
                JOIN files AS f ON f.path = m.file_path
                WHERE f.provenance = 'source' AND f.stale = 0
                GROUP BY m.symbol_id
            ),
            symbol_chunks AS (
                SELECT c.*, m.name AS symbol_name, m.priority,
                       m.symbol_id
                FROM matched_symbols AS m
                JOIN chunks AS c ON c.id = coalesce(
                    (
                        SELECT exact.id
                        FROM chunks AS exact
                        WHERE exact.file_path = m.file_path
                          AND exact.symbol = m.name
                          AND exact.start_line = m.start_line
                        ORDER BY exact.ordinal, exact.id
                        LIMIT 1
                    ),
                    (
                        SELECT exact.id
                        FROM chunks AS exact
                        WHERE exact.file_path = m.file_path
                          AND exact.symbol = m.name
                          AND exact.start_line <= m.start_line
                          AND exact.end_line >= m.start_line
                        ORDER BY exact.start_line DESC, exact.ordinal, exact.id
                        LIMIT 1
                    ),
                    (
                        SELECT exact.id
                        FROM chunks AS exact
                        WHERE exact.file_path = m.file_path
                          AND exact.symbol = m.name
                        ORDER BY exact.start_line, exact.ordinal, exact.id
                        LIMIT 1
                    ),
                    (
                        SELECT containing.id
                        FROM chunks AS containing
                        WHERE containing.file_path = m.file_path
                          AND containing.start_line <= m.start_line
                          AND containing.end_line >= m.start_line
                        ORDER BY containing.start_line, containing.ordinal, containing.id
                        LIMIT 1
                    ),
                    (
                        SELECT first.id
                        FROM chunks AS first
                        WHERE first.file_path = m.file_path
                        ORDER BY first.start_line, first.ordinal, first.id
                        LIMIT 1
                    )
                )
            ),
            distinct_chunks AS (
                SELECT sc.*,
                       row_number() OVER (
                           PARTITION BY sc.id
                           ORDER BY sc.priority, sc.symbol_name COLLATE NOCASE,
                                    sc.file_path, sc.start_line
                       ) AS chunk_rank
                FROM symbol_chunks AS sc
            )
            SELECT * FROM distinct_chunks
            WHERE chunk_rank = 1
            ORDER BY priority, symbol_name COLLATE NOCASE, file_path, start_line, id
            LIMIT ?
        """  # nosec B608 -- only generated VALUES placeholders are interpolated
        parameters.append(limit)
        with self._lock:
            rows = self._connection.execute(sql, tuple(parameters)).fetchall()
        return [
            SymbolChunkHit(
                chunk_id=int(row["id"]),
                chunk=self._row_to_chunk(row),
                symbol_name=str(row["symbol_name"]),
                match=(
                    "exact"
                    if int(row["priority"]) == 0
                    else "expanded"
                    if int(row["priority"]) in {1, 2}
                    else "partial"
                ),
            )
            for row in rows
        ]

    def get_resolved_dependencies(self, source_path: str | None = None) -> list[ResolvedDependency]:
        """Return the persisted dependency projection without resolving at query time."""

        self._ensure_open()
        where = ""
        parameters: tuple[str, ...] = ()
        if source_path is not None:
            where = "WHERE rd.source_path = ?"
            parameters = (source_path,)
        with self._lock:
            self._ensure_resolved_graph_current()
            rows = self._connection.execute(
                f"""
                SELECT rd.dependency_id, rd.source_path, d.target, rd.target_path,
                       rd.target_symbol, d.kind, rd.witness_line, rd.resolution_kind,
                       candidate.path AS candidate_path
                FROM resolved_dependencies AS rd
                JOIN dependencies AS d ON d.id = rd.dependency_id
                LEFT JOIN resolved_dependency_candidates AS candidate
                  ON candidate.dependency_id = rd.dependency_id
                {where}
                ORDER BY rd.source_path, rd.witness_line, d.target, d.kind,
                         rd.dependency_id, candidate.path
                """,  # nosec B608 -- the only optional fragment is a constant predicate
                parameters,
            ).fetchall()
        dependencies: dict[int, tuple[sqlite3.Row, list[str]]] = {}
        for row in rows:
            dependency_id = int(row["dependency_id"])
            stored = dependencies.setdefault(dependency_id, (row, []))
            if row["candidate_path"] is not None:
                stored[1].append(str(row["candidate_path"]))
        return [
            ResolvedDependency(
                source_path=str(row["source_path"]),
                raw_target=str(row["target"]),
                target_path=str(row["target_path"]) if row["target_path"] is not None else None,
                target_symbol=(
                    str(row["target_symbol"]) if row["target_symbol"] is not None else None
                ),
                kind=str(row["kind"]),
                line=int(row["witness_line"]),
                confidence=str(row["resolution_kind"]),  # type: ignore[arg-type]
                candidates=tuple(candidates),
            )
            for row, candidates in dependencies.values()
        ]

    def dependency_neighbors(
        self,
        seed_paths: Sequence[str],
        limit: int = 32,
        *,
        direction: str | None = None,
    ) -> list[NeighborChunkHit]:
        """Query direct resolved neighbors through indexed SQLite projections.

        Filtering by *direction* happens before the shared result ``limit`` is
        applied, so one direction cannot crowd out an explicitly requested one.
        Both the result limit and the number of seed entries are bounded at 500.
        """

        self._ensure_open()
        limit = _validate_retrieval_limit(limit)
        if direction not in {None, "dependency of", "dependent of"}:
            raise ValueError("dependency direction is invalid")
        if len(seed_paths) > _SQLITE_IN_BATCH_SIZE:
            raise ValueError(f"seed_paths must contain at most {_SQLITE_IN_BATCH_SIZE} entries")
        seeds = tuple(sorted(set(seed_paths)))
        if not seeds:
            return []
        values = ", ".join("(?)" for _ in seeds)
        sql = f"""
            WITH seeds(path) AS (VALUES {values}),
            neighbors(path, seed_path, direction, target_symbol, witness_line) AS (
                SELECT rd.target_path, rd.source_path, 'dependency of',
                       rd.target_symbol, NULL
                FROM resolved_dependencies AS rd
                JOIN seeds AS s ON s.path = rd.source_path
                WHERE rd.target_path IS NOT NULL
                  AND rd.target_path != rd.source_path
                  AND (? IS NULL OR ? = 'dependency of')
                UNION ALL
                SELECT rd.source_path, rd.target_path, 'dependent of',
                       NULL, rd.witness_line
                FROM resolved_dependencies AS rd
                JOIN seeds AS s ON s.path = rd.target_path
                WHERE rd.target_path IS NOT NULL
                  AND rd.source_path != rd.target_path
                  AND (? IS NULL OR ? = 'dependent of')
            ),
            selected_neighbors AS (
                SELECT path, seed_path, direction,
                       min(target_symbol) AS target_symbol,
                       min(witness_line) AS witness_line
                FROM neighbors
                GROUP BY path, seed_path, direction
            ),
            ranked_chunks AS (
                SELECT c.*, n.seed_path, n.direction,
                       row_number() OVER (
                           PARTITION BY n.path, n.seed_path, n.direction
                           ORDER BY
                               CASE
                                   WHEN n.direction = 'dependency of'
                                        AND n.target_symbol IS NOT NULL
                                        AND c.symbol = n.target_symbol THEN 0
                                   WHEN n.direction = 'dependent of'
                                        AND n.witness_line BETWEEN c.start_line AND c.end_line
                                       THEN 0
                                   ELSE 1
                               END,
                               CASE
                                   WHEN n.direction = 'dependent of'
                                        AND n.witness_line < c.start_line
                                       THEN c.start_line - n.witness_line
                                   WHEN n.direction = 'dependent of'
                                        AND n.witness_line > c.end_line
                                       THEN n.witness_line - c.end_line
                                   ELSE 0
                               END,
                               c.start_line, c.ordinal, c.id
                       ) AS chunk_rank
                FROM selected_neighbors AS n
                JOIN chunks AS c ON c.file_path = n.path
                JOIN files AS f ON f.path = c.file_path
                WHERE f.provenance = 'source' AND f.stale = 0
            ),
            limited_neighbors AS (
                SELECT rc.*,
                       row_number() OVER (
                           ORDER BY rc.direction, rc.file_path, rc.seed_path, rc.start_line,
                                    rc.ordinal, rc.id
                       ) AS direction_rank
                FROM ranked_chunks AS rc
                WHERE rc.chunk_rank = 1
            )
            SELECT * FROM limited_neighbors
            WHERE direction_rank <= ?
            ORDER BY direction, file_path, seed_path, start_line, id
        """  # nosec B608 -- only generated VALUES placeholders are interpolated
        with self._lock:
            self._ensure_resolved_graph_current()
            rows = self._connection.execute(
                sql,
                (
                    *seeds,
                    direction,
                    direction,
                    direction,
                    direction,
                    limit,
                ),
            ).fetchall()
        return [
            NeighborChunkHit(
                chunk_id=int(row["id"]),
                chunk=self._row_to_chunk(row),
                seed_path=str(row["seed_path"]),
                direction=str(row["direction"]),
            )
            for row in rows
        ]

    def _ensure_resolved_graph_current(self) -> None:
        row = self._connection.execute(
            "SELECT value FROM meta WHERE key = 'dependency_resolver_fingerprint'"
        ).fetchone()
        fingerprint = str(row["value"]) if row is not None else None
        if fingerprint != DEPENDENCY_RESOLVER_FINGERPRINT:
            raise IndexFormatError(
                "resolved dependency graph is stale; refresh the repository index"
            )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._connection.close()
            self._closed = True

    def __enter__(self) -> RepositoryIndex:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
