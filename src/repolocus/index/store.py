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
from collections import defaultdict
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from platformdirs import user_cache_path

from repolocus.analysis import DEFAULT_ANALYSIS_FINGERPRINTS, AnalysisFingerprints
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

SCHEMA_VERSION = 5
INDEX_FORMAT_VERSION = "5"
_PROVENANCE_SCHEMA_VERSION = 3
_IDENTITY_SCHEMA_VERSION = 4
# The product rename did not change the SQLite schema. Keep the original format
# magic so existing valid indexes remain recognizable when explicitly opened.
APPLICATION_ID = 0x4456504C  # "DVPL"
_SAFE_SLUG = re.compile(r"[^A-Za-z0-9._-]+")
_V2_REQUIRED_TABLES = frozenset(
    {"meta", "files", "symbols", "dependencies", "chunks", "chunks_fts"}
)
_REQUIRED_TABLES = _V2_REQUIRED_TABLES | {"chunk_terms"}
_OPEN_LOCKS_GUARD = threading.Lock()
_OPEN_LOCKS: dict[str, threading.RLock] = {}
_MAX_SNAPSHOT_WARNINGS = 256


class IndexFormatError(RuntimeError):
    """The cache exists but is not a compatible RepoLocus index."""


class IndexClosedError(RuntimeError):
    """An operation was attempted after an index was closed."""


class StaleScanError(RuntimeError):
    """A scan was based on an index generation that is no longer current."""


@dataclass(frozen=True, slots=True)
class IndexedChunkHit:
    """An internal chunk result with its SQLite FTS rank."""

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
                    missing_tables = _REQUIRED_TABLES - tables
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
                    if not _REQUIRED_TABLES.issubset(tables):
                        missing = ", ".join(sorted(_REQUIRED_TABLES - tables))
                        raise IndexFormatError(f"index schema is incomplete; missing: {missing}")
                    self._migrate_v4_to_v5()
                    version = SCHEMA_VERSION
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
                if current_version in {_IDENTITY_SCHEMA_VERSION, SCHEMA_VERSION}:
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
                if current_version == SCHEMA_VERSION:
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
                        ("schema_version", str(SCHEMA_VERSION)),
                        ("index_format_version", INDEX_FORMAT_VERSION),
                        ("content_generation", str(generation)),
                        ("scan_revision", str(generation)),
                        ("generation", str(generation)),
                        ("scan_fingerprint", ""),
                        ("parser_fingerprint", ""),
                        ("term_index_fingerprint", ""),
                        ("retrieval_fingerprint", ""),
                    ),
                )
                self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        except sqlite3.Error as exc:
            raise IndexFormatError(f"could not migrate v4 index: {exc}") from exc

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
            fact_changed = bool(added or changed or removed or newly_stale or term_fact_changed)
            physical_replacements = sorted(
                set(added)
                | changed_set
                | (incoming_paths & current_paths if scan.refresh_mode == "rebuild" else set())
            )
            if any(not incoming[path].facts_materialized for path in physical_replacements):
                raise ValueError("rebuild scans must include materialized parser facts")
            inserted_chunks = 0
            for path in removed + [path for path in physical_replacements if path in current_paths]:
                self._connection.execute("DELETE FROM files WHERE path = ?", (path,))
            for path in physical_replacements:
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
            generation,
            scan_revision,
            fingerprints,
            files,
            skipped,
            warnings,
            incomplete,
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
            SELECT f.path, f.language, f.size_bytes, f.sha256, f.line_count,
                   f.is_entry_point, f.mtime_ns, f.ctime_ns, f.provenance, f.stale,
                   (SELECT count(*) FROM chunks AS c WHERE c.file_path = f.path)
                       AS cached_chunk_count,
                   (SELECT count(*) FROM symbols AS s WHERE s.file_path = f.path)
                       AS cached_symbol_count,
                   (SELECT count(*) FROM dependencies AS d WHERE d.source_path = f.path)
                       AS cached_dependency_count
            FROM files AS f
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
        """Search FTS5 plus normalized CJK and source-identifier terms."""

        self._ensure_open()
        if limit <= 0:
            return []
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
                (expression, *coverage_parameters, min(int(limit), 500)),
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
                (*tokens, *coverage_parameters, min(int(limit), 500)),
            ).fetchall()
        hits: dict[int, IndexedChunkHit] = {}
        for row in fts_rows:
            hit = IndexedChunkHit(
                chunk_id=int(row["id"]),
                chunk=self._row_to_chunk(row),
                rank=float(row["fts_rank"]),
            )
            hits[hit.chunk_id] = hit
        for row in term_rows:
            chunk_id = int(row["id"])
            term_rank = -float(row["term_matches"])
            current = hits.get(chunk_id)
            if current is None:
                hits[chunk_id] = IndexedChunkHit(
                    chunk_id=chunk_id,
                    chunk=self._row_to_chunk(row),
                    rank=term_rank,
                )
            else:
                hits[chunk_id] = IndexedChunkHit(
                    chunk_id=chunk_id,
                    chunk=current.chunk,
                    rank=min(current.rank, term_rank),
                )
        return sorted(
            hits.values(),
            key=lambda hit: (hit.rank, hit.chunk.path, hit.chunk.start_line, hit.chunk_id),
        )[: min(int(limit), 500)]

    def find_symbol_chunks(
        self,
        query: str,
        limit: int = 32,
        *,
        synonyms: Mapping[str, Sequence[str]] | None = None,
    ) -> list[SymbolChunkHit]:
        """Find chunks for exact or partial symbol-name matches."""

        self._ensure_open()
        if limit <= 0:
            return []
        tokens = _query_tokens(query, synonyms)
        if not tokens:
            return []
        full = query.strip().casefold()
        token_set = {token.casefold() for token in tokens}
        literal_tokens = _literal_query_tokens(query)
        expanded_tokens = token_set - literal_tokens
        partial_tokens = {token for token in token_set if len(token) >= 4}
        expanded_partial_tokens = {token for token in expanded_tokens if len(token) >= 4}
        with self._lock:
            symbol_rows = self._connection.execute(
                """
                SELECT s.* FROM symbols AS s
                JOIN files AS f ON f.path = s.file_path
                WHERE f.provenance = 'source' AND f.stale = 0
                ORDER BY s.file_path, s.start_line, s.name, s.id
                """
            ).fetchall()
            matches: list[tuple[int, str, sqlite3.Row]] = []
            for row in symbol_rows:
                name = str(row["name"])
                folded = name.casefold()
                if folded == full or folded in literal_tokens:
                    matches.append((0, "exact", row))
                elif folded in expanded_tokens:
                    matches.append((1, "expanded", row))
                elif any(token in folded for token in expanded_partial_tokens):
                    matches.append((2, "expanded", row))
                elif (full and full in folded) or any(token in folded for token in partial_tokens):
                    matches.append((3, "partial", row))
            matches.sort(
                key=lambda item: (
                    item[0],
                    str(item[2]["name"]).casefold(),
                    str(item[2]["file_path"]),
                    int(item[2]["start_line"]),
                )
            )
            results: list[SymbolChunkHit] = []
            seen: set[int] = set()
            for _, match_type, symbol_row in matches:
                chunk_row = self._connection.execute(
                    """
                    SELECT * FROM chunks
                    WHERE file_path = ?
                      AND (symbol = ? OR (start_line <= ? AND end_line >= ?))
                    ORDER BY CASE WHEN symbol = ? THEN 0 ELSE 1 END,
                             start_line, ordinal, id
                    LIMIT 1
                    """,
                    (
                        symbol_row["file_path"],
                        symbol_row["name"],
                        symbol_row["start_line"],
                        symbol_row["start_line"],
                        symbol_row["name"],
                    ),
                ).fetchone()
                if chunk_row is None:
                    chunk_row = self._connection.execute(
                        """
                        SELECT * FROM chunks WHERE file_path = ?
                        ORDER BY start_line, ordinal, id LIMIT 1
                        """,
                        (symbol_row["file_path"],),
                    ).fetchone()
                if chunk_row is None or int(chunk_row["id"]) in seen:
                    continue
                chunk_id = int(chunk_row["id"])
                seen.add(chunk_id)
                results.append(
                    SymbolChunkHit(
                        chunk_id=chunk_id,
                        chunk=self._row_to_chunk(chunk_row),
                        symbol_name=str(symbol_row["name"]),
                        match=match_type,
                    )
                )
                if len(results) >= min(int(limit), 500):
                    break
        return results

    @staticmethod
    def _path_aliases(path: str) -> set[str]:
        lowered = path.casefold()
        aliases = {lowered, PurePosixPath(lowered).name}
        suffix = PurePosixPath(lowered).suffix
        without_suffix = lowered[: -len(suffix)] if suffix else lowered
        aliases.add(without_suffix)
        aliases.add(PurePosixPath(without_suffix).name)
        dotted = without_suffix.replace("/", ".")
        parts = dotted.split(".")
        aliases.update(".".join(parts[offset:]) for offset in range(len(parts)))
        if parts and parts[-1] == "__init__":
            package_parts = parts[:-1]
            aliases.update(".".join(package_parts[offset:]) for offset in range(len(package_parts)))
        return {alias for alias in aliases if alias}

    @classmethod
    def _resolve_dependency_target(
        cls,
        source_path: str,
        target: str,
        aliases: dict[str, set[str]],
        known_paths: dict[str, str],
    ) -> set[str]:
        cleaned = target.strip().strip("'\"").casefold().replace("\\", "/")
        if not cleaned:
            return set()
        candidates = {cleaned, cleaned.replace("/", ".")}
        if cleaned.startswith("./") or cleaned.startswith("../"):
            joined = PurePosixPath(source_path).parent.joinpath(cleaned)
            normalized_parts: list[str] = []
            for part in joined.parts:
                if part == ".":
                    continue
                if part == "..":
                    if normalized_parts:
                        normalized_parts.pop()
                    continue
                normalized_parts.append(part)
            relative = "/".join(normalized_parts)
            candidates.update({relative, relative.replace("/", ".")})
        elif cleaned.startswith("."):
            # Python relative imports use leading dots rather than ../.  One
            # dot means the source package, two dots mean its parent, etc.
            level = len(cleaned) - len(cleaned.lstrip("."))
            module = cleaned[level:].replace(".", "/")
            base_parts = list(PurePosixPath(source_path).parent.parts)
            if level > 1:
                base_parts = base_parts[: max(0, len(base_parts) - level + 1)]
            relative = "/".join([*base_parts, *([module] if module else [])])
            candidates.update({relative, relative.replace("/", ".")})
        resolved: set[str] = set()
        extensions = (
            "",
            ".py",
            ".pyi",
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".go",
            ".rs",
            ".java",
            ".c",
            ".cc",
            ".cpp",
            ".h",
            ".hpp",
        )
        for candidate in tuple(candidates):
            direct_path = known_paths.get(candidate)
            if direct_path is not None:
                resolved.add(direct_path)
            slash_candidate = candidate if "/" in candidate else candidate.replace(".", "/")
            candidates.add(slash_candidate)
            for extension in extensions:
                direct = f"{slash_candidate}{extension}"
                direct_path = known_paths.get(direct)
                if direct_path is not None:
                    resolved.add(direct_path)
        for candidate in candidates:
            resolved.update(aliases.get(candidate, ()))
            resolved.update(aliases.get(candidate.removesuffix(".py"), ()))
        return resolved

    def dependency_neighbors(
        self, seed_paths: Sequence[str], limit: int = 32
    ) -> list[NeighborChunkHit]:
        """Return one source-addressable chunk for each direct dependency neighbor."""

        self._ensure_open()
        if limit <= 0 or not seed_paths:
            return []
        seeds = set(seed_paths)
        with self._lock:
            path_rows = self._connection.execute(
                """
                SELECT path FROM files
                WHERE provenance = 'source' AND stale = 0
                ORDER BY path
                """
            ).fetchall()
            known_paths = {str(row["path"]).casefold(): str(row["path"]) for row in path_rows}
            alias_map: dict[str, set[str]] = defaultdict(set)
            for folded_path, canonical in known_paths.items():
                for alias in self._path_aliases(folded_path):
                    alias_map[alias].add(canonical)
            dependency_rows = self._connection.execute(
                """
                SELECT d.* FROM dependencies AS d
                JOIN files AS f ON f.path = d.source_path
                WHERE f.provenance = 'source' AND f.stale = 0
                ORDER BY d.source_path, d.line, d.target, d.id
                """
            ).fetchall()
            neighbor_info: dict[str, tuple[str, str]] = {}
            for row in dependency_rows:
                source = str(row["source_path"])
                targets = self._resolve_dependency_target(
                    source,
                    str(row["target"]),
                    alias_map,
                    known_paths,
                )
                if source in seeds:
                    for target_path in sorted(targets):
                        if target_path not in seeds:
                            neighbor_info.setdefault(target_path, (source, "dependency of"))
                if targets & seeds and source not in seeds:
                    seed = sorted(targets & seeds)[0]
                    neighbor_info.setdefault(source, (seed, "dependent of"))
            results: list[NeighborChunkHit] = []
            for path in sorted(neighbor_info):
                row = self._connection.execute(
                    """
                    SELECT * FROM chunks WHERE file_path = ?
                    ORDER BY start_line, ordinal, id LIMIT 1
                    """,
                    (path,),
                ).fetchone()
                if row is None:
                    continue
                seed, direction = neighbor_info[path]
                results.append(
                    NeighborChunkHit(
                        chunk_id=int(row["id"]),
                        chunk=self._row_to_chunk(row),
                        seed_path=seed,
                        direction=direction,
                    )
                )
                if len(results) >= min(int(limit), 500):
                    break
        return results

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
