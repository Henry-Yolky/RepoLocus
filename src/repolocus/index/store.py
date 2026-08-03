"""SQLite-backed, incremental repository index.

The database deliberately lives in the user's cache directory instead of the
repository.  Repository contents are data only: this module never invokes Git,
a shell, or any executable found in the indexed tree.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import threading
from collections import defaultdict
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from platformdirs import user_cache_path

from repolocus.models import Chunk, Dependency, IndexUpdate, ScannedFile, ScanResult, Symbol

SCHEMA_VERSION = 2
INDEX_FORMAT_VERSION = "2"
# The product rename did not change the SQLite schema. Keep the original format
# magic so existing valid indexes remain recognizable when explicitly opened.
APPLICATION_ID = 0x4456504C  # "DVPL"
_QUERY_TOKEN = re.compile(r"[^\W_]+(?:_[^\W_]+)*", re.UNICODE)
_SAFE_SLUG = re.compile(r"[^A-Za-z0-9._-]+")
_REQUIRED_TABLES = frozenset({"meta", "files", "symbols", "dependencies", "chunks", "chunks_fts"})
_QUERY_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "be",
        "does",
        "for",
        "from",
        "how",
        "in",
        "is",
        "it",
        "of",
        "on",
        "or",
        "the",
        "this",
        "to",
        "was",
        "what",
        "where",
        "which",
        "who",
        "why",
        "with",
    }
)
_QUERY_EXPANSIONS: dict[str, tuple[str, ...]] = {
    "cloud": ("provider", "privacy", "consent"),
    "configuration": ("config", "settings"),
    "configurations": ("config", "settings"),
    "api": ("create_app",),
    "protected": ("protect", "security", "privacy", "consent"),
    "protection": ("protect", "security", "privacy", "consent"),
    "requests": ("request",),
    "symlinks": ("symlink",),
    "validated": ("validate",),
    "validation": ("validate",),
}
_QUERY_PHRASE_EXPANSIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("配置", ("config", "settings")),
    ("校验", ("validate",)),
    ("验证", ("validate",)),
    ("入口", ("main", "entry")),
    ("请求", ("request",)),
    ("隐私", ("privacy",)),
    ("授权", ("consent",)),
    ("同意", ("consent",)),
    ("模型", ("model", "provider")),
)
_OPEN_LOCKS_GUARD = threading.Lock()
_OPEN_LOCKS: dict[str, threading.RLock] = {}


class IndexFormatError(RuntimeError):
    """The cache exists but is not a compatible RepoLocus index."""


class IndexClosedError(RuntimeError):
    """An operation was attempted after an index was closed."""


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


def _query_tokens(query: str, *, maximum: int = 32) -> tuple[str, ...]:
    if not isinstance(query, str):
        return ()
    seen: set[str] = set()
    tokens: list[str] = []
    candidates: list[str] = []
    for match in _QUERY_TOKEN.finditer(query):
        token = match.group(0)[:128]
        folded = token.casefold()
        if not token or folded in _QUERY_STOPWORDS:
            continue
        candidates.append(token)
        candidates.extend(_QUERY_EXPANSIONS.get(folded, ()))
        if folded.endswith("ed") and len(folded) >= 6:
            candidates.extend((folded[:-2], folded[:-1]))
        elif folded.endswith("s") and len(folded) >= 5:
            candidates.append(folded[:-1])
    folded_query = query.casefold()
    for phrase, expansions in _QUERY_PHRASE_EXPANSIONS:
        if phrase in folded_query:
            candidates.extend(expansions)
    for token in candidates:
        folded = token.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        tokens.append(token)
        if len(tokens) >= maximum:
            break
    return tuple(tokens)


def _literal_query_tokens(query: str) -> frozenset[str]:
    """Return user-written tokens only, excluding semantic query expansions."""

    return frozenset(
        match.group(0)[:128].casefold()
        for match in _QUERY_TOKEN.finditer(query)
        if match.group(0) and match.group(0).casefold() not in _QUERY_STOPWORDS
    )


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


def _effective_chunks(file: ScannedFile) -> tuple[Chunk, ...]:
    if file.chunks or not file.text:
        return file.chunks
    return (
        Chunk(
            path=file.path,
            start_line=1,
            end_line=max(1, file.line_count),
            content=file.text,
            language=file.language,
        ),
    )


class RepositoryIndex:
    """A versioned SQLite/FTS5 index for exactly one canonical repository."""

    def __init__(self, root: Path, database_path: Path) -> None:
        self._root = root
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
        """Restrict plaintext index access on POSIX; Windows uses ACLs instead."""

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
                if version != SCHEMA_VERSION:
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
        except sqlite3.Error as exc:
            raise IndexFormatError(f"invalid SQLite index at {self._database_path}: {exc}") from exc

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
                ctime_ns INTEGER NOT NULL CHECK (ctime_ns >= 0)
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
            "CREATE INDEX IF NOT EXISTS symbols_file_idx ON symbols(file_path, start_line, name)",
            "CREATE INDEX IF NOT EXISTS symbols_name_idx ON symbols(name COLLATE NOCASE)",
            "CREATE INDEX IF NOT EXISTS dependencies_source_idx ON dependencies(source_path, line)",
            "CREATE INDEX IF NOT EXISTS dependencies_target_idx "
            "ON dependencies(target COLLATE NOCASE)",
            "CREATE INDEX IF NOT EXISTS chunks_file_idx ON chunks(file_path, start_line, ordinal)",
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
                path,
                symbol,
                content,
                tokenize = 'unicode61 remove_diacritics 2'
            )
            """,
            """
            CREATE TRIGGER IF NOT EXISTS chunks_after_insert AFTER INSERT ON chunks BEGIN
                INSERT INTO chunks_fts(rowid, path, symbol, content)
                VALUES (new.id, new.file_path, new.symbol, new.content);
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS chunks_after_delete AFTER DELETE ON chunks BEGIN
                DELETE FROM chunks_fts WHERE rowid = old.id;
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS chunks_after_update AFTER UPDATE ON chunks BEGIN
                DELETE FROM chunks_fts WHERE rowid = old.id;
                INSERT INTO chunks_fts(rowid, path, symbol, content)
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
                    ),
                )
                self._connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        except sqlite3.Error as exc:
            raise IndexFormatError(
                "SQLite FTS5 support is required to create a RepoLocus index"
            ) from exc

    def update(self, scan: ScanResult) -> IndexUpdate:
        """Apply a complete scan using SHA256 values for incremental invalidation."""

        self._ensure_open()
        scan_root = _canonical_root(scan.root)
        if scan_root != self._root:
            raise ValueError(f"scan root {scan_root} does not match index root {self._root}")
        incoming: dict[str, ScannedFile] = {}
        if not scan.analysis_version or len(scan.analysis_version) > 128:
            raise ValueError("scan analysis version must be a short non-empty string")
        for file in scan.files:
            _validate_scanned_file(file)
            if file.path in incoming:
                raise ValueError(f"duplicate scanned path: {file.path}")
            incoming[file.path] = file

        with self._lock, self._transaction():
            # BEGIN IMMEDIATE precedes both the comparison and mutations.  Two
            # index instances in one process therefore cannot calculate deltas
            # from the same stale snapshot and race on inserts.
            current = {
                str(row["path"]): str(row["sha256"]).casefold()
                for row in self._connection.execute("SELECT path, sha256 FROM files")
            }
            incoming_paths = set(incoming)
            current_paths = set(current)
            analysis_changed = self.get_metadata().get("analysis_version") != scan.analysis_version
            added = sorted(incoming_paths - current_paths)
            removed = sorted(current_paths - incoming_paths)
            changed = sorted(
                path
                for path in incoming_paths & current_paths
                if analysis_changed or incoming[path].sha256.casefold() != current[path]
            )
            unchanged_paths = sorted((incoming_paths & current_paths) - set(changed))
            unchanged = len(unchanged_paths)
            replaced = added + changed
            inserted_chunks = 0

            for path in removed + changed:
                self._connection.execute("DELETE FROM files WHERE path = ?", (path,))
            for path in replaced:
                inserted_chunks += self._insert_file(incoming[path])
            for path in unchanged_paths:
                file = incoming[path]
                self._connection.execute(
                    "UPDATE files SET mtime_ns = ?, ctime_ns = ? WHERE path = ?",
                    (file.mtime_ns, file.ctime_ns, path),
                )
            scan_digest = hashlib.sha256()
            for path in sorted(incoming):
                scan_digest.update(path.encode("utf-8", errors="surrogatepass"))
                scan_digest.update(b"\0")
                scan_digest.update(incoming[path].sha256.casefold().encode("ascii"))
                scan_digest.update(b"\0")
            metadata = {
                "last_scan_digest": scan_digest.hexdigest(),
                "last_scan_file_count": str(len(incoming)),
                "last_scan_indexed_bytes": str(sum(file.size_bytes for file in incoming.values())),
                "last_update_added": str(len(added)),
                "last_update_changed": str(len(changed)),
                "last_update_unchanged": str(unchanged),
                "last_update_removed": str(len(removed)),
                "analysis_version": scan.analysis_version,
            }
            self._connection.executemany(
                """
                INSERT INTO meta(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                sorted(metadata.items()),
            )

        return IndexUpdate(
            added=len(added),
            changed=len(changed),
            unchanged=unchanged,
            removed=len(removed),
            chunks=inserted_chunks,
        )

    def _insert_file(self, file: ScannedFile) -> int:
        self._connection.execute(
            """
            INSERT INTO files(
                path, language, size_bytes, sha256, line_count, text, is_entry_point,
                mtime_ns, ctime_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        return len(chunks)

    def get_metadata(self) -> dict[str, str]:
        self._ensure_open()
        with self._lock:
            return {
                str(row["key"]): str(row["value"])
                for row in self._connection.execute("SELECT key, value FROM meta ORDER BY key")
            }

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
            )
            for row in file_rows
        ]

    def list_files(self) -> list[ScannedFile]:
        return self.get_files()

    def search_chunks(self, query: str, limit: int = 32) -> list[IndexedChunkHit]:
        """Run a punctuation-safe FTS5 query and return best BM25 chunks."""

        self._ensure_open()
        if limit <= 0:
            return []
        tokens = _query_tokens(query)
        if not tokens:
            return []
        expression = " OR ".join(f'"{token}"' for token in tokens)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT c.*, bm25(chunks_fts, 2.0, 5.0, 1.0) AS fts_rank
                FROM chunks_fts
                JOIN chunks AS c ON c.id = chunks_fts.rowid
                WHERE chunks_fts MATCH ?
                ORDER BY fts_rank, c.file_path, c.start_line, c.ordinal
                LIMIT ?
                """,
                (expression, min(int(limit), 500)),
            ).fetchall()
        return [
            IndexedChunkHit(
                chunk_id=int(row["id"]),
                chunk=self._row_to_chunk(row),
                rank=float(row["fts_rank"]),
            )
            for row in rows
        ]

    def find_symbol_chunks(self, query: str, limit: int = 32) -> list[SymbolChunkHit]:
        """Find chunks for exact or partial symbol-name matches."""

        self._ensure_open()
        if limit <= 0:
            return []
        tokens = _query_tokens(query)
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
                "SELECT * FROM symbols ORDER BY file_path, start_line, name, id"
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
            path_rows = self._connection.execute("SELECT path FROM files ORDER BY path").fetchall()
            known_paths = {str(row["path"]).casefold(): str(row["path"]) for row in path_rows}
            alias_map: dict[str, set[str]] = defaultdict(set)
            for folded_path, canonical in known_paths.items():
                for alias in self._path_aliases(folded_path):
                    alias_map[alias].add(canonical)
            dependency_rows = self._connection.execute(
                "SELECT * FROM dependencies ORDER BY source_path, line, target, id"
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
