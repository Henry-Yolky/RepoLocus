from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest

from repolocus.index import (
    IndexClosedError,
    IndexFormatError,
    RepositoryIndex,
    StaleScanError,
    cache_root,
    index_path_for,
)
from repolocus.models import (
    Chunk,
    Dependency,
    ScannedFile,
    ScanResult,
    ScanStats,
    Symbol,
)
from repolocus.scanner import RepositoryScanner


def _file(
    path: str,
    text: str,
    *,
    symbol: str = "",
    dependency: str = "",
    chunks: bool = True,
) -> ScannedFile:
    line_count = len(text.splitlines())
    source_symbol = (
        (Symbol(symbol, "function", path, 1, max(1, line_count), f"def {symbol}()"),)
        if symbol
        else ()
    )
    source_dependency = (Dependency(path, dependency, "import", 1),) if dependency else ()
    source_chunks = (
        (Chunk(path, 1, max(1, line_count), text, "python", symbol),) if chunks and text else ()
    )
    return ScannedFile(
        path=path,
        language="python",
        size_bytes=len(text.encode()),
        sha256=hashlib.sha256(text.encode()).hexdigest(),
        line_count=line_count,
        text=text,
        symbols=source_symbol,
        dependencies=source_dependency,
        chunks=source_chunks,
        is_entry_point=path == "app.py",
    )


def _scan(root: Path, *files: ScannedFile) -> ScanResult:
    return ScanResult(root=root, files=list(files), stats=ScanStats())


def test_manifest_snapshot_does_not_materialize_text_or_parser_facts(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = _file("app.py", "def main():\n    return 1\n", symbol="main")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(_scan(repository, source))
        snapshot = index.manifest_snapshot()

    assert len(snapshot.files) == 1
    manifest = snapshot.files[0]
    assert manifest.path == "app.py"
    assert manifest.text == ""
    assert manifest.symbols == ()
    assert manifest.dependencies == ()
    assert manifest.chunks == ()
    assert manifest.cached_symbol_count == 1
    assert manifest.cached_chunk_count == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions use mode bits")
def test_index_cache_permissions_are_private(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"

    with RepositoryIndex.open(repository, cache) as index:
        database = index.db_path

    assert stat.S_IMODE(cache.stat().st_mode) == 0o700
    assert stat.S_IMODE(database.stat().st_mode) == 0o600


def test_concurrent_first_open_is_serialized(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"
    barrier = Barrier(2)

    def open_once() -> str:
        barrier.wait()
        with RepositoryIndex.open(repository, cache) as index:
            return index.get_metadata()["repository_root"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _value: open_once(), range(2)))

    assert results == [str(repository.resolve()), str(repository.resolve())]


def test_cache_path_is_deterministic_external_and_not_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "project with spaces"
    repository.mkdir()
    base = tmp_path / "user-cache"
    monkeypatch.setattr(
        "repolocus.index.store.user_cache_path",
        lambda *args, **kwargs: base,
    )

    first = index_path_for(repository)
    second = index_path_for(repository / ".")

    assert first == second
    assert first.parent == cache_root()
    assert first.name.startswith("project-with-spaces-")
    assert first.suffix == ".sqlite3"
    assert not base.exists()
    with pytest.raises(ValueError, match="outside"):
        index_path_for(repository, repository / ".cache")


def test_incremental_update_round_trip_and_removal(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"
    app = _file(
        "app.py",
        "from src.store import load\n\ndef main():\n    return load()\n",
        symbol="main",
        dependency="src/store.py",
    )
    store = _file(
        "src/store.py",
        "def load():\n    return 'old_unique_value'\n",
        symbol="load",
    )

    with RepositoryIndex.open(repository, cache) as index:
        first = index.update(_scan(repository, app, store))
        assert first.added == 2
        assert first.changed == first.unchanged == first.removed == 0
        assert first.chunks == 2
        assert index.stats() == {
            "files": 2,
            "symbols": 2,
            "dependencies": 1,
            "chunks": 2,
            "indexed_bytes": app.size_bytes + store.size_bytes,
        }
        assert [file.path for file in index.get_files()] == ["app.py", "src/store.py"]
        assert index.list_symbols("app.py") == list(app.symbols)
        assert index.list_dependencies("app.py") == list(app.dependencies)
        assert index.get_metadata()["repository_root"] == str(repository.resolve())

        hot = index.update(_scan(repository, store, app))
        assert (hot.added, hot.changed, hot.unchanged, hot.removed, hot.chunks) == (
            0,
            0,
            2,
            0,
            0,
        )

        changed_app = _file("app.py", "def main():\n    return 2\n", symbol="main")
        added = _file("new.py", "VALUE = 'new_unique_value'\n")
        delta = index.update(_scan(repository, added, changed_app))
        assert (delta.added, delta.changed, delta.unchanged, delta.removed, delta.chunks) == (
            1,
            1,
            0,
            1,
            2,
        )
        assert [file.path for file in index.list_files()] == ["app.py", "new.py"]
        assert index.search_chunks("old_unique_value") == []
        assert index.search_chunks("new_unique_value")[0].chunk.path == "new.py"

    with RepositoryIndex.open(repository, cache) as reopened:
        assert [file.path for file in reopened.get_files()] == ["app.py", "new.py"]
        assert reopened.get_metadata()["last_update_removed"] == "1"


def test_manifest_query_never_reads_stored_source_text(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(_scan(repository, _file("source.py", "VALUE = 1\n")))

        def deny_text_read(
            action: int,
            table: str | None,
            column: str | None,
            _database: str | None,
            _trigger: str | None,
        ) -> int:
            if action == sqlite3.SQLITE_READ and table == "files" and column == "text":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        index._connection.set_authorizer(deny_text_read)
        try:
            manifest = index.get_file_manifest()
        finally:
            index._connection.set_authorizer(None)

    assert [file.path for file in manifest] == ["source.py"]
    assert manifest[0].text == ""


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX symlinks")
def test_directory_replaced_by_symlink_retains_old_facts_as_stale(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    nested = repository / "nested"
    nested.mkdir(parents=True)
    (nested / "value.py").write_text("VALUE = 'old'\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "value.py").write_text("VALUE = 'outside'\n", encoding="utf-8")
    scanner = RepositoryScanner()

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        initial_scan = scanner.scan(repository)
        initial = index.update(initial_scan)
        nested.rename(tmp_path / "old-nested")
        nested.symlink_to(outside, target_is_directory=True)

        changed_scan = scanner.scan(
            repository,
            cached_files={file.path: file for file in initial_scan.files},
            trusted_cache=True,
            base_generation=initial.generation,
        )
        changed = index.update(changed_scan)
        retained = index.get_files()

    assert "nested" in changed_scan.temporarily_unreadable
    assert changed.removed == 0
    assert changed.stale == 1
    assert [(file.path, file.stale) for file in retained] == [("nested/value.py", True)]


def test_scan_commit_rejects_repository_replaced_after_scan(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "old.py").write_text("OLD = 1\n", encoding="utf-8")
    scan = RepositoryScanner().scan(repository)

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        repository.rename(tmp_path / "old-repository")
        repository.mkdir()
        (repository / "new.py").write_text("NEW = 1\n", encoding="utf-8")

        with pytest.raises(StaleScanError, match="identity changed"):
            index.update(scan)

        assert index.get_files() == []


def test_file_text_becomes_fallback_chunk(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = _file("notes.txt", "fallback searchable prose\n", chunks=False)

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        update = index.update(_scan(repository, source))

        assert update.chunks == 1
        assert index.get_chunks() == [
            Chunk("notes.txt", 1, 1, "fallback searchable prose\n", "python")
        ]
        assert index.search_chunks("searchable")[0].chunk.path == "notes.txt"


def test_invalid_scan_is_rejected_without_mutating_existing_index(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    original = _file("good.py", "ORIGINAL = True\n")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(_scan(repository, original))
        invalid = ScannedFile(
            path="../escape.py",
            language="python",
            size_bytes=1,
            sha256="0" * 64,
            line_count=1,
            text="x",
        )
        with pytest.raises(ValueError, match="repository-relative"):
            index.update(_scan(repository, _file("good.py", "CHANGED = True\n"), invalid))

        assert index.get_files()[0].text == original.text


def test_wrong_root_and_duplicate_paths_are_rejected(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    other = tmp_path / "other"
    repository.mkdir()
    other.mkdir()
    source = _file("one.py", "x = 1\n")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        with pytest.raises(ValueError, match="does not match"):
            index.update(_scan(other, source))
        with pytest.raises(ValueError, match="duplicate"):
            index.update(_scan(repository, source, source))


def test_newer_or_foreign_database_is_never_overwritten(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"
    with RepositoryIndex.open(repository, cache) as index:
        database_path = index.db_path
        index.update(_scan(repository, _file("one.py", "x = 1\n")))

    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA user_version = 999")
    connection.close()
    with pytest.raises(IndexFormatError, match="unsupported index schema 999"):
        RepositoryIndex.open(repository, cache)

    connection = sqlite3.connect(database_path)
    assert connection.execute("SELECT count(*) FROM files").fetchone()[0] == 1
    connection.close()


def test_context_manager_closes_index(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    index = RepositoryIndex.open(repository, tmp_path / "cache")
    with index:
        assert index.stats()["files"] == 0
    index.close()  # idempotent
    with pytest.raises(IndexClosedError):
        index.stats()


def test_analysis_version_change_refreshes_unchanged_source(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"
    original = _file("one.py", "def value():\n    return 1\n", symbol="old_symbol")
    revised = replace(
        original,
        symbols=(Symbol("new_symbol", "function", "one.py", 1, 2, "def value()"),),
        chunks=(Chunk("one.py", 1, 2, original.text, "python", "new_symbol"),),
    )

    with RepositoryIndex.open(repository, cache) as index:
        index.update(ScanResult(repository, [original], ScanStats(), analysis_version="parser-v1"))
        update = index.update(
            ScanResult(repository, [revised], ScanStats(), analysis_version="parser-v2")
        )

        assert update.changed == 1
        assert [symbol.name for symbol in index.get_symbols()] == ["new_symbol"]
        assert index.get_metadata()["analysis_version"] == "parser-v2"


def test_out_of_range_parser_facts_are_rejected(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = _file("one.py", "value = 1\n")
    invalid = replace(
        source,
        chunks=(Chunk("one.py", 99, 100, "fabricated", "python"),),
    )

    with (
        RepositoryIndex.open(repository, tmp_path / "cache") as index,
        pytest.raises(ValueError, match="chunk line range"),
    ):
        index.update(_scan(repository, invalid))


def test_incomplete_scan_retains_old_facts_as_stale_until_refreshed(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"
    source = _file("src/keep.py", "KEEP_ME = True\n")

    with RepositoryIndex.open(repository, cache) as index:
        first = index.update(_scan(repository, source))
        incomplete = ScanResult(
            repository,
            [],
            ScanStats(),
            temporarily_unreadable=("src",),
            base_generation=first.generation,
        )
        retained = index.update(incomplete)

        assert retained.removed == 0
        assert retained.stale == 1
        assert index.get_files()[0].stale is True
        assert index.search_chunks("KEEP_ME") == []

        refreshed = index.update(
            ScanResult(
                repository,
                [source],
                ScanStats(),
                base_generation=retained.generation,
            )
        )
        assert refreshed.changed == 1
        assert refreshed.unchanged == 0
        assert refreshed.stale == 0
        assert index.get_files()[0].stale is False
        assert index.search_chunks("KEEP_ME")[0].chunk.path == "src/keep.py"

        deleted = index.update(
            ScanResult(
                repository,
                [],
                ScanStats(),
                base_generation=refreshed.generation,
            )
        )
        assert deleted.removed == 1
        assert index.get_files() == []


def test_generation_cas_rejects_an_older_scan_result(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"
    old = _file("state.py", "VALUE = 'old'\n")
    new = _file("state.py", "VALUE = 'new'\n")

    with (
        RepositoryIndex.open(repository, cache) as first,
        RepositoryIndex.open(repository, cache) as second,
    ):
        first_snapshot = first.snapshot()
        second_snapshot = second.snapshot()
        committed = second.update(
            ScanResult(
                repository,
                [new],
                ScanStats(),
                base_generation=second_snapshot.generation,
            )
        )

        with pytest.raises(StaleScanError, match="is stale"):
            first.update(
                ScanResult(
                    repository,
                    [old],
                    ScanStats(),
                    base_generation=first_snapshot.generation,
                )
            )

        assert first.get_files()[0].text == new.text
        assert first.generation() == committed.generation


def test_generated_provenance_round_trips_but_is_not_retrieved_by_default(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    generated = replace(
        _file("PROJECT_MAP.md", "UNIQUE_GENERATED_ASSERTION\n"),
        language="markdown",
        provenance="generated",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(_scan(repository, generated))

        stored = index.get_files()[0]
        assert stored.provenance == "generated"
        assert index.search_chunks("UNIQUE_GENERATED_ASSERTION") == []
        assert index.find_symbol_chunks("UNIQUE_GENERATED_ASSERTION") == []


def test_v2_index_migration_invalidates_untrusted_existing_facts(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"
    source = _file("one.py", "VALUE = 1\n")
    generated = _file(
        "renamed-generated.py",
        "# Project Map\n\n<!-- Generator: RepoLocus 0.1.2; deterministic source map. -->\n",
    )
    prose = replace(
        _file(
            "notes.md",
            "Ordinary prose mentions <!-- Generator: RepoLocus but is not a marker.\n",
        ),
        language="markdown",
    )
    with RepositoryIndex.open(repository, cache) as index:
        database = index.db_path
        index.update(_scan(repository, source, generated, prose))

    connection = sqlite3.connect(database)
    connection.execute("ALTER TABLE files DROP COLUMN stale")
    connection.execute("ALTER TABLE files DROP COLUMN provenance")
    connection.execute("DROP TABLE chunk_terms")
    connection.execute("DELETE FROM meta WHERE key = 'generation'")
    connection.execute("DELETE FROM meta WHERE key = 'repository_identity'")
    connection.execute("UPDATE meta SET value = '2' WHERE key = 'schema_version'")
    connection.execute("UPDATE meta SET value = '2' WHERE key = 'index_format_version'")
    connection.execute("PRAGMA user_version = 2")
    connection.commit()
    connection.row_factory = sqlite3.Row
    v2_migrator = object.__new__(RepositoryIndex)
    v2_migrator._connection = connection
    v2_migrator._migrate_v2_to_v3()
    migrated_provenance = {
        str(row["path"]): str(row["provenance"])
        for row in connection.execute("SELECT path, provenance FROM files")
    }
    assert migrated_provenance["renamed-generated.py"] == "generated"
    assert migrated_provenance["notes.md"] == "source"
    connection.close()

    with RepositoryIndex.open(repository, cache) as migrated:
        metadata = migrated.get_metadata()

        assert migrated.get_files() == []
        assert migrated.get_symbols() == []
        assert migrated.search_chunks("VALUE") == []
        assert migrated.generation() == 1
        assert metadata["analysis_version"] == ""
        assert metadata["schema_version"] == "5"
        assert metadata["index_format_version"] == "5"
        assert metadata["content_generation"] == "1"
        assert metadata["scan_revision"] == "1"
        assert len(metadata["repository_identity"]) == 64
        indexes = {
            str(row[1]) for row in migrated._connection.execute("PRAGMA index_list('chunk_terms')")
        }
        assert "chunk_terms_chunk_idx" in indexes
        migrated._migrate_v2_to_v3()  # Models a waiter after another migration.
        assert migrated.get_files() == []


def test_legacy_v3_search_layout_migrates_to_v5_without_reusing_facts(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"
    source = _file("legacy.py", "LEGACY_FACT = True\n", symbol="legacy_fact")

    with RepositoryIndex.open(repository, cache) as index:
        database = index.db_path
        committed = index.update(_scan(repository, source))

    connection = sqlite3.connect(database)
    for trigger in (
        "chunks_after_insert",
        "chunks_after_delete",
        "chunks_after_update",
    ):
        connection.execute(f"DROP TRIGGER {trigger}")  # nosec B608
    connection.execute("DROP TABLE chunks_fts")
    connection.execute("DROP TABLE chunk_terms")
    connection.execute("ALTER TABLE files DROP COLUMN facts_sha256")
    connection.execute(
        """
        CREATE VIRTUAL TABLE chunks_fts USING fts5(
            path,
            symbol,
            content,
            tokenize = 'unicode61 remove_diacritics 2'
        )
        """
    )
    connection.execute(
        """
        CREATE TRIGGER chunks_after_insert AFTER INSERT ON chunks BEGIN
            INSERT INTO chunks_fts(rowid, path, symbol, content)
            VALUES (new.id, new.file_path, new.symbol, new.content);
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER chunks_after_delete AFTER DELETE ON chunks BEGIN
            DELETE FROM chunks_fts WHERE rowid = old.id;
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER chunks_after_update AFTER UPDATE ON chunks BEGIN
            DELETE FROM chunks_fts WHERE rowid = old.id;
            INSERT INTO chunks_fts(rowid, path, symbol, content)
            VALUES (new.id, new.file_path, new.symbol, new.content);
        END
        """
    )
    connection.execute(
        """
        INSERT INTO chunks_fts(rowid, path, symbol, content)
        SELECT id, file_path, symbol, content FROM chunks
        """
    )
    connection.execute(
        "DELETE FROM meta WHERE key IN "
        "('content_generation', 'scan_revision', 'scan_fingerprint', "
        "'parser_fingerprint', 'term_index_fingerprint', "
        "'retrieval_fingerprint', 'repository_identity')"
    )
    connection.execute("UPDATE meta SET value = '3' WHERE key = 'schema_version'")
    connection.execute("UPDATE meta SET value = '3' WHERE key = 'index_format_version'")
    connection.execute("PRAGMA user_version = 3")
    connection.commit()
    assert [row[1] for row in connection.execute("PRAGMA table_info(chunks_fts)")] == [
        "path",
        "symbol",
        "content",
    ]
    assert connection.execute("SELECT count(*) FROM chunks_fts").fetchone()[0] == 1
    connection.close()

    with RepositoryIndex.open(repository, cache) as migrated:
        metadata = migrated.get_metadata()
        tables = {
            str(row[0])
            for row in migrated._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        file_columns = {
            str(row[1]) for row in migrated._connection.execute("PRAGMA table_info(files)")
        }
        fts_columns = [
            str(row[1]) for row in migrated._connection.execute("PRAGMA table_info(chunks_fts)")
        ]
        chunk_term_indexes = {
            str(row[1]) for row in migrated._connection.execute("PRAGMA index_list('chunk_terms')")
        }
        trigger_sql = {
            str(row[0]): str(row[1])
            for row in migrated._connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'chunks'"
            )
        }

        assert migrated.get_files() == []
        assert migrated.get_symbols() == []
        assert migrated.search_chunks("LEGACY_FACT") == []
        assert migrated.generation() == committed.generation + 1
        assert metadata["schema_version"] == "5"
        assert metadata["index_format_version"] == "5"
        assert metadata["content_generation"] == str(committed.generation + 1)
        assert metadata["scan_revision"] == str(committed.generation + 1)
        assert int(migrated._connection.execute("PRAGMA user_version").fetchone()[0]) == 5
        assert "chunk_terms" in tables
        assert "facts_sha256" in file_columns
        assert fts_columns == ["file_path", "symbol", "content"]
        assert "chunk_terms_chunk_idx" in chunk_term_indexes
        assert set(trigger_sql) == {
            "chunks_after_insert",
            "chunks_after_delete",
            "chunks_after_update",
        }
        assert all("file_path" in statement for statement in trigger_sql.values())
        assert migrated._connection.execute("SELECT count(*) FROM chunks").fetchone()[0] == 0
        assert migrated._connection.execute("SELECT count(*) FROM chunk_terms").fetchone()[0] == 0
        assert migrated._connection.execute("SELECT count(*) FROM chunks_fts").fetchone()[0] == 0


def test_same_path_repository_replacement_invalidates_index_identity(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"
    old = _file("old.py", "OLD_REPOSITORY = True\n")

    with RepositoryIndex.open(repository, cache) as index:
        committed = index.update(_scan(repository, old))
        old_identity = index.get_metadata()["repository_identity"]

    repository.rename(tmp_path / "old-repository")
    repository.mkdir()

    with RepositoryIndex.open(repository, cache) as replacement:
        metadata = replacement.get_metadata()

        assert replacement.get_files() == []
        assert replacement.search_chunks("OLD_REPOSITORY") == []
        assert replacement.generation() == committed.generation + 1
        assert metadata["analysis_version"] == ""
        assert metadata["repository_identity"] != old_identity


def test_restored_stale_file_replaces_same_hash_parser_facts(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"
    old = _file("same.py", "VALUE = 1\n", symbol="parser_v1")
    reparsed = replace(
        old,
        symbols=(Symbol("parser_v2", "function", "same.py", 1, 1, "parser_v2"),),
        chunks=(Chunk("same.py", 1, 1, old.text, "python", "parser_v2"),),
    )

    with RepositoryIndex.open(repository, cache) as index:
        first = index.update(
            ScanResult(repository, [old], ScanStats(), analysis_version="parser-v1")
        )
        incomplete = index.update(
            ScanResult(
                repository,
                [],
                ScanStats(),
                analysis_version="parser-v2",
                temporarily_unreadable=("same.py",),
                base_generation=first.generation,
            )
        )

        restored = index.update(
            ScanResult(
                repository,
                [reparsed],
                ScanStats(),
                analysis_version="parser-v2",
                base_generation=incomplete.generation,
            )
        )

        assert restored.changed == 1
        assert restored.unchanged == 0
        assert [symbol.name for symbol in index.get_symbols()] == ["parser_v2"]
        assert index.get_files()[0].stale is False
