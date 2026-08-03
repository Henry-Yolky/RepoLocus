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
