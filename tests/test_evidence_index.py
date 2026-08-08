from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Sequence
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from repolocus.analysis import DEPENDENCY_RESOLVER_FINGERPRINT
from repolocus.generators import MermaidGenerator, ProjectMapGenerator
from repolocus.graph import resolve_dependencies
from repolocus.index import EntryPoint, IndexFormatError, RepositoryIndex, StaleScanError
from repolocus.models import Chunk, Dependency, ScannedFile, ScanResult, ScanStats, Symbol
from repolocus.parsers import SourceLayout
from repolocus.retrieval import RetrievalEngine, classify_query_intent


def _file(
    path: str,
    text: str,
    *,
    symbols: tuple[str, ...] = (),
    dependencies: tuple[str, ...] = (),
    entry_point: bool = False,
) -> ScannedFile:
    line_count = max(1, len(text.splitlines()))
    return ScannedFile(
        path=path,
        language="python",
        size_bytes=len(text.encode()),
        sha256=hashlib.sha256(text.encode()).hexdigest(),
        line_count=line_count,
        text=text,
        symbols=tuple(Symbol(name, "function", path, 1, line_count) for name in symbols),
        dependencies=tuple(Dependency(path, target, "import", 1) for target in dependencies),
        chunks=(Chunk(path, 1, line_count, text, "python", symbols[0] if symbols else ""),),
        is_entry_point=entry_point,
    )


def test_resolver_preserves_ambiguity_and_index_rebuilds_after_path_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    caller = _file("src/caller.py", "import common\n", dependencies=("common",))
    first = _file("src/a/common.py", "VALUE = 1\n")
    second = _file("src/b/common.py", "VALUE = 2\n")

    pure = resolve_dependencies((caller.path, first.path, second.path), caller.dependencies)[0]
    assert pure.confidence == "ambiguous"
    assert pure.target_path is None
    assert pure.candidates == ("src/a/common.py", "src/b/common.py")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [caller, first, second], ScanStats()))
        ambiguous = index.get_resolved_dependencies()[0]
        assert ambiguous == pure
        assert index.dependency_neighbors([caller.path]) == []

        rebuilds = 0
        rebuild_resolved_graph = index._rebuild_resolved_graph

        def track_rebuild() -> None:
            nonlocal rebuilds
            rebuilds += 1
            rebuild_resolved_graph()

        monkeypatch.setattr(index, "_rebuild_resolved_graph", track_rebuild)

        index.update(ScanResult(repository, [caller, first], ScanStats()))
        resolved = index.get_resolved_dependencies()[0]
        assert rebuilds == 1
        assert resolved.confidence == "exact"
        assert resolved.target_path == first.path
        assert [item.chunk.path for item in index.dependency_neighbors([caller.path])] == [
            first.path
        ]


def test_body_only_updates_preserve_graph_without_full_rebuild(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    caller = _file(
        "src/caller.py",
        "import worker\nVALUE = 1\n",
        dependencies=("worker",),
    )
    worker = _file("src/worker.py", "VALUE = 1\n")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [caller, worker], ScanStats()))
        rebuilds = 0
        rebuild_resolved_graph = index._rebuild_resolved_graph
        local_resolutions = 0
        resolve_replaced_dependencies = index._resolve_replaced_dependencies

        def track_rebuild() -> None:
            nonlocal rebuilds
            rebuilds += 1
            rebuild_resolved_graph()

        def track_local_resolution(
            source_paths: Sequence[str],
            resolver_paths: Sequence[str] | set[str],
        ) -> None:
            nonlocal local_resolutions
            local_resolutions += 1
            resolve_replaced_dependencies(source_paths, resolver_paths)

        monkeypatch.setattr(index, "_rebuild_resolved_graph", track_rebuild)
        monkeypatch.setattr(index, "_resolve_replaced_dependencies", track_local_resolution)
        changed_worker = _file(worker.path, "VALUE = 2\n")

        index.update(ScanResult(repository, [caller, changed_worker], ScanStats()))

        assert rebuilds == 0
        assert local_resolutions == 0
        assert index.get_resolved_dependencies()[0].target_path == worker.path

        changed_caller = _file(
            caller.path,
            "import worker\nVALUE = 2\n",
            dependencies=("worker",),
        )

        index.update(ScanResult(repository, [changed_caller, changed_worker], ScanStats()))

        assert rebuilds == 0
        assert local_resolutions == 0
        assert index.get_resolved_dependencies()[0].target_path == worker.path


def test_dependency_fact_change_is_re_resolved_without_full_graph_rebuild(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    caller = _file(
        "src/caller.py",
        "import worker\nuse_dependency()\n",
        dependencies=("worker",),
    )
    worker = _file("src/worker.py", "VALUE = 1\n")
    replacement = _file("src/replacement.py", "VALUE = 2\n")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [caller, worker, replacement], ScanStats()))
        rebuilds = 0
        rebuild_resolved_graph = index._rebuild_resolved_graph
        resolved_sources: list[tuple[str, ...]] = []
        resolve_replaced_dependencies = index._resolve_replaced_dependencies

        def track_rebuild() -> None:
            nonlocal rebuilds
            rebuilds += 1
            rebuild_resolved_graph()

        def track_local_resolution(
            source_paths: Sequence[str],
            resolver_paths: Sequence[str] | set[str],
        ) -> None:
            resolved_sources.append(tuple(source_paths))
            resolve_replaced_dependencies(source_paths, resolver_paths)

        monkeypatch.setattr(index, "_rebuild_resolved_graph", track_rebuild)
        monkeypatch.setattr(index, "_resolve_replaced_dependencies", track_local_resolution)
        changed_caller = replace(
            caller,
            dependencies=(Dependency(caller.path, "replacement", "call", 2),),
        )

        index.update(ScanResult(repository, [changed_caller, worker, replacement], ScanStats()))

        assert rebuilds == 0
        assert resolved_sources == [(caller.path,)]
        assert index.get_resolved_dependencies() == [
            resolve_dependencies(
                (caller.path, worker.path, replacement.path),
                changed_caller.dependencies,
            )[0]
        ]


def test_go_module_identity_resolves_packages_and_invalidates_all_aliases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    module = _file("go.mod", "module fixture.local/service\n")
    caller = _file(
        "cmd/server/main.go",
        'package main\nimport "fixture.local/service/internal/health"\n',
        dependencies=("fixture.local/service/internal/health",),
    )
    handler = _file("internal/health/handler.go", "package health\n")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [module, caller, handler], ScanStats()))
        assert index.get_resolved_dependencies()[0].target_path == handler.path

        rebuilds = 0
        rebuild_resolved_graph = index._rebuild_resolved_graph

        def track_rebuild() -> None:
            nonlocal rebuilds
            rebuilds += 1
            rebuild_resolved_graph()

        monkeypatch.setattr(index, "_rebuild_resolved_graph", track_rebuild)
        changed_module = _file("go.mod", "module fixture.local/replacement\n")

        index.update(ScanResult(repository, [changed_module, caller, handler], ScanStats()))

        assert rebuilds == 1
        assert index.get_resolved_dependencies()[0].confidence == "unresolved"


@pytest.mark.parametrize("visibility_change", ["stale", "provenance"])
def test_source_visibility_change_triggers_full_graph_rebuild(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    visibility_change: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    caller = _file("src/caller.py", "import worker\n", dependencies=("worker",))
    worker = _file("src/worker.py", "VALUE = 1\n")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [caller, worker], ScanStats()))
        rebuilds = 0
        rebuild_resolved_graph = index._rebuild_resolved_graph

        def track_rebuild() -> None:
            nonlocal rebuilds
            rebuilds += 1
            rebuild_resolved_graph()

        monkeypatch.setattr(index, "_rebuild_resolved_graph", track_rebuild)
        if visibility_change == "stale":
            scan = ScanResult(
                repository,
                [caller],
                ScanStats(),
                temporarily_unreadable=(worker.path,),
            )
        else:
            scan = ScanResult(
                repository,
                [caller, replace(worker, provenance="generated")],
                ScanStats(),
            )

        index.update(scan)

        assert rebuilds == 1
        assert index.get_resolved_dependencies()[0].confidence == "unresolved"


def test_resolver_handles_rust_crate_symbol_paths() -> None:
    dependency = Dependency("src/main.rs", "crate::worker::run", "import", 1)

    resolved = resolve_dependencies(("src/main.rs", "src/worker.rs"), (dependency,))[0]

    assert resolved.target_path == "src/worker.rs"
    assert resolved.target_symbol == "run"
    assert resolved.confidence == "probable"


def test_symbol_lookup_uses_one_indexed_query_without_python_full_table_scan(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    symbols = (*(f"UnrelatedSymbol{index}" for index in range(500)), "TargetSymbol")
    source = _file("src/symbols.py", "def TargetSymbol():\n    pass\n", symbols=symbols)

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [source], ScanStats()))
        statements: list[str] = []
        index._connection.set_trace_callback(statements.append)
        try:
            hits = index.find_symbol_chunks("TargetSymbol", limit=5)
        finally:
            index._connection.set_trace_callback(None)

    assert hits[0].symbol_name == "TargetSymbol"
    selects = [
        statement for statement in statements if statement.lstrip().upper().startswith("WITH")
    ]
    assert len(selects) == 1
    assert "symbol_terms" in selects[0]
    assert "row_number()" in selects[0].lower()
    assert "SELECT s.* FROM symbols" not in selects[0]


def test_symbol_lookup_treats_literal_qualified_symbol_leaf_as_exact(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = _file(
        "src/config.py",
        "def __post_init__():\n    pass\n",
        symbols=("Settings.__post_init__",),
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [source], ScanStats()))
        hits = index.find_symbol_chunks("Where is __post_init__ defined?", limit=5)

    assert [(hit.symbol_name, hit.match) for hit in hits[:1]] == [
        ("Settings.__post_init__", "exact")
    ]


def test_symbol_lookup_selects_chunks_in_one_indexed_query(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    lines = [f"def SharedSymbol{number}(): return {number}\n" for number in range(1_000)]
    text = "".join(lines)
    source = ScannedFile(
        path="src/symbols.py",
        language="python",
        size_bytes=len(text.encode()),
        sha256=hashlib.sha256(text.encode()).hexdigest(),
        line_count=len(lines),
        text=text,
        symbols=tuple(
            Symbol(f"SharedSymbol{number}", "function", "src/symbols.py", number + 1, number + 1)
            for number in range(len(lines))
        ),
        chunks=tuple(
            Chunk(
                "src/symbols.py",
                number + 1,
                number + 1,
                line,
                "python",
                f"SharedSymbol{number}",
            )
            for number, line in enumerate(lines)
        ),
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [source], ScanStats()))
        statements: list[str] = []
        index._connection.set_trace_callback(statements.append)
        try:
            hits = index.find_symbol_chunks("SharedSymbol", limit=5)
        finally:
            index._connection.set_trace_callback(None)

    assert len(hits) == 5
    query = next(statement for statement in statements if statement.lstrip().startswith("WITH"))
    assert query.index("symbol_chunks AS") < query.index("distinct_chunks AS")
    assert "selected_symbols AS" not in query
    assert "JOIN chunks AS c ON c.id" in query
    assert "JOIN chunks AS c ON c.file_path = m.file_path" not in query


def test_symbol_lookup_maps_overloads_to_their_own_source_chunks(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    path = "src/main/java/example/Worker.java"
    text = (
        "public class Worker {\n"
        "    public void run() {\n"
        "        System.out.println(1);\n"
        "    }\n"
        "    public void run(String value) {\n"
        "        System.out.println(value);\n"
        "    }\n"
        "}\n"
    )
    source = ScannedFile(
        path=path,
        language="java",
        size_bytes=len(text.encode()),
        sha256=hashlib.sha256(text.encode()).hexdigest(),
        line_count=8,
        text=text,
        symbols=(
            Symbol("run", "method", path, 2, 4),
            Symbol("run", "method", path, 5, 7),
        ),
        chunks=(
            Chunk(
                path,
                2,
                4,
                "    public void run() {\n        System.out.println(1);\n    }\n",
                "java",
                "run",
            ),
            Chunk(
                path,
                5,
                7,
                "    public void run(String value) {\n        System.out.println(value);\n    }\n",
                "java",
                "run",
            ),
        ),
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [source], ScanStats()))
        hits = index.find_symbol_chunks("run", limit=5)

    assert [(hit.chunk.start_line, hit.chunk.end_line) for hit in hits] == [(2, 4), (5, 7)]


def test_symbol_lookup_applies_limit_after_deduplicating_chunks(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    crowded_path = "a.py"
    crowded_names = tuple(f"SharedAlpha{number:02d}" for number in range(20))
    crowded_text = "\n".join(f"def {name}(): pass" for name in crowded_names) + "\n"
    crowded = ScannedFile(
        path=crowded_path,
        language="python",
        size_bytes=len(crowded_text.encode()),
        sha256=hashlib.sha256(crowded_text.encode()).hexdigest(),
        line_count=len(crowded_names),
        text=crowded_text,
        symbols=tuple(
            Symbol(name, "function", crowded_path, line, line)
            for line, name in enumerate(crowded_names, 1)
        ),
        chunks=(Chunk(crowded_path, 1, len(crowded_names), crowded_text, "python"),),
    )
    distinct = [
        _file(
            f"z{number}.py",
            f"def SharedZeta{number}(): pass\n",
            symbols=(f"SharedZeta{number}",),
        )
        for number in range(5)
    ]

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [crowded, *distinct], ScanStats()))
        hits = index.find_symbol_chunks("Shared", limit=5)

    assert len(hits) == 5
    assert len({hit.chunk.path for hit in hits}) == 5


def test_dependency_neighbors_keep_seed_and_direction_together(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    first_seed = _file("a.py", "VALUE = 1\n")
    second_seed = _file("z.py", "import neighbor\n", dependencies=("neighbor",))
    neighbor = _file("neighbor.py", "import a\n", dependencies=("a",))

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [first_seed, neighbor, second_seed], ScanStats()))
        limited = index.dependency_neighbors([first_seed.path, second_seed.path], limit=1)
        both = index.dependency_neighbors([first_seed.path, second_seed.path], limit=10)
        reverse = index.dependency_neighbors(
            [first_seed.path, second_seed.path],
            limit=10,
            direction="dependent of",
        )

    assert len(limited) == 1
    assert {(hit.chunk.path, hit.seed_path, hit.direction) for hit in both} == {
        (neighbor.path, first_seed.path, "dependent of"),
        (neighbor.path, second_seed.path, "dependency of"),
    }
    assert [(hit.chunk.path, hit.seed_path, hit.direction) for hit in reverse] == [
        (neighbor.path, first_seed.path, "dependent of")
    ]


def test_dependency_neighbors_select_target_symbol_and_witness_chunks(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    caller_path = "src/caller.py"
    caller_text = "def unrelated():\n    return 0\n\ndef call_run():\n    return run()\n"
    caller = ScannedFile(
        path=caller_path,
        language="python",
        size_bytes=len(caller_text.encode()),
        sha256=hashlib.sha256(caller_text.encode()).hexdigest(),
        line_count=5,
        text=caller_text,
        symbols=(
            Symbol("unrelated", "function", caller_path, 1, 2),
            Symbol("call_run", "function", caller_path, 4, 5),
        ),
        dependencies=(Dependency(caller_path, "src.worker.run", "call", 5),),
        chunks=(
            Chunk(caller_path, 1, 2, "def unrelated():\n    return 0\n", "python", "unrelated"),
            Chunk(caller_path, 4, 5, "def call_run():\n    return run()\n", "python", "call_run"),
        ),
    )
    worker_path = "src/worker.py"
    worker_text = "def unrelated():\n    return 0\n\n\ndef run():\n    return 1\n"
    worker = ScannedFile(
        path=worker_path,
        language="python",
        size_bytes=len(worker_text.encode()),
        sha256=hashlib.sha256(worker_text.encode()).hexdigest(),
        line_count=6,
        text=worker_text,
        symbols=(
            Symbol("unrelated", "function", worker_path, 1, 2),
            Symbol("run", "function", worker_path, 5, 6),
        ),
        chunks=(
            Chunk(worker_path, 1, 2, "def unrelated():\n    return 0\n", "python", "unrelated"),
            Chunk(worker_path, 5, 6, "def run():\n    return 1\n", "python", "run"),
        ),
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [caller, worker], ScanStats()))
        resolved = index.get_resolved_dependencies()[0]
        outbound = index.dependency_neighbors(
            [caller.path],
            direction="dependency of",
        )
        reverse = index.dependency_neighbors(
            [worker.path],
            direction="dependent of",
        )

    assert resolved.target_symbol == "run"
    assert outbound[0].chunk.symbol == "run"
    assert outbound[0].chunk.start_line == 5
    assert reverse[0].chunk.symbol == "call_run"
    assert reverse[0].chunk.start_line == 4


def test_dependency_neighbors_reject_too_many_seed_paths(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    with (
        RepositoryIndex.open(repository, tmp_path / "cache") as index,
        pytest.raises(ValueError, match="seed_paths must contain at most 500 entries"),
    ):
        index.dependency_neighbors([f"src/{number}.py" for number in range(501)])


def test_repository_view_uses_exact_dunder_main_symbol_line(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    entry = replace(
        _file(
            "src/main.py",
            "VALUE = 1\n\ndef __main__():\n    return 0\n",
            entry_point=True,
        ),
        symbols=(Symbol("__main__", "function", "src/main.py", 3, 4),),
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        update = index.update(ScanResult(repository, [entry], ScanStats()))
        with index.repository_view(expected_generation=update.content_generation) as view:
            assert tuple(view.entry_points()) == (EntryPoint("src/main.py", 3),)


def test_repository_view_reads_projections_and_only_bounded_text_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    readme = _file("README.md", "# Example\n\nA bounded description.\n")
    entry = _file(
        "src/main.py",
        "def main():\n    return 0\n",
        symbols=("main",),
        dependencies=("src.worker",),
        entry_point=True,
    )
    worker = _file("src/worker.py", "def work():\n    return 1\n", symbols=("work",))

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        update = index.update(ScanResult(repository, [readme, entry, worker], ScanStats()))
        monkeypatch.setattr(
            index,
            "get_resolved_dependencies",
            lambda: (_ for _ in ()).throw(
                AssertionError("RepositoryView must stream its dependency projection")
            ),
        )
        statements: list[str] = []
        index._connection.set_trace_callback(statements.append)
        try:
            with index.repository_view(expected_generation=update.content_generation) as view:
                summaries = tuple(view.file_summaries())
                entries = tuple(view.entry_points())
                areas = tuple(view.symbols_by_area())
                dependencies = tuple(view.dependencies())
                before_prefix = tuple(statements)
                prefix = view.read_text_prefix("README.md", 12)
        finally:
            index._connection.set_trace_callback(None)

    assert {item.path for item in summaries} == {"README.md", "src/main.py", "src/worker.py"}
    assert entries[0].path == "src/main.py"
    assert entries[0].line == 1
    assert {item.area for item in areas} == {"(repository root)", "src"}
    assert dependencies[0].target_path == "src/worker.py"
    assert prefix == "# Example\n\nA"
    assert (
        len([statement for statement in before_prefix if "WITH symbol_counts AS" in statement]) == 1
    )
    assert (
        len(
            [
                statement
                for statement in before_prefix
                if "FROM resolved_dependencies AS rd" in statement
            ]
        )
        == 1
    )
    assert all("SELECT * FROM files" not in statement for statement in before_prefix)
    assert all("substr(text" not in statement.lower() for statement in before_prefix)
    assert any("substr(text" in statement.lower() for statement in statements)


def test_project_map_reads_only_one_root_readme_prefix(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    root_readme = _file("README.md", "# Root\n\nRoot description.\n")
    nested_readme = _file("docs/README.md", "# Nested\n\nNested description.\n")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        update = index.update(ScanResult(repository, [root_readme, nested_readme], ScanStats()))
        statements: list[str] = []
        index._connection.set_trace_callback(statements.append)
        try:
            with index.repository_view(expected_generation=update.content_generation) as view:
                document = ProjectMapGenerator().generate_view(view)
        finally:
            index._connection.set_trace_callback(None)

    prefix_reads = [statement for statement in statements if "substr(text" in statement.casefold()]
    summary_reads = [statement for statement in statements if "WITH symbol_counts AS" in statement]
    assert len(prefix_reads) == 1
    assert len(summary_reads) == 1
    assert all("dependency_counts AS" not in statement for statement in statements)
    assert "README.md" in prefix_reads[0]
    assert "Root description" in document
    assert "Nested description" not in document


def test_mermaid_reads_only_the_lightweight_file_projection(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    caller = _file(
        "src/caller.py",
        "import worker\ndef call():\n    return worker.run()\n",
        symbols=("call",),
        dependencies=("worker",),
    )
    worker = _file("src/worker.py", "def run():\n    return 1\n", symbols=("run",))

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        update = index.update(ScanResult(repository, [caller, worker], ScanStats()))
        statements: list[str] = []
        index._connection.set_trace_callback(statements.append)
        try:
            with index.repository_view(expected_generation=update.content_generation) as view:
                document = MermaidGenerator().generate_view(view)
        finally:
            index._connection.set_trace_callback(None)

    assert "[src/caller.py:1](src/caller.py#L1)" in document
    assert (
        len(
            [statement for statement in statements if "SELECT f.path, 1 AS first_line" in statement]
        )
        == 1
    )
    assert all("WITH symbol_counts AS" not in statement for statement in statements)
    assert all("dependency_counts AS" not in statement for statement in statements)
    assert all("FROM chunks" not in statement for statement in statements)


def test_repository_view_dependency_iterator_is_lazy_and_cannot_escape_closed_index(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        update = index.update(ScanResult(repository, [_file("one.py", "VALUE = 1\n")], ScanStats()))
        statements: list[str] = []
        index._connection.set_trace_callback(statements.append)
        try:
            with index.repository_view(expected_generation=update.content_generation) as view:
                dependencies = view.dependencies()
                assert all("FROM resolved_dependencies AS rd" not in item for item in statements)
        finally:
            index._connection.set_trace_callback(None)

    with pytest.raises(RuntimeError, match="must be used as a context manager"):
        next(dependencies)


def test_unstarted_dependency_iterator_cannot_cross_view_lifecycles(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    first_caller = _file("caller.py", "import a\n", dependencies=("a",))
    first_target = _file("a.py", "VALUE = 1\n")
    second_caller = _file("caller.py", "import b\n", dependencies=("b",))
    second_target = _file("b.py", "VALUE = 2\n")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [first_caller, first_target], ScanStats()))
        view = index.repository_view()
        with view:
            dependencies = view.dependencies()

        index.update(ScanResult(repository, [second_caller, second_target], ScanStats()))
        with view, pytest.raises(RuntimeError, match="different repository view lifecycle"):
            next(dependencies)


def test_partially_consumed_dependency_iterator_cannot_cross_view_lifecycles(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    caller = _file("caller.py", "import a\nimport b\n", dependencies=("a", "b"))
    targets = [_file(f"{name}.py", "VALUE = 1\n") for name in ("a", "b")]

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [caller, *targets], ScanStats()))
        view = index.repository_view()
        with view:
            dependencies = view.dependencies()
            assert next(dependencies).raw_target == "a"

        with view, pytest.raises(RuntimeError, match="different repository view lifecycle"):
            next(dependencies)


def test_repository_view_closes_a_partially_consumed_dependency_cursor(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    caller = _file("caller.py", "import a\nimport b\nimport c\n", dependencies=("a", "b", "c"))
    targets = [_file(f"{name}.py", "VALUE = 1\n") for name in ("a", "b", "c")]

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        update = index.update(ScanResult(repository, [caller, *targets], ScanStats()))
        with index.repository_view(expected_generation=update.content_generation) as view:
            dependencies = view.dependencies()
            assert next(dependencies).raw_target == "a"

        checkpoint_connection = sqlite3.connect(index.db_path, isolation_level=None)
        try:
            checkpoint = checkpoint_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        finally:
            checkpoint_connection.close()
        assert checkpoint is not None
        assert checkpoint[0] == 0

    with pytest.raises(RuntimeError, match="must be used as a context manager"):
        next(dependencies)


def test_project_map_legacy_and_view_share_resolved_dependencies(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    caller = _file(
        "src/caller.py",
        "import common\nimport requests\n",
        dependencies=("common", "requests"),
    )
    first = _file("src/a/common.py", "VALUE = 1\n")
    second = _file("src/b/common.py", "VALUE = 2\n")
    scan = ScanResult(repository, [caller, first, second], ScanStats())

    legacy = ProjectMapGenerator().generate(scan)
    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        update = index.update(scan)
        with index.repository_view(expected_generation=update.content_generation) as view:
            projected = ProjectMapGenerator().generate_view(view)

    def dependency_section(document: str) -> str:
        return document.split("## External dependencies", 1)[1].split(
            "## Configuration and environment", 1
        )[0]

    assert dependency_section(projected) == dependency_section(legacy)
    assert "`requests`" in dependency_section(projected)
    assert "`common`" not in dependency_section(projected)


def test_resolver_fingerprint_change_rebuilds_persisted_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    caller = _file("src/caller.py", "import worker\n", dependencies=("worker",))
    worker = _file("src/worker.py", "VALUE = 1\n")
    scan = ScanResult(repository, [caller, worker], ScanStats())

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        first = index.update(scan)
        index._connection.execute(
            "UPDATE resolved_dependencies SET target_path = NULL, "
            "resolution_kind = 'unresolved', confidence = 0.0"
        )
        index._connection.execute(
            "UPDATE meta SET value = 'stale' WHERE key = 'dependency_resolver_fingerprint'"
        )
        rebuilds = 0
        rebuild_resolved_graph = index._rebuild_resolved_graph

        def track_rebuild() -> None:
            nonlocal rebuilds
            rebuilds += 1
            rebuild_resolved_graph()

        monkeypatch.setattr(index, "_rebuild_resolved_graph", track_rebuild)

        second = index.update(scan)

        assert rebuilds == 1
        assert second.content_generation == first.content_generation + 1
        assert index.get_resolved_dependencies()[0].target_path == worker.path
        assert (
            index.get_metadata()["dependency_resolver_fingerprint"]
            == DEPENDENCY_RESOLVER_FINGERPRINT
        )


def test_source_layout_pairs_braces_and_clamps_offsets() -> None:
    text = "function run() {\n  const fake = '}'; // {\n  return {ok: true};\n}\n"
    layout = SourceLayout.build(text)
    opening = text.index("{")

    assert layout.line_at_offset(-100) == 1
    assert layout.line_at_offset(len(text) + 100) == 5
    assert layout.brace_end_line(opening) == 4
    assert len(layout.lines) == 4


def test_structured_retrieval_exposes_intent_rrf_and_no_answer(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = _file(
        "src/service.py",
        "# placeholder implemented in an external system\n"
        "def authenticate_user():\n    return True\n",
        symbols=("authenticate_user",),
    )
    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [source], ScanStats()))
        retrieval = RetrievalEngine(index)
        result = retrieval.search_result("Where is authenticate_user implemented?", limit=3)
        weak = retrieval.search_result("implemented", limit=3)
        rejected = retrieval.search_result("!@#$%^&*", limit=3)

    assert classify_query_intent("Who calls authenticate_user?") == "references"
    assert result.intent == "definition"
    assert result.rejected_reason is None
    assert result.evidence[0].path == "src/service.py"
    assert {hit.retriever for hit in result.hits} >= {"full_text", "symbol_exact"}
    assert all("rrf_weight" in hit.features for hit in result.hits)
    assert json.loads(json.dumps(asdict(result)))["hits"][0]["features"]["rrf_k"] == 60.0
    assert weak.hits
    assert weak.evidence == ()
    assert weak.rejected_reason == "below_minimum_relevance"
    assert rejected.evidence == ()
    assert rejected.rejected_reason == "no_candidates"


def test_repository_view_rejects_a_stale_expected_generation(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [_file("one.py", "VALUE = 1\n")], ScanStats()))
        with (
            pytest.raises(StaleScanError, match="expected index generation"),
            index.repository_view(expected_generation=999),
        ):
            pass


@pytest.mark.parametrize("expected_generation", [True, False, -1, 1.5, "1"])
def test_repository_view_rejects_invalid_expected_generation(
    tmp_path: Path,
    expected_generation: object,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    with (
        RepositoryIndex.open(repository, tmp_path / "cache") as index,
        pytest.raises(
            ValueError,
            match="expected_generation must be a non-negative integer or None",
        ),
    ):
        index.repository_view(expected_generation=expected_generation)  # type: ignore[arg-type]


def test_repository_view_rejects_a_stale_resolver_fingerprint(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        update = index.update(ScanResult(repository, [_file("one.py", "VALUE = 1\n")], ScanStats()))
        index._connection.execute(
            "UPDATE meta SET value = 'stale' WHERE key = 'dependency_resolver_fingerprint'"
        )

        with (
            pytest.raises(StaleScanError, match="resolved dependency graph is stale"),
            index.repository_view(expected_generation=update.content_generation),
        ):
            pass


def test_v5_migration_builds_evidence_indexes_without_losing_facts(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"
    caller = _file(
        "src/caller.py",
        "from src.worker import work\n",
        symbols=("call_work",),
        dependencies=("src.worker",),
    )
    worker = _file("src/worker.py", "def work():\n    return 1\n", symbols=("work",))
    with RepositoryIndex.open(repository, cache) as index:
        database = index.db_path
        generation = index.update(
            ScanResult(repository, [caller, worker], ScanStats())
        ).content_generation

    connection = sqlite3.connect(database)
    connection.execute("DROP TABLE resolved_dependency_candidates")
    connection.execute("DROP TABLE resolved_dependencies")
    connection.execute("DROP TABLE path_aliases")
    connection.execute("DROP TABLE symbol_terms")
    connection.execute("UPDATE meta SET value = '5' WHERE key = 'schema_version'")
    connection.execute("UPDATE meta SET value = '5' WHERE key = 'index_format_version'")
    connection.execute("PRAGMA user_version = 5")
    connection.commit()
    connection.close()

    with RepositoryIndex.open(repository, cache) as migrated:
        assert migrated.content_generation() == generation + 1
        assert migrated.get_resolved_dependencies()[0].target_path == "src/worker.py"
        assert migrated.find_symbol_chunks("work", limit=1)[0].symbol_name == "work"
        assert migrated.get_metadata()["schema_version"] == "6"
        indexes = {
            str(row[1]) for row in migrated._connection.execute("PRAGMA index_list('symbol_terms')")
        }
        assert "symbol_terms_term_idx" not in indexes


def test_v5_migration_rejects_preexisting_malformed_evidence_schema(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"
    with RepositoryIndex.open(repository, cache) as index:
        database = index.db_path

    connection = sqlite3.connect(database)
    connection.execute("DROP TABLE path_aliases")
    connection.execute("CREATE TABLE path_aliases(alias TEXT, path TEXT)")
    connection.execute("CREATE INDEX path_aliases_path_idx ON path_aliases(path)")
    connection.execute("UPDATE meta SET value = '5' WHERE key = 'schema_version'")
    connection.execute("UPDATE meta SET value = '5' WHERE key = 'index_format_version'")
    connection.execute("PRAGMA user_version = 5")
    connection.commit()
    connection.close()

    with pytest.raises(
        IndexFormatError,
        match="v5 index contains an incompatible v6 evidence table: path_aliases",
    ):
        RepositoryIndex.open(repository, cache)

    connection = sqlite3.connect(database)
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
        assert connection.execute("PRAGMA foreign_key_list(path_aliases)").fetchall() == []
    finally:
        connection.close()


def test_resolved_graph_reads_reject_a_stale_resolver_fingerprint(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    caller = _file("caller.py", "import worker\n", dependencies=("worker",))
    worker = _file("worker.py", "VALUE = 1\n")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [caller, worker], ScanStats()))
        snapshot = index.snapshot()
        assert snapshot.dependency_resolver_fingerprint == DEPENDENCY_RESOLVER_FINGERPRINT
        index._connection.execute(
            "UPDATE meta SET value = 'stale' WHERE key = 'dependency_resolver_fingerprint'"
        )

        with pytest.raises(IndexFormatError, match="resolved dependency graph is stale"):
            index.get_resolved_dependencies()
        with pytest.raises(IndexFormatError, match="resolved dependency graph is stale"):
            index.dependency_neighbors([caller.path])
