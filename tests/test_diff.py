from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from repolocus.analysis import (
    DEFAULT_ANALYSIS_FINGERPRINTS,
    DEPENDENCY_RESOLVER_FINGERPRINT,
    AnalysisFingerprints,
)
from repolocus.diff import (
    EntryPointIdentity,
    FileDigest,
    RepositoryFacts,
    RepositorySnapshot,
    ResolvedDependencyIdentity,
    SourceEvidence,
    SymbolIdentity,
    compare_snapshots,
    dumps_diff,
    dumps_snapshot,
    load_snapshot,
    loads_snapshot,
    render_diff_markdown,
    save_snapshot,
    snapshot_from_index,
)
from repolocus.index import RepositoryIndex
from repolocus.models import Chunk, Dependency, ScannedFile, ScanResult, ScanStats, Symbol


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _file(
    path: str,
    text: str,
    *,
    symbols: tuple[tuple[str, int, int], ...] = (),
    dependencies: tuple[tuple[str, int], ...] = (),
    entry_point: bool = False,
) -> ScannedFile:
    line_count = max(1, len(text.splitlines()))
    return ScannedFile(
        path=path,
        language="python",
        size_bytes=len(text.encode()),
        sha256=_sha(text),
        line_count=line_count,
        text=text,
        symbols=tuple(
            Symbol(name, "function", path, start, end, f"def {name}()")
            for name, start, end in symbols
        ),
        dependencies=tuple(
            Dependency(path, target, "import", line) for target, line in dependencies
        ),
        chunks=(Chunk(path, 1, line_count, text, "python"),),
        is_entry_point=entry_point,
    )


def _snapshot(
    generation: int,
    files: tuple[FileDigest, ...],
    *,
    symbols: tuple[SymbolIdentity, ...] = (),
    dependencies: tuple[ResolvedDependencyIdentity, ...] = (),
    entries: tuple[EntryPointIdentity, ...] = (),
    fingerprints: AnalysisFingerprints | None = DEFAULT_ANALYSIS_FINGERPRINTS,
    identity: str = "1" * 64,
    schema: int = 6,
) -> RepositorySnapshot:
    return RepositorySnapshot(
        schema_version=schema,
        repository_identity=identity,
        generation=generation,
        fingerprints=fingerprints,
        dependency_resolver_fingerprint=DEPENDENCY_RESOLVER_FINGERPRINT,
        facts=RepositoryFacts(
            files={file.path: file for file in files},
            symbols=frozenset(symbols),
            dependencies=frozenset(dependencies),
            entry_points=frozenset(entries),
        ),
    )


def _digest(path: str, content: str, generation: int, *, line_count: int = 1) -> FileDigest:
    return FileDigest(
        path,
        _sha(content),
        "python",
        len(content.encode()),
        line_count,
        SourceEvidence(path, 1, line_count, generation),
    )


def _symbol(path: str, name: str, generation: int, line: int = 1) -> SymbolIdentity:
    return SymbolIdentity(
        name,
        "function",
        f"def {name}()",
        SourceEvidence(path, line, line, generation),
    )


def test_same_snapshot_diff_is_empty_deterministic_and_identity_agnostic() -> None:
    file = _digest("src/app.py", "same", 7)
    first = _snapshot(7, (file,), symbols=(_symbol(file.path, "run", 7),))
    identical_facts = replace(first, repository_identity="2" * 64)

    first_diff = compare_snapshots(first, identical_facts)
    second_diff = compare_snapshots(first, identical_facts)

    assert first_diff.is_empty
    assert first_diff == second_diff
    assert dumps_diff(first_diff) == dumps_diff(second_diff)
    assert first_diff.compatibility.degraded is False


def test_diff_reports_files_symbols_exact_moves_entry_points_and_areas() -> None:
    old_move = _digest("src/old.py", "move", 2)
    new_move = _digest("src/new.py", "move", 5)
    old_config = _digest("pyproject.toml", "version=1", 2)
    new_config = _digest("pyproject.toml", "version=2", 5)
    removed_security = _digest("src/security/auth.py", "allow", 2)
    added_test = _digest("tests/test_new.py", "assert True", 5)
    old = _snapshot(
        2,
        (old_move, old_config, removed_security),
        symbols=(
            _symbol(old_move.path, "run", 2),
            _symbol(removed_security.path, "authorize", 2),
        ),
        entries=(EntryPointIdentity(SourceEvidence(old_move.path, 1, 1, 2)),),
    )
    new = _snapshot(
        5,
        (new_move, new_config, added_test),
        symbols=(
            _symbol(new_move.path, "run", 5),
            _symbol(added_test.path, "test_new", 5),
        ),
        entries=(EntryPointIdentity(SourceEvidence(new_move.path, 1, 1, 5)),),
    )

    result = compare_snapshots(old, new)

    assert [(move.old.path, move.new.path) for move in result.moved_files] == [
        ("src/old.py", "src/new.py")
    ]
    assert [(move.old.name, move.new.name) for move in result.moved_symbols] == [("run", "run")]
    assert [item.path for item in result.removed_files] == ["src/security/auth.py"]
    assert [item.path for item in result.added_files] == ["tests/test_new.py"]
    assert result.changed_files[0].old.evidence.generation == 2  # type: ignore[union-attr]
    assert result.changed_files[0].new.evidence.generation == 5  # type: ignore[union-attr]
    assert {item.new.path for item in result.configuration_changes if item.new} == {
        "pyproject.toml"
    }
    assert result.security_boundary_changes[0].old == removed_security
    assert result.test_area_changes[0].new == added_test
    assert result.review_order[0].area == "security boundary"
    assert any(item.area == "symbol" for item in result.review_order)


def test_duplicate_file_digest_and_symbol_candidates_are_not_guessed_as_moves() -> None:
    old_files = (
        _digest("old/a.py", "duplicate", 1),
        _digest("old/b.py", "duplicate", 1),
    )
    new_files = (
        _digest("new/a.py", "duplicate", 2),
        _digest("new/b.py", "duplicate", 2),
    )
    old = _snapshot(
        1,
        old_files,
        symbols=tuple(_symbol(file.path, "same", 1) for file in old_files),
    )
    new = _snapshot(
        2,
        new_files,
        symbols=tuple(_symbol(file.path, "same", 2) for file in new_files),
    )

    result = compare_snapshots(old, new)

    assert result.moved_files == ()
    assert result.moved_symbols == ()
    assert len(result.removed_files) == len(result.added_files) == 2
    assert len(result.removed_symbols) == len(result.added_symbols) == 2

    unchanged_old = _digest("shared.py", "duplicate", 1)
    unchanged_new = _digest("shared.py", "duplicate", 2)
    result_with_unchanged_duplicate = compare_snapshots(
        _snapshot(1, (old_files[0], unchanged_old)),
        _snapshot(2, (new_files[0], unchanged_new)),
    )
    assert result_with_unchanged_duplicate.moved_files == ()


def test_ambiguous_dependencies_remain_explicit_and_generation_pinned() -> None:
    caller_old = _digest("src/caller.py", "import common", 1)
    caller_new = _digest("src/caller.py", "import common", 2)
    first_old = _digest("src/a/common.py", "a", 1)
    second_old = _digest("src/b/common.py", "b", 1)
    first_new = _digest("src/a/common.py", "a", 2)
    second_new = _digest("src/b/common.py", "b", 2)
    dependency_old = ResolvedDependencyIdentity(
        "common",
        None,
        None,
        "import",
        "ambiguous",
        ("src/a/common.py", "src/b/common.py"),
        SourceEvidence(caller_old.path, 1, 1, 1),
    )
    dependency_new = replace(
        dependency_old,
        candidates=("src/a/common.py", "src/b/common.py", "src/c/common.py"),
        evidence=SourceEvidence(caller_new.path, 1, 1, 2),
    )
    third_new = _digest("src/c/common.py", "c", 2)

    result = compare_snapshots(
        _snapshot(1, (caller_old, first_old, second_old), dependencies=(dependency_old,)),
        _snapshot(
            2,
            (caller_new, first_new, second_new, third_new),
            dependencies=(dependency_new,),
        ),
    )

    assert result.removed_dependencies == (dependency_old,)
    assert result.added_dependencies == (dependency_new,)
    assert result.removed_dependencies[0].evidence.generation == 1
    assert result.added_dependencies[0].evidence.generation == 2
    assert result.added_dependencies[0].confidence == "ambiguous"


def test_fingerprint_schema_mismatch_degrades_but_repository_identity_does_not() -> None:
    file_old = _digest("app.py", "one", 1)
    file_new = _digest("app.py", "one", 2)
    changed_fingerprints = replace(DEFAULT_ANALYSIS_FINGERPRINTS, parser="a" * 64)

    result = compare_snapshots(
        _snapshot(1, (file_old,), identity="1" * 64),
        _snapshot(
            2,
            (file_new,),
            identity="2" * 64,
            schema=7,
            fingerprints=changed_fingerprints,
        ),
    )

    assert result.compatibility.degraded
    assert result.compatibility.schema is False
    assert result.compatibility.parser is False
    assert all("repository" not in reason for reason in result.compatibility.reasons)


def test_snapshot_from_index_uses_projection_only_and_active_source_facts(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    caller = _file(
        "src/caller.py",
        "import common\ndef run():\n    return 1\n",
        symbols=(("run", 2, 3),),
        dependencies=(("common", 1),),
        entry_point=True,
    )
    first = _file("src/a/common.py", "VALUE = 1\n")
    second = _file("src/b/common.py", "VALUE = 2\n")
    generated = replace(
        _file("generated.py", "def hidden():\n    return 0\n", symbols=(("hidden", 1, 2),)),
        provenance="generated",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        update = index.update(
            ScanResult(repository, [caller, first, second, generated], ScanStats())
        )
        statements: list[str] = []
        index._connection.set_trace_callback(statements.append)
        try:
            snapshot = snapshot_from_index(index, expected_generation=update.content_generation)
        finally:
            index._connection.set_trace_callback(None)

    assert set(snapshot.facts.files) == {caller.path, first.path, second.path}
    assert {symbol.name for symbol in snapshot.facts.symbols} == {"run"}
    dependency = next(iter(snapshot.facts.dependencies))
    assert dependency.confidence == "ambiguous"
    assert dependency.candidates == (first.path, second.path)
    assert snapshot.facts.entry_points == frozenset(
        {EntryPointIdentity(SourceEvidence(caller.path, 1, 1, snapshot.generation))}
    )
    assert all("SELECT * FROM files" not in statement for statement in statements)
    assert all("SELECT * FROM chunks" not in statement for statement in statements)
    assert all("substr(text" not in statement.casefold() for statement in statements)
    assert all(" f.text" not in statement.casefold() for statement in statements)


def test_snapshot_json_is_canonical_integrity_checked_and_strict(tmp_path: Path) -> None:
    snapshot = _snapshot(3, (_digest("app.py", "content", 3),))
    payload = dumps_snapshot(snapshot)
    destination = save_snapshot(snapshot, tmp_path / "snapshot.json")

    if os.name != "nt":
        assert destination.stat().st_mode & 0o077 == 0
    assert load_snapshot(destination) == snapshot
    assert loads_snapshot(payload) == snapshot
    assert dumps_snapshot(loads_snapshot(payload)) == payload

    tampered = json.loads(payload)
    tampered["generation"] = 4
    with pytest.raises(ValueError, match="integrity"):
        loads_snapshot(json.dumps(tampered))

    duplicate_key = payload.replace(
        '{"dependency_resolver_fingerprint"', '{"generation":3,"dependency_resolver_fingerprint"', 1
    )
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        loads_snapshot(duplicate_key)

    unknown = json.loads(payload)
    unsigned = {key: value for key, value in unknown.items() if key != "snapshot_sha256"}
    unsigned["unexpected"] = True
    unsigned["snapshot_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in unsigned.items() if key != "snapshot_sha256"},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    with pytest.raises(ValueError, match="unknown"):
        loads_snapshot(json.dumps(unsigned))

    with pytest.raises(ValueError, match="non-finite"):
        loads_snapshot(payload.replace('"generation":3', '"generation":NaN'))
    if os.name != "nt":
        symlink = tmp_path / "link.json"
        symlink.symlink_to(destination)
        with pytest.raises(ValueError, match="non-symlink"):
            load_snapshot(symlink)


def test_markdown_renderer_neutralizes_repository_controlled_markup_and_mentions() -> None:
    path = "src/<img src=x onerror=alert(1)>@team|[x].py"
    old_file = _digest(path, "old", 1)
    new_file = _digest(path, "new", 2)
    old = _snapshot(1, (old_file,), symbols=(_symbol(path, "@all<script>", 1),))
    new = _snapshot(2, (new_file,))

    rendered = render_diff_markdown(compare_snapshots(old, new), "@old<script>", "new|label")

    assert "<script>" not in rendered
    assert "<img " not in rendered
    assert "@old" not in rendered
    assert "@all" not in rendered
    assert "&#64;old" in rendered
    assert "&#64;all" in rendered
    assert "http://" not in rendered
    assert "https://" not in rendered


def test_large_snapshot_diff_is_deterministic_without_source_text() -> None:
    count = 4_000
    old_files = tuple(
        _digest(f"src/module_{index:05d}.py", f"value={index}", 10) for index in range(count)
    )
    new_files = tuple(
        _digest(
            f"src/module_{index:05d}.py",
            f"value={index + 1}" if index % 1_000 == 0 else f"value={index}",
            11,
        )
        for index in reversed(range(count))
    )
    old_symbols = tuple(
        _symbol(file.path, f"symbol_{index}", 10) for index, file in enumerate(old_files)
    )
    new_symbols = tuple(
        _symbol(file.path, f"symbol_{index}", 11) for index, file in enumerate(reversed(new_files))
    )

    old = _snapshot(10, old_files, symbols=old_symbols)
    new = _snapshot(11, new_files, symbols=new_symbols)
    first = compare_snapshots(old, new)
    second = compare_snapshots(old, new)

    assert len(first.changed_files) == 4
    assert first == second
    assert dumps_diff(first) == dumps_diff(second)
    assert "content" not in dumps_snapshot(old)
