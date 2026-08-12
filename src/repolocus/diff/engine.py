"""Projection-only snapshot capture and pure architecture comparison."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from pathlib import PurePosixPath
from typing import TypeVar

from repolocus.index.view import RepositoryView
from repolocus.scanner.filters import CONFIG_FILENAMES

from .models import (
    EntryPointIdentity,
    FileChange,
    FileDigest,
    FileMove,
    FingerprintCompatibility,
    RepositoryDiff,
    RepositoryFacts,
    RepositorySnapshot,
    ResolvedDependencyIdentity,
    ReviewItem,
    SourceEvidence,
    SymbolIdentity,
    SymbolMove,
)

_T = TypeVar("_T")


def snapshot_from_view(view: RepositoryView) -> RepositorySnapshot:
    """Capture compact facts from one active, generation-pinned view.

    The adapter uses only metadata, symbols, resolved dependencies, and entry
    points.  It never asks the view for a text prefix or materializes chunks.
    """

    generation = view.generation
    files = {
        file.path: FileDigest(
            path=file.path,
            sha256=file.sha256,
            language=file.language,
            size_bytes=file.size_bytes,
            line_count=file.line_count,
            evidence=SourceEvidence(file.path, 1, max(1, file.line_count), generation),
        )
        for file in view.file_manifest()
    }
    symbols = frozenset(
        SymbolIdentity(
            name=symbol.name,
            kind=symbol.kind,
            signature=symbol.signature,
            evidence=SourceEvidence(
                symbol.path,
                symbol.start_line,
                symbol.end_line,
                generation,
            ),
        )
        for symbol in view.symbols()
        if symbol.path in files
    )
    dependencies = frozenset(
        ResolvedDependencyIdentity(
            raw_target=dependency.raw_target,
            target_path=dependency.target_path,
            target_symbol=dependency.target_symbol,
            kind=dependency.kind,
            confidence=dependency.confidence,
            candidates=tuple(sorted(set(dependency.candidates))),
            evidence=SourceEvidence(
                dependency.source_path,
                dependency.line,
                dependency.line,
                generation,
            ),
        )
        for dependency in view.dependencies()
        if dependency.source_path in files
    )
    entry_points = frozenset(
        EntryPointIdentity(SourceEvidence(entry.path, entry.line, entry.line, generation))
        for entry in view.entry_points()
        if entry.path in files
    )
    return RepositorySnapshot(
        schema_version=view.schema_version,
        repository_identity=view.repository_identity,
        generation=generation,
        fingerprints=view.fingerprints,
        dependency_resolver_fingerprint=view.dependency_resolver_fingerprint,
        facts=RepositoryFacts(
            files=files,
            symbols=symbols,
            dependencies=dependencies,
            entry_points=entry_points,
        ),
    )


def snapshot_from_index(
    index: object, *, expected_generation: int | None = None
) -> RepositorySnapshot:
    """Open one public RepositoryView and capture an immutable snapshot."""

    repository_view = getattr(index, "repository_view", None)
    if not callable(repository_view):
        raise TypeError("index must provide repository_view()")
    with repository_view(expected_generation=expected_generation) as view:
        return snapshot_from_view(view)


def _component_compatibility(
    old: RepositorySnapshot,
    new: RepositorySnapshot,
) -> FingerprintCompatibility:
    reasons: list[str] = []
    schema = old.schema_version == new.schema_version
    if not schema:
        reasons.append(
            f"schema version differs ({old.schema_version} != {new.schema_version}); "
            "rebuild snapshots"
        )

    names = ("scan", "parser", "term_index", "retrieval")
    component_matches: dict[str, bool] = {}
    if old.fingerprints is None or new.fingerprints is None:
        for name in names:
            component_matches[name] = False
        reasons.append("component fingerprints are missing; comparison is degraded")
    else:
        for name in names:
            matches = getattr(old.fingerprints, name) == getattr(new.fingerprints, name)
            component_matches[name] = matches
            if not matches:
                reasons.append(
                    f"{name} fingerprint differs; rebuild with one analysis configuration"
                )

    dependency_resolver = (
        old.dependency_resolver_fingerprint is not None
        and old.dependency_resolver_fingerprint == new.dependency_resolver_fingerprint
    )
    if not dependency_resolver:
        reasons.append(
            "dependency resolver fingerprint is missing or differs; edge diff is degraded"
        )
    return FingerprintCompatibility(
        schema=schema,
        scan=component_matches["scan"],
        parser=component_matches["parser"],
        term_index=component_matches["term_index"],
        retrieval=component_matches["retrieval"],
        dependency_resolver=dependency_resolver,
        degraded=bool(reasons),
        reasons=tuple(reasons),
    )


def _sort_file(file: FileDigest) -> tuple[str]:
    return (file.path,)


def _sort_symbol(symbol: SymbolIdentity) -> tuple[str, int, int, str, str, str]:
    return (
        symbol.evidence.path,
        symbol.evidence.start_line,
        symbol.evidence.end_line,
        symbol.name,
        symbol.kind,
        symbol.signature,
    )


def _sort_dependency(
    dependency: ResolvedDependencyIdentity,
) -> tuple[str, int, str, str, str, tuple[str, ...]]:
    return (
        dependency.evidence.path,
        dependency.evidence.start_line,
        dependency.raw_target,
        dependency.kind,
        dependency.confidence,
        dependency.candidates,
    )


def _sort_entry(entry: EntryPointIdentity) -> tuple[str, int]:
    return (entry.evidence.path, entry.evidence.start_line)


def _partition_by_key(
    old_items: Iterable[_T],
    new_items: Iterable[_T],
    key: Callable[[_T], object],
) -> tuple[list[_T], list[_T]]:
    old_by_key: dict[object, _T] = {}
    new_by_key: dict[object, _T] = {}
    for side, items, destination in (
        ("old", old_items, old_by_key),
        ("new", new_items, new_by_key),
    ):
        for item in items:
            item_key = key(item)
            if item_key in destination:
                raise ValueError(f"{side} snapshot contains a comparison-key collision")
            destination[item_key] = item
    return (
        [old_by_key[item_key] for item_key in old_by_key.keys() - new_by_key.keys()],
        [new_by_key[item_key] for item_key in new_by_key.keys() - old_by_key.keys()],
    )


def _file_moves(
    removed: list[FileDigest],
    added: list[FileDigest],
    old_files: Iterable[FileDigest],
    new_files: Iterable[FileDigest],
) -> tuple[list[FileMove], list[FileDigest], list[FileDigest]]:
    old_by_digest: dict[str, list[FileDigest]] = defaultdict(list)
    new_by_digest: dict[str, list[FileDigest]] = defaultdict(list)
    for file in removed:
        old_by_digest[file.sha256].append(file)
    for file in added:
        new_by_digest[file.sha256].append(file)
    old_digest_counts: dict[str, int] = defaultdict(int)
    new_digest_counts: dict[str, int] = defaultdict(int)
    for file in old_files:
        old_digest_counts[file.sha256] += 1
    for file in new_files:
        new_digest_counts[file.sha256] += 1
    moves: list[FileMove] = []
    moved_old: set[str] = set()
    moved_new: set[str] = set()
    for digest in sorted(old_by_digest.keys() & new_by_digest.keys()):
        old_candidates = old_by_digest[digest]
        new_candidates = new_by_digest[digest]
        if (
            len(old_candidates) != 1
            or len(new_candidates) != 1
            or old_digest_counts[digest] != 1
            or new_digest_counts[digest] != 1
        ):
            continue
        old_file, new_file = old_candidates[0], new_candidates[0]
        moves.append(FileMove(old_file, new_file))
        moved_old.add(old_file.path)
        moved_new.add(new_file.path)
    return (
        moves,
        [file for file in removed if file.path not in moved_old],
        [file for file in added if file.path not in moved_new],
    )


def _symbol_moves(
    removed: list[SymbolIdentity],
    added: list[SymbolIdentity],
    file_moves: Iterable[FileMove],
) -> tuple[list[SymbolMove], list[SymbolIdentity], list[SymbolIdentity]]:
    """Promote symbols only when a unique digest-identical file move proves the path move."""

    path_moves = {move.old.path: move.new.path for move in file_moves}
    old_groups: dict[tuple[str, tuple[str, str, str]], list[SymbolIdentity]] = defaultdict(list)
    new_groups: dict[tuple[str, tuple[str, str, str]], list[SymbolIdentity]] = defaultdict(list)
    for symbol in removed:
        old_groups[(symbol.evidence.path, symbol.semantic_key)].append(symbol)
    for symbol in added:
        new_groups[(symbol.evidence.path, symbol.semantic_key)].append(symbol)
    moves: list[SymbolMove] = []
    moved_old: set[tuple[str, str, str, str, int, int]] = set()
    moved_new: set[tuple[str, str, str, str, int, int]] = set()
    for (old_path, semantic_key), old_candidates in sorted(old_groups.items()):
        new_path = path_moves.get(old_path)
        if new_path is None:
            continue
        new_candidates = new_groups.get((new_path, semantic_key), [])
        if len(old_candidates) != 1 or len(new_candidates) != 1:
            continue
        old_symbol, new_symbol = old_candidates[0], new_candidates[0]
        moves.append(SymbolMove(old_symbol, new_symbol))
        moved_old.add(old_symbol.comparison_key)
        moved_new.add(new_symbol.comparison_key)
    return (
        moves,
        [symbol for symbol in removed if symbol.comparison_key not in moved_old],
        [symbol for symbol in added if symbol.comparison_key not in moved_new],
    )


def _is_config(path: str) -> bool:
    candidate = PurePosixPath(path)
    name = candidate.name.casefold()
    return (
        name in CONFIG_FILENAMES
        or name.startswith(("requirements", ".env.example"))
        or candidate.suffix.casefold()
        in {
            ".cfg",
            ".conf",
            ".config",
            ".gradle",
            ".ini",
            ".json",
            ".toml",
            ".xml",
            ".yaml",
            ".yml",
        }
    )


def _is_security_boundary(path: str) -> bool:
    parts = tuple(part.casefold() for part in PurePosixPath(path).parts)
    name = parts[-1]
    security_parts = {
        "auth",
        "authentication",
        "authorization",
        "crypto",
        "permissions",
        "privacy",
        "secrets",
        "security",
        "tls",
    }
    return (
        any(part in security_parts for part in parts)
        or name in {"codeowners", "security.md", "dependabot.yml"}
        or parts[:2] == (".github", "workflows")
    )


def _is_test(path: str) -> bool:
    candidate = PurePosixPath(path.casefold())
    name = candidate.name
    return (
        any(part in {"__tests__", "spec", "specs", "test", "tests"} for part in candidate.parts)
        or name.startswith("test_")
        or name.endswith(("_test.py", ".spec.js", ".spec.ts", ".test.js", ".test.ts"))
    )


def _as_changes(
    added: Iterable[FileDigest],
    removed: Iterable[FileDigest],
    changed: Iterable[FileChange],
    moved: Iterable[FileMove],
) -> tuple[FileChange, ...]:
    return (
        *(FileChange(None, file) for file in added),
        *(FileChange(file, None) for file in removed),
        *changed,
        *(FileChange(move.old, move.new) for move in moved),
    )


def _change_sort(change: FileChange) -> tuple[str, str, str]:
    old_path = change.old.path if change.old is not None else ""
    new_path = change.new.path if change.new is not None else ""
    return (new_path or old_path, old_path, change.kind)


def _classified_changes(
    changes: Iterable[FileChange], predicate: Callable[[str], bool]
) -> tuple[FileChange, ...]:
    return tuple(
        sorted(
            (
                change
                for change in changes
                if (change.old is not None and predicate(change.old.path))
                or (change.new is not None and predicate(change.new.path))
            ),
            key=_change_sort,
        )
    )


def _review_order(
    changes: tuple[FileChange, ...],
    added_entries: Iterable[EntryPointIdentity],
    removed_entries: Iterable[EntryPointIdentity],
    added_dependencies: Iterable[ResolvedDependencyIdentity],
    removed_dependencies: Iterable[ResolvedDependencyIdentity],
    added_symbols: Iterable[SymbolIdentity],
    removed_symbols: Iterable[SymbolIdentity],
    moved_symbols: Iterable[SymbolMove],
) -> tuple[ReviewItem, ...]:
    review: list[ReviewItem] = []
    for change in changes:
        old_evidence = change.old.evidence if change.old is not None else None
        new_evidence = change.new.evidence if change.new is not None else None
        path = new_evidence.path if new_evidence is not None else old_evidence.path  # type: ignore[union-attr]
        if _is_security_boundary(path):
            priority, area = 0, "security boundary"
        elif _is_config(path):
            priority, area = 1, "configuration"
        elif _is_test(path):
            priority, area = 4, "test area"
        else:
            priority, area = 5, "source"
        review.append(
            ReviewItem(
                priority,
                area,
                path,
                f"{change.kind} file",
                old_evidence,
                new_evidence,
            )
        )
    for entry, old_side in (
        *((entry, False) for entry in added_entries),
        *((entry, True) for entry in removed_entries),
    ):
        review.append(
            ReviewItem(
                2,
                "entry point",
                entry.evidence.path,
                f"{'removed' if old_side else 'added'} entry point",
                entry.evidence if old_side else None,
                None if old_side else entry.evidence,
            )
        )
    for dependency, old_side in (
        *((item, False) for item in added_dependencies),
        *((item, True) for item in removed_dependencies),
    ):
        review.append(
            ReviewItem(
                3,
                "dependency edge",
                dependency.evidence.path,
                f"{'removed' if old_side else 'added'} {dependency.confidence} edge to "
                f"{dependency.raw_target}",
                dependency.evidence if old_side else None,
                None if old_side else dependency.evidence,
            )
        )
    for symbol, old_side in (
        *((item, False) for item in added_symbols),
        *((item, True) for item in removed_symbols),
    ):
        review.append(
            ReviewItem(
                4,
                "symbol",
                symbol.evidence.path,
                f"{'removed' if old_side else 'added'} {symbol.kind} {symbol.name}",
                symbol.evidence if old_side else None,
                None if old_side else symbol.evidence,
            )
        )
    for move in moved_symbols:
        review.append(
            ReviewItem(
                4,
                "symbol",
                move.new.evidence.path,
                f"moved {move.new.kind} {move.new.name} with exact file-digest evidence",
                move.old.evidence,
                move.new.evidence,
            )
        )
    return tuple(
        sorted(
            review,
            key=lambda item: (
                item.priority,
                item.path,
                item.reason,
                item.old.start_line if item.old is not None else 0,
                item.new.start_line if item.new is not None else 0,
            ),
        )
    )


def compare_snapshots(old: RepositorySnapshot, new: RepositorySnapshot) -> RepositoryDiff:
    """Return a deterministic, side-effect-free architecture comparison."""

    if not isinstance(old, RepositorySnapshot) or not isinstance(new, RepositorySnapshot):
        raise TypeError("old and new must be RepositorySnapshot values")
    compatibility = _component_compatibility(old, new)

    old_paths = set(old.facts.files)
    new_paths = set(new.facts.files)
    removed_files = [old.facts.files[path] for path in sorted(old_paths - new_paths)]
    added_files = [new.facts.files[path] for path in sorted(new_paths - old_paths)]
    changed_files = [
        FileChange(old.facts.files[path], new.facts.files[path])
        for path in sorted(old_paths & new_paths)
        if old.facts.files[path].comparison_key != new.facts.files[path].comparison_key
    ]
    moved_files, removed_files, added_files = _file_moves(
        removed_files,
        added_files,
        old.facts.files.values(),
        new.facts.files.values(),
    )

    removed_symbols, added_symbols = _partition_by_key(
        old.facts.symbols,
        new.facts.symbols,
        lambda item: item.comparison_key,
    )
    moved_symbols, removed_symbols, added_symbols = _symbol_moves(
        removed_symbols,
        added_symbols,
        moved_files,
    )
    removed_dependencies, added_dependencies = _partition_by_key(
        old.facts.dependencies,
        new.facts.dependencies,
        lambda item: item.comparison_key,
    )
    removed_entries, added_entries = _partition_by_key(
        old.facts.entry_points,
        new.facts.entry_points,
        lambda item: item.comparison_key,
    )

    added_files_tuple = tuple(sorted(added_files, key=_sort_file))
    removed_files_tuple = tuple(sorted(removed_files, key=_sort_file))
    changed_files_tuple = tuple(sorted(changed_files, key=_change_sort))
    moved_files_tuple = tuple(sorted(moved_files, key=lambda move: (move.old.path, move.new.path)))
    added_symbols_tuple = tuple(sorted(added_symbols, key=_sort_symbol))
    removed_symbols_tuple = tuple(sorted(removed_symbols, key=_sort_symbol))
    moved_symbols_tuple = tuple(
        sorted(moved_symbols, key=lambda move: (_sort_symbol(move.old), _sort_symbol(move.new)))
    )
    added_entries_tuple = tuple(sorted(added_entries, key=_sort_entry))
    removed_entries_tuple = tuple(sorted(removed_entries, key=_sort_entry))
    added_dependencies_tuple = tuple(sorted(added_dependencies, key=_sort_dependency))
    removed_dependencies_tuple = tuple(sorted(removed_dependencies, key=_sort_dependency))
    all_file_changes = _as_changes(
        added_files_tuple,
        removed_files_tuple,
        changed_files_tuple,
        moved_files_tuple,
    )
    return RepositoryDiff(
        old_generation=old.generation,
        new_generation=new.generation,
        compatibility=compatibility,
        added_files=added_files_tuple,
        removed_files=removed_files_tuple,
        changed_files=changed_files_tuple,
        moved_files=moved_files_tuple,
        added_symbols=added_symbols_tuple,
        removed_symbols=removed_symbols_tuple,
        moved_symbols=moved_symbols_tuple,
        added_entry_points=added_entries_tuple,
        removed_entry_points=removed_entries_tuple,
        added_dependencies=added_dependencies_tuple,
        removed_dependencies=removed_dependencies_tuple,
        configuration_changes=_classified_changes(all_file_changes, _is_config),
        security_boundary_changes=_classified_changes(all_file_changes, _is_security_boundary),
        test_area_changes=_classified_changes(all_file_changes, _is_test),
        review_order=_review_order(
            all_file_changes,
            added_entries_tuple,
            removed_entries_tuple,
            added_dependencies_tuple,
            removed_dependencies_tuple,
            added_symbols_tuple,
            removed_symbols_tuple,
            moved_symbols_tuple,
        ),
    )
