"""Immutable, source-addressable facts for architecture comparisons."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Literal

from repolocus.analysis import AnalysisFingerprints

SNAPSHOT_FORMAT_VERSION = 1
DependencyConfidence = Literal["exact", "probable", "ambiguous", "unresolved"]
MoveConfidence = Literal["exact"]


def _require_non_negative(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _require_positive(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must not be empty")


def _require_digest(value: str, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest") from exc


def _require_path(value: str, name: str = "path") -> None:
    _require_text(value, name)
    candidate = PurePosixPath(value)
    if (
        "\\" in value
        or candidate.is_absolute()
        or ".." in candidate.parts
        or candidate.as_posix() != value
        or value == "."
    ):
        raise ValueError(f"{name} must be normalized and repository-relative")


@dataclass(frozen=True, slots=True)
class SourceEvidence:
    """A location in exactly one content generation, without source text."""

    path: str
    start_line: int
    end_line: int
    generation: int

    def __post_init__(self) -> None:
        _require_path(self.path)
        _require_positive(self.start_line, "start_line")
        _require_positive(self.end_line, "end_line")
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        _require_non_negative(self.generation, "generation")

    @property
    def citation(self) -> str:
        end = f"-{self.end_line}" if self.end_line != self.start_line else ""
        return f"{self.path}:{self.start_line}{end}@{self.generation}"


@dataclass(frozen=True, slots=True)
class FileDigest:
    """Content identity and bounded metadata for one indexed source file."""

    path: str
    sha256: str
    language: str
    size_bytes: int
    line_count: int
    evidence: SourceEvidence

    def __post_init__(self) -> None:
        _require_path(self.path)
        _require_digest(self.sha256, "sha256")
        _require_text(self.language, "language")
        _require_non_negative(self.size_bytes, "size_bytes")
        _require_non_negative(self.line_count, "line_count")
        if self.evidence.path != self.path:
            raise ValueError("file evidence path must match file path")
        if self.evidence.start_line != 1 or self.evidence.end_line != max(1, self.line_count):
            raise ValueError("file evidence must cover the indexed line range")

    @property
    def comparison_key(self) -> tuple[str, str, int, int]:
        return (self.sha256, self.language, self.size_bytes, self.line_count)


@dataclass(frozen=True, slots=True)
class SymbolIdentity:
    """A parser-derived symbol with a precise generation-pinned location."""

    name: str
    kind: str
    signature: str
    evidence: SourceEvidence

    def __post_init__(self) -> None:
        _require_text(self.name, "symbol name")
        _require_text(self.kind, "symbol kind")
        if not isinstance(self.signature, str):
            raise ValueError("symbol signature must be text")

    @property
    def semantic_key(self) -> tuple[str, str, str]:
        """Identity used only to nominate unique move candidates."""

        return (self.name, self.kind, self.signature)

    @property
    def comparison_key(self) -> tuple[str, str, str, str, int, int]:
        return (
            self.evidence.path,
            self.name,
            self.kind,
            self.signature,
            self.evidence.start_line,
            self.evidence.end_line,
        )


@dataclass(frozen=True, slots=True)
class ResolvedDependencyIdentity:
    """One persisted resolver result, preserving ambiguous candidates."""

    raw_target: str
    target_path: str | None
    target_symbol: str | None
    kind: str
    confidence: DependencyConfidence
    candidates: tuple[str, ...]
    evidence: SourceEvidence

    def __post_init__(self) -> None:
        _require_text(self.raw_target, "raw_target")
        _require_text(self.kind, "dependency kind")
        if self.target_path is not None:
            _require_path(self.target_path, "target_path")
        if self.target_symbol is not None and not isinstance(self.target_symbol, str):
            raise ValueError("target_symbol must be text or None")
        if self.confidence not in {"exact", "probable", "ambiguous", "unresolved"}:
            raise ValueError("dependency confidence is invalid")
        if not isinstance(self.candidates, tuple):
            raise ValueError("dependency candidates must be a tuple")
        for candidate in self.candidates:
            _require_path(candidate, "dependency candidate")
        if tuple(sorted(set(self.candidates))) != self.candidates:
            raise ValueError("dependency candidates must be sorted and unique")
        if self.confidence == "ambiguous" and len(self.candidates) < 2:
            raise ValueError("ambiguous dependencies must preserve at least two candidates")

    @property
    def comparison_key(
        self,
    ) -> tuple[str, str, str | None, str | None, str, str, tuple[str, ...], int]:
        return (
            self.evidence.path,
            self.raw_target,
            self.target_path,
            self.target_symbol,
            self.kind,
            self.confidence,
            self.candidates,
            self.evidence.start_line,
        )


@dataclass(frozen=True, slots=True)
class EntryPointIdentity:
    """An executable entry point and its best source witness."""

    evidence: SourceEvidence

    @property
    def comparison_key(self) -> tuple[str, int, int]:
        return (self.evidence.path, self.evidence.start_line, self.evidence.end_line)


@dataclass(frozen=True, slots=True)
class RepositoryFacts:
    """Compact architecture facts; source bodies and chunks are deliberately absent."""

    files: Mapping[str, FileDigest]
    symbols: frozenset[SymbolIdentity]
    dependencies: frozenset[ResolvedDependencyIdentity]
    entry_points: frozenset[EntryPointIdentity]

    def __post_init__(self) -> None:
        if not isinstance(self.files, Mapping):
            raise ValueError("files must be a mapping")
        normalized_files = dict(self.files)
        if any(path != fact.path for path, fact in normalized_files.items()):
            raise ValueError("file mapping keys must match file paths")
        if any(not isinstance(fact, FileDigest) for fact in normalized_files.values()):
            raise ValueError("files must contain FileDigest values")
        object.__setattr__(self, "files", MappingProxyType(dict(sorted(normalized_files.items()))))
        for name, value, expected in (
            ("symbols", self.symbols, SymbolIdentity),
            ("dependencies", self.dependencies, ResolvedDependencyIdentity),
            ("entry_points", self.entry_points, EntryPointIdentity),
        ):
            if not isinstance(value, frozenset) or any(
                not isinstance(item, expected) for item in value
            ):
                raise ValueError(f"{name} must be a frozenset of {expected.__name__} values")
        paths = set(normalized_files)
        for fact_kind, facts in (
            ("symbol", self.symbols),
            ("dependency", self.dependencies),
            ("entry-point", self.entry_points),
        ):
            for fact in facts:
                if fact.evidence.path not in paths:
                    raise ValueError(f"{fact_kind} evidence must reference a snapshot file")
                file = normalized_files[fact.evidence.path]
                if fact.evidence.end_line > max(1, file.line_count):
                    raise ValueError(f"{fact_kind} evidence exceeds the indexed file range")
        for dependency in self.dependencies:
            if dependency.target_path is not None and dependency.target_path not in paths:
                raise ValueError("dependency target_path must reference a snapshot file")
            if any(candidate not in paths for candidate in dependency.candidates):
                raise ValueError("dependency candidates must reference snapshot files")


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    """An immutable, portable architecture snapshot."""

    schema_version: int
    repository_identity: str
    generation: int
    fingerprints: AnalysisFingerprints | None
    dependency_resolver_fingerprint: str | None
    facts: RepositoryFacts
    format_version: int = SNAPSHOT_FORMAT_VERSION

    def __post_init__(self) -> None:
        _require_positive(self.schema_version, "schema_version")
        _require_digest(self.repository_identity, "repository_identity")
        _require_non_negative(self.generation, "generation")
        if self.fingerprints is not None and not isinstance(
            self.fingerprints, AnalysisFingerprints
        ):
            raise ValueError("fingerprints must be AnalysisFingerprints or None")
        if self.dependency_resolver_fingerprint is not None:
            _require_digest(
                self.dependency_resolver_fingerprint,
                "dependency_resolver_fingerprint",
            )
        if not isinstance(self.facts, RepositoryFacts):
            raise ValueError("facts must be RepositoryFacts")
        if self.format_version != SNAPSHOT_FORMAT_VERSION:
            raise ValueError(
                f"unsupported snapshot format {self.format_version}; "
                f"expected {SNAPSHOT_FORMAT_VERSION}"
            )
        for fact in (
            *self.facts.files.values(),
            *self.facts.symbols,
            *self.facts.dependencies,
            *self.facts.entry_points,
        ):
            if fact.evidence.generation != self.generation:
                raise ValueError("all snapshot evidence must use the snapshot generation")


@dataclass(frozen=True, slots=True)
class FingerprintCompatibility:
    """Explicit comparability of every recorded analysis component."""

    schema: bool
    scan: bool
    parser: bool
    term_index: bool
    retrieval: bool
    dependency_resolver: bool
    degraded: bool
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in (
            "schema",
            "scan",
            "parser",
            "term_index",
            "retrieval",
            "dependency_resolver",
            "degraded",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"compatibility {name} must be true or false")
        if not isinstance(self.reasons, tuple) or any(
            not isinstance(reason, str) or not reason for reason in self.reasons
        ):
            raise ValueError("compatibility reasons must be a tuple of non-empty text")
        if tuple(sorted(set(self.reasons))) != tuple(sorted(self.reasons)):
            raise ValueError("compatibility reasons must be unique")
        if self.degraded != bool(self.reasons):
            raise ValueError("degraded must reflect whether compatibility reasons exist")


@dataclass(frozen=True, slots=True)
class FileChange:
    old: FileDigest | None
    new: FileDigest | None

    def __post_init__(self) -> None:
        if self.old is None and self.new is None:
            raise ValueError("a file change must include old or new evidence")

    @property
    def kind(self) -> Literal["added", "removed", "changed", "moved"]:
        if self.old is None:
            return "added"
        if self.new is None:
            return "removed"
        return "changed" if self.old.path == self.new.path else "moved"


@dataclass(frozen=True, slots=True)
class FileMove:
    old: FileDigest
    new: FileDigest
    confidence: MoveConfidence = "exact"

    def __post_init__(self) -> None:
        if self.old.path == self.new.path or self.old.sha256 != self.new.sha256:
            raise ValueError("a file move requires different paths with the same digest")
        if self.confidence != "exact":
            raise ValueError("only exact unique file moves are supported")


@dataclass(frozen=True, slots=True)
class SymbolMove:
    old: SymbolIdentity
    new: SymbolIdentity
    confidence: MoveConfidence = "exact"

    def __post_init__(self) -> None:
        if self.old.evidence.path == self.new.evidence.path:
            raise ValueError("a symbol move requires different paths")
        if self.old.semantic_key != self.new.semantic_key:
            raise ValueError("a symbol move requires the same semantic identity")
        if self.confidence != "exact":
            raise ValueError("only exact unique symbol moves are supported")


@dataclass(frozen=True, slots=True)
class ReviewItem:
    priority: int
    area: str
    path: str
    reason: str
    old: SourceEvidence | None
    new: SourceEvidence | None

    def __post_init__(self) -> None:
        _require_non_negative(self.priority, "priority")
        _require_text(self.area, "review area")
        _require_path(self.path)
        _require_text(self.reason, "review reason")
        if self.old is None and self.new is None:
            raise ValueError("review items require old or new evidence")
        evidence_paths = {
            evidence.path for evidence in (self.old, self.new) if evidence is not None
        }
        if self.path not in evidence_paths:
            raise ValueError("review path must identify old or new evidence")


@dataclass(frozen=True, slots=True)
class RepositoryDiff:
    """Deterministic architecture changes between two immutable snapshots."""

    old_generation: int
    new_generation: int
    compatibility: FingerprintCompatibility
    added_files: tuple[FileDigest, ...] = ()
    removed_files: tuple[FileDigest, ...] = ()
    changed_files: tuple[FileChange, ...] = ()
    moved_files: tuple[FileMove, ...] = ()
    added_symbols: tuple[SymbolIdentity, ...] = ()
    removed_symbols: tuple[SymbolIdentity, ...] = ()
    moved_symbols: tuple[SymbolMove, ...] = ()
    added_entry_points: tuple[EntryPointIdentity, ...] = ()
    removed_entry_points: tuple[EntryPointIdentity, ...] = ()
    added_dependencies: tuple[ResolvedDependencyIdentity, ...] = ()
    removed_dependencies: tuple[ResolvedDependencyIdentity, ...] = ()
    configuration_changes: tuple[FileChange, ...] = ()
    security_boundary_changes: tuple[FileChange, ...] = ()
    test_area_changes: tuple[FileChange, ...] = ()
    review_order: tuple[ReviewItem, ...] = ()

    def __post_init__(self) -> None:
        _require_non_negative(self.old_generation, "old_generation")
        _require_non_negative(self.new_generation, "new_generation")
        if not isinstance(self.compatibility, FingerprintCompatibility):
            raise ValueError("compatibility must be FingerprintCompatibility")
        expected_types = {
            "added_files": FileDigest,
            "removed_files": FileDigest,
            "changed_files": FileChange,
            "moved_files": FileMove,
            "added_symbols": SymbolIdentity,
            "removed_symbols": SymbolIdentity,
            "moved_symbols": SymbolMove,
            "added_entry_points": EntryPointIdentity,
            "removed_entry_points": EntryPointIdentity,
            "added_dependencies": ResolvedDependencyIdentity,
            "removed_dependencies": ResolvedDependencyIdentity,
            "configuration_changes": FileChange,
            "security_boundary_changes": FileChange,
            "test_area_changes": FileChange,
            "review_order": ReviewItem,
        }
        for name, expected in expected_types.items():
            value = getattr(self, name)
            if not isinstance(value, tuple) or any(
                not isinstance(item, expected) for item in value
            ):
                raise ValueError(f"{name} must be a tuple of {expected.__name__} values")

    @property
    def is_empty(self) -> bool:
        return not any(
            (
                self.added_files,
                self.removed_files,
                self.changed_files,
                self.moved_files,
                self.added_symbols,
                self.removed_symbols,
                self.moved_symbols,
                self.added_entry_points,
                self.removed_entry_points,
                self.added_dependencies,
                self.removed_dependencies,
                self.configuration_changes,
                self.security_boundary_changes,
                self.test_area_changes,
            )
        )
