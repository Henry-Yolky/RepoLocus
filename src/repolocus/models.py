"""Shared immutable data structures used by the scanner and index."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from repolocus.analysis import AnalysisFingerprints

Confidence = Literal["confirmed", "inferred", "needs_review"]
Provenance = Literal["source", "generated"]
ANALYSIS_VERSION = "3"


@dataclass(frozen=True, slots=True)
class Symbol:
    """A source symbol with a precise, one-based location."""

    name: str
    kind: str
    path: str
    start_line: int
    end_line: int
    signature: str = ""

    @property
    def citation(self) -> str:
        end = f"-{self.end_line}" if self.end_line != self.start_line else ""
        return f"{self.path}:{self.start_line}{end}"


@dataclass(frozen=True, slots=True)
class Dependency:
    """A static dependency observed in one source file."""

    source_path: str
    target: str
    kind: str
    line: int

    @property
    def citation(self) -> str:
        return f"{self.source_path}:{self.line}"


@dataclass(frozen=True, slots=True)
class Chunk:
    """A retrievable, source-addressable section of a file."""

    path: str
    start_line: int
    end_line: int
    content: str
    language: str
    symbol: str = ""

    @property
    def citation(self) -> str:
        end = f"-{self.end_line}" if self.end_line != self.start_line else ""
        return f"{self.path}:{self.start_line}{end}"


@dataclass(frozen=True, slots=True)
class ScannedFile:
    """A text file accepted by the secure repository scanner."""

    path: str
    language: str
    size_bytes: int
    sha256: str
    line_count: int
    text: str
    symbols: tuple[Symbol, ...] = ()
    dependencies: tuple[Dependency, ...] = ()
    chunks: tuple[Chunk, ...] = ()
    is_entry_point: bool = False
    mtime_ns: int = 0
    ctime_ns: int = 0
    provenance: Provenance = "source"
    stale: bool = False
    cached_chunk_count: int = 0
    cached_symbol_count: int = 0
    cached_dependency_count: int = 0
    facts_materialized: bool = True


@dataclass(slots=True)
class ScanStats:
    """Stable counters suitable for CLI and API output."""

    discovered_files: int = 0
    indexed_files: int = 0
    indexed_bytes: int = 0
    languages: dict[str, int] = field(default_factory=dict)
    skipped: dict[str, int] = field(default_factory=dict)
    content_reads: int = 0
    parsed_files: int = 0

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


@dataclass(slots=True)
class ScanResult:
    """Complete output from one deterministic repository scan."""

    root: Path
    files: list[ScannedFile]
    stats: ScanStats
    warnings: list[str] = field(default_factory=list)
    analysis_version: str = ANALYSIS_VERSION
    temporarily_unreadable: tuple[str, ...] = ()
    base_generation: int | None = None
    repository_identity: str = ""
    base_scan_revision: int | None = None
    fingerprints: AnalysisFingerprints | None = None
    refresh_mode: Literal["auto", "always", "never", "rebuild"] = "auto"


@dataclass(frozen=True, slots=True)
class Evidence:
    """A ranked source excerpt returned by retrieval."""

    path: str
    start_line: int
    end_line: int
    content: str
    score: float
    symbol: str = ""
    reason: str = "full-text match"
    generation: int = 0

    @property
    def citation(self) -> str:
        end = f"-{self.end_line}" if self.end_line != self.start_line else ""
        return f"{self.path}:{self.start_line}{end}"


@dataclass(frozen=True, slots=True)
class IndexUpdate:
    """Incremental index update counters."""

    added: int
    changed: int
    unchanged: int
    removed: int
    chunks: int
    stale: int = 0
    content_generation: int = 0
    scan_revision: int = 0

    @property
    def generation(self) -> int:
        """Deprecated compatibility alias for ``content_generation``."""

        return self.content_generation


@dataclass(frozen=True, slots=True)
class IndexSnapshot:
    """One transactionally consistent index state used to seed a scan."""

    content_generation: int
    scan_revision: int
    fingerprints: AnalysisFingerprints | None
    files: tuple[ScannedFile, ...]
    skipped: tuple[tuple[str, int], ...] = ()
    warnings: tuple[str, ...] = ()
    temporarily_unreadable: tuple[str, ...] = ()
    dependency_resolver_fingerprint: str | None = None

    @property
    def generation(self) -> int:
        """Deprecated compatibility alias for ``content_generation``."""

        return self.content_generation

    @property
    def analysis_version(self) -> str:
        """Deprecated composite identity retained for older integrations."""

        if self.fingerprints is None:
            return ""
        return (
            f"scan={self.fingerprints.scan[:16]}:"
            f"parser={self.fingerprints.parser[:16]}:"
            f"terms={self.fingerprints.term_index[:16]}"
        )


@dataclass(frozen=True, slots=True)
class Answer:
    """An answer whose evidence has already been validated."""

    text: str
    evidence: tuple[Evidence, ...]
    confidence: Confidence
    provider: str
