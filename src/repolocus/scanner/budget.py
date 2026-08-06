"""Transactional repository resource budgets for secure scans."""

from __future__ import annotations

from dataclasses import dataclass
from time import monotonic


@dataclass(frozen=True, slots=True)
class FactCounts:
    chunks: int = 0
    symbols: int = 0
    dependencies: int = 0

    def __post_init__(self) -> None:
        for name in ("chunks", "symbols", "dependencies"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} count must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class BudgetCheckpoint:
    entries: int
    bytes_seen: int
    chunks: int
    symbols: int
    dependencies: int


@dataclass(slots=True)
class ScanBudget:
    max_entries: int
    max_bytes: int
    max_chunks: int
    max_symbols: int
    max_dependencies: int
    deadline: float
    entries: int = 0
    bytes_seen: int = 0
    chunks: int = 0
    symbols: int = 0
    dependencies: int = 0
    exhausted_reason: str | None = None
    reported: bool = False

    def check_deadline(self) -> bool:
        if self.exhausted_reason is None and monotonic() > self.deadline:
            self.exhausted_reason = "scan deadline"
        return self.exhausted_reason is None

    def observe_entry(self) -> bool:
        if not self.check_deadline():
            return False
        if self.entries + 1 > self.max_entries:
            self.exhausted_reason = "repository file/entry count"
            return False
        self.entries += 1
        return True

    def observe_bytes(self, size: int) -> bool:
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError("observed byte count must be a non-negative integer")
        if not self.check_deadline():
            return False
        if self.bytes_seen + size > self.max_bytes:
            self.exhausted_reason = "repository byte count"
            return False
        self.bytes_seen += size
        return True

    def require_capacity(self, counts: FactCounts) -> bool:
        """Check capacity without consuming it."""

        if not self.check_deadline():
            return False
        for current, additional, maximum, reason in (
            (self.chunks, counts.chunks, self.max_chunks, "repository chunk count"),
            (self.symbols, counts.symbols, self.max_symbols, "repository symbol count"),
            (
                self.dependencies,
                counts.dependencies,
                self.max_dependencies,
                "repository dependency count",
            ),
        ):
            if current + additional > maximum:
                self.exhausted_reason = reason
                return False
        return True

    def commit_facts(self, counts: FactCounts) -> None:
        """Consume counts only after validation and a successful capacity check."""

        if not self.require_capacity(counts):
            raise RuntimeError(self.exhausted_reason or "repository fact budget exhausted")
        self.chunks += counts.chunks
        self.symbols += counts.symbols
        self.dependencies += counts.dependencies

    def checkpoint(self) -> BudgetCheckpoint:
        return BudgetCheckpoint(
            self.entries,
            self.bytes_seen,
            self.chunks,
            self.symbols,
            self.dependencies,
        )

    def restore(self, checkpoint: BudgetCheckpoint) -> None:
        """Roll back consumed counters for a directory whose identity changed."""

        self.entries = checkpoint.entries
        self.bytes_seen = checkpoint.bytes_seen
        self.chunks = checkpoint.chunks
        self.symbols = checkpoint.symbols
        self.dependencies = checkpoint.dependencies


def deadline_after(seconds: int) -> float:
    return monotonic() + seconds
