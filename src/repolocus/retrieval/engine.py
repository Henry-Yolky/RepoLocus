"""Deterministic hybrid code retrieval."""

from __future__ import annotations

from dataclasses import dataclass, field

from repolocus.index.store import RepositoryIndex
from repolocus.models import Chunk, Evidence


@dataclass(slots=True)
class _Candidate:
    chunk: Chunk
    score: float = 0.0
    reasons: set[str] = field(default_factory=set)


class RetrievalEngine:
    """Combine FTS5, symbol matching, and direct dependency neighbors."""

    def __init__(self, index: RepositoryIndex) -> None:
        self._index = index

    def search(self, query: str, limit: int = 8) -> list[Evidence]:
        """Return ranked excerpts with one-based source line ranges.

        Punctuation-only input is intentionally treated as an empty query.  All
        FTS syntax is constructed from sanitized word tokens by the index.
        """

        if limit <= 0 or not isinstance(query, str) or not query.strip():
            return []
        candidate_limit = min(max(limit * 8, 32), 500)
        fts_hits = self._index.search_chunks(query, candidate_limit)
        symbol_hits = self._index.find_symbol_chunks(query, candidate_limit)
        if not fts_hits and not symbol_hits:
            return []

        candidates: dict[int, _Candidate] = {}
        strengths = [max(0.0, -hit.rank) for hit in fts_hits]
        maximum_strength = max(strengths, default=0.0)
        for position, (hit, strength) in enumerate(zip(fts_hits, strengths, strict=True)):
            normalized = strength / maximum_strength if maximum_strength else 0.0
            score = 8.0 * normalized + 2.0 / (position + 1)
            candidate = candidates.setdefault(hit.chunk_id, _Candidate(hit.chunk))
            candidate.score += score
            candidate.reasons.add("full-text match")

        for hit in symbol_hits:
            candidate = candidates.setdefault(hit.chunk_id, _Candidate(hit.chunk))
            if hit.match == "exact":
                candidate.score += 24.0
                candidate.reasons.add(f"exact symbol match: {hit.symbol_name}")
            elif hit.match == "expanded":
                candidate.score += 10.0
                candidate.reasons.add(f"query-expansion symbol match: {hit.symbol_name}")
            else:
                candidate.score += 12.0
                candidate.reasons.add(f"partial symbol match: {hit.symbol_name}")

        direct = sorted(
            candidates.values(),
            key=lambda item: (-item.score, item.chunk.path, item.chunk.start_line),
        )
        seed_scores: dict[str, float] = {}
        for candidate in direct:
            seed_scores[candidate.chunk.path] = max(
                seed_scores.get(candidate.chunk.path, 0.0), candidate.score
            )
        seed_paths = [
            path
            for path, _ in sorted(seed_scores.items(), key=lambda item: (-item[1], item[0]))[
                : min(limit, 8)
            ]
        ]
        for hit in self._index.dependency_neighbors(seed_paths, candidate_limit):
            candidate = candidates.setdefault(hit.chunk_id, _Candidate(hit.chunk))
            candidate.score += max(1.0, seed_scores.get(hit.seed_path, 1.0) * 0.25)
            candidate.reasons.add(f"{hit.direction} {hit.seed_path}")

        ranked = sorted(
            candidates.values(),
            key=lambda item: (-item.score, item.chunk.path, item.chunk.start_line),
        )[:limit]
        return [
            Evidence(
                path=candidate.chunk.path,
                start_line=candidate.chunk.start_line,
                end_line=candidate.chunk.end_line,
                content=candidate.chunk.content,
                score=round(candidate.score, 6),
                symbol=candidate.chunk.symbol,
                reason="; ".join(sorted(candidate.reasons)),
            )
            for candidate in ranked
        ]
