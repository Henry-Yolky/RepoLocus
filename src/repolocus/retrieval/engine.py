"""Deterministic structured retrieval with reciprocal-rank fusion."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from repolocus.index.store import (
    MAX_RETRIEVAL_LIMIT,
    RepositoryIndex,
    _validate_retrieval_limit,
)
from repolocus.models import Chunk, Evidence
from repolocus.retrieval.terms import document_terms, literal_query_terms

QueryIntent = Literal[
    "identifier",
    "path",
    "definition",
    "references",
    "dependency",
    "configuration",
    "architecture",
    "natural_language",
]

_RRF_K = 60
_SPECIFIC_QUERY_MINIMUM_COVERAGE = 0.75
_QUALIFIED_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*(?:(?:::|\.)[A-Za-z_$][\w$]*)*")
_RELATIONSHIP_TARGET = re.compile(
    rf"(?:\b(?:calls?|uses?|references?|imports?|depends?\s+on)\s+|"
    rf"(?:调用|使用|引用|导入|依赖)\s*)({_QUALIFIED_IDENTIFIER.pattern})",
    re.IGNORECASE,
)
_DIRECT_IDENTIFIER_QUERY = re.compile(
    rf"\s*(?:(?:where\s+is|find|locate)\s+(?:the\s+)?)?"
    rf"{_QUALIFIED_IDENTIFIER.pattern}(?:\(\))?\s*[?!.]?\s*",
    re.IGNORECASE,
)
_OUTBOUND_RELATIONSHIP = re.compile(
    r"\b(?:does|do)\b(?P<source>[^\r\n?]{1,120}?)"
    r"\b(?P<verb>imports?|depends?|have|has)\b"
    r"(?P<remainder>[^\r\n?]{0,120})",
    re.IGNORECASE,
)
_ENTITY_DESCRIPTORS = frozenset(
    {
        "a",
        "an",
        "class",
        "component",
        "dependencies",
        "dependency",
        "entry",
        "file",
        "function",
        "method",
        "module",
        "package",
        "point",
        "service",
        "the",
    }
)
_MINIMUM_RELEVANCE: dict[QueryIntent, float] = {
    "identifier": 0.02,
    "path": 0.02,
    "definition": 0.02,
    "references": 0.02,
    "dependency": 0.02,
    "configuration": 0.02,
    "architecture": 0.02,
    "natural_language": 0.02,
}


@dataclass(frozen=True, slots=True)
class RetrievalHit:
    chunk_id: int
    retriever: str
    rank: int
    raw_score: float | None
    features: Mapping[str, float]


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    evidence: tuple[Evidence, ...]
    confidence: float
    rejected_reason: str | None
    intent: QueryIntent
    hits: tuple[RetrievalHit, ...] = ()
    suppressed: tuple[tuple[int, str], ...] = ()


@dataclass(slots=True)
class _Candidate:
    chunk: Chunk
    score: float = 0.0
    reasons: set[str] = field(default_factory=set)


def classify_query_intent(query: str) -> QueryIntent:
    """Classify only intents that have a distinct deterministic retrieval path."""

    value = query.strip()
    folded = value.casefold()
    caller_question = re.search(
        r"\b(?:who\s+calls?|callers?|references?)\b|"
        r"\b(?:which|what)\s+(?:[\w$.-]+\s+){0,4}"
        r"(?:class(?:es)?|files?|modules?|packages?|components?|services?|functions?|methods?|"
        r"entry\s+points?)\s+(?:calls?|uses?|references?)\b|"
        r"\bwhere\b[^\r\n]{0,80}\b(?:class|file|module|function|method|entry\s+point)\b"
        r"[^\r\n]{0,40}\b(?:calls?|uses?|references?)\b|"
        r"谁调用|调用者|引用|哪(?:些|个)[^\r\n]{0,32}(?:调用|使用|引用)",
        folded,
    )
    if caller_question:
        return "references"
    if re.search(r"\b(imports?|depends?|dependency|dependencies)\b|依赖|导入", folded):
        return "dependency"
    if re.search(r"\b(defined?|definition|implemented?|implementation)\b|定义|实现", folded):
        return "definition"
    if re.search(r"\b(config|configuration|setting|settings)\b|配置", folded):
        return "configuration"
    if re.search(r"\b(architecture|data[ -]?flow|runtime flow)\b|架构|数据流", folded):
        return "architecture"
    if re.search(r"(?:^|\s)[\w.-]+/[\w./-]+|\.[A-Za-z0-9]{1,8}\b", value):
        return "path"
    tokens = re.findall(r"[A-Za-z_$][\w$]*", value)
    if (
        len(tokens) == 1
        or any("_" in token for token in tokens)
        or re.search(r"[a-z0-9][A-Z]", value)
    ):
        return "identifier"
    return "natural_language"


def _specific_identifier_groups(query: str) -> tuple[frozenset[str], ...]:
    """Return acceptable exact forms for each explicit compound identifier."""

    output: list[frozenset[str]] = []
    normalized = unicodedata.normalize("NFKC", query)
    for match in _QUALIFIED_IDENTIFIER.finditer(normalized):
        identifier = match.group(0)
        if not (
            "." in identifier
            or "::" in identifier
            or "_" in identifier
            or (
                any(character.islower() for character in identifier)
                and any(character.isupper() for character in identifier[1:])
            )
        ):
            continue
        folded = identifier.casefold()
        alternatives = {folded}
        if "." in folded or "::" in folded:
            alternatives.add(re.split(r"::|\.", folded)[-1])
        output.append(frozenset(alternatives))
    return tuple(output)


def _identifier_forms(identifier: str) -> frozenset[str]:
    folded = unicodedata.normalize("NFKC", identifier).casefold()
    forms = {folded}
    if "." in folded or "::" in folded:
        forms.add(re.split(r"::|\.", folded)[-1])
    return frozenset(forms)


def _entity_identifier_groups(value: str) -> tuple[frozenset[str], ...]:
    groups: list[frozenset[str]] = []
    for match in _QUALIFIED_IDENTIFIER.finditer(value):
        forms = _identifier_forms(match.group(0))
        if len(forms) == 1 and next(iter(forms)) in _ENTITY_DESCRIPTORS:
            continue
        groups.append(forms)
    return tuple(groups)


def _explicit_outbound_entities(
    query: str,
) -> tuple[tuple[frozenset[str], ...], tuple[frozenset[str], ...]] | None:
    """Return source and target identifiers for an explicit outbound relation."""

    match = _OUTBOUND_RELATIONSHIP.search(unicodedata.normalize("NFKC", query))
    if match is None:
        return None
    remainder = match.group("remainder")
    verb = match.group("verb").casefold()
    if verb.startswith("depend") or verb in {"have", "has"}:
        target_match = re.match(r"\s+on\b(?P<target>.*)", remainder, re.IGNORECASE)
    else:
        target_match = re.match(
            r"\s+(?:(?:for|from)\s+)?(?P<target>.*)",
            remainder,
            re.IGNORECASE,
        )
    if target_match is None:
        return None
    source_groups = _entity_identifier_groups(match.group("source"))
    target_groups = _entity_identifier_groups(target_match.group("target"))
    if not source_groups or not target_groups:
        return None
    return source_groups, target_groups


def _direct_underscore_identifier(query: str) -> frozenset[str] | None:
    if _DIRECT_IDENTIFIER_QUERY.fullmatch(query) is None:
        return None
    identifiers = list(_QUALIFIED_IDENTIFIER.finditer(query))
    if not identifiers or "_" not in identifiers[-1].group(0):
        return None
    return _identifier_forms(identifiers[-1].group(0))


def _chunk_contains_identifier(chunk: Chunk, forms: frozenset[str]) -> bool:
    for value in (chunk.path, chunk.symbol, chunk.content):
        normalized = unicodedata.normalize("NFKC", value).casefold()
        if any(re.search(rf"(?<![\w$]){re.escape(form)}(?![\w$])", normalized) for form in forms):
            return True
    return False


def _relationship_target_terms(query: str) -> frozenset[str]:
    """Return exact symbol forms explicitly named after a relationship verb."""

    normalized = unicodedata.normalize("NFKC", query)
    targets: set[str] = set()
    for match in _RELATIONSHIP_TARGET.finditer(normalized):
        identifier = match.group(1).casefold()
        targets.add(identifier)
        if "." in identifier or "::" in identifier:
            targets.add(re.split(r"::|\.", identifier)[-1])
    return frozenset(targets)


def _dependency_direction(query: str, intent: QueryIntent) -> str | None:
    """Return the graph direction explicitly requested by the query."""

    if intent == "references":
        return "dependent of"
    if intent != "dependency":
        return None
    folded = query.casefold()
    reverse_question = re.search(
        r"\b(?:who|what)\s+(?:modules?\s+|files?\s+|packages?\s+)?"
        r"(?:imports?|depends?\s+on)\b|"
        r"\bwhich\s+(?:[\w$.-]+\s+){0,3}"
        r"(?:modules?|files?|packages?|class(?:es)?|components?|services?)\s+"
        r"(?:imports?|depends?\s+on)\b",
        folded,
    )
    if reverse_question or re.search(r"(?:谁|哪(?:些|个)[^\r\n]{0,24})(?:导入|依赖)", query):
        return "dependent of"
    return "dependency of"


def _is_specific_query(query: str, strongest_chunk: Chunk | None) -> bool:
    """Require strong literal coverage before applying the stronger text rank."""

    terms = set(literal_query_terms(query))
    has_cjk = re.search(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]", query) is not None
    minimum_terms = 1 if has_cjk else 2
    if len(terms) < minimum_terms or strongest_chunk is None:
        return False
    indexed_terms = set(
        document_terms(
            strongest_chunk.path,
            strongest_chunk.symbol,
            strongest_chunk.content,
        )
    )
    return len(terms & indexed_terms) / len(terms) >= _SPECIFIC_QUERY_MINIMUM_COVERAGE


def _line_iou(first: Chunk, second: Chunk) -> float:
    if first.path != second.path:
        return 0.0
    intersection = max(
        0,
        min(first.end_line, second.end_line) - max(first.start_line, second.start_line) + 1,
    )
    union = max(first.end_line, second.end_line) - min(first.start_line, second.start_line) + 1
    return intersection / union if union else 0.0


class RetrievalEngine:
    """Fuse full-text, normalized symbols, and resolved graph neighbors."""

    def __init__(
        self,
        index: RepositoryIndex,
        *,
        synonyms: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        self._index = index
        self._synonyms = synonyms

    def search(self, query: str, limit: int = 8) -> list[Evidence]:
        """Compatibility API returning only the accepted evidence projection."""

        return list(self.search_result(query, limit).evidence)

    def search_result(self, query: str, limit: int = 8) -> RetrievalResult:
        """Return diagnostics and at most ``MAX_RETRIEVAL_LIMIT`` evidence items."""

        intent = classify_query_intent(query) if isinstance(query, str) else "natural_language"
        limit = _validate_retrieval_limit(limit)
        if not isinstance(query, str) or not query.strip():
            return RetrievalResult((), 0.0, "invalid_or_empty_query", intent)
        with self._index.consistent_read() as generation:
            return self._search_snapshot(query, limit, generation, intent)

    @staticmethod
    def _weights(
        intent: QueryIntent,
        *,
        specific_query: bool = False,
    ) -> dict[str, float]:
        return {
            "full_text": 3.2 if specific_query else 1.2,
            "symbol_exact": 3.2 if intent in {"identifier", "definition"} else 2.8,
            "symbol_expanded": 1.8,
            "symbol_partial": 1.6,
            "reverse_dependency": 3.2 if intent == "references" else 1.4,
            "outbound_dependency": 2.6 if intent == "dependency" else 1.2,
        }

    def _search_snapshot(
        self,
        query: str,
        limit: int,
        generation: int,
        intent: QueryIntent,
    ) -> RetrievalResult:
        candidate_limit = min(max(limit * 8, 32), MAX_RETRIEVAL_LIMIT)
        fts_hits = self._index.search_chunks(query, candidate_limit, synonyms=self._synonyms)
        symbol_hits = self._index.find_symbol_chunks(
            query, candidate_limit, synonyms=self._synonyms
        )
        candidates: dict[int, _Candidate] = {}
        all_hits: list[RetrievalHit] = []
        weights = self._weights(
            intent,
            specific_query=_is_specific_query(
                query,
                fts_hits[0].chunk if fts_hits else None,
            ),
        )
        scored_candidates: set[tuple[str, int]] = set()

        def add_hit(
            chunk_id: int,
            chunk: Chunk,
            retriever: str,
            rank: int,
            raw_score: float | None,
            reason: str,
        ) -> None:
            candidate = candidates.setdefault(chunk_id, _Candidate(chunk))
            candidate.reasons.add(reason)
            score_key = (retriever, chunk_id)
            if score_key in scored_candidates:
                return
            scored_candidates.add(score_key)
            hit = RetrievalHit(
                chunk_id=chunk_id,
                retriever=retriever,
                rank=rank,
                raw_score=raw_score,
                features={"rrf_weight": weights[retriever], "rrf_k": float(_RRF_K)},
            )
            candidate.score += weights[retriever] / (_RRF_K + rank)
            all_hits.append(hit)

        for rank, hit in enumerate(fts_hits, 1):
            add_hit(
                hit.chunk_id,
                hit.chunk,
                "full_text",
                rank,
                hit.rank,
                "full-text match",
            )

        symbol_ranks: dict[str, int] = defaultdict(int)
        specific_identifier_groups = _specific_identifier_groups(query)
        graph_direction = _dependency_direction(query, intent)
        relationship_targets = (
            _relationship_target_terms(query) if graph_direction == "dependent of" else frozenset()
        )
        if graph_direction == "dependent of":
            required_exact_groups = tuple(
                group
                for group in specific_identifier_groups
                if not group.isdisjoint(relationship_targets)
            )
        elif intent == "definition" or (
            intent == "identifier" and _DIRECT_IDENTIFIER_QUERY.fullmatch(query)
        ):
            required_exact_groups = specific_identifier_groups[:1]
        else:
            required_exact_groups = ()
        exact_symbol_paths: list[str] = []
        seen_exact_symbol_paths: set[str] = set()
        exact_symbol_names: set[str] = set()
        exact_symbol_paths_by_form: dict[str, list[str]] = defaultdict(list)
        required_exact_chunk_ids: set[int] = set()
        for hit in symbol_hits:
            retriever = f"symbol_{hit.match}"
            symbol_ranks[retriever] += 1
            label = (
                f"exact symbol match: {hit.symbol_name}"
                if hit.match == "exact"
                else f"query-expansion symbol match: {hit.symbol_name}"
                if hit.match == "expanded"
                else f"partial symbol match: {hit.symbol_name}"
            )
            add_hit(
                hit.chunk_id,
                hit.chunk,
                retriever,
                symbol_ranks[retriever],
                None,
                label,
            )
            symbol_name = unicodedata.normalize("NFKC", hit.symbol_name).casefold()
            if hit.match == "exact":
                symbol_forms = _identifier_forms(symbol_name)
                exact_symbol_names.update(symbol_forms)
                if any(not group.isdisjoint(symbol_forms) for group in required_exact_groups):
                    required_exact_chunk_ids.add(hit.chunk_id)
                for form in symbol_forms:
                    paths = exact_symbol_paths_by_form[form]
                    if hit.chunk.path not in paths:
                        paths.append(hit.chunk.path)
                valid_relationship_target = not relationship_targets or not symbol_forms.isdisjoint(
                    relationship_targets
                )
                if valid_relationship_target and hit.chunk.path not in seen_exact_symbol_paths:
                    seen_exact_symbol_paths.add(hit.chunk.path)
                    exact_symbol_paths.append(hit.chunk.path)

        if graph_direction == "dependent of" and relationship_targets and not exact_symbol_paths:
            return RetrievalResult((), 0.0, "no_candidates", intent, tuple(all_hits))

        unresolved_identifiers = [
            group for group in required_exact_groups if group.isdisjoint(exact_symbol_names)
        ]
        exact_text_candidate_ids: set[int] | None = None
        exact_text_seed_paths: list[str] = []
        if unresolved_identifiers:
            direct_underscore = _direct_underscore_identifier(query)
            if (
                intent == "identifier"
                and direct_underscore is not None
                and direct_underscore in unresolved_identifiers
            ):
                exact_text_candidate_ids = {
                    hit.chunk_id
                    for hit in fts_hits
                    if _chunk_contains_identifier(hit.chunk, direct_underscore)
                }
                if not exact_text_candidate_ids:
                    return RetrievalResult((), 0.0, "no_candidates", intent, tuple(all_hits))
                exact_text_seed_paths = list(
                    dict.fromkeys(
                        hit.chunk.path
                        for hit in fts_hits
                        if hit.chunk_id in exact_text_candidate_ids
                    )
                )
            else:
                return RetrievalResult((), 0.0, "no_candidates", intent, tuple(all_hits))

        outbound_source_paths: list[str] = []
        outbound_target_paths: set[str] = set()
        outbound_entities = (
            _explicit_outbound_entities(query) if graph_direction == "dependency of" else None
        )
        if outbound_entities is not None:
            source_groups, target_groups = outbound_entities
            for group in reversed(source_groups):
                outbound_source_paths = list(
                    dict.fromkeys(
                        path
                        for form in sorted(group)
                        for path in exact_symbol_paths_by_form.get(form, ())
                    )
                )
                if outbound_source_paths:
                    break
            target_group = target_groups[0]
            outbound_target_paths = {
                path for form in target_group for path in exact_symbol_paths_by_form.get(form, ())
            }
            if not outbound_source_paths or not outbound_target_paths:
                return RetrievalResult((), 0.0, "no_candidates", intent, tuple(all_hits))

        direct = sorted(
            candidates.values(),
            key=lambda item: (-item.score, item.chunk.path, item.chunk.start_line),
        )
        maximum_seed_paths = min(limit, 8)
        if graph_direction == "dependent of" and exact_symbol_paths:
            seed_paths = exact_symbol_paths[:maximum_seed_paths]
        elif graph_direction == "dependent of" and required_exact_groups:
            seed_paths = []
        elif outbound_source_paths:
            seed_paths = outbound_source_paths[:maximum_seed_paths]
        elif exact_text_seed_paths:
            seed_paths = exact_text_seed_paths[:maximum_seed_paths]
        else:
            seed_paths = []
            seen_seed_paths: set[str] = set()
            for candidate in direct:
                if candidate.chunk.path in seen_seed_paths:
                    continue
                seen_seed_paths.add(candidate.chunk.path)
                seed_paths.append(candidate.chunk.path)
                if len(seed_paths) >= maximum_seed_paths:
                    break
        graph_ranks: dict[str, int] = defaultdict(int)
        graph_candidate_ranks: dict[tuple[str, int], int] = {}
        graph_candidates: set[int] = set()
        for hit in self._index.dependency_neighbors(
            seed_paths,
            candidate_limit,
            direction=graph_direction,
        ):
            if outbound_target_paths and hit.chunk.path not in outbound_target_paths:
                continue
            retriever = (
                "reverse_dependency" if hit.direction == "dependent of" else "outbound_dependency"
            )
            graph_key = (retriever, hit.chunk_id)
            rank = graph_candidate_ranks.get(graph_key)
            if rank is None:
                graph_ranks[retriever] += 1
                rank = graph_ranks[retriever]
                graph_candidate_ranks[graph_key] = rank
            add_hit(
                hit.chunk_id,
                hit.chunk,
                retriever,
                rank,
                None,
                f"{hit.direction} {hit.seed_path}",
            )
            graph_candidates.add(hit.chunk_id)

        allowed_candidate_ids: set[int] | None = None
        if graph_direction is not None:
            allowed_candidate_ids = graph_candidates
        elif exact_text_candidate_ids is not None:
            allowed_candidate_ids = exact_text_candidate_ids | graph_candidates
        elif required_exact_groups and not (
            intent == "definition" and re.search(r"\bdeclarations?\b", query, re.IGNORECASE)
        ):
            allowed_candidate_ids = required_exact_chunk_ids
        rankable_candidates = candidates.items()
        if allowed_candidate_ids is not None:
            rankable_candidates = (
                item for item in rankable_candidates if item[0] in allowed_candidate_ids
            )
        ranked = sorted(
            rankable_candidates,
            key=lambda item: (-item[1].score, item[1].chunk.path, item[1].chunk.start_line),
        )
        if not ranked:
            return RetrievalResult((), 0.0, "no_candidates", intent, tuple(all_hits))
        partial_only = bool(all_hits) and all(hit.retriever == "symbol_partial" for hit in all_hits)
        if (partial_only and intent != "identifier") or ranked[0][1].score < _MINIMUM_RELEVANCE[
            intent
        ]:
            return RetrievalResult(
                (),
                0.0,
                "below_minimum_relevance",
                intent,
                tuple(all_hits),
            )

        selected: list[tuple[int, _Candidate]] = []
        suppressed: list[tuple[int, str]] = []
        seen_hashes: set[str] = set()
        selected_paths: set[str] = set()
        selected_by_path: dict[str, list[Chunk]] = defaultdict(list)
        remaining = ranked.copy()
        maximum_score = ranked[0][1].score
        while remaining and len(selected) < limit:
            best_index = 0
            best_value = float("-inf")
            for index, (_chunk_id, candidate) in enumerate(remaining):
                path_penalty = 0.18 if candidate.chunk.path in selected_paths else 0.0
                value = candidate.score / maximum_score - path_penalty
                if value > best_value:
                    best_index = index
                    best_value = value
            chunk_id, candidate = remaining.pop(best_index)
            digest = hashlib.sha256(candidate.chunk.content.encode("utf-8")).hexdigest()
            if digest in seen_hashes:
                suppressed.append((chunk_id, "duplicate_content"))
                continue
            if any(
                _line_iou(candidate.chunk, chosen) >= 0.8
                for chosen in selected_by_path[candidate.chunk.path]
            ):
                suppressed.append((chunk_id, "overlapping_range"))
                continue
            seen_hashes.add(digest)
            selected_paths.add(candidate.chunk.path)
            selected_by_path[candidate.chunk.path].append(candidate.chunk)
            selected.append((chunk_id, candidate))

        confidence = min(1.0, selected[0][1].score / 0.08) if selected else 0.0
        evidence = tuple(
            Evidence(
                path=candidate.chunk.path,
                start_line=candidate.chunk.start_line,
                end_line=candidate.chunk.end_line,
                content=candidate.chunk.content,
                score=round(candidate.score, 6),
                symbol=candidate.chunk.symbol,
                reason="; ".join(sorted(candidate.reasons)),
                generation=generation,
            )
            for _chunk_id, candidate in selected
        )
        return RetrievalResult(
            evidence,
            round(confidence, 6),
            None if evidence else "all_candidates_suppressed",
            intent,
            tuple(all_hits),
            tuple(suppressed),
        )
