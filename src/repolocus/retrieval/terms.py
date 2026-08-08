"""Deterministic terms for multilingual source-code retrieval."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence

_WORD = re.compile(r"[^\W_]+(?:_[^\W_]+)*", re.UNICODE)
_IDENTIFIER_PART = re.compile(
    r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+|[A-Z]+",
)
_CJK_RUN = re.compile(
    r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff"
    r"\u3040-\u30ff\u31f0-\u31ff\uac00-\ud7af]+"
)
_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "be",
        "does",
        "for",
        "from",
        "how",
        "in",
        "is",
        "it",
        "locate",
        "of",
        "on",
        "or",
        "the",
        "that",
        "this",
        "to",
        "was",
        "what",
        "where",
        "which",
        "who",
        "why",
        "with",
    }
)


def _normalized(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _append_unique(output: list[str], seen: set[str], value: str) -> None:
    normalized = _normalized(value)[:128]
    if not normalized or normalized in seen or normalized in _STOPWORDS:
        return
    seen.add(normalized)
    output.append(normalized)


def _cjk_ngrams(value: str) -> tuple[str, ...]:
    terms: list[str] = []
    for match in _CJK_RUN.finditer(value):
        run = match.group(0)
        if len(run) == 1:
            terms.append(run)
            continue
        for width in (2, 3):
            if len(run) < width:
                continue
            terms.extend(run[index : index + width] for index in range(len(run) - width + 1))
    return tuple(terms)


def _cjk_coverage_terms(value: str) -> tuple[str, ...]:
    """Return bounded, position-spread anchors for one contiguous CJK run.

    Overlapping n-grams are highly correlated: ``配置在`` alone contains three
    generated terms for a longer question that starts the same way.  Coverage
    therefore uses the complete run plus at most three bigrams spread across
    its beginning, middle, and end.  Ranking may still use every n-gram.
    """

    if len(value) <= 2:
        return (value,)
    positions = {0, len(value) - 2}
    if len(value) >= 5:
        positions.add((len(value) - 2) // 2)
    return tuple(dict.fromkeys((value, *(value[index : index + 2] for index in sorted(positions)))))


def _lexical_terms(text: str, *, maximum: int) -> tuple[str, ...]:
    if not isinstance(text, str) or maximum <= 0:
        return ()
    normalized = unicodedata.normalize("NFKC", text)
    output: list[str] = []
    seen: set[str] = set()
    for match in _WORD.finditer(normalized):
        token = match.group(0)
        _append_unique(output, seen, token)
        for underscore_part in token.split("_"):
            _append_unique(output, seen, underscore_part)
            for identifier_part in _IDENTIFIER_PART.findall(underscore_part):
                _append_unique(output, seen, identifier_part)
        if len(output) >= maximum:
            return tuple(output[:maximum])
    for term in _cjk_ngrams(normalized):
        _append_unique(output, seen, term)
        if len(output) >= maximum:
            break
    return tuple(output[:maximum])


def literal_query_terms(query: str, *, maximum: int = 64) -> tuple[str, ...]:
    """Return only terms written by the user, without synonym expansion."""

    return _lexical_terms(query, maximum=maximum)


def is_cjk_term(term: str) -> bool:
    """Return whether a normalized term consists entirely of one CJK run."""

    return isinstance(term, str) and _CJK_RUN.fullmatch(term) is not None


def literal_query_term_groups(
    query: str,
    *,
    maximum: int = 64,
) -> tuple[tuple[str, ...], ...]:
    """Return the literal coverage groups required for a retrieval candidate.

    Non-CJK terms remain singleton groups so the index can apply a bounded
    coverage ratio across them. Each contiguous CJK run is represented by one
    group containing position-spread anchors, because counting every overlapping
    bigram and trigram would overstate coverage of one small matching fragment.
    """

    literal = literal_query_terms(query, maximum=maximum)
    if not literal:
        return ()
    available = set(literal)
    normalized = unicodedata.normalize("NFKC", query)
    cjk_groups: list[tuple[str, ...]] = []
    for match in _CJK_RUN.finditer(normalized):
        candidates = _cjk_coverage_terms(match.group(0))
        group: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            term = _normalized(candidate)[:128]
            if term in available and term not in seen:
                seen.add(term)
                group.append(term)
        if group:
            cjk_groups.append(tuple(group))

    groups: list[tuple[str, ...]] = []
    emitted_cjk_groups: set[int] = set()
    for term in literal:
        matching_groups = [index for index, group in enumerate(cjk_groups) if term in group]
        if matching_groups:
            for index in matching_groups:
                if index not in emitted_cjk_groups:
                    emitted_cjk_groups.add(index)
                    groups.append(cjk_groups[index])
            continue
        if _CJK_RUN.search(term):
            # Mixed CJK/non-CJK lexical tokens are represented by their
            # independently generated components.  If bounding left no CJK
            # component, retain the mixed token as a fail-closed requirement.
            if not cjk_groups:
                groups.append((term,))
            continue
        groups.append((term,))
    return tuple(groups)


def _morphological_expansions(term: str) -> tuple[str, ...]:
    """Return small language-agnostic English suffix variants, never semantics."""

    if not term.isascii() or not term.isalnum():
        return ()
    variants: list[str] = []
    if term.endswith("ies") and len(term) >= 5:
        variants.append(term[:-3] + "y")
    elif term.endswith("s") and not term.endswith("ss") and len(term) >= 5:
        variants.append(term[:-1])
    if term.endswith("ed") and len(term) >= 6:
        stem = term[:-2]
        variants.extend((stem, stem + "e"))
        if len(stem) >= 2 and stem[-1] == stem[-2]:
            variants.append(stem[:-1])
    elif term.endswith("ing") and len(term) >= 7:
        stem = term[:-3]
        variants.extend((stem, stem + "e"))
        if len(stem) >= 2 and stem[-1] == stem[-2]:
            variants.append(stem[:-1])
    return tuple(variants)


def query_terms(
    query: str,
    synonyms: Mapping[str, Sequence[str]] | None = None,
    *,
    maximum: int = 64,
) -> tuple[str, ...]:
    """Return normalized literal and explicitly configured synonym terms."""

    literal = list(literal_query_terms(query, maximum=maximum))
    if not literal or len(literal) >= maximum:
        return tuple(literal)
    output = list(literal)
    seen = set(literal)
    for term in literal:
        for expansion in _morphological_expansions(term):
            _append_unique(output, seen, expansion)
            if len(output) >= maximum:
                return tuple(output)
    if not synonyms:
        return tuple(output)
    normalized_query = _normalized(query.strip())
    lookup_keys = (normalized_query, *literal)
    for key in lookup_keys:
        for expansion in synonyms.get(key, ()):
            for term in _lexical_terms(expansion, maximum=maximum):
                _append_unique(output, seen, term)
                if len(output) >= maximum:
                    return tuple(output)
    return tuple(output)


def document_terms(*texts: str, maximum: int = 4096) -> tuple[str, ...]:
    """Return bounded terms for content, paths, symbols, and identifiers."""

    output: list[str] = []
    seen: set[str] = set()
    for value in texts:
        for term in _lexical_terms(value, maximum=maximum):
            _append_unique(output, seen, term)
            if len(output) >= maximum:
                return tuple(output)
    return tuple(output)
