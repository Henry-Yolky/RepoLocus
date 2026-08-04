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
        "of",
        "on",
        "or",
        "the",
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
