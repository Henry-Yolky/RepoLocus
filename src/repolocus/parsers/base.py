"""Parser plugin contracts and registry.

The scanner deliberately depends on this small interface rather than on a
particular parsing implementation.  Third-party parsers can therefore be
registered without changing repository traversal or its security policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from repolocus.models import Chunk, Dependency, Symbol

DEFAULT_MAX_DEPENDENCIES_PER_FILE = 10_000
DEFAULT_MAX_SYMBOLS_PER_FILE = 10_000
DEFAULT_MAX_CHUNKS_PER_FILE = 10_000


@dataclass(frozen=True, slots=True)
class ParseResult:
    """Language-neutral facts extracted from one source file."""

    symbols: tuple[Symbol, ...] = ()
    dependencies: tuple[Dependency, ...] = ()
    chunks: tuple[Chunk, ...] = ()
    is_entry_point: bool = False


class SourceParser(Protocol):
    """Protocol implemented by language parser plugins."""

    languages: frozenset[str]
    cache_key: str
    priority: int

    def parse(
        self,
        path: str,
        text: str,
        language: str,
        *,
        max_chunk_lines: int,
        max_chunk_chars: int,
        max_dependencies_per_file: int = DEFAULT_MAX_DEPENDENCIES_PER_FILE,
        max_symbols_per_file: int = DEFAULT_MAX_SYMBOLS_PER_FILE,
        max_chunks_per_file: int = DEFAULT_MAX_CHUNKS_PER_FILE,
    ) -> ParseResult:
        """Extract source facts from *text*."""


class ParserRegistry:
    """A deterministic registry of language parser plugins."""

    def __init__(self) -> None:
        self._parsers: dict[str, SourceParser] = {}
        self._frozen_manifest: tuple[tuple[str, tuple[str, ...], int], ...] | None = None

    def register(self, parser: SourceParser, *, replace: bool = False) -> None:
        """Register *parser* for all of its languages.

        Accidental replacement is rejected because plugin import order should
        never silently change scan results.
        """

        if self._frozen_manifest is not None:
            raise RuntimeError("a frozen parser registry cannot be modified")
        if not parser.languages:
            raise ValueError("a parser must declare at least one language")
        cache_key = getattr(parser, "cache_key", "")
        if (
            not isinstance(cache_key, str)
            or not cache_key
            or len(cache_key) > 128
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+/-]*", cache_key) is None
        ):
            raise ValueError("a parser must declare a stable, bounded cache_key")
        priority = getattr(parser, "priority", 0)
        if (
            isinstance(priority, bool)
            or not isinstance(priority, int)
            or not -1000 <= priority <= 1000
        ):
            raise ValueError("parser priority must be an integer between -1000 and 1000")
        languages = frozenset(parser.languages)
        if any(
            not isinstance(language, str)
            or not language
            or len(language) > 64
            or re.fullmatch(r"[a-z0-9][a-z0-9_+-]*", language) is None
            for language in languages
        ):
            raise ValueError("parser languages must use bounded normalized identifiers")
        collisions = sorted(language for language in languages if language in self._parsers)
        if collisions and not replace:
            joined = ", ".join(collisions)
            raise ValueError(f"parser already registered for: {joined}")
        for language in sorted(languages):
            self._parsers[language] = parser

    def parser_for(self, language: str) -> SourceParser:
        """Return the plugin for *language* or raise a clear error."""

        try:
            return self._parsers[language]
        except KeyError as exc:
            raise ValueError(f"unsupported parser language: {language}") from exc

    @property
    def languages(self) -> tuple[str, ...]:
        """Return registered language names in stable order."""

        return tuple(sorted(self._parsers))

    def cache_manifest(self) -> tuple[dict[str, object], ...]:
        """Return a registration-order-independent parser cache manifest."""

        return tuple(
            {
                "cache_key": cache_key,
                "languages": list(languages),
                "priority": priority,
            }
            for cache_key, languages, priority in self._cache_records()
        )

    def frozen_copy(self) -> ParserRegistry:
        """Snapshot parser selection and cache identity for one scanner lifetime."""

        frozen = ParserRegistry()
        frozen._parsers = dict(self._parsers)
        frozen._frozen_manifest = self._cache_records()
        return frozen

    def _cache_records(self) -> tuple[tuple[str, tuple[str, ...], int], ...]:
        if self._frozen_manifest is not None:
            return self._frozen_manifest
        return self._current_cache_records()

    def _current_cache_records(self) -> tuple[tuple[str, tuple[str, ...], int], ...]:
        grouped: dict[int, tuple[SourceParser, set[str]]] = {}
        for language, parser in self._parsers.items():
            key = id(parser)
            if key not in grouped:
                grouped[key] = (parser, set())
            grouped[key][1].add(language)
        records = [
            (
                parser.cache_key,
                tuple(sorted(languages)),
                getattr(parser, "priority", 0),
            )
            for parser, languages in grouped.values()
        ]
        return tuple(
            sorted(
                records,
                key=lambda item: (
                    item[1],
                    item[2],
                    item[0],
                ),
            )
        )

    def require_stable(self) -> None:
        """Fail closed if a frozen plugin changes its declared cache identity."""

        if self._frozen_manifest is None:
            return
        try:
            current = self._current_cache_records()
        except (AttributeError, TypeError, ValueError) as exc:
            raise RuntimeError("a frozen parser changed its cache identity") from exc
        if current != self._frozen_manifest:
            raise RuntimeError("a frozen parser changed its cache identity")

    def parse(
        self,
        path: str,
        text: str,
        language: str,
        *,
        max_chunk_lines: int = 160,
        max_chunk_chars: int = 16_000,
        max_dependencies_per_file: int = DEFAULT_MAX_DEPENDENCIES_PER_FILE,
        max_symbols_per_file: int = DEFAULT_MAX_SYMBOLS_PER_FILE,
        max_chunks_per_file: int = DEFAULT_MAX_CHUNKS_PER_FILE,
    ) -> ParseResult:
        for name, value in (
            ("max_chunk_lines", max_chunk_lines),
            ("max_chunk_chars", max_chunk_chars),
            ("max_dependencies_per_file", max_dependencies_per_file),
            ("max_symbols_per_file", max_symbols_per_file),
            ("max_chunks_per_file", max_chunks_per_file),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        return self.parser_for(language).parse(
            path,
            text,
            language,
            max_chunk_lines=max_chunk_lines,
            max_chunk_chars=max_chunk_chars,
            max_dependencies_per_file=max_dependencies_per_file,
            max_symbols_per_file=max_symbols_per_file,
            max_chunks_per_file=max_chunks_per_file,
        )
