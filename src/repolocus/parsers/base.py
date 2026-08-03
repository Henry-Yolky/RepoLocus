"""Parser plugin contracts and registry.

The scanner deliberately depends on this small interface rather than on a
particular parsing implementation.  Third-party parsers can therefore be
registered without changing repository traversal or its security policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from repolocus.models import Chunk, Dependency, Symbol


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

    def parse(
        self,
        path: str,
        text: str,
        language: str,
        *,
        max_chunk_lines: int,
        max_chunk_chars: int,
    ) -> ParseResult:
        """Extract source facts from *text*."""


class ParserRegistry:
    """A deterministic registry of language parser plugins."""

    def __init__(self) -> None:
        self._parsers: dict[str, SourceParser] = {}

    def register(self, parser: SourceParser, *, replace: bool = False) -> None:
        """Register *parser* for all of its languages.

        Accidental replacement is rejected because plugin import order should
        never silently change scan results.
        """

        if not parser.languages:
            raise ValueError("a parser must declare at least one language")
        collisions = sorted(language for language in parser.languages if language in self._parsers)
        if collisions and not replace:
            joined = ", ".join(collisions)
            raise ValueError(f"parser already registered for: {joined}")
        for language in sorted(parser.languages):
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

    def parse(
        self,
        path: str,
        text: str,
        language: str,
        *,
        max_chunk_lines: int = 160,
        max_chunk_chars: int = 16_000,
    ) -> ParseResult:
        if max_chunk_lines <= 0:
            raise ValueError("max_chunk_lines must be positive")
        if max_chunk_chars <= 0:
            raise ValueError("max_chunk_chars must be positive")
        return self.parser_for(language).parse(
            path,
            text,
            language,
            max_chunk_lines=max_chunk_lines,
            max_chunk_chars=max_chunk_chars,
        )
