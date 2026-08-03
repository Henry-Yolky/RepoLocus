"""Language parser plugin layer."""

from __future__ import annotations

from repolocus.parsers.base import ParseResult, ParserRegistry, SourceParser
from repolocus.parsers.heuristic import HeuristicParser
from repolocus.parsers.python import PythonParser


def build_default_registry() -> ParserRegistry:
    """Create a registry containing RepoLocus's built-in parsers."""

    registry = ParserRegistry()
    registry.register(PythonParser())
    registry.register(HeuristicParser())
    return registry


DEFAULT_REGISTRY = build_default_registry()


def parse_source(
    path: str,
    text: str,
    language: str,
    *,
    max_chunk_lines: int = 160,
    max_chunk_chars: int = 16_000,
    registry: ParserRegistry | None = None,
) -> ParseResult:
    """Parse source with the default registry or an injected plugin registry."""

    return (registry or DEFAULT_REGISTRY).parse(
        path,
        text,
        language,
        max_chunk_lines=max_chunk_lines,
        max_chunk_chars=max_chunk_chars,
    )


parse_file = parse_source

__all__ = [
    "DEFAULT_REGISTRY",
    "HeuristicParser",
    "ParseResult",
    "ParserRegistry",
    "PythonParser",
    "SourceParser",
    "build_default_registry",
    "parse_file",
    "parse_source",
]
