"""Language parser plugin layer."""

from __future__ import annotations

from repolocus.parsers.base import (
    DEFAULT_MAX_CHUNKS_PER_FILE,
    DEFAULT_MAX_DEPENDENCIES_PER_FILE,
    DEFAULT_MAX_SYMBOLS_PER_FILE,
    ParseResult,
    ParserRegistry,
    SourceParser,
)
from repolocus.parsers.heuristic import HeuristicParser
from repolocus.parsers.python import PythonParser
from repolocus.parsers.source_layout import SourceLayout
from repolocus.parsers.treesitter import TreeSitterParser


def build_default_registry() -> ParserRegistry:
    """Create a registry containing RepoLocus's built-in parsers."""

    registry = ParserRegistry()
    registry.register(PythonParser())
    registry.register(HeuristicParser())
    tree_sitter = TreeSitterParser.discover()
    if tree_sitter is not None:
        registry.register(tree_sitter, replace=True)
    return registry


DEFAULT_REGISTRY = build_default_registry()


def parse_source(
    path: str,
    text: str,
    language: str,
    *,
    max_chunk_lines: int = 160,
    max_chunk_chars: int = 16_000,
    max_dependencies_per_file: int = DEFAULT_MAX_DEPENDENCIES_PER_FILE,
    max_symbols_per_file: int = DEFAULT_MAX_SYMBOLS_PER_FILE,
    max_chunks_per_file: int = DEFAULT_MAX_CHUNKS_PER_FILE,
    registry: ParserRegistry | None = None,
) -> ParseResult:
    """Parse source with the default registry or an injected plugin registry."""

    return (registry or DEFAULT_REGISTRY).parse(
        path,
        text,
        language,
        max_chunk_lines=max_chunk_lines,
        max_chunk_chars=max_chunk_chars,
        max_dependencies_per_file=max_dependencies_per_file,
        max_symbols_per_file=max_symbols_per_file,
        max_chunks_per_file=max_chunks_per_file,
    )


parse_file = parse_source

__all__ = [
    "DEFAULT_REGISTRY",
    "HeuristicParser",
    "ParseResult",
    "ParserRegistry",
    "PythonParser",
    "SourceLayout",
    "SourceParser",
    "TreeSitterParser",
    "build_default_registry",
    "parse_file",
    "parse_source",
]
