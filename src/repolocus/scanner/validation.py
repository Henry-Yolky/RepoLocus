"""Parser-plugin output normalization and postcondition enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from repolocus.models import Chunk, Dependency, Symbol
from repolocus.parsers.base import (
    DEFAULT_MAX_CHUNKS_PER_FILE,
    DEFAULT_MAX_DEPENDENCIES_PER_FILE,
    DEFAULT_MAX_SYMBOLS_PER_FILE,
    ParseResult,
)
from repolocus.parsers.chunking import semantic_chunks
from repolocus.scanner.budget import FactCounts
from repolocus.security.display import has_unsafe_display_controls

DEFAULT_MAX_REPOSITORY_DEPENDENCIES = 1_000_000
HARD_MAX_REPOSITORY_DEPENDENCIES = 2_000_000
HARD_MAX_DEPENDENCIES_PER_FILE = 20_000
HARD_MAX_SYMBOLS_PER_FILE = 20_000
HARD_MAX_CHUNKS_PER_FILE = 20_000
MAX_SYMBOL_NAME_CHARS = 512
MAX_DEPENDENCY_TARGET_CHARS = 1_024
MAX_KIND_CHARS = 64
MAX_SIGNATURE_CHARS = 4_096
MAX_LANGUAGE_CHARS = 64


@dataclass(frozen=True, slots=True)
class ParseLimits:
    max_chunk_lines: int
    max_chunk_chars: int
    max_dependencies_per_file: int = DEFAULT_MAX_DEPENDENCIES_PER_FILE
    max_symbols_per_file: int = DEFAULT_MAX_SYMBOLS_PER_FILE
    max_chunks_per_file: int = DEFAULT_MAX_CHUNKS_PER_FILE
    max_symbol_name_chars: int = MAX_SYMBOL_NAME_CHARS
    max_dependency_target_chars: int = MAX_DEPENDENCY_TARGET_CHARS
    max_kind_chars: int = MAX_KIND_CHARS
    max_signature_chars: int = MAX_SIGNATURE_CHARS

    def __post_init__(self) -> None:
        for name in (
            "max_chunk_lines",
            "max_chunk_chars",
            "max_dependencies_per_file",
            "max_symbols_per_file",
            "max_chunks_per_file",
            "max_symbol_name_chars",
            "max_dependency_target_chars",
            "max_kind_chars",
            "max_signature_chars",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        for value, maximum, name in (
            (
                self.max_dependencies_per_file,
                HARD_MAX_DEPENDENCIES_PER_FILE,
                "max_dependencies_per_file",
            ),
            (self.max_symbols_per_file, HARD_MAX_SYMBOLS_PER_FILE, "max_symbols_per_file"),
            (self.max_chunks_per_file, HARD_MAX_CHUNKS_PER_FILE, "max_chunks_per_file"),
        ):
            if value > maximum:
                raise ValueError(f"{name} exceeds the global safety ceiling of {maximum}")


def _safe_field(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"parser emitted an invalid or oversized {name}")
    if has_unsafe_display_controls(value):
        raise ValueError(f"parser emitted unsafe controls in {name}")
    return value


def _safe_optional_field(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError(f"parser emitted an invalid or oversized {name}")
    if value and has_unsafe_display_controls(value):
        raise ValueError(f"parser emitted unsafe controls in {name}")
    return value


def _validate_source_identity(path: str, language: str) -> None:
    _safe_field(path, "path", 4_096)
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or parsed.as_posix() != path or ".." in parsed.parts or "\\" in path:
        raise ValueError("parser source path must be normalized repository-relative POSIX text")
    _safe_field(language, "language", MAX_LANGUAGE_CHARS)


def _bounded_items(values: object, *, maximum: int, fact_name: str) -> list[object]:
    """Collect at most *maximum* plugin facts without trusting container types."""

    if isinstance(values, (str, bytes, bytearray)):
        raise ValueError(f"parser {fact_name} facts must be an iterable of fact objects")
    if isinstance(values, (tuple, list)) and len(values) > maximum:
        raise ValueError(f"parser emitted more {fact_name} than the per-file safety limit")
    try:
        iterator = iter(values)  # type: ignore[call-overload]
    except TypeError as exc:
        raise ValueError(f"parser {fact_name} facts must be iterable") from exc
    items: list[object] = []
    for item in iterator:
        if len(items) >= maximum:
            raise ValueError(f"parser emitted more {fact_name} than the per-file safety limit")
        items.append(item)
    return items


def finalize_parse_result(
    parsed: ParseResult,
    *,
    text: str,
    path: str,
    language: str,
    limits: ParseLimits,
) -> tuple[ParseResult, FactCounts]:
    """Normalize untrusted parser facts and enforce bounded source postconditions."""

    if not isinstance(parsed, ParseResult):
        raise ValueError("parser must return ParseResult")
    if not isinstance(text, str):
        raise TypeError("parser source text must be a string")
    _validate_source_identity(path, language)
    if not isinstance(parsed.is_entry_point, bool):
        raise ValueError("parser is_entry_point must be true or false")
    source_lines = text.splitlines(keepends=True)
    line_count = len(source_lines)

    def valid_range(start: int, end: int) -> bool:
        return (
            not isinstance(start, bool)
            and not isinstance(end, bool)
            and isinstance(start, int)
            and isinstance(end, int)
            and 1 <= start <= end <= line_count
        )

    raw_symbols = _bounded_items(
        parsed.symbols,
        maximum=limits.max_symbols_per_file,
        fact_name="symbols",
    )
    symbols: list[Symbol] = []
    for symbol in raw_symbols:
        if not isinstance(symbol, Symbol):
            raise ValueError("parser emitted a non-Symbol fact")
        if symbol.path != path or not valid_range(symbol.start_line, symbol.end_line):
            raise ValueError("parser emitted an invalid symbol source range")
        _safe_field(symbol.name, "symbol name", limits.max_symbol_name_chars)
        _safe_field(symbol.kind, "symbol kind", limits.max_kind_chars)
        _safe_optional_field(symbol.signature, "symbol signature", limits.max_signature_chars)
        symbols.append(symbol)
    symbols = sorted(
        set(symbols),
        key=lambda item: (
            item.start_line,
            item.end_line,
            item.kind,
            item.name,
            item.signature,
        ),
    )
    if len(symbols) > limits.max_symbols_per_file:
        raise ValueError("parser emitted more symbols than the per-file safety limit")
    symbol_ranges: dict[str, list[tuple[int, int]]] = {}
    for symbol in symbols:
        symbol_ranges.setdefault(symbol.name, []).append((symbol.start_line, symbol.end_line))

    raw_dependencies = _bounded_items(
        parsed.dependencies,
        maximum=limits.max_dependencies_per_file,
        fact_name="dependencies",
    )
    dependencies: list[Dependency] = []
    for dependency in raw_dependencies:
        if not isinstance(dependency, Dependency):
            raise ValueError("parser emitted a non-Dependency fact")
        if dependency.source_path != path or not valid_range(dependency.line, dependency.line):
            raise ValueError("parser emitted an invalid dependency source line")
        _safe_field(
            dependency.target,
            "dependency target",
            limits.max_dependency_target_chars,
        )
        _safe_field(dependency.kind, "dependency kind", limits.max_kind_chars)
        dependencies.append(dependency)
    dependencies = sorted(set(dependencies), key=lambda item: (item.line, item.target, item.kind))
    if len(dependencies) > limits.max_dependencies_per_file:
        raise ValueError("parser emitted more dependencies than the per-file safety limit")

    raw_chunks = _bounded_items(
        parsed.chunks,
        maximum=limits.max_chunks_per_file,
        fact_name="chunks",
    )
    if text and not raw_chunks:
        raw_chunks = _bounded_items(
            semantic_chunks(
                path=path,
                text=text,
                language=language,
                max_lines=limits.max_chunk_lines,
                max_chars=limits.max_chunk_chars,
                max_chunks=limits.max_chunks_per_file,
            ),
            maximum=limits.max_chunks_per_file,
            fact_name="chunks",
        )
    chunks: list[Chunk] = []
    for chunk in raw_chunks:
        if not isinstance(chunk, Chunk):
            raise ValueError("parser emitted a non-Chunk fact")
        if chunk.path != path or chunk.language != language:
            raise ValueError("parser emitted a chunk for a different source")
        if not valid_range(chunk.start_line, chunk.end_line):
            raise ValueError("parser emitted an invalid chunk source range")
        if chunk.end_line - chunk.start_line + 1 > limits.max_chunk_lines:
            raise ValueError("parser emitted a chunk beyond the line budget")
        if len(chunk.content) > limits.max_chunk_chars:
            raise ValueError("parser emitted a chunk beyond the character budget")
        # CRLF is a normal source line ending on POSIX as well as Windows.
        # Remove only intact pairs for the display-control check so a bare CR
        # remains unsafe and cannot rewrite terminal output.
        display_content = chunk.content.replace("\r\n", "\n")
        if has_unsafe_display_controls(display_content, allow_layout=True):
            raise ValueError("parser emitted unsafe controls in chunk content")
        _safe_optional_field(chunk.symbol, "chunk symbol", limits.max_symbol_name_chars)
        if chunk.symbol and not any(
            start <= chunk.start_line <= chunk.end_line <= end
            for start, end in symbol_ranges.get(chunk.symbol, [])
        ):
            raise ValueError("parser emitted a chunk outside its declared symbol range")
        source_region = "".join(source_lines[chunk.start_line - 1 : chunk.end_line])
        if chunk.content not in source_region:
            raise ValueError("parser emitted chunk content not present in its source range")
        chunks.append(chunk)
    chunks = sorted(
        set(chunks),
        key=lambda item: (
            item.start_line,
            item.end_line,
            item.symbol,
            item.content,
        ),
    )
    if len(chunks) > limits.max_chunks_per_file:
        raise ValueError("parser emitted more chunks than the per-file safety limit")
    active: list[Chunk] = []
    for chunk in sorted(chunks, key=lambda item: (item.start_line, -item.end_line)):
        while active and chunk.start_line > active[-1].end_line:
            active.pop()
        if active and chunk.end_line > active[-1].end_line:
            parent = active[-1]
            nested_symbols = bool(parent.symbol and chunk.symbol) and any(
                (first_start <= second_start and second_end <= first_end)
                or (second_start <= first_start and first_end <= second_end)
                for first_start, first_end in symbol_ranges.get(parent.symbol, [])
                for second_start, second_end in symbol_ranges.get(chunk.symbol, [])
            )
            if not nested_symbols:
                raise ValueError("parser emitted partially overlapping chunk ranges")
        active.append(chunk)

    normalized = ParseResult(
        symbols=tuple(symbols),
        dependencies=tuple(dependencies),
        chunks=tuple(chunks),
        is_entry_point=parsed.is_entry_point,
    )
    return normalized, FactCounts(
        chunks=len(chunks),
        symbols=len(symbols),
        dependencies=len(dependencies),
    )
