"""Line-addressable semantic chunk construction."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from repolocus.models import Chunk


@dataclass(frozen=True, slots=True, order=True)
class Region:
    """A one-based inclusive semantic region."""

    start_line: int
    end_line: int
    symbol: str = ""


def _split_region(
    *,
    path: str,
    language: str,
    lines: list[str],
    region: Region,
    max_lines: int,
    max_chars: int,
    max_chunks: int | None,
) -> list[Chunk]:
    chunks: list[Chunk] = []
    parts: list[str] = []
    part_start = region.start_line
    part_end = region.start_line
    chars = 0

    def flush() -> None:
        nonlocal parts, chars, part_start, part_end
        if not parts:
            return
        if max_chunks is not None and len(chunks) >= max_chunks:
            raise ValueError("semantic chunking exceeded the configured chunk limit")
        chunks.append(
            Chunk(
                path=path,
                start_line=part_start,
                end_line=part_end,
                content="".join(parts),
                language=language,
                symbol=region.symbol,
            )
        )
        parts = []
        chars = 0

    for line_number in range(region.start_line, region.end_line + 1):
        line = lines[line_number - 1]
        piece_offsets = range(0, len(line), max_chars) if line else (0,)
        for index in piece_offsets:
            piece = line[index : index + max_chars]
            exceeds_lines = bool(parts) and line_number - part_start + 1 > max_lines
            exceeds_chars = bool(parts) and chars + len(piece) > max_chars
            if exceeds_lines or exceeds_chars:
                flush()
            if not parts:
                part_start = line_number
            part_end = line_number
            parts.append(piece)
            chars += len(piece)
            if chars >= max_chars:
                flush()
    flush()
    return chunks


def semantic_chunks(
    *,
    path: str,
    text: str,
    language: str,
    regions: Iterable[Region] = (),
    max_lines: int = 160,
    max_chars: int = 16_000,
    max_chunks: int | None = None,
    source_lines: list[str] | None = None,
) -> tuple[Chunk, ...]:
    """Build bounded chunks around symbols or document sections.

    Symbol regions remain individually retrievable.  Text outside those
    regions is retained in anonymous chunks, so parsing never makes source
    evidence disappear.  Nested regions may intentionally overlap their
    parent region; this provides both class-level and method-level retrieval.
    """

    if max_lines <= 0 or max_chars <= 0:
        raise ValueError("chunk limits must be positive")
    if max_chunks is not None and (
        isinstance(max_chunks, bool) or not isinstance(max_chunks, int) or max_chunks <= 0
    ):
        raise ValueError("max_chunks must be a positive integer or None")
    lines = source_lines if source_lines is not None else text.splitlines(keepends=True)
    if not lines:
        return ()

    line_count = len(lines)
    normalized = {
        Region(
            max(1, min(region.start_line, line_count)),
            max(1, min(region.end_line, line_count)),
            region.symbol,
        )
        for region in regions
        if region.start_line > 0 and region.end_line >= region.start_line
    }
    ordered = sorted(region for region in normalized if region.end_line >= region.start_line)

    if not ordered:
        ordered = [Region(1, line_count)]
    else:
        gaps: list[Region] = []
        covered_until = 0
        for region in ordered:
            if region.start_line > covered_until + 1:
                gaps.append(Region(covered_until + 1, region.start_line - 1))
            covered_until = max(covered_until, region.end_line)
        if covered_until < line_count:
            gaps.append(Region(covered_until + 1, line_count))
        ordered.extend(gaps)
        ordered.sort()

    chunks: list[Chunk] = []
    for region in ordered:
        remaining_chunks = None if max_chunks is None else max_chunks - len(chunks)
        if remaining_chunks is not None and remaining_chunks <= 0:
            raise ValueError("semantic chunking exceeded the configured chunk limit")
        chunks.extend(
            _split_region(
                path=path,
                language=language,
                lines=lines,
                region=region,
                max_lines=max_lines,
                max_chars=max_chars,
                max_chunks=remaining_chunks,
            )
        )
    return tuple(
        sorted(
            chunks,
            key=lambda chunk: (
                chunk.start_line,
                chunk.end_line,
                chunk.symbol,
                chunk.content,
            ),
        )
    )
