"""One-pass source layout shared by heuristic parsers."""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass

_LINE_BREAK_CHARACTERS = frozenset("\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")
_CPP_DIGIT_CHARACTERS = frozenset("0123456789abcdefABCDEF")


def _ends_with_line_break(value: str) -> bool:
    return bool(value) and value[-1] in _LINE_BREAK_CHARACTERS


def _is_cpp_digit_separator(text: str, index: int) -> bool:
    if not (
        0 < index < len(text) - 1
        and text[index - 1] in _CPP_DIGIT_CHARACTERS
        and text[index + 1] in _CPP_DIGIT_CHARACTERS
    ):
        return False
    if text[max(0, index - 2) : index] == "u8":
        prefix = text[index - 3] if index >= 3 else ""
        if not prefix or not (prefix.isalnum() or prefix in {"_", "$"}):
            return False
    return True


def _starts_quoted_literal(text: str, index: int, language: str) -> bool:
    if text[index] != "'":
        return True
    if language == "rust":
        following = text[index + 1] if index + 1 < len(text) else ""
        if following == "\\":
            escaped = False
            for character in text[index + 2 :]:
                if character in "\r\n":
                    return False
                if character == "'" and not escaped:
                    return True
                escaped = character == "\\" and not escaped
            return False
        return index + 2 < len(text) and text[index + 2] == "'"
    return not (language == "cpp" and _is_cpp_digit_separator(text, index))


@dataclass(slots=True)
class SourceLayout:
    """Cached line offsets and brace pairs for one source document."""

    text: str
    lines: list[str]
    source_lines: list[str]
    line_starts: list[int]
    byte_line_starts: list[int]
    brace_pairs: dict[int, int]
    ignored_ranges: tuple[tuple[int, int], ...]
    _ignored_starts: tuple[int, ...]
    _byte_length: int

    @classmethod
    def build(cls, text: str, *, language: str = "") -> SourceLayout:
        source_lines = text.splitlines(keepends=True)
        line_starts = [0]
        byte_line_starts = [0]
        character_offset = 0
        byte_offset = 0
        for line in source_lines:
            character_offset += len(line)
            byte_offset += len(line.encode("utf-8"))
            if _ends_with_line_break(line):
                line_starts.append(character_offset)
                byte_line_starts.append(byte_offset)

        brace_pairs: dict[int, int] = {}
        brace_stack: list[int] = []
        ignored_ranges: list[tuple[int, int]] = []
        ignored_start: int | None = None
        quote = ""
        escaped = False
        line_comment = False
        block_comment = False
        index = 0
        while index < len(text):
            character = text[index]
            following = text[index + 1] if index + 1 < len(text) else ""
            if line_comment:
                if character in _LINE_BREAK_CHARACTERS:
                    line_comment = False
                    if ignored_start is not None:
                        ignored_ranges.append((ignored_start, index))
                        ignored_start = None
                index += 1
                continue
            if block_comment:
                if character == "*" and following == "/":
                    block_comment = False
                    if ignored_start is not None:
                        ignored_ranges.append((ignored_start, index + 2))
                        ignored_start = None
                    index += 2
                else:
                    index += 1
                continue
            if quote:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = ""
                    if ignored_start is not None:
                        ignored_ranges.append((ignored_start, index + 1))
                        ignored_start = None
                index += 1
                continue
            if character == "/" and following == "/":
                line_comment = True
                ignored_start = index
                index += 2
                continue
            if character == "/" and following == "*":
                block_comment = True
                ignored_start = index
                index += 2
                continue
            if character in {'"', "'", "`"} and _starts_quoted_literal(text, index, language):
                quote = character
                ignored_start = index
            elif character == "{":
                brace_stack.append(index)
            elif character == "}" and brace_stack:
                brace_pairs[brace_stack.pop()] = index
            index += 1
        if ignored_start is not None:
            ignored_ranges.append((ignored_start, len(text)))
        return cls(
            text=text,
            lines=[line.rstrip("\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029") for line in source_lines],
            source_lines=source_lines,
            line_starts=line_starts,
            byte_line_starts=byte_line_starts,
            brace_pairs=brace_pairs,
            ignored_ranges=tuple(ignored_ranges),
            _ignored_starts=tuple(start for start, _end in ignored_ranges),
            _byte_length=byte_offset,
        )

    def line_at_offset(self, offset: int) -> int:
        """Return a clamped, one-based line number in logarithmic time."""

        clamped = min(max(offset, 0), len(self.text))
        return bisect_right(self.line_starts, clamped)

    def line_at_byte_offset(self, offset: int) -> int:
        """Return a clamped line number for a UTF-8 byte offset."""

        clamped = min(max(offset, 0), self._byte_length)
        return bisect_right(self.byte_line_starts, clamped)

    def brace_end_line(self, brace_offset: int) -> int:
        """Return the matching brace line, or the document end when unmatched."""

        end = self.brace_pairs.get(brace_offset, len(self.text))
        return self.line_at_offset(end)

    def is_code(self, offset: int) -> bool:
        """Return whether an offset lies outside a comment or string literal."""

        position = min(max(offset, 0), len(self.text))
        range_index = bisect_right(self._ignored_starts, position) - 1
        if range_index < 0:
            return True
        _start, end = self.ignored_ranges[range_index]
        return position >= end
