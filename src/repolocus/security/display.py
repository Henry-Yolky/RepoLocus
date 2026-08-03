"""Safe rendering helpers for repository-controlled text."""

from __future__ import annotations

_BIDI_CONTROLS = frozenset(
    {
        0x061C,
        0x200E,
        0x200F,
        *range(0x202A, 0x202F),
        *range(0x2066, 0x206A),
    }
)


def has_unsafe_display_controls(value: str, *, allow_layout: bool = False) -> bool:
    """Return whether text could alter terminal state or visual ordering."""

    return any(
        _unsafe_codepoint(ord(character)) and not (allow_layout and character in {"\n", "\t"})
        for character in value
    )


def escape_untrusted_display(value: str, *, preserve_layout: bool = False) -> str:
    """Make control and bidi characters explicit while retaining ordinary Unicode."""

    output: list[str] = []
    for character in value:
        codepoint = ord(character)
        if preserve_layout and character in {"\n", "\t"}:
            output.append(character)
        elif _unsafe_codepoint(codepoint):
            width = 4 if codepoint <= 0xFFFF else 8
            output.append(f"\\u{codepoint:0{width}x}")
        else:
            output.append(character)
    return "".join(output)


def _unsafe_codepoint(codepoint: int) -> bool:
    return codepoint < 0x20 or 0x7F <= codepoint <= 0x9F or codepoint in _BIDI_CONTROLS
