"""Validate citation addresses and exact quotes in untrusted model output."""

from __future__ import annotations

import json
import re
from html import escape as html_escape
from pathlib import PurePosixPath
from urllib.parse import quote

from repolocus.models import Evidence
from repolocus.security.display import (
    escape_untrusted_display,
    has_unsafe_display_controls,
)

MODEL_CITATION = re.compile(r"\[\[([^\]\n]+?):([1-9]\d*)(?:-([1-9]\d*))?\]\]")
_QUOTE_LINE = re.compile(
    r'^\s*Evidence quote:\s*("(?:[^"\\]|\\.)*")\s*'
    r"(\[\[[^\]\n]+?:[1-9]\d*(?:-[1-9]\d*)?\]\])\.?\s*$"
)
_UNSAFE_MODEL_OUTPUT = re.compile(
    r"!\[|\[[^\]\n]*\]\(|(?:https?|file)://",
    re.IGNORECASE,
)
_MODEL_FENCE = re.compile(r"(?m)^[ \t]*(?:`{3,}|~{3,})")
_INSUFFICIENT_CLAIM = re.compile(
    r"(?:insufficient evidence|not enough evidence|"
    r"cannot determine(?: this)? from (?:the )?(?:supplied )?evidence)[.!?]?",
    re.IGNORECASE,
)
_LIST_PREFIX = re.compile(r"^(?:#{1,6}\s+|(?:[-*+]|\d+[.)])\s+)")


def _citation_tuple(match: re.Match[str]) -> tuple[str, int, int]:
    start = int(match.group(2))
    return match.group(1), start, int(match.group(3) or start)


def _material_claims(line: str) -> tuple[str, ...]:
    normalized = MODEL_CITATION.sub("[[CITATION]]", line)
    claims: list[str] = []
    for claim in re.split(r"(?<=[.!?;\u3002\uFF01\uFF1F\uFF1B])\s*", normalized):
        claim = claim.strip()
        if not claim or not any(character.isalnum() for character in claim):
            continue
        if _INSUFFICIENT_CLAIM.fullmatch(claim):
            continue
        claims.append(claim)
    return tuple(claims)


def _quote_is_in_evidence(
    exact_quote: str,
    citation: tuple[str, int, int],
    evidence: list[Evidence],
) -> bool:
    path, start, end = citation
    if len(exact_quote.strip()) < 4 or len(exact_quote) > 500:
        return False
    for item in evidence:
        if item.path != path or not (item.start_line <= start <= end <= item.end_line):
            continue
        lines = item.content.splitlines(keepends=True)
        first = start - item.start_line
        last = end - item.start_line + 1
        region = "".join(lines[first:last])
        if exact_quote in region:
            return True
    return False


def _claims_have_exact_quotes(text: str, evidence: list[Evidence]) -> bool:
    lines = [(index, line) for index, line in enumerate(text.splitlines()) if line.strip()]
    parsed_quotes: dict[int, tuple[str, int, int]] = {}
    for index, line in lines:
        quote_match = _QUOTE_LINE.fullmatch(_LIST_PREFIX.sub("", line.strip()))
        if quote_match is None:
            continue
        try:
            exact_quote = json.loads(quote_match.group(1))
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        citation_match = MODEL_CITATION.fullmatch(quote_match.group(2))
        if not isinstance(exact_quote, str) or citation_match is None:
            return False
        citation = _citation_tuple(citation_match)
        if not _quote_is_in_evidence(exact_quote, citation, evidence):
            return False
        parsed_quotes[index] = citation

    material_claim_count = 0
    for position, (index, line) in enumerate(lines):
        if index in parsed_quotes:
            continue
        stripped = _LIST_PREFIX.sub("", line.strip())
        claims = _material_claims(stripped)
        if not claims:
            continue
        material_claim_count += len(claims)
        if any("[[CITATION]]" not in claim for claim in claims):
            return False
        claim_citations = {_citation_tuple(match) for match in MODEL_CITATION.finditer(stripped)}
        if len(claim_citations) != 1 or position + 1 >= len(lines):
            return False
        next_index = lines[position + 1][0]
        if parsed_quotes.get(next_index) != next(iter(claim_citations)):
            return False
    return material_claim_count > 0 and bool(parsed_quotes)


def validate_model_text(text: str, evidence: list[Evidence]) -> str | None:
    """Return safe linked Markdown only when citations and exact quotes validate."""

    if (
        has_unsafe_display_controls(text, allow_layout=True)
        or _UNSAFE_MODEL_OUTPUT.search(text)
        or _MODEL_FENCE.search(text)
    ):
        return None
    matches = list(MODEL_CITATION.finditer(text))
    if not matches or not _claims_have_exact_quotes(text, evidence):
        return None
    allowed: dict[str, list[tuple[int, int]]] = {}
    for item in evidence:
        allowed.setdefault(item.path, []).append((item.start_line, item.end_line))
    for match in matches:
        path, start, end = _citation_tuple(match)
        if end < start or not any(
            low <= start <= end <= high for low, high in allowed.get(path, [])
        ):
            return None

    def replace(match: re.Match[str]) -> str:
        path = match.group(1)
        start = int(match.group(2))
        end_text = f"-{match.group(3)}" if match.group(3) else ""
        label = f"{path}:{start}{end_text}"
        safe_label = html_escape(escape_untrusted_display(label), quote=False).replace("\\", "\\\\")
        for marker in ("[", "]", "|"):
            safe_label = safe_label.replace(marker, f"\\{marker}")
        safe_path = PurePosixPath(path).as_posix()
        return f"[{safe_label}]({quote(safe_path, safe='/._-')}#L{start})"

    def escape_model_segment(segment: str) -> str:
        safe = html_escape(segment, quote=False).replace("\\", "\\\\")
        return safe.replace("[", "\\[").replace("]", "\\]")

    rendered: list[str] = []
    position = 0
    for match in MODEL_CITATION.finditer(text):
        rendered.append(escape_model_segment(text[position : match.start()]))
        rendered.append(replace(match))
        position = match.end()
    rendered.append(escape_model_segment(text[position:]))
    return "".join(rendered).strip()
