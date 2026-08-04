"""Shared typed detection and redaction of likely credentials.

The repository scanner and provider boundary intentionally use this single
rule set.  Scanner callers can restrict matches to high-confidence values,
while transport redaction also covers contextual assignments.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Literal

REDACTION_MARKER = "[REDACTED]"

SecretConfidence = Literal["contextual", "high"]


@dataclass(frozen=True, slots=True)
class SecretMatch:
    """Location and classification of a secret without retaining its value."""

    kind: str
    start: int
    end: int
    confidence: SecretConfidence


_PRIVATE_KEY = re.compile(
    r"(?P<secret>-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.*?"
    r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z))",
    re.IGNORECASE | re.DOTALL,
)
_HIGH_CONFIDENCE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", _PRIVATE_KEY),
    ("aws_access_key", re.compile(r"\b(?P<secret>(?:AKIA|ASIA)[0-9A-Z]{16})\b", re.IGNORECASE)),
    (
        "github_token",
        re.compile(r"\b(?P<secret>gh[pousr]_[A-Za-z0-9]{20,})\b", re.IGNORECASE),
    ),
    (
        "github_fine_grained_token",
        re.compile(r"\b(?P<secret>github_pat_[A-Za-z0-9_]{20,})\b", re.IGNORECASE),
    ),
    (
        "gitlab_token",
        re.compile(r"\b(?P<secret>glpat-[A-Za-z0-9_-]{20,})\b", re.IGNORECASE),
    ),
    (
        "slack_token",
        re.compile(r"\b(?P<secret>xox[baprs]-[A-Za-z0-9-]{10,})\b", re.IGNORECASE),
    ),
    (
        "google_api_key",
        re.compile(r"\b(?P<secret>AIza[0-9A-Za-z_-]{30,})\b", re.IGNORECASE),
    ),
    (
        "provider_api_key",
        re.compile(
            r"\b(?P<secret>sk-(?:(?:proj|svcacct|ant)-)?[A-Za-z0-9_-]{16,})\b",
            re.IGNORECASE,
        ),
    ),
    (
        "hugging_face_token",
        re.compile(r"\b(?P<secret>hf_[A-Za-z0-9]{20,})\b", re.IGNORECASE),
    ),
    (
        "stripe_live_key",
        re.compile(r"\b(?P<secret>(?:sk|rk)_live_[A-Za-z0-9]{16,})\b", re.IGNORECASE),
    ),
    (
        "jwt",
        re.compile(
            r"\b(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{8,})\b",
            re.IGNORECASE,
        ),
    ),
)
_URL_PASSWORD = re.compile(
    r"[a-z][a-z0-9+.-]*://[^\s/:@]+:(?P<secret>[^\s/@]+)(?=@)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\bBearer\s+(?P<secret>[A-Za-z0-9._~+/=-]{12,})")
_ASSIGNMENT_NAMES = (
    r"password|passwd|pwd|secret(?:[_-]?key)?|client[_-]?secret|api[_-]?key|"
    r"access[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|"
    r"private[_-]?key|hf[_-]?token|database[_-]?url|db[_-]?url|dsn"
)
_QUOTED_ASSIGNMENT = re.compile(
    rf"(?im)[\"']?(?:{_ASSIGNMENT_NAMES})[\"']?\s*[:=]\s*(?:[rubf]{{0,2}})"
    r"(?P<quote>[\"'])(?P<secret>[^\r\n\"']*)(?P=quote)"
)
_BARE_ASSIGNMENT = re.compile(
    rf"(?im)^[ \t]*(?:export\s+)?(?:{_ASSIGNMENT_NAMES})\s*[:=]\s*"
    r"(?P<secret>(?![\"'])[^\s#;,}]+)"
)
_PLACEHOLDER_FRAGMENTS = (
    "${",
    "{{",
    "<your",
    "changeme",
    "change_me",
    "dummy",
    "example",
    "fake",
    "env.get",
    "getenv",
    "os.environ",
    "placeholder",
    "process.env",
    "redacted",
    "replace_me",
    "sample",
    "your_",
)


def _entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _plausible_assigned_secret(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.casefold()
    if len(stripped) < 8 or len(stripped) > 4_096:
        return False
    if any(fragment in lowered for fragment in _PLACEHOLDER_FRAGMENTS):
        return False
    if lowered in {"password", "secret", "undefined", "none", "null"}:
        return False
    if len(set(stripped)) <= 2:
        return False
    return _entropy(stripped) >= 2.5


def _match_from_group(
    kind: str,
    match: re.Match[str],
    confidence: SecretConfidence,
) -> SecretMatch | None:
    start, end = match.span("secret")
    if start == end:
        return None
    return SecretMatch(kind, start, end, confidence)


def _normalise_matches(matches: list[SecretMatch]) -> tuple[SecretMatch, ...]:
    """Collapse overlapping rules so each transported occurrence is counted once."""

    ordered = sorted(matches, key=lambda item: (item.start, -item.end, item.kind))
    normalised: list[SecretMatch] = []
    for candidate in ordered:
        if not normalised or candidate.start >= normalised[-1].end:
            normalised.append(candidate)
            continue
        previous = normalised[-1]
        confidence: SecretConfidence = (
            "high" if "high" in {previous.confidence, candidate.confidence} else "contextual"
        )
        kind = candidate.kind if candidate.confidence == "high" else previous.kind
        normalised[-1] = SecretMatch(
            kind=kind,
            start=previous.start,
            end=max(previous.end, candidate.end),
            confidence=confidence,
        )
    return tuple(normalised)


def find_likely_secrets(text: str) -> tuple[SecretMatch, ...]:
    """Return non-overlapping typed matches without exposing their values."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    matches: list[SecretMatch] = []
    for kind, pattern in _HIGH_CONFIDENCE_PATTERNS:
        matches.extend(
            candidate
            for match in pattern.finditer(text)
            if (candidate := _match_from_group(kind, match, "high")) is not None
        )
    for kind, pattern in (("url_password", _URL_PASSWORD), ("bearer_token", _BEARER)):
        for match in pattern.finditer(text):
            if match.group("secret") == REDACTION_MARKER:
                continue
            candidate = _match_from_group(kind, match, "high")
            if candidate is not None:
                matches.append(candidate)
    for pattern in (_QUOTED_ASSIGNMENT, _BARE_ASSIGNMENT):
        for match in pattern.finditer(text):
            value = match.group("secret")
            if value.strip() == REDACTION_MARKER:
                continue
            confidence: SecretConfidence = (
                "high" if _plausible_assigned_secret(value) else "contextual"
            )
            candidate = _match_from_group("credential_assignment", match, confidence)
            if candidate is not None:
                matches.append(candidate)
    return _normalise_matches(matches)


def contains_high_confidence_secret(text: str) -> bool:
    """Return whether scanner-grade, high-confidence evidence is present."""

    return any(match.confidence == "high" for match in find_likely_secrets(text))


def contains_likely_secret(text: str) -> bool:
    """Return whether transport redaction would change ``text``."""

    return bool(find_likely_secrets(text))


def redact_likely_secrets(text: str) -> tuple[str, int]:
    """Redact every shared detector match and return the occurrence count."""

    matches = find_likely_secrets(text)
    redacted = text
    for match in reversed(matches):
        redacted = redacted[: match.start] + REDACTION_MARKER + redacted[match.end :]
    return redacted, len(matches)


__all__ = [
    "REDACTION_MARKER",
    "SecretConfidence",
    "SecretMatch",
    "contains_high_confidence_secret",
    "contains_likely_secret",
    "find_likely_secrets",
    "redact_likely_secrets",
]
