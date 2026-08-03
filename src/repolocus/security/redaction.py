"""Conservative credential redaction before cloud requests or logging."""

from __future__ import annotations

import re
from collections.abc import Callable

REDACTION_MARKER = "[REDACTED]"

_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)* PRIVATE KEY-----",
    re.DOTALL,
)
_ASSIGNMENT = re.compile(
    r"(?P<prefix>[\"']?(?:api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|"
    r"auth[_-]?token|access[_-]?token|refresh[_-]?token|password|passwd|hf[_-]?token|"
    r"database[_-]?url|db[_-]?url|dsn)"
    r"[\"']?\s*[:=]\s*)"
    r"(?:(?P<quote>[\"'])(?P<quoted>.*?)(?P=quote)|(?P<bare>[^\s,;#}]+))",
    re.IGNORECASE,
)
_URL_PASSWORD = re.compile(
    r"(?P<prefix>[a-z][a-z0-9+.-]*://[^\s/:@]+:)(?P<secret>[^\s/@]+)(?=@)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}")
_KNOWN_TOKENS = re.compile(
    r"(?:"
    r"sk-(?:ant-)?[A-Za-z0-9_-]{16,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"hf_[A-Za-z0-9]{20,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{30,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}"
    r")"
)


def redact_secrets(text: str) -> tuple[str, int]:
    """Return redacted text and the number of likely credential matches."""

    return redact_secrets_with_count(text)


def redact_text(text: str) -> str:
    """Return only the redacted text for presentation-oriented callers."""

    return redact_secrets_with_count(text)[0]


def redact_secrets_with_count(text: str) -> tuple[str, int]:
    """Return redacted text and the number of matched secret occurrences."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    count = 0

    def replace(pattern: re.Pattern[str], value: str, repl: Callable[[re.Match[str]], str]) -> str:
        nonlocal count

        def counted(match: re.Match[str]) -> str:
            nonlocal count
            count += 1
            return repl(match)

        return pattern.sub(counted, value)

    redacted = replace(_PRIVATE_KEY, text, lambda _match: REDACTION_MARKER)

    def assignment_replacement(match: re.Match[str]) -> str:
        quote = match.group("quote") or ""
        return f"{match.group('prefix')}{quote}{REDACTION_MARKER}{quote}"

    redacted = replace(_ASSIGNMENT, redacted, assignment_replacement)
    redacted = replace(
        _URL_PASSWORD,
        redacted,
        lambda match: f"{match.group('prefix')}{REDACTION_MARKER}",
    )
    redacted = replace(_BEARER, redacted, lambda _match: f"Bearer {REDACTION_MARKER}")
    redacted = replace(_KNOWN_TOKENS, redacted, lambda _match: REDACTION_MARKER)
    return redacted, count


def contains_likely_secret(text: str) -> bool:
    """Return whether redaction would change ``text``."""

    _, count = redact_secrets_with_count(text)
    return count > 0
