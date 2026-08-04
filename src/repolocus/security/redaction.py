"""Conservative credential redaction before cloud requests or logging."""

from __future__ import annotations

from .secrets import (
    REDACTION_MARKER,
    contains_likely_secret,
    redact_likely_secrets,
)


def redact_secrets(text: str) -> tuple[str, int]:
    """Return redacted text and the number of likely credential matches."""

    return redact_likely_secrets(text)


def redact_text(text: str) -> str:
    """Return only the redacted text for presentation-oriented callers."""

    return redact_likely_secrets(text)[0]


def redact_secrets_with_count(text: str) -> tuple[str, int]:
    """Return redacted text and the number of matched secret occurrences."""

    return redact_likely_secrets(text)


__all__ = [
    "REDACTION_MARKER",
    "contains_likely_secret",
    "redact_secrets",
    "redact_secrets_with_count",
    "redact_text",
]
