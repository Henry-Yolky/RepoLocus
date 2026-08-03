"""Secure repository discovery and filtering."""

from devpilot.scanner.filters import (
    CONFIG_FILENAMES,
    DEFAULT_IGNORED_DIRS,
    LANGUAGE_EXTENSIONS,
    contains_likely_secret,
    detect_language,
    is_binary,
    is_default_ignored,
    is_sensitive_path,
    looks_like_secret,
)
from devpilot.scanner.ignore import IgnoreRules
from devpilot.scanner.repository import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_IGNORE_BYTES,
    RepositoryScanner,
)

__all__ = [
    "CONFIG_FILENAMES",
    "DEFAULT_IGNORED_DIRS",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_IGNORE_BYTES",
    "LANGUAGE_EXTENSIONS",
    "IgnoreRules",
    "RepositoryScanner",
    "contains_likely_secret",
    "detect_language",
    "is_binary",
    "is_default_ignored",
    "is_sensitive_path",
    "looks_like_secret",
]
