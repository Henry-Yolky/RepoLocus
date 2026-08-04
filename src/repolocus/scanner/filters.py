"""Pure filtering helpers used by the repository scanner."""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path, PurePosixPath

LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".ipp": "cpp",
    ".md": "markdown",
    ".markdown": "markdown",
    ".mdown": "markdown",
    ".mdx": "markdown",
    ".json": "config",
    ".jsonc": "config",
    ".json5": "config",
    ".yaml": "config",
    ".yml": "config",
    ".toml": "config",
    ".ini": "config",
    ".cfg": "config",
    ".conf": "config",
    ".config": "config",
    ".xml": "config",
    ".properties": "config",
    ".gradle": "config",
    ".lock": "config",
    ".mod": "config",
    ".sum": "config",
}

_GENERATED_MARKER = re.compile(
    r"^[ \t]*<!--[ \t]*Generator:[ \t]*(?:RepoLocus|DevPilot)"
    r"(?:[ \t]+[^;<>\r\n]+)?;[ \t]*deterministic[ \t]+"
    r"(?:source[ \t]+map|static[ \t]+graph)\.[ \t]*-->[ \t]*$"
)


def is_generated_document(text: str, language: str) -> bool:
    """Recognize only exact RepoLocus headers near a Markdown document start."""

    if language != "markdown":
        return False
    return any(_GENERATED_MARKER.fullmatch(line) for line in text[:4096].splitlines()[:16])


CONFIG_FILENAMES = frozenset(
    {
        ".editorconfig",
        ".gitattributes",
        ".gitignore",
        ".npmignore",
        ".prettierignore",
        ".prettierrc",
        ".python-version",
        "cmakelists.txt",
        "dockerfile",
        "gemfile",
        "go.mod",
        "go.sum",
        "justfile",
        "makefile",
        "package.json",
        "pipfile",
        "procfile",
        "pyproject.toml",
        "requirements.txt",
        "rust-toolchain",
        "rust-toolchain.toml",
        "workspace",
    }
)

MARKDOWN_FILENAMES = frozenset(
    {
        "authors",
        "changelog",
        "code_of_conduct",
        "contributing",
        "history",
        "license",
        "notice",
        "readme",
        "security",
    }
)

DEFAULT_IGNORED_DIRS = frozenset(
    {
        ".bzr",
        ".cache",
        ".devpilot",
        ".repolocus",
        ".git",
        ".gradle",
        ".hg",
        ".mypy_cache",
        ".next",
        ".nox",
        ".nuxt",
        ".parcel-cache",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".svelte-kit",
        ".tox",
        ".turbo",
        ".venv",
        "__pycache__",
        "bower_components",
        "build",
        "coverage",
        "deriveddata",
        "dist",
        "htmlcov",
        "node_modules",
        "out",
        "pods",
        "target",
        "venv",
    }
)

DEFAULT_IGNORED_FILES = frozenset(
    {
        ".coverage",
        ".ds_store",
        "desktop.ini",
        "npm-debug.log",
        "thumbs.db",
        "yarn-error.log",
    }
)

DEFAULT_IGNORED_SUFFIXES = (
    ".a",
    ".class",
    ".dll",
    ".dylib",
    ".exe",
    ".lib",
    ".min.css",
    ".min.js",
    ".o",
    ".obj",
    ".pyc",
    ".pyo",
    ".so",
)

_SAFE_ENV_TEMPLATES = frozenset(
    {
        ".env.defaults",
        ".env.dist",
        ".env.example",
        ".env.sample",
        ".env.template",
    }
)
_SENSITIVE_EXACT_NAMES = frozenset(
    {
        ".dockercfg",
        ".htpasswd",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "auth.json",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "kubeconfig",
        "secrets",
        "secrets.json",
        "secrets.toml",
        "secrets.yaml",
        "secrets.yml",
    }
)
_SENSITIVE_SUFFIXES = (
    ".jks",
    ".kdbx",
    ".key",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
    ".pkcs12",
    ".tfstate",
)

_HIGH_CONFIDENCE_SECRET_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    for pattern in (
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
        r"\bgithub_pat_[A-Za-z0-9_]{50,}\b",
        r"\bglpat-[A-Za-z0-9_-]{20,}\b",
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b",
        r"\bhf_[A-Za-z0-9]{20,}\b",
        r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b",
        r"[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@[^\s/]+",
    )
)

_QUOTED_ASSIGNMENT_RE = re.compile(
    r"(?im)[\"']?(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|"
    r"auth[_-]?token|private[_-]?key|hf[_-]?token|database[_-]?url|db[_-]?url|dsn)"
    r"[\"']?\s*[:=]\s*(?:[rubf]{0,2})"
    r"(?P<quote>[\"'])(?P<value>[^\r\n\"']{4,})(?P=quote)"
)
_BARE_ASSIGNMENT_RE = re.compile(
    r"(?im)^[ \t]*(?:export\s+)?(?:password|passwd|pwd|secret|client_secret|api[_-]?key|"
    r"access[_-]?token|auth[_-]?token|private[_-]?key|hf[_-]?token|database[_-]?url|"
    r"db[_-]?url|dsn)\s*[:=]\s*(?P<value>[^\s#;,]{4,})"
)


def detect_language(path: str | Path) -> str | None:
    """Return the supported language for *path*, if any."""

    candidate = PurePosixPath(str(path).replace("\\", "/"))
    name = candidate.name.casefold()
    suffix = candidate.suffix.casefold()
    if suffix in LANGUAGE_EXTENSIONS:
        return LANGUAGE_EXTENSIONS[suffix]
    if (
        name in CONFIG_FILENAMES
        or name in _SAFE_ENV_TEMPLATES
        or (name.startswith("requirements") and name.endswith(".txt"))
    ):
        return "config"
    stem_name = name.rsplit(".", 1)[0]
    if name in MARKDOWN_FILENAMES or stem_name in MARKDOWN_FILENAMES:
        return "markdown"
    return None


def is_default_ignored(path: str | PurePosixPath, *, is_dir: bool = False) -> bool:
    """Apply non-overridable build/cache/VCS exclusions."""

    candidate = PurePosixPath(path)
    lowered_parts = tuple(part.casefold() for part in candidate.parts)
    if any(part in DEFAULT_IGNORED_DIRS for part in lowered_parts):
        return True
    name = candidate.name.casefold()
    ignored_file = name in DEFAULT_IGNORED_FILES or any(
        name.endswith(suffix) for suffix in DEFAULT_IGNORED_SUFFIXES
    )
    return not is_dir and ignored_file


def is_sensitive_path(path: str | PurePosixPath) -> bool:
    """Return whether a filename conventionally stores credentials or keys."""

    candidate = PurePosixPath(path)
    parts = tuple(part.casefold() for part in candidate.parts)
    name = parts[-1] if parts else ""
    if name in _SAFE_ENV_TEMPLATES:
        return False
    if name == ".env" or name.startswith(".env."):
        return True
    if name in _SENSITIVE_EXACT_NAMES:
        return True
    if any(name.endswith(suffix) for suffix in _SENSITIVE_SUFFIXES):
        return True
    if ".ssh" in parts and not name.endswith(".pub"):
        return True
    if ".aws" in parts and name == "credentials":
        return True
    return bool(re.fullmatch(r"(?:service[-_.]?account|[^/]*credentials?)[-_.]?.*\.json", name))


def is_binary(data: bytes) -> bool:
    """Conservatively identify binary or non-UTF-8 payloads."""

    sample = data[:65_536]
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    if sample.startswith((b"PK\x03\x04", b"\x1f\x8b", b"\x89PNG", b"\x7fELF", b"%PDF")):
        return True
    try:
        decoded = sample.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        return True
    control_count = sum(
        1 for character in decoded if ord(character) < 32 and character not in "\b\t\n\f\r"
    )
    return control_count / max(1, len(decoded)) > 0.02


def _entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _plausible_assigned_secret(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.casefold()
    if len(stripped) < 8 or len(stripped) > 4_096:
        return False
    placeholder_fragments = (
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
    if any(fragment in lowered for fragment in placeholder_fragments):
        return False
    if lowered in {"password", "secret", "undefined", "none", "null"}:
        return False
    if len(set(stripped)) <= 2:
        return False
    return _entropy(stripped) >= 2.5


def contains_likely_secret(text: str) -> bool:
    """Detect high-confidence credentials without returning their value."""

    if any(pattern.search(text) for pattern in _HIGH_CONFIDENCE_SECRET_PATTERNS):
        return True
    assignments = list(_QUOTED_ASSIGNMENT_RE.finditer(text))
    assignments.extend(_BARE_ASSIGNMENT_RE.finditer(text))
    return any(_plausible_assigned_secret(match.group("value")) for match in assignments)


looks_like_secret = contains_likely_secret

__all__ = [
    "CONFIG_FILENAMES",
    "DEFAULT_IGNORED_DIRS",
    "LANGUAGE_EXTENSIONS",
    "contains_likely_secret",
    "detect_language",
    "is_binary",
    "is_default_ignored",
    "is_sensitive_path",
    "looks_like_secret",
]
