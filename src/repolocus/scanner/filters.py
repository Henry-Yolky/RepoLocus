"""Pure filtering helpers used by the repository scanner."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from repolocus.security.secrets import contains_high_confidence_secret

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


def is_generated_document(text: str, language: str | None = None) -> bool:
    """Recognize an exact RepoLocus header near any supported document start.

    ``language`` is retained for caller compatibility, but deliberately does not
    gate detection.  Generated Markdown can be copied or renamed to another
    scanner-supported extension, and must not become source evidence merely
    because its filename changed.
    """

    del language
    prefix = text[:4096].encode("utf-8", errors="replace")[:4096].decode("utf-8", errors="ignore")
    return any(_GENERATED_MARKER.fullmatch(line) for line in prefix.splitlines()[:16])


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


def contains_likely_secret(text: str) -> bool:
    """Detect high-confidence credentials without returning their value."""

    return contains_high_confidence_secret(text)


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
