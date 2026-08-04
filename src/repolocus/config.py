"""Configuration loading for RepoLocus.

Configuration is deliberately split from credentials.  Repository and user
TOML files may contain behaviour settings, while provider secrets are read by
the provider adapters directly from their documented environment variables.
"""

from __future__ import annotations

import ast
import json
import math
import os
import re
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from repolocus.security.display import has_unsafe_display_controls
from repolocus.security.identity import descriptor_path
from repolocus.security.network import is_loopback_url

DEFAULT_MODEL = "local"
MAX_CONFIG_BYTES = 1_000_000


class ConfigError(ValueError):
    """Raised when a configuration source is invalid or unsafe."""


_DEFAULTS: dict[str, object] = {
    "model": DEFAULT_MODEL,
    "telemetry": False,
    "ollama_base_url": "http://127.0.0.1:11434",
    "openai_base_url": "https://api.openai.com/v1",
    "anthropic_base_url": "https://api.anthropic.com",
    "request_timeout": 30.0,
    "max_output_tokens": 2048,
    "max_file_bytes": 1_000_000,
    "context_char_budget": 24_000,
    "max_repository_files": 100_000,
    "max_repository_bytes": 512_000_000,
    "max_directory_depth": 64,
    "max_repository_chunks": 500_000,
    "max_repository_symbols": 500_000,
    "max_scan_seconds": 120,
    "query_synonyms": "{}",
}

_ALIASES = {
    "telemetry_enabled": "telemetry",
    "timeout": "request_timeout",
}

_ENV_KEYS = {
    "REPOLOCUS_MODEL": "model",
    "REPOLOCUS_TELEMETRY": "telemetry",
    "REPOLOCUS_OLLAMA_BASE_URL": "ollama_base_url",
    "REPOLOCUS_OPENAI_BASE_URL": "openai_base_url",
    "REPOLOCUS_ANTHROPIC_BASE_URL": "anthropic_base_url",
    "REPOLOCUS_REQUEST_TIMEOUT": "request_timeout",
    "REPOLOCUS_MAX_OUTPUT_TOKENS": "max_output_tokens",
    "REPOLOCUS_MAX_FILE_BYTES": "max_file_bytes",
    "REPOLOCUS_CONTEXT_CHAR_BUDGET": "context_char_budget",
    "REPOLOCUS_MAX_REPOSITORY_FILES": "max_repository_files",
    "REPOLOCUS_MAX_REPOSITORY_BYTES": "max_repository_bytes",
    "REPOLOCUS_MAX_DIRECTORY_DEPTH": "max_directory_depth",
    "REPOLOCUS_MAX_REPOSITORY_CHUNKS": "max_repository_chunks",
    "REPOLOCUS_MAX_REPOSITORY_SYMBOLS": "max_repository_symbols",
    "REPOLOCUS_MAX_SCAN_SECONDS": "max_scan_seconds",
    "REPOLOCUS_QUERY_SYNONYMS": "query_synonyms",
}

_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:api_?key|access_?key|secret|token|password|passwd|credential)s?(?:$|_)",
    re.IGNORECASE,
)

# Repository files are untrusted input. A committed config may only tighten
# local resource limits; it cannot select a model, network destination,
# telemetry policy, request timeout, or spending limit.
_REPOSITORY_LIMIT_KEYS = frozenset(
    {
        "max_file_bytes",
        "context_char_budget",
        "max_repository_files",
        "max_repository_bytes",
        "max_directory_depth",
        "max_repository_chunks",
        "max_repository_symbols",
        "max_scan_seconds",
    }
)


def _default_user_config_path() -> Path:
    """Return the platform-specific config path without a mandatory import."""

    try:
        from platformdirs import user_config_dir

        return Path(user_config_dir("repolocus", appauthor=False)) / "config.toml"
    except ImportError:  # pragma: no cover - installed as a project dependency
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        return base / "repolocus" / "config.toml"


@dataclass(frozen=True, slots=True)
class Settings:
    """Effective, non-secret RepoLocus settings.

    Precedence, from lowest to highest, is defaults, user config, repository
    config, then environment variables.  Telemetry and cloud access are both
    opt-in; the default provider is a deterministic local provider.
    """

    model: str = DEFAULT_MODEL
    telemetry: bool = False
    ollama_base_url: str = "http://127.0.0.1:11434"
    openai_base_url: str = "https://api.openai.com/v1"
    anthropic_base_url: str = "https://api.anthropic.com"
    request_timeout: float = 30.0
    max_output_tokens: int = 2048
    max_file_bytes: int = 1_000_000
    context_char_budget: int = 24_000
    max_repository_files: int = 100_000
    max_repository_bytes: int = 512_000_000
    max_directory_depth: int = 64
    max_repository_chunks: int = 500_000
    max_repository_symbols: int = 500_000
    max_scan_seconds: int = 120
    query_synonyms: str = "{}"

    def __post_init__(self) -> None:
        if not isinstance(self.model, str) or not self.model.strip():
            raise ConfigError("model must be a non-empty string")
        if not isinstance(self.telemetry, bool):
            raise ConfigError("telemetry must be true or false")
        if self.telemetry:
            raise ConfigError("telemetry is not implemented in v0.1 and must remain false")
        for field_name in ("ollama_base_url", "openai_base_url", "anthropic_base_url"):
            _validate_base_url(field_name, getattr(self, field_name))
        if (
            isinstance(self.request_timeout, bool)
            or not isinstance(self.request_timeout, (int, float))
            or not math.isfinite(self.request_timeout)
            or self.request_timeout <= 0
        ):
            raise ConfigError("request_timeout must be greater than zero")
        for field_name in (
            "max_output_tokens",
            "max_file_bytes",
            "context_char_budget",
            "max_repository_files",
            "max_repository_bytes",
            "max_directory_depth",
            "max_repository_chunks",
            "max_repository_symbols",
            "max_scan_seconds",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ConfigError(f"{field_name} must be a positive integer")
        _parse_query_synonyms(self.query_synonyms)

    @property
    def telemetry_enabled(self) -> bool:
        """Compatibility alias with an explicit boolean name."""

        return self.telemetry

    @property
    def query_synonym_map(self) -> dict[str, tuple[str, ...]]:
        """Return validated, user-controlled retrieval synonyms."""

        return _parse_query_synonyms(self.query_synonyms)

    @classmethod
    def load(
        cls,
        root: Path | str | None = None,
        *,
        environ: Mapping[str, str] | None = None,
        user_config_path: Path | str | None = None,
        repo_config_path: Path | str | None = None,
    ) -> Settings:
        """Load settings without ever reading credentials from a TOML file."""

        env = os.environ if environ is None else environ
        values = dict(_DEFAULTS)

        if user_config_path is None:
            configured_path = env.get("REPOLOCUS_CONFIG")
            user_path = Path(configured_path) if configured_path else _default_user_config_path()
        else:
            user_path = Path(user_config_path)
        if user_path.is_file():
            values.update(_normalise_config(_read_config(user_path, source="user"), user_path))

        if repo_config_path is not None:
            repo_paths = [Path(repo_config_path)]
        elif root is not None:
            repo_root = Path(root).expanduser().resolve()
            repo_paths = [
                repo_root / "pyproject.toml",
                repo_root / ".repolocus" / "config.toml",
                repo_root / ".repolocus.toml",
            ]
        else:
            repo_paths = []

        if repo_config_path is not None and root is None:
            raise ConfigError("root is required when repo_config_path is supplied")

        repo_root = Path(root).expanduser().resolve(strict=True) if root is not None else None
        for path in repo_paths:
            if repo_root is None:
                if not path.is_file():
                    continue
                raw = _read_config_bytes(path, source="repository")
            else:
                raw = _read_repository_config_bytes(repo_root, path)
                if raw is None:
                    continue
            if path.name == "pyproject.toml" and not _pyproject_declares_repolocus(raw, path):
                continue
            table = _parse_config(raw, path, source="repository")
            # A pyproject is relevant only when it contains [tool.repolocus].
            if path.name == "pyproject.toml" and not _has_repolocus_table(table):
                continue
            repository_values = _normalise_config(
                table,
                path,
                allowed_keys=_REPOSITORY_LIMIT_KEYS,
            )
            for key, value in repository_values.items():
                values[key] = min(int(values[key]), int(value))

        for env_name, setting_name in _ENV_KEYS.items():
            if env_name in env:
                values[setting_name] = _coerce_value(setting_name, env[env_name], env_name)

        return cls(**values)


def load_settings(
    root: Path | str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    user_config_path: Path | str | None = None,
    repo_config_path: Path | str | None = None,
) -> Settings:
    """Functional wrapper around :meth:`Settings.load`."""

    return Settings.load(
        root,
        environ=environ,
        user_config_path=user_config_path,
        repo_config_path=repo_config_path,
    )


def _validate_base_url(name: str, value: object) -> None:
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a URL string")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ConfigError(f"{name} must not contain control characters")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigError(f"{name} must be an absolute http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError(f"{name} must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ConfigError(f"{name} must not contain a query or fragment")
    if parsed.scheme == "http" and not is_loopback_url(value):
        raise ConfigError(f"{name} must use HTTPS unless it targets a loopback address")


def _ensure_repo_config_path(root: Path, config_path: Path) -> Path:
    """Return a lexical path below ``root`` without following repository links."""

    root_real = root.expanduser().resolve(strict=True)
    config_absolute = config_path.expanduser().absolute()
    try:
        return config_absolute.relative_to(root_real)
    except ValueError as exc:
        raise ConfigError(f"repository config escapes repository root: {config_path}") from exc


def _has_repolocus_table(data: Mapping[str, Any]) -> bool:
    tool = data.get("tool")
    return isinstance(tool, Mapping) and isinstance(tool.get("repolocus"), Mapping)


def _pyproject_declares_repolocus(raw: bytes, path: Path) -> bool:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"cannot inspect repository config {path}: {exc}") from exc
    return bool(re.search(r"(?m)^\s*\[tool\.repolocus\]\s*(?:#.*)?$", text))


def _extract_table(data: Mapping[str, Any]) -> Mapping[str, Any]:
    tool = data.get("tool")
    if isinstance(tool, Mapping) and isinstance(tool.get("repolocus"), Mapping):
        return tool["repolocus"]
    repolocus = data.get("repolocus")
    if isinstance(repolocus, Mapping):
        return repolocus
    return data


def _normalise_config(
    data: Mapping[str, Any],
    path: Path,
    *,
    allowed_keys: frozenset[str] | None = None,
) -> dict[str, object]:
    table = _extract_table(data)
    result: dict[str, object] = {}
    for raw_key, value in table.items():
        key = str(raw_key).strip().lower().replace("-", "_")
        if _SECRET_KEY_RE.search(key):
            raise ConfigError(
                f"credentials are not allowed in {path}; use provider environment variables"
            )
        key = _ALIASES.get(key, key)
        if key not in _DEFAULTS:
            raise ConfigError(f"unknown RepoLocus setting {raw_key!r} in {path}")
        if allowed_keys is not None and key not in allowed_keys:
            allowed = ", ".join(sorted(allowed_keys))
            raise ConfigError(
                f"repository config cannot set {raw_key!r}; only local limits are allowed "
                f"({allowed}). Put model and network settings in the user config or environment."
            )
        result[key] = _coerce_value(key, value, str(path))
    return result


def _coerce_value(key: str, value: object, source: str) -> object:
    if key == "telemetry":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"1", "true", "yes", "on"}:
                return True
            if lowered in {"0", "false", "no", "off"}:
                return False
        raise ConfigError(f"{source}: telemetry must be true or false")
    if key == "request_timeout":
        try:
            parsed = float(value)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{source}: request_timeout must be a number") from exc
        return parsed
    if key in {
        "max_output_tokens",
        "max_file_bytes",
        "context_char_budget",
        "max_repository_files",
        "max_repository_bytes",
        "max_directory_depth",
        "max_repository_chunks",
        "max_repository_symbols",
        "max_scan_seconds",
    }:
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ConfigError(f"{source}: {key} must be an integer")
        try:
            parsed_int = int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{source}: {key} must be an integer") from exc
        return parsed_int
    if key == "query_synonyms":
        if isinstance(value, Mapping):
            encoded = json.dumps(value, ensure_ascii=False, sort_keys=True)
        elif isinstance(value, str):
            encoded = value.strip()
        else:
            raise ConfigError(f"{source}: query_synonyms must be a JSON object or TOML table")
        _parse_query_synonyms(encoded, source=source)
        return encoded
    if not isinstance(value, str):
        raise ConfigError(f"{source}: {key} must be a string")
    return value.strip()


def _parse_query_synonyms(
    value: str,
    *,
    source: str = "query_synonyms",
) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 32_768:
        raise ConfigError(f"{source}: query_synonyms must be a JSON object under 32768 bytes")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{source}: query_synonyms must be valid JSON") from exc
    if not isinstance(parsed, dict) or len(parsed) > 128:
        raise ConfigError(f"{source}: query_synonyms must contain at most 128 terms")
    normalized: dict[str, tuple[str, ...]] = {}
    for raw_term, raw_expansions in parsed.items():
        if not isinstance(raw_term, str) or not raw_term.strip() or len(raw_term) > 128:
            raise ConfigError(f"{source}: synonym terms must be non-empty strings")
        if has_unsafe_display_controls(raw_term):
            raise ConfigError(f"{source}: synonym terms must not contain display controls")
        if not isinstance(raw_expansions, list) or not 1 <= len(raw_expansions) <= 16:
            raise ConfigError(f"{source}: each synonym term must map to 1-16 strings")
        expansions: list[str] = []
        for expansion in raw_expansions:
            if (
                not isinstance(expansion, str)
                or not expansion.strip()
                or len(expansion) > 128
                or has_unsafe_display_controls(expansion)
            ):
                raise ConfigError(f"{source}: synonym expansions must be safe strings")
            normalized_expansion = expansion.strip().casefold()
            if normalized_expansion not in expansions:
                expansions.append(normalized_expansion)
        normalized[raw_term.strip().casefold()] = tuple(expansions)
    return normalized


def _read_config(path: Path, *, source: str) -> Mapping[str, Any]:
    raw = _read_config_bytes(path, source=source)
    return _parse_config(raw, path, source=source)


def _parse_config(raw: bytes, path: Path, *, source: str) -> Mapping[str, Any]:
    """Parse exactly one already-pinned configuration byte snapshot."""

    try:
        try:
            import tomllib  # type: ignore[import-not-found]

            parsed = tomllib.loads(raw.decode("utf-8"))
        except ModuleNotFoundError:
            text = raw.decode("utf-8")
            if path.name == "pyproject.toml":
                text = _repolocus_pyproject_subset(text)
            parsed = _parse_toml_subset(text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ConfigError(f"invalid TOML in {source} config {path}: {exc}") from exc
    if not isinstance(parsed, Mapping):
        raise ConfigError(f"invalid TOML table in {source} config {path}")
    return parsed


def _same_config_state(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
    )


def _same_config_identity_and_content(first: os.stat_result, second: os.stat_result) -> bool:
    """Compare metadata collected from a path and an open handle."""

    return (
        (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
    )


def _is_reparse_point(metadata: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & marker)


def _read_config_descriptor(descriptor: int) -> bytes:
    blocks: list[bytes] = []
    remaining = MAX_CONFIG_BYTES + 1
    while remaining:
        block = os.read(descriptor, min(65_536, remaining))
        if not block:
            break
        blocks.append(block)
        remaining -= len(block)
    return b"".join(blocks)


def _read_repository_config_bytes(root: Path, path: Path) -> bytes | None:
    """Open one repository config beneath a pinned root and read it exactly once.

    POSIX walks each component relative to directory descriptors, rejecting links.
    The fallback keeps a file handle open while it revalidates identity, boundary,
    and content state before accepting the snapshot.
    """

    relative = _ensure_repo_config_path(root, path)
    if not relative.parts:
        raise ConfigError(f"repository config is not a regular file: {path}")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ConfigError(f"repository config escapes repository root: {path}")

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    supports_openat = (
        bool(nofollow) and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
    )
    if supports_openat:
        descriptors: list[int] = []
        directory_fd: int | None = None
        file_opened = False
        try:
            root_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            root_flags |= getattr(os, "O_DIRECTORY", 0) | nofollow
            directory_fd = os.open(root, root_flags)
            descriptors.append(directory_fd)
            for component in relative.parts[:-1]:
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_DIRECTORY", 0) | nofollow
                directory_fd = os.open(component, flags, dir_fd=directory_fd)
                descriptors.append(directory_fd)
            name = relative.parts[-1]
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= nofollow | getattr(os, "O_NONBLOCK", 0)
            descriptor = os.open(name, flags, dir_fd=directory_fd)
            file_opened = True
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or _is_reparse_point(opened):
                raise ConfigError(f"repository config is not a safe regular file: {path}")
            if opened.st_size > MAX_CONFIG_BYTES:
                raise ConfigError(
                    f"repository config exceeds the {MAX_CONFIG_BYTES}-byte limit: {path}"
                )
            raw = _read_config_descriptor(descriptor)
            finished = os.fstat(descriptor)
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                _is_reparse_point(current)
                or not _same_config_state(opened, finished)
                or not _same_config_state(finished, current)
            ):
                raise ConfigError(f"repository config changed while being read: {path}")
        except FileNotFoundError as exc:
            if not file_opened:
                return None
            raise ConfigError(f"repository config changed while being read: {path}") from exc
        except ConfigError:
            raise
        except OSError as exc:
            raise ConfigError(
                f"repository config escapes repository root or uses an unsafe link: {path}"
            ) from exc
        finally:
            for descriptor in reversed(descriptors):
                with suppress(OSError):
                    os.close(descriptor)
    else:
        candidate = root.joinpath(*relative.parts)
        file_opened = False
        try:
            expected = candidate.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ConfigError(f"cannot inspect repository config {path}: {exc}") from exc
        if (
            not stat.S_ISREG(expected.st_mode)
            or stat.S_ISLNK(expected.st_mode)
            or _is_reparse_point(expected)
        ):
            raise ConfigError(
                f"repository config escapes repository root or uses an unsafe link: {path}"
            )
        try:
            current_directory = root
            for component in relative.parts[:-1]:
                current_directory /= component
                component_metadata = current_directory.lstat()
                if (
                    not stat.S_ISDIR(component_metadata.st_mode)
                    or stat.S_ISLNK(component_metadata.st_mode)
                    or _is_reparse_point(component_metadata)
                ):
                    raise ConfigError(
                        f"repository config escapes repository root or uses an unsafe link: {path}"
                    )
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            descriptor = os.open(candidate, flags)
            file_opened = True
            try:
                opened = os.fstat(descriptor)
                opened_path = descriptor_path(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or _is_reparse_point(opened)
                    or (expected.st_dev, expected.st_ino) != (opened.st_dev, opened.st_ino)
                    or opened_path is None
                    or not opened_path.is_relative_to(root)
                ):
                    raise ConfigError(f"repository config changed while being opened: {path}")
                if opened.st_size > MAX_CONFIG_BYTES:
                    raise ConfigError(
                        f"repository config exceeds the {MAX_CONFIG_BYTES}-byte limit: {path}"
                    )
                raw = _read_config_descriptor(descriptor)
                finished = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            current = candidate.lstat()
            if stat.S_ISLNK(current.st_mode) or _is_reparse_point(current):
                raise ConfigError(f"repository config changed while being read: {path}")
            current_resolved = candidate.resolve(strict=True)
            current_resolved.relative_to(root)
            if (
                not _same_config_state(opened, finished)
                or not _same_config_identity_and_content(finished, current)
                or not _same_config_state(expected, current)
            ):
                raise ConfigError(f"repository config changed while being read: {path}")
        except ConfigError:
            raise
        except (OSError, ValueError) as exc:
            if file_opened:
                raise ConfigError(f"repository config changed while being read: {path}") from exc
            raise ConfigError(
                f"repository config escapes repository root or uses an unsafe link: {path}"
            ) from exc

    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(f"repository config exceeds the {MAX_CONFIG_BYTES}-byte limit: {path}")
    return raw


def _read_config_bytes(path: Path, *, source: str) -> bytes:
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f"{source} config exceeds the {MAX_CONFIG_BYTES}-byte limit: {path}")
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read {source} config {path}: {exc}") from exc
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(f"{source} config exceeds the {MAX_CONFIG_BYTES}-byte limit: {path}")
    return raw


def _parse_toml_subset(text: str) -> dict[str, Any]:
    """Parse the scalar TOML subset used by RepoLocus on Python 3.10.

    Python 3.11 and newer use the standard-library parser.  Keeping this tiny
    fallback avoids making Python 3.10 silently unsupported solely for config.
    """

    result: dict[str, Any] = {}
    current = result
    for line_number, original in enumerate(text.splitlines(), start=1):
        line = _strip_toml_comment(original).strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            if not section or section.startswith("["):
                raise ValueError(f"unsupported table declaration on line {line_number}")
            current = result
            for part in section.split("."):
                key = part.strip().strip("\"'")
                if not key:
                    raise ValueError(f"empty table name on line {line_number}")
                child = current.setdefault(key, {})
                if not isinstance(child, dict):
                    raise ValueError(f"table conflicts with value on line {line_number}")
                current = child
            continue
        if "=" not in line:
            raise ValueError(f"expected key = value on line {line_number}")
        raw_key, raw_value = line.split("=", 1)
        key = raw_key.strip().strip("\"'")
        if not key:
            raise ValueError(f"empty key on line {line_number}")
        current[key] = _parse_toml_scalar(raw_value.strip(), line_number)
    return result


def _repolocus_pyproject_subset(text: str) -> str:
    """Extract [tool.repolocus] so the Python 3.10 parser skips unrelated TOML."""

    selected: list[str] = []
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_section = stripped == "[tool.repolocus]"
        if in_section:
            selected.append(line)
    return "\n".join(selected)


def _strip_toml_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote == '"':
            escaped = True
            continue
        if char in {'"', "'"}:
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
        elif char == "#" and quote is None:
            return line[:index]
    return line


def _parse_toml_scalar(value: str, line_number: int) -> object:
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if value.startswith('"'):
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid string on line {line_number}") from exc
    if value.startswith("'"):
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError) as exc:
            raise ValueError(f"invalid string on line {line_number}") from exc
    try:
        return int(value.replace("_", ""))
    except ValueError:
        try:
            return float(value.replace("_", ""))
        except ValueError as exc:
            raise ValueError(f"unsupported value on line {line_number}") from exc
