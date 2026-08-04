"""Persistent, per-repository consent and cloud-send previews."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import tempfile
import threading
from collections.abc import Iterable, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .display import has_unsafe_display_controls
from .redaction import redact_secrets_with_count

_STATE_LOCKS_GUARD = threading.Lock()
_STATE_LOCKS: dict[str, threading.RLock] = {}


class PrivacyStoreError(RuntimeError):
    """Raised when consent state cannot be safely read or written."""


class ConsentRequiredError(PermissionError):
    """Raised when a cloud provider has not received explicit consent."""


def canonical_endpoint(endpoint: str) -> str:
    """Return the privacy identity for one exact HTTP provider endpoint.

    Consent keys intentionally include the scheme, canonical host, effective
    port, and request path.  Queries, fragments, and embedded credentials are
    rejected so the returned value is also safe to display and persist.
    """

    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ValueError("provider endpoint must be a non-empty URL")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in endpoint):
        raise ValueError("provider endpoint must not contain control characters")
    try:
        parsed = urlsplit(endpoint.strip())
        port = parsed.port
    except ValueError as exc:
        raise ValueError("provider endpoint contains an invalid port") from exc
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("provider endpoint must be an absolute http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("provider endpoint must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("provider endpoint must not contain a query or fragment")

    host = parsed.hostname.rstrip(".").casefold()
    if not host:
        raise ValueError("provider endpoint contains an invalid hostname")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("provider endpoint contains an invalid hostname") from exc
        rendered_host = host
    else:
        host = address.compressed
        rendered_host = f"[{host}]" if address.version == 6 else host
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if "\\" in path:
        raise ValueError("provider endpoint path must not contain backslashes")
    return f"{scheme}://{rendered_host}:{effective_port}{path}"


def provider_family(model_or_provider: str) -> str:
    """Normalise a model string to its privacy-relevant provider family."""

    value = model_or_provider.strip().lower()
    if not value:
        raise ValueError("provider must not be empty")
    if has_unsafe_display_controls(value):
        raise ValueError("provider must not contain control or bidirectional characters")
    if value in {"local", "extractive", "local/extractive", "local:extractive"}:
        return "local"
    prefix = re_split_provider(value)
    aliases = {
        "openai-compatible": "openai",
        "openai_compatible": "openai",
        "openai": "openai",
        "anthropic": "anthropic",
        "ollama": "ollama",
        "local": "local",
        "extractive": "local",
    }
    return aliases.get(prefix, prefix)


def re_split_provider(value: str) -> str:
    """Split only the provider portion; model identifiers may contain slashes."""

    slash = value.find("/")
    colon = value.find(":")
    positions = [position for position in (slash, colon) if position >= 0]
    return value[: min(positions)] if positions else value


def is_local_provider(model_or_provider: str) -> bool:
    """Return true only for built-in local providers and Ollama."""

    return provider_family(model_or_provider) in {"local", "ollama"}


def _default_state_path() -> Path:
    try:
        from platformdirs import user_state_dir

        return Path(user_state_dir("repolocus", appauthor=False)) / "privacy.json"
    except ImportError:  # pragma: no cover - installed as a project dependency
        base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
        return base / "repolocus" / "privacy.json"


class PrivacyStore:
    """Store remembered cloud consent outside repositories.

    State contains canonical repository paths and grant timestamps, never code,
    prompts, credentials, or provider responses.
    """

    def __init__(self, state_path: Path | str | None = None) -> None:
        self.path = Path(state_path) if state_path is not None else _default_state_path()

    def status(self, root: Path | str) -> dict[str, bool]:
        """Return remembered provider grants for ``root``."""

        root_path = self._root(root)
        self._ensure_outside_repository(root_path)
        with self._locked_state():
            state = self._read()
        entry = state["repositories"].get(_repository_id(root_path), {})
        if entry.get("path") != str(root_path):
            return {}
        providers = entry.get("providers", {})
        if not isinstance(providers, dict):
            raise PrivacyStoreError("privacy state contains an invalid providers table")
        return {
            str(provider): True
            for provider, endpoints in sorted(providers.items())
            if isinstance(endpoints, dict) and endpoints
        }

    def grant_details(self, root: Path | str) -> dict[str, tuple[str, ...]]:
        """Return canonical endpoint identities for remembered provider grants."""

        root_path = self._root(root)
        self._ensure_outside_repository(root_path)
        with self._locked_state():
            state = self._read()
        entry = state["repositories"].get(_repository_id(root_path), {})
        if entry.get("path") != str(root_path):
            return {}
        providers = entry.get("providers", {})
        if not isinstance(providers, dict):
            raise PrivacyStoreError("privacy state contains an invalid providers table")
        return {
            str(provider): tuple(sorted(str(endpoint) for endpoint in endpoints))
            for provider, endpoints in sorted(providers.items())
            if isinstance(endpoints, dict) and endpoints
        }

    def grant(self, root: Path | str, provider: str, endpoint: str | None = None) -> None:
        """Remember consent for one provider endpoint and repository."""

        family = provider_family(provider)
        if is_local_provider(family):
            return
        if endpoint is None:
            raise PrivacyStoreError("a canonical endpoint is required for remembered cloud consent")
        endpoint_identity = canonical_endpoint(endpoint)
        root_path = self._root(root)
        self._ensure_outside_repository(root_path)
        with self._locked_state():
            state = self._read()
            repository = state["repositories"].setdefault(
                _repository_id(root_path), {"path": str(root_path), "providers": {}}
            )
            repository["path"] = str(root_path)
            providers = repository.setdefault("providers", {})
            endpoints = providers.setdefault(family, {})
            if not isinstance(endpoints, dict):
                raise PrivacyStoreError("privacy state contains an invalid endpoint grants table")
            endpoints[endpoint_identity] = {"granted_at": datetime.now(timezone.utc).isoformat()}
            self._write(state)

    def revoke(self, root: Path | str, provider: str | None = None) -> None:
        """Revoke one provider grant, or all grants for a repository."""

        root_path = self._root(root)
        self._ensure_outside_repository(root_path)
        with self._locked_state():
            state = self._read()
            repository_id = _repository_id(root_path)
            if provider is None:
                state["repositories"].pop(repository_id, None)
            else:
                family = provider_family(provider)
                repository = state["repositories"].get(repository_id)
                if isinstance(repository, dict):
                    providers = repository.get("providers", {})
                    if isinstance(providers, dict):
                        providers.pop(family, None)
                        if not providers:
                            state["repositories"].pop(repository_id, None)
            self._write(state)

    def is_allowed(
        self,
        root: Path | str,
        provider: str,
        endpoint: str | None = None,
    ) -> bool:
        """Return whether local use or remembered cloud consent permits use."""

        family = provider_family(provider)
        if is_local_provider(family):
            return True
        if endpoint is None:
            return False
        endpoint_identity = canonical_endpoint(endpoint)
        root_path = self._root(root)
        self._ensure_outside_repository(root_path)
        with self._locked_state():
            state = self._read()
        entry = state["repositories"].get(_repository_id(root_path), {})
        if entry.get("path") != str(root_path):
            return False
        providers = entry.get("providers", {})
        if not isinstance(providers, dict):
            raise PrivacyStoreError("privacy state contains an invalid providers table")
        endpoints = providers.get(family, {})
        if not isinstance(endpoints, dict):
            raise PrivacyStoreError("privacy state contains an invalid endpoint grants table")
        return endpoint_identity in endpoints

    @staticmethod
    def _root(root: Path | str) -> Path:
        try:
            path = Path(root).expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise PrivacyStoreError(f"repository root cannot be resolved: {root}") from exc
        if not path.is_dir():
            raise PrivacyStoreError(f"repository root is not a directory: {path}")
        return path

    def _ensure_outside_repository(self, root: Path) -> None:
        state_path = self.path.expanduser().resolve(strict=False)
        try:
            state_path.relative_to(root)
        except ValueError:
            return
        raise PrivacyStoreError("privacy consent state must be stored outside the repository")

    @contextmanager
    def _locked_state(self):  # type: ignore[no-untyped-def]
        """Serialize read-modify-write cycles across threads and POSIX processes."""

        lock_key = str(self.path.expanduser().resolve(strict=False))
        with _STATE_LOCKS_GUARD:
            thread_lock = _STATE_LOCKS.setdefault(lock_key, threading.RLock())
        with thread_lock:
            lock_path = self.path.expanduser().with_suffix(self.path.suffix + ".lock")
            try:
                lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            except OSError as exc:
                raise PrivacyStoreError(
                    f"cannot open privacy state lock {lock_path}: {exc}"
                ) from exc
            try:
                if os.name != "nt":
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                if os.name != "nt":
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def _read(self) -> dict[str, Any]:
        path = self.path.expanduser()
        if not path.exists():
            return {"version": 2, "repositories": {}}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PrivacyStoreError(f"cannot read privacy state {path}: {exc}") from exc
        if not isinstance(data, dict) or data.get("version") not in {1, 2}:
            raise PrivacyStoreError("privacy state has an unsupported format")
        repositories = data.get("repositories")
        if not isinstance(repositories, dict):
            raise PrivacyStoreError("privacy state contains an invalid repositories table")
        for repository in repositories.values():
            if not isinstance(repository, dict):
                raise PrivacyStoreError("privacy state contains an invalid repository entry")
            providers = repository.get("providers", {})
            if not isinstance(providers, dict):
                raise PrivacyStoreError("privacy state contains an invalid providers table")
        if data.get("version") == 1:
            # Family-only grants cannot be safely attached to the endpoint that
            # happens to be configured during an upgrade.  Migrate fail-closed;
            # the next explicit grant writes a v2 endpoint-bound record.
            return {
                "version": 2,
                "repositories": {
                    repository_id: {
                        "path": repository.get("path", ""),
                        "providers": {},
                    }
                    for repository_id, repository in repositories.items()
                },
            }
        for repository in repositories.values():
            providers = repository.get("providers", {})
            for endpoints in providers.values():
                if not isinstance(endpoints, dict):
                    raise PrivacyStoreError(
                        "privacy state contains an invalid endpoint grants table"
                    )
                for endpoint, grant in endpoints.items():
                    if not isinstance(endpoint, str) or not isinstance(grant, dict):
                        raise PrivacyStoreError("privacy state contains an invalid endpoint grant")
                    try:
                        canonical = canonical_endpoint(endpoint)
                    except ValueError as exc:
                        raise PrivacyStoreError(
                            "privacy state contains an invalid endpoint identity"
                        ) from exc
                    if canonical != endpoint:
                        raise PrivacyStoreError(
                            "privacy state contains a non-canonical endpoint identity"
                        )
        return data

    def _write(self, state: Mapping[str, Any]) -> None:
        path = self.path.expanduser()
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with suppress(OSError):
                path.parent.chmod(0o700)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
            )
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(state, handle, indent=2, sort_keys=True)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                temporary.chmod(0o600)
                os.replace(temporary, path)
                with suppress(OSError):
                    path.chmod(0o600)
            finally:
                if temporary.exists():
                    temporary.unlink()
        except OSError as exc:
            raise PrivacyStoreError(f"cannot write privacy state {path}: {exc}") from exc


def _repository_id(root: Path) -> str:
    return hashlib.sha256(str(root).encode("utf-8")).hexdigest()


def require_provider_consent(
    root: Path | str,
    provider: str,
    store: PrivacyStore,
    *,
    allow_once: bool = False,
    endpoint: str | None = None,
) -> None:
    """Enforce cloud consent at the service/CLI boundary."""

    if is_local_provider(provider) or allow_once or store.is_allowed(root, provider, endpoint):
        return
    family = provider_family(provider)
    raise ConsentRequiredError(
        f"cloud provider {family!r} requires explicit consent for this repository"
    )


@dataclass(frozen=True, slots=True)
class CloudSendPreview:
    """Safe summary of code context proposed for a cloud provider."""

    provider: str
    paths: tuple[str, ...]
    fragment_count: int
    estimated_tokens: int
    redaction_count: int = 0
    model: str = ""
    endpoint: str | None = None
    payload_bytes: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.provider, str) or not self.provider.strip():
            raise ValueError("preview provider must not be empty")
        if any(not isinstance(path, str) or not path for path in self.paths):
            raise ValueError("preview paths must be non-empty strings")
        if not isinstance(self.model, str):
            raise ValueError("preview model must be a string")
        if self.endpoint is not None and canonical_endpoint(self.endpoint) != self.endpoint:
            raise ValueError("preview endpoint must be canonical")
        for name in (
            "fragment_count",
            "estimated_tokens",
            "redaction_count",
            "payload_bytes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"preview {name} must be a non-negative integer")

    @property
    def fragments(self) -> int:
        """Readable alias used by terminal and API presentation layers."""

        return self.fragment_count

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "paths": list(self.paths),
            "fragments": self.fragment_count,
            "fragment_count": self.fragment_count,
            "estimated_tokens": self.estimated_tokens,
            "redaction_count": self.redaction_count,
            "model": self.model,
            "endpoint": self.endpoint,
            "payload_bytes": self.payload_bytes,
        }


def build_cloud_send_preview(
    provider: str,
    fragments: Iterable[object],
) -> CloudSendPreview:
    """Build a send preview from objects/mappings with ``path`` and ``content``."""

    family = provider_family(provider)
    paths: list[str] = []
    total_characters = 0
    redaction_count = 0
    count = 0
    for fragment in fragments:
        path, content = _fragment_values(fragment)
        count += 1
        if path not in paths:
            paths.append(path)
        redacted, matches = redact_secrets_with_count(content)
        total_characters += len(redacted)
        redaction_count += matches
    estimated_tokens = (total_characters + 3) // 4 if total_characters else 0
    return CloudSendPreview(
        provider=family,
        paths=tuple(paths),
        fragment_count=count,
        estimated_tokens=estimated_tokens,
        redaction_count=redaction_count,
    )


def _fragment_values(fragment: object) -> tuple[str, str]:
    if isinstance(fragment, Mapping):
        path = fragment.get("path")
        content = fragment.get("content")
    elif isinstance(fragment, tuple) and len(fragment) == 2:
        path, content = fragment
    else:
        path = getattr(fragment, "path", None)
        content = getattr(fragment, "content", None)
    if not isinstance(path, str) or not isinstance(content, str):
        raise TypeError("each fragment must provide string path and content values")
    return path, content
