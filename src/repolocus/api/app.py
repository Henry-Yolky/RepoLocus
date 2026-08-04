"""FastAPI routes with local-first authentication and immutable cloud previews."""

import hmac
import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from repolocus import __version__
from repolocus.core import PreparedAsk, RepoLocusService


class _PreviewNotFoundError(KeyError):
    pass


class _PreviewExpiredError(KeyError):
    pass


class _PreviewCapacityError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class _StoredPreview:
    prepared: PreparedAsk
    scan: dict[str, object]
    expires_at: float


class _PreviewRegistry:
    """Small, process-local, single-use store for redacted evidence snapshots."""

    def __init__(self, *, ttl_seconds: int, capacity: int) -> None:
        self._ttl_seconds = ttl_seconds
        self._capacity = capacity
        self._entries: dict[str, _StoredPreview] = {}
        self._expired: dict[str, float] = {}
        self._lock = threading.Lock()

    def create(self, prepared: PreparedAsk, scan: dict[str, object]) -> tuple[str, int]:
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            if len(self._entries) >= self._capacity:
                raise _PreviewCapacityError("too many pending cloud previews")
            preview_id = secrets.token_urlsafe(32)
            expires_at = now + self._ttl_seconds
            self._entries[preview_id] = _StoredPreview(prepared, scan, expires_at)
        return preview_id, self._ttl_seconds

    def consume(self, preview_id: str) -> _StoredPreview:
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            if preview_id in self._expired:
                raise _PreviewExpiredError(preview_id)
            stored = self._entries.pop(preview_id, None)
            if stored is None:
                raise _PreviewNotFoundError(preview_id)
            if stored.expires_at <= now:
                self._expired[preview_id] = now + self._ttl_seconds
                raise _PreviewExpiredError(preview_id)
            # A consumed id remains a tombstone, preventing accidental retries
            # from being mistaken for a newly issued preview.
            self._expired[preview_id] = now + self._ttl_seconds
            return stored

    def _prune(self, now: float) -> None:
        for preview_id, stored in tuple(self._entries.items()):
            if stored.expires_at <= now:
                self._entries.pop(preview_id, None)
                self._expired[preview_id] = now + self._ttl_seconds
        for preview_id, expires_at in tuple(self._expired.items()):
            if expires_at <= now:
                self._expired.pop(preview_id, None)


class _ApiSecurityMiddleware:
    """Authenticate early and bound Host, body size, and in-flight work."""

    def __init__(
        self,
        app: Any,
        *,
        token: str,
        allowed_hosts: tuple[str, ...],
        max_request_body_bytes: int,
        max_concurrent_requests: int,
    ) -> None:
        self.app = app
        self._token = token
        self._allowed_hosts = frozenset(_normalise_allowed_host(host) for host in allowed_hosts)
        self._max_request_body_bytes = max_request_body_bytes
        self._max_concurrent_requests = max_concurrent_requests
        self._active_requests = 0
        self._active_lock = threading.Lock()

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = scope.get("headers", [])
        host_headers = [value for name, value in headers if name.lower() == b"host"]
        if len(host_headers) != 1:
            await _json_error(send, 400, "exactly one Host header is required")
            return
        try:
            host = _normalise_host_header(host_headers[0])
        except ValueError:
            await _json_error(send, 400, "invalid Host header")
            return
        if host not in self._allowed_hosts:
            await _json_error(send, 400, "Host header is not allowed")
            return

        authorization = [value for name, value in headers if name.lower() == b"authorization"]
        expected = f"Bearer {self._token}".encode()
        if len(authorization) != 1 or not hmac.compare_digest(authorization[0], expected):
            await _json_error(
                send,
                401,
                "Bearer authentication is required",
                headers=((b"www-authenticate", b"Bearer"),),
            )
            return

        content_lengths = [value for name, value in headers if name.lower() == b"content-length"]
        if len(content_lengths) > 1:
            await _json_error(send, 400, "multiple Content-Length headers are not allowed")
            return
        if content_lengths:
            try:
                declared_length = int(content_lengths[0])
            except ValueError:
                await _json_error(send, 400, "invalid Content-Length header")
                return
            if declared_length < 0:
                await _json_error(send, 400, "invalid Content-Length header")
                return
            if declared_length > self._max_request_body_bytes:
                await _json_error(send, 413, "request body is too large")
                return

        limited = str(scope.get("path", "")).startswith("/v1/")
        capacity_available = True
        if limited:
            with self._active_lock:
                if self._active_requests >= self._max_concurrent_requests:
                    capacity_available = False
                else:
                    self._active_requests += 1
        if not capacity_available:
            await _json_error(
                send,
                429,
                "too many concurrent requests",
                headers=((b"retry-after", b"1"),),
            )
            return
        try:
            body = bytearray()
            more_body = True
            while more_body:
                message = await receive()
                if message.get("type") == "http.disconnect":
                    return
                if message.get("type") != "http.request":
                    continue
                body.extend(message.get("body", b""))
                if len(body) > self._max_request_body_bytes:
                    await _json_error(send, 413, "request body is too large")
                    return
                more_body = bool(message.get("more_body", False))

            first_receive = True

            async def replay_receive() -> dict[str, object]:
                nonlocal first_receive
                if first_receive:
                    first_receive = False
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return {"type": "http.request", "body": b"", "more_body": False}

            async def no_store_send(message: dict[str, Any]) -> None:
                if message.get("type") == "http.response.start" and limited:
                    response_headers = list(message.get("headers", []))
                    response_headers.append((b"cache-control", b"no-store"))
                    message["headers"] = response_headers
                await send(message)

            await self.app(scope, replay_receive, no_store_send)
        finally:
            if limited:
                with self._active_lock:
                    self._active_requests -= 1


async def _json_error(
    send: Any,
    status: int,
    detail: str,
    *,
    headers: tuple[tuple[bytes, bytes], ...] = (),
) -> None:
    body = json.dumps({"detail": detail}, separators=(",", ":")).encode("utf-8")
    response_headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        *headers,
    ]
    await send({"type": "http.response.start", "status": status, "headers": response_headers})
    await send({"type": "http.response.body", "body": body})


def _normalise_allowed_host(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("allowed hosts must be non-empty")
    candidate = value.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if ":" in candidate and candidate.count(":") == 1:
        host, possible_port = candidate.rsplit(":", 1)
        if possible_port.isdigit():
            candidate = host
    candidate = candidate.rstrip(".").casefold()
    if not candidate or any(character in candidate for character in "/\\@"):
        raise ValueError("allowed host is invalid")
    return candidate


def _normalise_host_header(value: bytes) -> str:
    try:
        candidate = value.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("Host must be ASCII") from exc
    if candidate.startswith("["):
        closing = candidate.find("]")
        if closing < 0:
            raise ValueError("invalid IPv6 Host")
        host = candidate[1:closing]
        remainder = candidate[closing + 1 :]
        if remainder and (not remainder.startswith(":") or not remainder[1:].isdigit()):
            raise ValueError("invalid Host port")
    else:
        if candidate.count(":") > 1:
            raise ValueError("IPv6 Host must use brackets")
        host, separator, port = candidate.rpartition(":")
        if separator:
            if not port.isdigit():
                raise ValueError("invalid Host port")
        else:
            host = candidate
    host = host.rstrip(".").casefold()
    if not host or any(character in host for character in "/\\@"):
        raise ValueError("invalid Host")
    return host


def create_app(
    root: Path | str | None = None,
    *,
    allow_cloud_requests: bool = False,
    api_token: str | None = None,
    allowed_hosts: tuple[str, ...] | None = None,
    max_request_body_bytes: int = 65_536,
    max_concurrent_requests: int = 4,
    preview_ttl_seconds: int = 300,
    max_pending_previews: int = 64,
):  # type: ignore[no-untyped-def]
    try:
        from fastapi import FastAPI, HTTPException
        from pydantic import BaseModel, ConfigDict, Field
    except ImportError as exc:  # pragma: no cover - exercised without the optional extra
        raise RuntimeError("install repolocus[api] to use the HTTP service") from exc

    api_root = Path.cwd().resolve(strict=True) if root is None else Path(root).resolve(strict=True)
    if not api_root.is_dir():
        raise ValueError(f"API root is not a directory: {api_root}")
    token = secrets.token_urlsafe(32) if api_token is None else api_token.strip()
    if len(token) < 24 or any(
        ord(character) < 0x21 or ord(character) > 0x7E for character in token
    ):
        raise ValueError("API token must contain at least 24 printable non-space characters")
    hosts = allowed_hosts or ("localhost", "127.0.0.1", "::1")
    for name, value in (
        ("max_request_body_bytes", max_request_body_bytes),
        ("max_concurrent_requests", max_concurrent_requests),
        ("preview_ttl_seconds", preview_ttl_seconds),
        ("max_pending_previews", max_pending_previews),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")

    class RepositoryRequest(BaseModel):
        model_config = ConfigDict(extra="forbid")

        path: str = Field(default=".", min_length=1, max_length=4096)

    class OutputRequest(RepositoryRequest):
        refresh: Literal["auto", "always", "never"] = "auto"

    class AskRequest(RepositoryRequest):
        question: str = Field(min_length=1, max_length=4000)
        model: str | None = Field(default=None, min_length=1, max_length=512)
        limit: int = Field(default=8, ge=1, le=20)
        refresh: Literal["auto", "always", "never"] = "auto"

    application = FastAPI(
        title="RepoLocus",
        version=__version__,
        description="Self-hosted, read-only repository understanding API.",
    )
    application.state.api_token = token
    application.add_middleware(
        _ApiSecurityMiddleware,
        token=token,
        allowed_hosts=tuple(hosts),
        max_request_body_bytes=max_request_body_bytes,
        max_concurrent_requests=max_concurrent_requests,
    )
    previews = _PreviewRegistry(
        ttl_seconds=preview_ttl_seconds,
        capacity=max_pending_previews,
    )

    def repository(path: str) -> Path:
        requested = Path(path).expanduser()
        if not requested.is_absolute():
            requested = api_root / requested
        resolved = requested.resolve(strict=True)
        try:
            resolved.relative_to(api_root)
        except ValueError as exc:
            raise HTTPException(
                status_code=403,
                detail=f"repository path is outside the configured API root: {api_root}",
            ) from exc
        if not resolved.is_dir():
            raise HTTPException(status_code=400, detail="repository path is not a directory")
        return resolved

    def service(path: str) -> tuple[Path, RepoLocusService]:
        from repolocus.config import Settings

        repository_root = repository(path)
        return repository_root, RepoLocusService(Settings.load(repository_root))

    def answer_payload(
        answer: Any,
        preview: Any,
        scan: dict[str, object],
    ) -> dict[str, object]:
        return {
            "answer": answer.text,
            "confidence": answer.confidence,
            "provider": answer.provider,
            "evidence": [asdict(item) | {"citation": item.citation} for item in answer.evidence],
            "preview": preview.to_dict(),
            "scan": scan,
        }

    @application.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @application.post("/v1/scan")
    def scan(payload: RepositoryRequest) -> dict[str, object]:
        try:
            repository_root, instance = service(payload.path)
            return instance.scan(repository_root).to_dict()
        except (OSError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/v1/map")
    def project_map(payload: OutputRequest) -> dict[str, object]:
        try:
            repository_root, instance = service(payload.path)
            document, operation = instance.map(repository_root, refresh=payload.refresh)
            return {"document": document, "scan": operation.to_dict()}
        except (OSError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/v1/diagram")
    def diagram(payload: OutputRequest) -> dict[str, object]:
        try:
            repository_root, instance = service(payload.path)
            document, operation = instance.diagram(repository_root, refresh=payload.refresh)
            return {"document": document, "scan": operation.to_dict()}
        except (OSError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/v1/ask")
    def ask(payload: AskRequest) -> dict[str, object]:
        try:
            repository_root, instance = service(payload.path)
            chosen_model = payload.model or instance.settings.model
            scope = instance.consent_scope(chosen_model)
            instance.consent_endpoint(chosen_model)
            if scope not in {"local", "ollama"}:
                if not allow_cloud_requests:
                    raise HTTPException(
                        status_code=403,
                        detail="cloud models are disabled for this API server",
                    )
                raise HTTPException(
                    status_code=428,
                    detail="cloud models require /v1/ask/preview followed by one approval",
                )
            answer, operation, preview = instance.ask(
                payload.question,
                repository_root,
                model=payload.model,
                limit=payload.limit,
                refresh=payload.refresh,
            )
            return answer_payload(answer, preview, operation.to_dict())
        except HTTPException:
            raise
        except (OSError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/v1/ask/preview", status_code=201)
    def preview_ask(payload: AskRequest) -> dict[str, object]:
        try:
            repository_root, instance = service(payload.path)
            chosen_model = payload.model or instance.settings.model
            scope = instance.consent_scope(chosen_model)
            instance.consent_endpoint(chosen_model)
            if scope not in {"local", "ollama"} and not allow_cloud_requests:
                raise HTTPException(
                    status_code=403,
                    detail="cloud models are disabled for this API server",
                )
            prepared, operation = instance.prepare_ask(
                payload.question,
                repository_root,
                model=payload.model,
                limit=payload.limit,
                refresh=payload.refresh,
            )
            preview_id, expires_in = previews.create(prepared, operation.to_dict())
            return {
                "preview_id": preview_id,
                "expires_in_seconds": expires_in,
                "preview": prepared.preview.to_dict(),
                "fragments": [
                    asdict(item) | {"citation": item.citation} for item in prepared.evidence
                ],
                "scan": operation.to_dict(),
            }
        except HTTPException:
            raise
        except _PreviewCapacityError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except (OSError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/v1/ask/previews/{preview_id}/approve")
    def approve_ask(preview_id: str) -> dict[str, object]:
        try:
            stored = previews.consume(preview_id)
        except _PreviewExpiredError as exc:
            raise HTTPException(
                status_code=410,
                detail="cloud preview expired or was consumed",
            ) from exc
        except _PreviewNotFoundError as exc:
            raise HTTPException(status_code=404, detail="cloud preview was not found") from exc
        try:
            instance = RepoLocusService(stored.prepared.settings)
            answer = instance.execute_prepared(
                stored.prepared,
                allow_cloud=True,
                remember_consent=False,
            )
            return answer_payload(answer, stored.prepared.preview, stored.scan)
        except (OSError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return application
