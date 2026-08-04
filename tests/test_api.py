from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import httpx
import pytest

from repolocus import __version__
from repolocus.api import create_app
from repolocus.api.app import (
    _normalise_allowed_host,
    _normalise_host_header,
    _PreviewCapacityError,
    _PreviewExpiredError,
    _PreviewNotFoundError,
    _PreviewRegistry,
)
from repolocus.security import PrivacyStore


def _request(application, method: str, path: str, **kwargs: object) -> httpx.Response:
    authenticated = bool(kwargs.pop("authenticated", True))
    host = str(kwargs.pop("host", "localhost"))
    headers = dict(kwargs.pop("headers", {}))
    headers["Host"] = host
    if authenticated:
        headers["Authorization"] = f"Bearer {application.state.api_token}"

    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.request(method, path, headers=headers, **kwargs)

    return asyncio.run(send())


def test_self_hosted_api_health_and_local_workflow(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    application = create_app(sample_repo)

    health = _request(application, "GET", "/health")
    scan = _request(application, "POST", "/v1/scan", json={"path": str(sample_repo)})
    project_map = _request(application, "POST", "/v1/map", json={"path": str(sample_repo)})
    diagram = _request(application, "POST", "/v1/diagram", json={"path": str(sample_repo)})
    ask = _request(
        application,
        "POST",
        "/v1/ask",
        json={"path": str(sample_repo), "question": "Where is load_config defined?"},
    )

    assert health.status_code == 200
    assert health.json()["version"] == __version__
    assert scan.status_code == 200, scan.text
    assert scan.json()["scan"]["indexed_files"] >= 4
    assert project_map.status_code == 200, project_map.text
    assert "# Project Map" in project_map.json()["document"]
    assert diagram.status_code == 200, diagram.text
    assert "```mermaid" in diagram.json()["document"]
    assert ask.status_code == 200, ask.text
    assert ask.json()["provider"] == "extractive"
    assert ask.json()["evidence"]


def test_self_hosted_api_enforces_cloud_consent(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    application = create_app(sample_repo)

    response = _request(
        application,
        "POST",
        "/v1/ask",
        json={
            "path": str(sample_repo),
            "question": "Where is load_config defined?",
            "model": "openai/test-model",
        },
    )

    assert response.status_code == 403
    assert "disabled" in response.json()["detail"]


def test_self_hosted_api_rejects_paths_outside_configured_root(
    sample_repo: Path, isolated_user_dirs: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("SECRET = 'do-not-index'\n", encoding="utf-8")
    application = create_app(sample_repo)

    response = _request(application, "POST", "/v1/scan", json={"path": str(outside)})

    assert response.status_code == 403
    assert "outside the configured API root" in response.json()["detail"]


def test_api_requires_random_bearer_token_and_valid_host(sample_repo: Path) -> None:
    first = create_app(sample_repo)
    second = create_app(sample_repo)

    assert first.state.api_token != second.state.api_token
    assert _request(first, "GET", "/health", authenticated=False).status_code == 401
    assert _request(first, "GET", "/health", host="evil.example").status_code == 400
    assert _request(first, "GET", "/health").status_code == 200


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Example.COM.", "example.com"),
        ("example.com:8765", "example.com"),
        ("[::1]", "::1"),
    ],
)
def test_api_allowed_host_normalization(value: str, expected: str) -> None:
    assert _normalise_allowed_host(value) == expected


@pytest.mark.parametrize("value", ["", "bad/host", "bad\\host", "user@host"])
def test_api_rejects_invalid_allowed_hosts(value: str) -> None:
    with pytest.raises(ValueError, match="allowed host"):
        _normalise_allowed_host(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"example.com:443", "example.com"),
        (b"[::1]:8765", "::1"),
        (b"LOCALHOST.", "localhost"),
    ],
)
def test_api_host_header_normalization(value: bytes, expected: str) -> None:
    assert _normalise_host_header(value) == expected


@pytest.mark.parametrize(
    "value",
    [b"\xff", b"[::1", b"[::1]bad", b"::1", b"host:bad", b"", b"bad/host"],
)
def test_api_rejects_invalid_host_headers(value: bytes) -> None:
    with pytest.raises(ValueError):
        _normalise_host_header(value)


def test_api_preview_registry_is_bounded_expiring_and_single_use(monkeypatch) -> None:
    now = [10.0]
    monkeypatch.setattr("repolocus.api.app.time.monotonic", lambda: now[0])
    registry = _PreviewRegistry(ttl_seconds=5, capacity=1)

    preview_id, ttl = registry.create(None, {"generation": 1})  # type: ignore[arg-type]
    assert ttl == 5
    with pytest.raises(_PreviewCapacityError):
        registry.create(None, {})  # type: ignore[arg-type]
    with pytest.raises(_PreviewNotFoundError):
        registry.consume("unknown")

    now[0] = 16.0
    with pytest.raises(_PreviewExpiredError):
        registry.consume(preview_id)
    now[0] = 22.0
    with pytest.raises(_PreviewNotFoundError):
        registry.consume(preview_id)


def test_api_configuration_rejects_weak_token_and_invalid_limits(sample_repo: Path) -> None:
    with pytest.raises(ValueError, match="at least 24"):
        create_app(sample_repo, api_token="too-short")
    with pytest.raises(ValueError, match="positive integer"):
        create_app(sample_repo, max_concurrent_requests=0)
    with pytest.raises(ValueError, match="positive integer"):
        create_app(sample_repo, preview_ttl_seconds=True)  # type: ignore[arg-type]


def test_api_rejects_oversized_request_body(sample_repo: Path) -> None:
    application = create_app(sample_repo, max_request_body_bytes=1024)

    response = _request(
        application,
        "POST",
        "/v1/scan",
        content=b"x" * 1025,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413


def test_cloud_api_uses_single_use_immutable_preview_and_cannot_remember_consent(
    sample_repo: Path,
    isolated_user_dirs: Path,
    monkeypatch,
) -> None:
    captured: dict[str, str] = {}

    class FakeProvider:
        name = "openai"

        def generate(self, system_prompt: str, user_prompt: str) -> str:
            captured["prompt"] = user_prompt
            return (
                "Configuration is loaded here [[src/demo/config.py:1]].\n"
                'Evidence quote: "def load_config(path: str) -> dict:" '
                "[[src/demo/config.py:1]]"
            )

    monkeypatch.setattr("repolocus.core.service.create_provider", lambda *_args: FakeProvider())
    application = create_app(sample_repo, allow_cloud_requests=True)
    preview = _request(
        application,
        "POST",
        "/v1/ask/preview",
        json={
            "path": str(sample_repo),
            "question": "Where is load_config defined?",
            "model": "openai/test-model",
        },
    )

    assert preview.status_code == 201, preview.text
    preview_data = preview.json()
    assert preview_data["preview"]["model"] == "openai/test-model"
    assert preview_data["preview"]["endpoint"] == ("https://api.openai.com:443/v1/chat/completions")
    assert preview_data["preview"]["payload_bytes"] > 0
    config = sample_repo / "src" / "demo" / "config.py"
    config.write_text("def changed_after_preview():\n    return None\n", encoding="utf-8")

    preview_id = preview_data["preview_id"]
    approved = _request(
        application,
        "POST",
        f"/v1/ask/previews/{preview_id}/approve",
    )
    repeated = _request(
        application,
        "POST",
        f"/v1/ask/previews/{preview_id}/approve",
    )

    assert approved.status_code == 200, approved.text
    assert "def load_config" in captured["prompt"]
    assert "changed_after_preview" not in captured["prompt"]
    assert repeated.status_code == 410
    assert PrivacyStore().status(sample_repo) == {}

    forbidden_field = _request(
        application,
        "POST",
        "/v1/ask/preview",
        json={
            "path": str(sample_repo),
            "question": "Where is load_config defined?",
            "model": "openai/test-model",
            "remember_consent": True,
        },
    )
    assert forbidden_field.status_code == 422


def test_cloud_api_direct_ask_requires_two_stage_flow(sample_repo: Path) -> None:
    application = create_app(sample_repo, allow_cloud_requests=True)

    response = _request(
        application,
        "POST",
        "/v1/ask",
        json={
            "path": str(sample_repo),
            "question": "Where is load_config defined?",
            "model": "openai/test-model",
        },
    )

    assert response.status_code == 428
    assert "preview" in response.json()["detail"]


def test_api_concurrency_limit_rejects_excess_work(
    sample_repo: Path,
    monkeypatch,
) -> None:
    from repolocus.core import RepoLocusService

    original_scan = RepoLocusService.scan
    started = threading.Event()
    release = threading.Event()

    def slow_scan(self, root):  # type: ignore[no-untyped-def]
        started.set()
        release.wait(timeout=5)
        return original_scan(self, root)

    monkeypatch.setattr(RepoLocusService, "scan", slow_scan)
    application = create_app(sample_repo, max_concurrent_requests=1)

    async def exercise() -> tuple[httpx.Response, httpx.Response]:
        transport = httpx.ASGITransport(app=application)
        headers = {
            "Host": "localhost",
            "Authorization": f"Bearer {application.state.api_token}",
        }
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            first_task = asyncio.create_task(
                client.post("/v1/scan", json={"path": str(sample_repo)}, headers=headers)
            )
            await asyncio.to_thread(started.wait, 5)
            second = await client.post(
                "/v1/scan",
                json={"path": str(sample_repo)},
                headers=headers,
            )
            release.set()
            first = await first_task
        return first, second

    first, second = asyncio.run(exercise())

    assert first.status_code == 200
    assert second.status_code == 429
