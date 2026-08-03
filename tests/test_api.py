from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from repolocus.api import create_app


def _request(application, method: str, path: str, **kwargs: object) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.request(method, path, **kwargs)

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
    assert health.json()["version"] == "0.1.0"
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
