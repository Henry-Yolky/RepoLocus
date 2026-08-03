"""FastAPI routes that share the exact CLI service layer."""

from dataclasses import asdict
from pathlib import Path

from repolocus import __version__
from repolocus.core import PrivacyRequiredError, RepoLocusService


def create_app(
    root: Path | str | None = None,
    *,
    allow_cloud_requests: bool = False,
):  # type: ignore[no-untyped-def]
    try:
        from fastapi import FastAPI, HTTPException
        from pydantic import BaseModel, Field
    except ImportError as exc:  # pragma: no cover - exercised without the optional extra
        raise RuntimeError("install repolocus[api] to use the HTTP service") from exc

    api_root = Path.cwd().resolve(strict=True) if root is None else Path(root).resolve(strict=True)
    if not api_root.is_dir():
        raise ValueError(f"API root is not a directory: {api_root}")

    class RepositoryRequest(BaseModel):
        path: str = "."

    class OutputRequest(RepositoryRequest):
        pass

    class AskRequest(RepositoryRequest):
        question: str = Field(min_length=1, max_length=4000)
        model: str | None = None
        limit: int = Field(default=8, ge=1, le=20)
        allow_cloud: bool = False
        remember_consent: bool = False

    application = FastAPI(
        title="RepoLocus",
        version=__version__,
        description="Self-hosted, read-only repository understanding API.",
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
            document, operation = instance.map(repository_root)
            return {"document": document, "scan": operation.to_dict()}
        except (OSError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/v1/diagram")
    def diagram(payload: OutputRequest) -> dict[str, object]:
        try:
            repository_root, instance = service(payload.path)
            document, operation = instance.diagram(repository_root)
            return {"document": document, "scan": operation.to_dict()}
        except (OSError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/v1/ask")
    def ask(payload: AskRequest) -> dict[str, object]:
        try:
            repository_root, instance = service(payload.path)
            chosen_model = payload.model or instance.settings.model
            if (
                instance.consent_scope(chosen_model) not in {"local", "ollama"}
                and not allow_cloud_requests
            ):
                raise HTTPException(
                    status_code=403,
                    detail="cloud models are disabled for this API server",
                )
            answer, operation, preview = instance.ask(
                payload.question,
                repository_root,
                model=payload.model,
                limit=payload.limit,
                allow_cloud=payload.allow_cloud,
                remember_consent=payload.remember_consent,
            )
            return {
                "answer": answer.text,
                "confidence": answer.confidence,
                "provider": answer.provider,
                "evidence": [
                    asdict(item) | {"citation": item.citation} for item in answer.evidence
                ],
                "preview": preview.to_dict(),
                "scan": operation.to_dict(),
            }
        except PrivacyRequiredError as exc:
            detail = exc.preview.to_dict() | {
                "fragments": [asdict(item) | {"citation": item.citation} for item in exc.evidence]
            }
            raise HTTPException(status_code=403, detail=detail) from exc
        except (OSError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return application
