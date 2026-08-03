"""DevPilot command-line interface."""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import sqlite3
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import httpx
import typer
from platformdirs import user_cache_path
from rich.console import Console
from rich.table import Table
from rich.text import Text

from devpilot import __version__
from devpilot.config import Settings
from devpilot.core import DevPilotService, PrivacyRequiredError
from devpilot.index import cache_root, index_path_for
from devpilot.models import Evidence
from devpilot.security import (
    CloudSendPreview,
    PrivacyStore,
    ensure_within_root,
    escape_untrusted_display,
    is_loopback_url,
)

app = typer.Typer(
    name="devpilot",
    help="Read-only, local-first codebase maps and source-backed answers.",
    no_args_is_help=True,
    invoke_without_command=True,
    pretty_exceptions_enable=False,
)
privacy_app = typer.Typer(help="Inspect and control per-repository cloud consent.")
app.add_typer(privacy_app, name="privacy")
console = Console()
error_console = Console(stderr=True)

RepoArgument = Annotated[
    Path,
    typer.Argument(
        help="Repository directory.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
]


def _json(data: object) -> None:
    console.print_json(json.dumps(data, ensure_ascii=False, default=str))


def _preview_fragments(evidence: Iterable[Evidence]) -> list[dict[str, object]]:
    return [
        {
            "path": item.path,
            "start_line": item.start_line,
            "end_line": item.end_line,
            "reason": item.reason,
            "content": item.content,
        }
        for item in evidence
    ]


def _print_preview_fragments(evidence: Iterable[Evidence], *, stderr: bool = False) -> None:
    target = error_console if stderr else console
    for item in evidence:
        target.print(
            f"- {escape_untrusted_display(item.path)}:{item.start_line}-{item.end_line} "
            f"({escape_untrusted_display(item.reason)})",
            markup=False,
            highlight=False,
        )
        # JSON string escaping makes control characters visible instead of executing them
        # in the user's terminal, while preserving the exact redacted content.
        target.print(
            "  content="
            + json.dumps(
                escape_untrusted_display(item.content, preserve_layout=True),
                ensure_ascii=False,
            ),
            markup=False,
            highlight=False,
            soft_wrap=True,
        )


def _settings(root: Path) -> Settings:
    return Settings.load(root)


def _service(root: Path) -> DevPilotService:
    return DevPilotService(_settings(root))


def _fail(exc: Exception, code: int = 1) -> None:
    error_console.print(
        "Error: " + escape_untrusted_display(str(exc)),
        markup=False,
        highlight=False,
    )
    raise typer.Exit(code)


def _generated_file(root: Path, requested: Path, content: str, force: bool) -> Path:
    requested_destination = requested if requested.is_absolute() else root / requested
    if requested_destination.is_symlink():
        raise ValueError(f"refusing to replace symlink output: {requested_destination}")
    destination = ensure_within_root(root, requested_destination)
    if destination.exists():
        if destination.is_symlink() or not destination.is_file():
            raise ValueError(f"refusing to replace non-regular output: {destination}")
        prior = destination.read_text(encoding="utf-8", errors="replace")[:4096]
        generated = "Generator: DevPilot" in prior
        if not (force or generated):
            raise ValueError(
                f"output already exists and is not recognized as generated: {destination}; "
                "pass --force to replace it"
            )
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        Path(temporary_name).replace(destination)
    finally:
        Path(temporary_name).unlink(missing_ok=True)
    return destination


_INDEX_ARTIFACT = re.compile(r"^[A-Za-z0-9._-]+-[0-9a-f]{20}\.sqlite3(?:-(?:wal|shm))?$")


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _remove_all_indexes(target: Path, repository_root: Path) -> int:
    """Remove only recognized index artifacts from a dedicated external directory."""

    if target.is_symlink():
        raise ValueError(f"refusing to clean a symlinked cache directory: {target}")
    resolved = target.resolve(strict=True)
    if _is_within(resolved, repository_root):
        raise ValueError(f"refusing to clean a cache inside the repository: {resolved}")
    if not resolved.is_dir() or resolved.name != "indexes":
        raise ValueError(f"refusing to recursively clean an unexpected path: {resolved}")
    entries = sorted(resolved.iterdir(), key=lambda path: path.name)
    unsafe = [
        entry.name
        for entry in entries
        if entry.is_symlink() or not entry.is_file() or not _INDEX_ARTIFACT.fullmatch(entry.name)
    ]
    if unsafe:
        names = ", ".join(unsafe[:5])
        raise ValueError(f"cache contains unrecognized entries; nothing was deleted: {names}")
    for entry in entries:
        entry.unlink()
    resolved.rmdir()
    return len(entries)


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().strip("[]").rstrip(".").casefold()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", help="Show the DevPilot version and exit."),
    ] = False,
) -> None:
    if version:
        console.print(f"DevPilot {__version__}")
        raise typer.Exit()


@app.command()
def scan(
    path: RepoArgument = Path("."),
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    """Securely scan a repository and incrementally update its local index."""

    try:
        operation = _service(path).scan(path)
    except (OSError, ValueError, RuntimeError) as exc:
        _fail(exc)
    if json_output:
        _json(operation.to_dict())
        return
    stats = operation.result.stats
    table = Table(title="DevPilot scan")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Indexed files", str(stats.indexed_files))
    table.add_row("Indexed bytes", str(stats.indexed_bytes))
    table.add_row("Added / changed", f"{operation.update.added} / {operation.update.changed}")
    table.add_row(
        "Unchanged / removed", f"{operation.update.unchanged} / {operation.update.removed}"
    )
    table.add_row("Index", Text(escape_untrusted_display(str(operation.index_path))))
    console.print(table)
    if stats.skipped:
        console.print("Skipped: " + ", ".join(f"{k}={v}" for k, v in sorted(stats.skipped.items())))
    for warning in operation.result.warnings:
        console.print(
            "Warning: " + escape_untrusted_display(warning),
            markup=False,
            highlight=False,
        )


@app.command("map")
def map_command(
    path: RepoArgument = Path("."),
    output: Annotated[Path, typer.Option("--output", "-o", help="Generated Markdown path.")] = Path(
        "PROJECT_MAP.md"
    ),
    stdout: Annotated[
        bool, typer.Option("--stdout", help="Print instead of writing a file.")
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", help="Replace a non-generated output file.")
    ] = False,
) -> None:
    """Generate a stable, source-linked PROJECT_MAP.md."""

    try:
        document, operation = _service(path).map(path)
        if stdout:
            sys.stdout.write(document)
            return
        destination = _generated_file(operation.result.root, output, document, force)
    except (OSError, ValueError, RuntimeError) as exc:
        _fail(exc)
    console.print(
        f"Generated {escape_untrusted_display(str(destination))} from "
        f"{operation.result.stats.indexed_files} files.",
        markup=False,
        highlight=False,
    )


@app.command()
def diagram(
    path: RepoArgument = Path("."),
    output: Annotated[Path, typer.Option("--output", "-o", help="Generated Markdown path.")] = Path(
        "ARCHITECTURE.md"
    ),
    stdout: Annotated[
        bool, typer.Option("--stdout", help="Print instead of writing a file.")
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", help="Replace a non-generated output file.")
    ] = False,
) -> None:
    """Generate a deterministic, validated Mermaid architecture graph."""

    try:
        document, operation = _service(path).diagram(path)
        if stdout:
            sys.stdout.write(document)
            return
        destination = _generated_file(operation.result.root, output, document, force)
    except (OSError, ValueError, RuntimeError) as exc:
        _fail(exc)
    console.print(
        f"Generated {escape_untrusted_display(str(destination))}.",
        markup=False,
        highlight=False,
    )


@app.command()
def ask(
    question: Annotated[str, typer.Argument(help="Question about the repository.")],
    path: RepoArgument = Path("."),
    model: Annotated[
        str | None,
        typer.Option("--model", help="local, ollama/MODEL, openai/MODEL, or anthropic/MODEL."),
    ] = None,
    limit: Annotated[int, typer.Option("--limit", min=1, max=20)] = 8,
    allow_cloud: Annotated[
        bool,
        typer.Option("--allow-cloud", help="Allow selected fragments to leave this machine once."),
    ] = False,
    remember_consent: Annotated[
        bool,
        typer.Option("--remember-consent", help="Remember this provider for this repository."),
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
    follow_up: Annotated[
        bool,
        typer.Option(
            "--follow-up",
            help="Keep an in-memory question session until an empty line; incompatible with JSON.",
        ),
    ] = False,
) -> None:
    """Answer with retrieved, line-addressable source evidence."""

    if follow_up and json_output:
        _fail(ValueError("--follow-up cannot be combined with --json"))
    try:
        service = _service(path)

        def show_preview(
            send_preview: CloudSendPreview,
            fragments: tuple[Evidence, ...],
        ) -> None:
            if send_preview.provider not in {"local", "ollama"}:
                error_console.print(
                    "Cloud send preview: "
                    f"provider={escape_untrusted_display(send_preview.provider)}, "
                    f"fragments={send_preview.fragment_count}, "
                    f"estimated_tokens={send_preview.estimated_tokens}",
                    markup=False,
                    highlight=False,
                )
                _print_preview_fragments(fragments, stderr=True)

        answer, operation, preview_data = service.ask(
            question,
            path,
            model=model,
            limit=limit,
            allow_cloud=allow_cloud,
            remember_consent=remember_consent,
            preview_callback=show_preview,
        )
    except PrivacyRequiredError as exc:
        payload = exc.preview.to_dict() | {"fragments": _preview_fragments(exc.evidence)}
        if json_output:
            _json({"error": "cloud_consent_required", "preview": payload})
            raise typer.Exit(2) from None
        error_console.print("[yellow]Cloud send preview[/yellow]")
        error_console.print(
            f"Provider: {escape_untrusted_display(str(payload['provider']))}; "
            f"fragments: {payload['fragment_count']}; "
            f"estimated tokens: {payload['estimated_tokens']}; "
            f"redactions: {payload['redaction_count']}",
            markup=False,
            highlight=False,
        )
        _print_preview_fragments(exc.evidence, stderr=True)
        _fail(exc, 2)
    except (OSError, ValueError, RuntimeError, httpx.HTTPError) as exc:
        _fail(exc)
    if json_output:
        _json(
            {
                "answer": answer.text,
                "confidence": answer.confidence,
                "provider": answer.provider,
                "evidence": [
                    asdict(item) | {"citation": item.citation} for item in answer.evidence
                ],
                "preview": preview_data.to_dict(),
                "root": str(operation.result.root),
            }
        )
        return
    console.print(answer.text, markup=False)
    console.print(f"\nConfidence: {answer.confidence}; provider: {answer.provider}")
    if not follow_up:
        return

    history = [question]
    while True:
        next_question = console.input("\nFollow-up (blank to finish): ").strip()
        if not next_question:
            break
        prior = " | ".join(item[:600] for item in history[-3:])
        contextual_question = f"Earlier questions: {prior}. Current follow-up: {next_question}"
        try:
            answer, _operation, _preview_data = service.ask(
                contextual_question,
                path,
                model=model,
                limit=limit,
                allow_cloud=allow_cloud,
                remember_consent=remember_consent,
                preview_callback=show_preview,
            )
        except PrivacyRequiredError as exc:
            error_console.print("Cloud send preview", markup=False)
            _print_preview_fragments(exc.evidence, stderr=True)
            _fail(exc, 2)
        except (OSError, ValueError, RuntimeError, httpx.HTTPError) as exc:
            _fail(exc)
        console.print(answer.text, markup=False)
        console.print(f"\nConfidence: {answer.confidence}; provider: {answer.provider}")
        history.append(next_question)


@privacy_app.command("status")
def privacy_status(
    path: RepoArgument = Path("."),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show remembered cloud consent for this repository."""

    try:
        root = path.resolve(strict=True)
        grants = PrivacyStore().status(root)
        data = {"repository": str(root), "telemetry": False, "grants": grants}
    except (OSError, ValueError, RuntimeError) as exc:
        _fail(exc)
    if json_output:
        _json(data)
        return
    console.print(
        f"Repository: {escape_untrusted_display(str(root))}",
        markup=False,
        highlight=False,
    )
    console.print("Telemetry: disabled")
    if grants:
        for provider, allowed in sorted(grants.items()):
            console.print(
                f"{escape_untrusted_display(provider)}: {'allowed' if allowed else 'denied'}",
                markup=False,
                highlight=False,
            )
    else:
        console.print("Remembered cloud providers: none")


@privacy_app.command("preview")
def privacy_preview(
    question: Annotated[str, typer.Argument(help="Question used to select source fragments.")],
    path: RepoArgument = Path("."),
    model: Annotated[str | None, typer.Option("--model")] = None,
    limit: Annotated[int, typer.Option("--limit", min=1, max=20)] = 8,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Preview source fragments selected for a model request without sending them."""

    try:
        preview_data, evidence, _ = _service(path).preview(question, path, model=model, limit=limit)
        data = preview_data.to_dict() | {"fragments": _preview_fragments(evidence)}
    except (OSError, ValueError, RuntimeError) as exc:
        _fail(exc)
    if json_output:
        _json(data)
        return
    console.print(
        f"Provider: {escape_untrusted_display(str(data['provider']))}",
        markup=False,
        highlight=False,
    )
    console.print(
        f"Fragments: {data['fragment_count']}; estimated tokens: {data['estimated_tokens']}; "
        f"redactions: {data['redaction_count']}"
    )
    _print_preview_fragments(evidence)
    console.print("Nothing was sent.")


@privacy_app.command("grant")
def privacy_grant(
    provider: Annotated[str, typer.Argument(help="Cloud provider family, e.g. openai.")],
    path: RepoArgument = Path("."),
) -> None:
    """Remember an explicit cloud-provider grant for this repository."""

    try:
        root = path.resolve(strict=True)
        PrivacyStore().grant(root, provider)
    except (OSError, ValueError, RuntimeError) as exc:
        _fail(exc)
    console.print(
        f"Remembered {escape_untrusted_display(provider)!r} consent for "
        f"{escape_untrusted_display(str(root))}.",
        markup=False,
        highlight=False,
    )


@privacy_app.command("revoke")
def privacy_revoke(
    path: RepoArgument = Path("."),
    provider: Annotated[
        str | None,
        typer.Option("--provider", help="Provider family; omit to revoke every cloud grant."),
    ] = None,
) -> None:
    """Forget one or all cloud-provider grants for this repository."""

    try:
        root = path.resolve(strict=True)
        PrivacyStore().revoke(root, provider)
    except (OSError, ValueError, RuntimeError) as exc:
        _fail(exc)
    provider_text = (
        "all providers" if provider is None else repr(escape_untrusted_display(provider))
    )
    console.print(
        f"Revoked {provider_text} for {escape_untrusted_display(str(root))}.",
        markup=False,
        highlight=False,
    )


@app.command()
def doctor(
    path: RepoArgument = Path("."),
    security: Annotated[
        bool, typer.Option("--security", help="Include security-boundary checks.")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Check the runtime, cache, SQLite FTS5, and optional local-model endpoint."""

    checks: list[dict[str, object]] = []

    def record(name: str, ok: bool, detail: str, required: bool = True) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail, "required": required})

    record("python", sys.version_info >= (3, 10), platform.python_version())
    try:
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE VIRTUAL TABLE probe USING fts5(content)")
        connection.close()
        record("sqlite_fts5", True, sqlite3.sqlite_version)
    except sqlite3.Error as exc:
        record("sqlite_fts5", False, str(exc))

    cache = user_cache_path("devpilot", appauthor=False)
    try:
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=cache):
            pass
        record("cache_write", True, str(cache))
    except OSError as exc:
        record("cache_write", False, str(exc))

    settings = _settings(path)
    if not is_loopback_url(settings.ollama_base_url):
        record(
            "ollama",
            False,
            "not probed because the configured URL is not loopback",
            required=False,
        )
    else:
        try:
            with httpx.Client(timeout=1.0, trust_env=False) as client:
                response = client.get(f"{settings.ollama_base_url.rstrip('/')}/api/tags")
            record("ollama", response.is_success, f"HTTP {response.status_code}", required=False)
        except (httpx.HTTPError, OSError) as exc:
            record("ollama", False, f"not reachable: {exc}", required=False)

    index_cache = cache_root()
    index_cache_private = False
    index_cache_mode = "unavailable"
    try:
        index_cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            index_cache.chmod(0o700)
        with tempfile.NamedTemporaryFile(dir=index_cache):
            pass
        if os.name == "nt":
            index_cache_private = True
            index_cache_mode = "platform ACLs"
        else:
            index_cache_mode = oct(index_cache.stat().st_mode & 0o777)
            index_cache_private = index_cache.stat().st_mode & 0o077 == 0
        record("index_cache_write", True, str(index_cache))
    except OSError as exc:
        record("index_cache_write", False, str(exc))

    if security:
        try:
            canonical = ensure_within_root(path, path)
            record("canonical_root", canonical == path.resolve(), str(canonical))
        except (OSError, ValueError) as exc:
            record("canonical_root", False, str(exc))
        record(
            "telemetry",
            not _settings(path).telemetry,
            "disabled" if not _settings(path).telemetry else "enabled",
        )
        record(
            "index_cache_permissions",
            index_cache_private,
            index_cache_mode,
        )
        record("repository_execution", True, "scanner has no command-execution interface")

    failed = [check for check in checks if check["required"] and not check["ok"]]
    if json_output:
        _json({"ok": not failed, "checks": checks})
    else:
        table = Table(title="DevPilot doctor")
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Detail")
        for check in checks:
            status = "OK" if check["ok"] else ("WARN" if not check["required"] else "FAIL")
            table.add_row(
                Text(escape_untrusted_display(str(check["name"]))),
                Text(status),
                Text(escape_untrusted_display(str(check["detail"]))),
            )
        console.print(table)
    if failed:
        raise typer.Exit(1)


@app.command()
def clean(
    path: RepoArgument = Path("."),
    all_repositories: Annotated[
        bool,
        typer.Option("--all", help="Remove every local DevPilot repository index."),
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation prompt.")] = False,
) -> None:
    """Delete local indexes; source files are never touched."""

    root = path.resolve(strict=True)
    try:
        target = cache_root() if all_repositories else index_path_for(root)
    except (OSError, ValueError, RuntimeError) as exc:
        _fail(exc)
    if not target.exists():
        console.print(
            f"No index found at {escape_untrusted_display(str(target))}.",
            markup=False,
            highlight=False,
        )
        return
    scope = "all repository indexes" if all_repositories else f"the index for {root}"
    safe_scope = escape_untrusted_display(scope)
    safe_target = escape_untrusted_display(str(target))
    confirmation = "Remove " + safe_scope + " from " + safe_target + "?"
    if not yes and not typer.confirm(confirmation):
        raise typer.Abort()
    if all_repositories:
        try:
            _remove_all_indexes(target, root)
        except (OSError, ValueError) as exc:
            _fail(exc)
    else:
        if target.is_symlink() or not target.is_file():
            _fail(ValueError(f"refusing to remove a non-regular index: {target}"))
        target.unlink()
        for suffix in ("-wal", "-shm"):
            Path(str(target) + suffix).unlink(missing_ok=True)
    console.print(
        f"Removed {safe_scope}. Source files were not changed.",
        markup=False,
        highlight=False,
    )


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65535)] = 8765,
    root: Annotated[
        Path,
        typer.Option("--root", help="Only repositories below this directory are accessible."),
    ] = Path("."),
    allow_remote: Annotated[
        bool,
        typer.Option("--allow-remote", help="Acknowledge binding beyond loopback."),
    ] = False,
    allow_cloud_api: Annotated[
        bool,
        typer.Option("--allow-cloud-api", help="Permit API clients to request cloud models."),
    ] = False,
) -> None:
    """Start the optional self-hosted HTTP API."""

    try:
        import uvicorn

        from devpilot.api import create_app
    except ImportError:
        _fail(RuntimeError("API dependencies are missing; install devpilot-codebase[api]"))
    if not _is_loopback_host(host) and not allow_remote:
        _fail(RuntimeError("non-loopback binding requires --allow-remote"))
    try:
        api_root = root.expanduser().resolve(strict=True)
        if not api_root.is_dir():
            raise ValueError(f"API root is not a directory: {api_root}")
    except (OSError, ValueError) as exc:
        _fail(exc)
    uvicorn.run(
        create_app(api_root, allow_cloud_requests=allow_cloud_api),
        host=host,
        port=port,
    )
