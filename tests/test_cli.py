from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote

from typer.testing import CliRunner

from repolocus import __version__
from repolocus.cli import _index_cache_permission_status, app
from repolocus.config import Settings
from repolocus.core import RepoLocusService
from repolocus.security import PrivacyStore

runner = CliRunner()


def test_cli_help_and_version() -> None:
    help_result = runner.invoke(app, ["--help"])
    version_result = runner.invoke(app, ["--version"])

    assert help_result.exit_code == 0
    assert "source-backed answers" in help_result.stdout
    assert version_result.exit_code == 0
    assert f"RepoLocus {__version__}" in version_result.stdout


def test_cli_scan_map_ask_and_diagram(sample_repo: Path, isolated_user_dirs: Path) -> None:
    scan_result = runner.invoke(app, ["scan", str(sample_repo), "--json"])
    map_result = runner.invoke(app, ["map", str(sample_repo)])
    ask_result = runner.invoke(
        app, ["ask", "Where is load_config defined?", str(sample_repo), "--json"]
    )
    diagram_result = runner.invoke(app, ["diagram", str(sample_repo)])

    assert scan_result.exit_code == 0, scan_result.output
    scan_data = json.loads(scan_result.stdout)
    assert scan_data["scan"]["indexed_files"] >= 4
    assert map_result.exit_code == 0, map_result.output
    assert (sample_repo / "PROJECT_MAP.md").is_file()
    assert ask_result.exit_code == 0, ask_result.output
    ask_data = json.loads(ask_result.stdout)
    assert ask_data["provider"] == "extractive"
    assert ask_data["evidence"]
    assert diagram_result.exit_code == 0, diagram_result.output
    assert (sample_repo / "ARCHITECTURE.md").is_file()


def test_cli_cloud_without_consent_prints_preview(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    result = runner.invoke(
        app,
        [
            "ask",
            "Where is load_config defined?",
            str(sample_repo),
            "--model",
            "openai/test-model",
        ],
    )

    assert result.exit_code == 2
    assert "Cloud send preview" in result.output
    assert "src/demo/config.py" in result.output
    assert "def load_config" in result.output
    assert "--allow-cloud" in result.output


def test_cloud_consent_error_is_machine_readable_json(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    result = runner.invoke(
        app,
        [
            "ask",
            "Where is load_config defined?",
            str(sample_repo),
            "--model",
            "openai/test-model",
            "--json",
        ],
    )

    assert result.exit_code == 2
    data = json.loads(result.stdout)
    assert data["error"] == "cloud_consent_required"
    assert data["preview"]["fragments"][0]["content"]


def test_remembered_cloud_grant_still_prints_exact_preview(
    sample_repo: Path,
    isolated_user_dirs: Path,
    monkeypatch,
) -> None:
    class FakeProvider:
        name = "openai"

        def generate(self, system_prompt: str, user_prompt: str) -> str:
            return (
                "Configuration is loaded here [[src/demo/config.py:1]].\n"
                'Evidence quote: "def load_config(path: str) -> dict:" '
                "[[src/demo/config.py:1]]"
            )

    PrivacyStore().grant(
        sample_repo,
        "openai",
        "https://api.openai.com/v1/chat/completions",
    )
    monkeypatch.setattr(
        "repolocus.core.service.create_provider",
        lambda *_args, **_kwargs: FakeProvider(),
    )

    result = runner.invoke(
        app,
        [
            "ask",
            "Where is load_config defined?",
            str(sample_repo),
            "--model",
            "openai/test-model",
        ],
    )

    assert result.exit_code == 0, result.output
    assert result.output.count("Cloud send preview") == 1
    assert "src/demo/config.py" in result.output
    assert "def load_config" in result.output


def test_doctor_does_not_probe_non_loopback_ollama(
    sample_repo: Path,
    isolated_user_dirs: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("REPOLOCUS_OLLAMA_BASE_URL", "https://ollama.example.invalid")

    def unexpected_client(*args: object, **kwargs: object) -> None:
        raise AssertionError("remote Ollama endpoint must not be probed by doctor")

    monkeypatch.setattr("repolocus.cli.httpx.Client", unexpected_client)
    result = runner.invoke(app, ["doctor", str(sample_repo), "--json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    ollama = next(check for check in data["checks"] if check["name"] == "ollama")
    assert ollama["required"] is False
    assert "not loopback" in ollama["detail"]


def test_windows_cache_acl_status_is_unknown(tmp_path: Path) -> None:
    ok, detail, required = _index_cache_permission_status(tmp_path, "nt")

    assert ok is False
    assert detail == "unknown: Windows ACLs were not inspected"
    assert required is False


def test_doctor_reports_unverified_cache_permissions_as_warning(
    sample_repo: Path,
    isolated_user_dirs: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "repolocus.cli._index_cache_permission_status",
        lambda _path, _platform_name: (
            False,
            "unknown: Windows ACLs were not inspected",
            False,
        ),
    )

    result = runner.invoke(app, ["doctor", str(sample_repo), "--security", "--json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    permissions = next(
        check for check in data["checks"] if check["name"] == "index_cache_permissions"
    )
    assert permissions == {
        "name": "index_cache_permissions",
        "ok": False,
        "detail": "unknown: Windows ACLs were not inspected",
        "required": False,
    }

    table_result = runner.invoke(app, ["doctor", str(sample_repo), "--security"])
    assert table_result.exit_code == 0, table_result.output
    assert "WARN" in table_result.output
    assert "Windows ACLs were not inspected" in table_result.output


def test_generated_output_refuses_escape_and_unrecognized_overwrite(
    sample_repo: Path, isolated_user_dirs: Path, tmp_path: Path
) -> None:
    existing = sample_repo / "PROJECT_MAP.md"
    existing.write_text("user-authored map\n", encoding="utf-8")

    overwrite = runner.invoke(app, ["map", str(sample_repo)])
    escape = runner.invoke(
        app,
        ["map", str(sample_repo), "--output", str(tmp_path / "outside.md")],
    )

    assert overwrite.exit_code == 1
    assert "not recognized as generated" in overwrite.output
    assert existing.read_text(encoding="utf-8") == "user-authored map\n"
    assert escape.exit_code == 1
    assert "escapes repository root" in escape.output

    existing.write_text(
        "User notes mentioning Generator: RepoLocus are not generated output.\n",
        encoding="utf-8",
    )
    prose_marker = runner.invoke(app, ["map", str(sample_repo)])
    assert prose_marker.exit_code == 1
    assert "not recognized as generated" in prose_marker.output


def test_generated_output_migrates_the_pre_rename_marker(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    output = sample_repo / "PROJECT_MAP.md"
    output.write_text(
        "<!-- Generator: DevPilot 0.1.0; deterministic source map. -->\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["map", str(sample_repo)])

    assert result.exit_code == 0, result.output
    generated = output.read_text(encoding="utf-8")
    assert "Generator: RepoLocus" in generated
    assert "Generator: DevPilot" not in generated


def test_generated_commands_require_markdown_outputs_and_fix_nested_links(
    sample_repo: Path,
    isolated_user_dirs: Path,
) -> None:
    rejected = runner.invoke(
        app,
        ["map", str(sample_repo), "--output", "generated-map.py"],
    )
    mapped = runner.invoke(
        app,
        ["map", str(sample_repo), "--output", "docs/generated/PROJECT_MAP.md"],
    )
    diagrammed = runner.invoke(
        app,
        ["diagram", str(sample_repo), "--output", "docs/generated/ARCHITECTURE.md"],
    )

    assert rejected.exit_code == 1
    assert "must use a Markdown suffix" in rejected.output
    assert not (sample_repo / "generated-map.py").exists()
    assert mapped.exit_code == 0, mapped.output
    project_map = (sample_repo / "docs/generated/PROJECT_MAP.md").read_text(encoding="utf-8")
    assert "(../../src/demo/config.py#L1)" in project_map
    assert "Source link base: generated-document-relative" in project_map
    assert diagrammed.exit_code == 0, diagrammed.output
    architecture = (sample_repo / "docs/generated/ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "(../../src/demo/config.py#L1)" in architecture
    assert "Source links are relative to this generated document." in architecture
    for output_path, document in (
        (sample_repo / "docs/generated/PROJECT_MAP.md", project_map),
        (sample_repo / "docs/generated/ARCHITECTURE.md", architecture),
    ):
        match = re.search(r"\(([^)#]+config\.py)#L1\)", document)
        assert match is not None
        assert (output_path.parent / unquote(match.group(1))).resolve(strict=True).is_file()


def test_privacy_status_defaults_to_no_grants(sample_repo: Path, isolated_user_dirs: Path) -> None:
    result = runner.invoke(app, ["privacy", "status", str(sample_repo), "--json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["telemetry"] is False
    assert data["grants"] == {}


def test_map_stdout_is_byte_exact_without_terminal_wrapping(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    expected, _scan = RepoLocusService(Settings(model="local")).map(sample_repo)

    result = runner.invoke(app, ["map", str(sample_repo), "--stdout"])

    assert result.exit_code == 0, result.output
    assert result.stdout == expected


def test_clean_all_refuses_cache_inside_repository(
    sample_repo: Path,
    isolated_user_dirs: Path,
    monkeypatch,
) -> None:
    dangerous_cache = sample_repo / ".cache" / "indexes"
    monkeypatch.setattr("repolocus.cli.cache_root", lambda: dangerous_cache)
    valuable = dangerous_cache / "valuable_source.py"
    valuable.parent.mkdir(parents=True)
    valuable.write_text("keep me\n", encoding="utf-8")

    result = runner.invoke(app, ["clean", str(sample_repo), "--all", "--yes"])

    assert result.exit_code == 1
    assert "cache inside the repository" in result.output
    assert valuable.read_text(encoding="utf-8") == "keep me\n"


def test_clean_all_removes_only_generated_indexes(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    scan = runner.invoke(app, ["scan", str(sample_repo), "--json"])
    assert scan.exit_code == 0, scan.output
    index_path = Path(json.loads(scan.stdout)["index_path"])
    source = sample_repo / "src" / "demo" / "config.py"

    clean = runner.invoke(app, ["clean", str(sample_repo), "--all", "--yes"])

    assert clean.exit_code == 0, clean.output
    assert not index_path.exists()
    assert not index_path.parent.exists()
    assert source.is_file()


def test_clean_all_is_all_or_nothing_with_unknown_cache_entry(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    scan = runner.invoke(app, ["scan", str(sample_repo), "--json"])
    index_path = Path(json.loads(scan.stdout)["index_path"])
    unknown = index_path.parent / "keep.txt"
    unknown.write_text("not an index\n", encoding="utf-8")

    clean = runner.invoke(app, ["clean", str(sample_repo), "--all", "--yes"])

    assert clean.exit_code == 1
    assert "unrecognized entries" in clean.output
    assert index_path.is_file()
    assert unknown.is_file()


def test_serve_requires_opt_in_for_non_loopback_host(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    result = runner.invoke(
        app,
        ["serve", "--root", str(sample_repo), "--host", "0.0.0.0"],
    )

    assert result.exit_code == 1
    assert "--allow-remote" in result.output


def test_serve_requires_tls_and_allowed_host_for_non_loopback(
    sample_repo: Path,
    isolated_user_dirs: Path,
) -> None:
    without_tls = runner.invoke(
        app,
        [
            "serve",
            "--root",
            str(sample_repo),
            "--host",
            "0.0.0.0",
            "--allow-remote",
            "--allowed-host",
            "repolocus.example",
        ],
    )

    assert without_tls.exit_code == 1
    assert "requires TLS" in without_tls.output


def test_serve_passes_tls_auth_and_host_controls(
    sample_repo: Path,
    isolated_user_dirs: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    certificate = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    certificate.write_text("test certificate", encoding="utf-8")
    key.write_text("test key", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_run(application, **kwargs: object) -> None:  # type: ignore[no-untyped-def]
        captured["application"] = application
        captured.update(kwargs)

    monkeypatch.setattr("uvicorn.run", fake_run)
    token = "a" * 32
    result = runner.invoke(
        app,
        [
            "serve",
            "--root",
            str(sample_repo),
            "--host",
            "0.0.0.0",
            "--allow-remote",
            "--allowed-host",
            "repolocus.example",
            "--ssl-certfile",
            str(certificate),
            "--ssl-keyfile",
            str(key),
            "--api-token",
            token,
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["host"] == "0.0.0.0"
    assert captured["ssl_certfile"] == str(certificate)
    assert captured["ssl_keyfile"] == str(key)
    assert captured["application"].state.api_token == token  # type: ignore[union-attr]


def test_follow_up_session_is_in_memory_and_source_backed(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    result = runner.invoke(
        app,
        ["ask", "Where is load_config defined?", str(sample_repo), "--follow-up"],
        input="What calls it?\n\n",
    )

    assert result.exit_code == 0, result.output
    assert result.output.count("Evidence for:") == 2
    assert "follow-up: What calls it?" in result.output
    assert "src/demo/config.py" in result.output
