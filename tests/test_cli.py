from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from devpilot.cli import app
from devpilot.config import Settings
from devpilot.core import DevPilotService
from devpilot.security import PrivacyStore

runner = CliRunner()


def test_cli_help_and_version() -> None:
    help_result = runner.invoke(app, ["--help"])
    version_result = runner.invoke(app, ["--version"])

    assert help_result.exit_code == 0
    assert "source-backed answers" in help_result.stdout
    assert version_result.exit_code == 0
    assert "DevPilot 0.1.0" in version_result.stdout


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
            return "Configuration is loaded here [[src/demo/config.py:1]]."

    PrivacyStore().grant(sample_repo, "openai")
    monkeypatch.setattr("devpilot.core.service.create_provider", lambda *_args: FakeProvider())

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
    monkeypatch.setenv("DEVPILOT_OLLAMA_BASE_URL", "https://ollama.example.invalid")

    def unexpected_client(*args: object, **kwargs: object) -> None:
        raise AssertionError("remote Ollama endpoint must not be probed by doctor")

    monkeypatch.setattr("devpilot.cli.httpx.Client", unexpected_client)
    result = runner.invoke(app, ["doctor", str(sample_repo), "--json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    ollama = next(check for check in data["checks"] if check["name"] == "ollama")
    assert ollama["required"] is False
    assert "not loopback" in ollama["detail"]


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


def test_privacy_status_defaults_to_no_grants(sample_repo: Path, isolated_user_dirs: Path) -> None:
    result = runner.invoke(app, ["privacy", "status", str(sample_repo), "--json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["telemetry"] is False
    assert data["grants"] == {}


def test_map_stdout_is_byte_exact_without_terminal_wrapping(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    expected, _scan = DevPilotService(Settings(model="local")).map(sample_repo)

    result = runner.invoke(app, ["map", str(sample_repo), "--stdout"])

    assert result.exit_code == 0, result.output
    assert result.stdout == expected


def test_clean_all_refuses_cache_inside_repository(
    sample_repo: Path,
    isolated_user_dirs: Path,
    monkeypatch,
) -> None:
    dangerous_cache = sample_repo / ".cache" / "indexes"
    monkeypatch.setattr("devpilot.cli.cache_root", lambda: dangerous_cache)
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
