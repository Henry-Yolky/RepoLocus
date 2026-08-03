from __future__ import annotations

from pathlib import Path

import pytest

from repolocus.config import ConfigError, Settings


def test_defaults_are_local_first_and_telemetry_is_off(tmp_path: Path) -> None:
    settings = Settings.load(
        tmp_path,
        environ={},
        user_config_path=tmp_path / "missing-user-config.toml",
    )

    assert settings.model == "local"
    assert settings.telemetry is False
    assert settings.max_file_bytes == 1_000_000
    assert settings.context_char_budget == 24_000


def test_pre_rename_environment_and_repository_config_are_not_loaded(tmp_path: Path) -> None:
    (tmp_path / ".devpilot.toml").write_text(
        "max_file_bytes = 1\n",
        encoding="utf-8",
    )

    settings = Settings.load(
        tmp_path,
        environ={"DEVPILOT_MODEL": "openai/legacy-model"},
        user_config_path=tmp_path / "missing-user-config.toml",
    )

    assert settings.model == "local"
    assert settings.max_file_bytes == 1_000_000


def test_user_repo_and_environment_precedence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    user_config = tmp_path / "user.toml"
    user_config.write_text(
        """
[repolocus]
model = "ollama/user-model"
telemetry = true
request_timeout = 11
max_file_bytes = 512000
""",
        encoding="utf-8",
    )
    (repo / ".repolocus.toml").write_text(
        """
context_char_budget = 16000
""",
        encoding="utf-8",
    )

    settings = Settings.load(
        repo,
        user_config_path=user_config,
        environ={
            "REPOLOCUS_MODEL": "ollama/env-model",
            "REPOLOCUS_TELEMETRY": "false",
            "REPOLOCUS_REQUEST_TIMEOUT": "7.5",
        },
    )

    assert settings.model == "ollama/env-model"
    assert settings.telemetry is False
    assert settings.request_timeout == 7.5
    assert settings.max_file_bytes == 512_000
    assert settings.context_char_budget == 16_000


def test_pyproject_tool_table_is_supported(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
dependencies = [
  "something>=1",
]

[tool.repolocus]
max_file_bytes = 250000
""",
        encoding="utf-8",
    )

    settings = Settings.load(
        tmp_path,
        environ={},
        user_config_path=tmp_path / "missing.toml",
    )

    assert settings.model == "local"
    assert settings.max_file_bytes == 250_000


@pytest.mark.parametrize("key", ["model", "ollama_base_url", "telemetry", "request_timeout"])
def test_repository_config_cannot_select_network_or_policy(tmp_path: Path, key: str) -> None:
    value = "https://attacker.invalid" if key.endswith("base_url") else "ollama/exfil"
    if key == "telemetry":
        value = "true"
    elif key == "request_timeout":
        value = "5"
    (tmp_path / ".repolocus.toml").write_text(f"{key} = {value!r}\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="repository config cannot set"):
        Settings.load(tmp_path, environ={}, user_config_path=tmp_path / "missing.toml")


def test_repository_limits_can_only_tighten_user_limits(tmp_path: Path) -> None:
    user = tmp_path / "user.toml"
    user.write_text("max_file_bytes = 1000\n", encoding="utf-8")
    (tmp_path / ".repolocus.toml").write_text("max_file_bytes = 9000\n", encoding="utf-8")

    settings = Settings.load(tmp_path, environ={}, user_config_path=user)

    assert settings.max_file_bytes == 1000


@pytest.mark.parametrize("key", ["api_key", "openai_api_key", "access_token", "password"])
def test_toml_credentials_are_rejected(tmp_path: Path, key: str) -> None:
    config = tmp_path / "config.toml"
    config.write_text(f'{key} = "do-not-store-this"\n', encoding="utf-8")

    with pytest.raises(ConfigError, match="credentials are not allowed"):
        Settings.load(environ={}, user_config_path=config)


def test_repo_config_symlink_cannot_escape_root(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    external = tmp_path / "external.toml"
    external.write_text('model = "ollama/external"\n', encoding="utf-8")
    (repo / ".repolocus.toml").symlink_to(external)

    with pytest.raises(ConfigError, match="escapes repository root"):
        Settings.load(repo, environ={}, user_config_path=tmp_path / "missing.toml")


@pytest.mark.parametrize("value", ["sometimes", "", "2"])
def test_invalid_telemetry_environment_value_fails(tmp_path: Path, value: str) -> None:
    with pytest.raises(ConfigError, match="telemetry must be true or false"):
        Settings.load(
            tmp_path,
            environ={"REPOLOCUS_TELEMETRY": value},
            user_config_path=tmp_path / "missing.toml",
        )


def test_telemetry_cannot_be_enabled_in_v01(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not implemented"):
        Settings.load(
            tmp_path,
            environ={"REPOLOCUS_TELEMETRY": "true"},
            user_config_path=tmp_path / "missing.toml",
        )


def test_base_url_cannot_embed_credentials() -> None:
    with pytest.raises(ConfigError, match="must not contain credentials"):
        Settings(openai_base_url="https://user:password@example.invalid/v1")

    with pytest.raises(ConfigError, match="control characters"):
        Settings(openai_base_url="https://example.invalid/\nredirect")


def test_oversized_repository_config_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / ".repolocus.toml"
    config.write_text("#" + "x" * 1_000_000, encoding="utf-8")

    with pytest.raises(ConfigError, match="exceeds"):
        Settings.load(tmp_path, environ={}, user_config_path=tmp_path / "missing.toml")
