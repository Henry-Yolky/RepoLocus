from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

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
    assert settings.max_repository_files == 100_000
    assert settings.max_repository_bytes == 512_000_000
    assert settings.max_directory_depth == 64
    assert settings.max_repository_chunks == 500_000
    assert settings.max_repository_symbols == 500_000
    assert settings.max_scan_seconds == 120
    assert settings.query_synonym_map == {}


def test_query_synonyms_are_user_configurable_json(tmp_path: Path) -> None:
    settings = Settings.load(
        tmp_path,
        environ={
            "REPOLOCUS_QUERY_SYNONYMS": '{"configuration":["config","settings"],"配置":["config"]}'
        },
        user_config_path=tmp_path / "missing.toml",
    )

    assert settings.query_synonym_map == {
        "configuration": ("config", "settings"),
        "配置": ("config",),
    }


@pytest.mark.parametrize(
    "value",
    ["[]", '{"term":[]}', '{"term":"not-a-list"}', '{"term":["\u001b"]}'],
)
def test_invalid_query_synonyms_are_rejected(value: str) -> None:
    with pytest.raises(ConfigError, match=r"query_synonyms|synonym"):
        Settings(query_synonyms=value)


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


def test_repository_scan_budgets_are_tightenable_and_environment_configurable(
    tmp_path: Path,
) -> None:
    (tmp_path / ".repolocus.toml").write_text(
        """
max_repository_files = 20
max_repository_bytes = 3000
max_directory_depth = 7
max_repository_chunks = 80
max_repository_symbols = 90
max_scan_seconds = 4
""",
        encoding="utf-8",
    )

    settings = Settings.load(
        tmp_path,
        environ={"REPOLOCUS_MAX_REPOSITORY_FILES": "12"},
        user_config_path=tmp_path / "missing.toml",
    )

    assert settings.max_repository_files == 12
    assert settings.max_repository_bytes == 3000
    assert settings.max_directory_depth == 7
    assert settings.max_repository_chunks == 80
    assert settings.max_repository_symbols == 90
    assert settings.max_scan_seconds == 4


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


def test_repository_config_swap_after_open_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from repolocus import config as config_module

    repo = tmp_path / "repo"
    repo.mkdir()
    config = repo / ".repolocus.toml"
    config.write_text("max_file_bytes = 8000\n", encoding="utf-8")
    external = tmp_path / "external.toml"
    external.write_text("max_file_bytes = 1\n", encoding="utf-8")
    original_read = config_module._read_config_descriptor
    swapped = False

    def swap_after_read(descriptor: int) -> bytes:
        nonlocal swapped
        raw = original_read(descriptor)
        if not swapped:
            swapped = True
            config.rename(repo / "original-config.toml")
            config.symlink_to(external)
        return raw

    monkeypatch.setattr(config_module, "_read_config_descriptor", swap_after_read)

    with pytest.raises(ConfigError, match="changed while being read"):
        Settings.load(repo, environ={}, user_config_path=tmp_path / "missing.toml")


def test_pyproject_declaration_and_parse_share_one_pinned_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from repolocus import config as config_module

    (tmp_path / "pyproject.toml").write_text(
        "[tool.repolocus]\nmax_file_bytes = 5000\n",
        encoding="utf-8",
    )
    original_read = config_module._read_config_descriptor
    reads = 0

    def count_read(descriptor: int) -> bytes:
        nonlocal reads
        reads += 1
        return original_read(descriptor)

    monkeypatch.setattr(config_module, "_read_config_descriptor", count_read)

    settings = Settings.load(
        tmp_path,
        environ={},
        user_config_path=tmp_path / "missing.toml",
    )

    assert settings.max_file_bytes == 5000
    assert reads == 1


def test_repository_config_deleted_after_read_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from repolocus import config as config_module

    config = tmp_path / ".repolocus.toml"
    config.write_text("max_file_bytes = 8000\n", encoding="utf-8")
    original_read = config_module._read_config_descriptor

    def delete_after_read(descriptor: int) -> bytes:
        raw = original_read(descriptor)
        config.unlink()
        return raw

    monkeypatch.setattr(config_module, "_read_config_descriptor", delete_after_read)

    with pytest.raises(ConfigError, match="changed while being read"):
        Settings.load(tmp_path, environ={}, user_config_path=tmp_path / "missing.toml")


def test_repository_config_path_requires_a_repository_root(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text("max_file_bytes = 8000\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="root is required"):
        Settings.load(
            root=None,
            repo_config_path=config,
            environ={},
            user_config_path=tmp_path / "missing.toml",
        )


def test_repository_config_fallback_rejects_intermediate_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from repolocus import config as config_module

    repo = tmp_path / "repo"
    repo.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    (external / "config.toml").write_text("max_file_bytes = 1\n", encoding="utf-8")
    (repo / ".repolocus").symlink_to(external, target_is_directory=True)
    monkeypatch.setattr(config_module.os, "O_NOFOLLOW", 0, raising=False)

    with pytest.raises(ConfigError, match=r"unsafe link|escapes repository root"):
        Settings.load(repo, environ={}, user_config_path=tmp_path / "missing.toml")


def test_repository_config_identity_checked_fallback_reads_one_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from repolocus import config as config_module

    config = tmp_path / ".repolocus.toml"
    config.write_text("max_file_bytes = 7000\n", encoding="utf-8")
    monkeypatch.setattr(config_module.os, "O_NOFOLLOW", 0, raising=False)

    settings = Settings.load(
        tmp_path,
        environ={},
        user_config_path=tmp_path / "missing.toml",
    )

    assert settings.max_file_bytes == 7000


def test_repository_config_does_not_treat_ctrl_z_as_eof(tmp_path: Path) -> None:
    (tmp_path / ".repolocus.toml").write_bytes(
        b"max_file_bytes = 7000\r\n\x1aignored_if_read_in_text_mode"
    )

    with pytest.raises(ConfigError, match="invalid TOML"):
        Settings.load(
            tmp_path,
            environ={},
            user_config_path=tmp_path / "missing.toml",
        )


def test_repository_config_compares_path_and_handle_metadata_portably(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from repolocus import config as config_module

    config = tmp_path / ".repolocus.toml"
    config.write_text("max_file_bytes = 7000\n", encoding="utf-8")
    monkeypatch.setattr(config_module.os, "O_NOFOLLOW", 0, raising=False)
    original_fstat = config_module.os.fstat

    def windows_like_fstat(descriptor: int) -> SimpleNamespace:
        metadata = original_fstat(descriptor)
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino,
            st_size=metadata.st_size,
            st_mtime_ns=metadata.st_mtime_ns,
            st_ctime_ns=metadata.st_ctime_ns + 1,
        )

    monkeypatch.setattr(config_module.os, "fstat", windows_like_fstat)

    settings = Settings.load(
        tmp_path,
        environ={},
        user_config_path=tmp_path / "missing.toml",
    )

    assert settings.max_file_bytes == 7000


def test_repository_config_read_error_after_open_is_reported_as_changed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from repolocus import config as config_module

    config = tmp_path / ".repolocus.toml"
    config.write_text("max_file_bytes = 7000\n", encoding="utf-8")
    monkeypatch.setattr(config_module.os, "O_NOFOLLOW", 0, raising=False)

    def fail_read(_descriptor: int) -> bytes:
        raise OSError(32, "file is in use")

    monkeypatch.setattr(config_module, "_read_config_descriptor", fail_read)

    with pytest.raises(ConfigError, match="changed while being read"):
        Settings.load(
            tmp_path,
            environ={},
            user_config_path=tmp_path / "missing.toml",
        )


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


@pytest.mark.parametrize(
    "environment_name",
    [
        "REPOLOCUS_OLLAMA_BASE_URL",
        "REPOLOCUS_OPENAI_BASE_URL",
        "REPOLOCUS_ANTHROPIC_BASE_URL",
    ],
)
def test_non_loopback_plain_http_base_urls_are_rejected_during_load(
    tmp_path: Path,
    environment_name: str,
) -> None:
    with pytest.raises(
        ConfigError,
        match="must use HTTPS unless it targets a loopback address",
    ):
        Settings.load(
            environ={environment_name: "http://provider.example.invalid"},
            user_config_path=tmp_path / "missing.toml",
        )


def test_loopback_http_and_https_base_urls_are_allowed() -> None:
    loopback = Settings(
        ollama_base_url="http://localhost:11434",
        openai_base_url="http://127.0.0.1:8080/v1",
        anthropic_base_url="http://[::1]:8081",
    )
    secure_remote = Settings(
        ollama_base_url="https://ollama.example.invalid",
        openai_base_url="https://openai.example.invalid/v1",
        anthropic_base_url="https://anthropic.example.invalid",
    )

    assert loopback.ollama_base_url.startswith("http://")
    assert loopback.openai_base_url.startswith("http://")
    assert loopback.anthropic_base_url.startswith("http://")
    assert secure_remote.ollama_base_url.startswith("https://")
    assert secure_remote.openai_base_url.startswith("https://")
    assert secure_remote.anthropic_base_url.startswith("https://")


def test_oversized_repository_config_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / ".repolocus.toml"
    config.write_text("#" + "x" * 1_000_000, encoding="utf-8")

    with pytest.raises(ConfigError, match="exceeds"):
        Settings.load(tmp_path, environ={}, user_config_path=tmp_path / "missing.toml")
