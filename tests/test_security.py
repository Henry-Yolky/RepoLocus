from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from devpilot.security import (
    ConsentRequiredError,
    PathSecurityError,
    PrivacyStore,
    PrivacyStoreError,
    build_cloud_send_preview,
    ensure_within_root,
    redact_secrets,
    require_provider_consent,
)


def test_canonical_path_check_accepts_descendants(tmp_path: Path) -> None:
    nested = tmp_path / "src" / "module.py"
    nested.parent.mkdir()
    nested.write_text("pass\n", encoding="utf-8")

    assert ensure_within_root(tmp_path, "src/module.py", must_exist=True) == nested.resolve()


def test_canonical_path_check_rejects_traversal(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.py"

    with pytest.raises(PathSecurityError, match="escapes repository root"):
        ensure_within_root(tmp_path, outside)


def test_canonical_path_check_rejects_symlink_escape(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (repo / "linked").symlink_to(outside, target_is_directory=True)

    with pytest.raises(PathSecurityError, match="escapes repository root"):
        ensure_within_root(repo, "linked/secret.txt")


def test_redaction_covers_common_credentials_without_hiding_keys() -> None:
    source = "\n".join(
        [
            'api_key = "sk-abcdefghijklmnopqrstuvwxyz1234"',
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
            "remote=https://alice:hunter2@example.invalid/project.git",
            'HF_TOKEN = "hf_abcdefghijklmnopqrstuvwxyz123456"',
            'DATABASE_URL = "postgresql://dbuser:dbpassword@db.internal/app"',
            "safe_value = 42",
        ]
    )

    redacted, count = redact_secrets(source)

    assert count == 5
    assert redacted.count("[REDACTED]") == 5
    assert "hunter2" not in redacted
    assert "dbpassword" not in redacted
    assert "abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "safe_value = 42" in redacted
    assert "api_key" in redacted


def test_private_key_is_redacted() -> None:
    source = """-----BEGIN PRIVATE KEY-----
YWJjZA==
-----END PRIVATE KEY-----"""

    assert redact_secrets(source) == ("[REDACTED]", 1)


def test_privacy_store_remembers_per_repo_provider_outside_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    state_path = tmp_path / "state" / "privacy.json"
    store = PrivacyStore(state_path)

    assert store.is_allowed(repo, "ollama/qwen3-coder") is True
    assert store.is_allowed(repo, "openai/gpt-test") is False

    store.grant(repo, "openai/gpt-test")

    assert store.status(repo) == {"openai": True}
    assert store.is_allowed(repo, "openai/another-model") is True
    raw_state = state_path.read_text(encoding="utf-8")
    assert "gpt-test" not in raw_state

    store.revoke(repo, "openai")
    assert store.status(repo) == {}


def test_privacy_store_requests_restrictive_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    state_path = tmp_path / "state" / "privacy.json"
    store = PrivacyStore(state_path)
    chmod_calls: list[tuple[Path, int]] = []
    original_chmod = Path.chmod

    def record_chmod(path: Path, mode: int, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        chmod_calls.append((path, mode))
        original_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "chmod", record_chmod)

    store.grant(repo, "openai")

    assert (state_path.parent, 0o700) in chmod_calls
    assert (state_path, 0o600) in chmod_calls


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows permissions are represented by ACLs, not POSIX mode bits",
)
def test_privacy_store_enforces_posix_modes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    state_path = tmp_path / "state" / "privacy.json"
    store = PrivacyStore(state_path)

    store.grant(repo, "openai")

    assert stat.S_IMODE(state_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(state_path.with_suffix(".json.lock").stat().st_mode) == 0o600


def test_privacy_store_revoke_all_is_repository_scoped(tmp_path: Path) -> None:
    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    repo_a.mkdir()
    repo_b.mkdir()
    store = PrivacyStore(tmp_path / "state" / "privacy.json")
    store.grant(repo_a, "openai")
    store.grant(repo_a, "anthropic")
    store.grant(repo_b, "openai")

    store.revoke(repo_a)

    assert store.status(repo_a) == {}
    assert store.status(repo_b) == {"openai": True}


def test_privacy_store_refuses_state_inside_repository(tmp_path: Path) -> None:
    store = PrivacyStore(tmp_path / ".devpilot-privacy.json")

    with pytest.raises(PrivacyStoreError, match="outside the repository"):
        store.grant(tmp_path, "openai")


def test_privacy_store_does_not_silently_replace_corrupt_state(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    state_path = tmp_path / "privacy.json"
    state_path.write_text("not json", encoding="utf-8")

    with pytest.raises(PrivacyStoreError, match="cannot read privacy state"):
        PrivacyStore(state_path).status(repo)


def test_cloud_consent_guard_distinguishes_local_and_cloud(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    store = PrivacyStore(tmp_path / "privacy.json")

    require_provider_consent(repo, "ollama/model", store)
    with pytest.raises(ConsentRequiredError, match="explicit consent"):
        require_provider_consent(repo, "anthropic/model", store)
    require_provider_consent(repo, "anthropic/model", store, allow_once=True)


def test_cloud_send_preview_is_content_free_and_counts_redaction() -> None:
    preview = build_cloud_send_preview(
        "openai/gpt-test",
        [
            {"path": "src/a.py", "content": 'api_key = "secret-value"'},
            {"path": "src/a.py", "content": "print('safe')"},
            ("src/b.py", "return 1"),
        ],
    )

    assert preview.provider == "openai"
    assert preview.paths == ("src/a.py", "src/b.py")
    assert preview.fragment_count == 3
    assert preview.estimated_tokens > 0
    assert preview.redaction_count == 1
    assert "secret-value" not in json.dumps(preview.to_dict())
