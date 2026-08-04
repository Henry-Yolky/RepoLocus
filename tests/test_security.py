from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from platformdirs import user_state_dir

from repolocus.scanner import contains_likely_secret as scanner_detects_likely_secret
from repolocus.security import (
    ConsentRequiredError,
    PathSecurityError,
    PrivacyStore,
    PrivacyStoreError,
    build_cloud_send_preview,
    canonical_endpoint,
    ensure_within_root,
    find_likely_secrets,
    redact_secrets,
    require_provider_consent,
)
from repolocus.security.identity import descriptor_path, filesystem_identity

OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions"
ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages"


def test_filesystem_identity_fails_closed_without_stable_ids() -> None:
    metadata = type("Metadata", (), {"st_dev": 0, "st_ino": 0})()

    with pytest.raises(ValueError, match="stable object identity"):
        filesystem_identity(metadata)  # type: ignore[arg-type]
    assert descriptor_path(-1) is None


def test_descriptor_path_uses_darwin_f_getpath(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolocus.security import identity as identity_module

    source = tmp_path / "opened.txt"
    source.write_text("content\n", encoding="utf-8")
    expected = source.resolve()
    encoded = os.fsencode(expected)
    fake_fcntl = SimpleNamespace(
        F_GETPATH=50,
        fcntl=lambda _descriptor, _command, buffer: (encoded + b"\0").ljust(len(buffer), b"\0"),
    )
    monkeypatch.setattr(identity_module.sys, "platform", "darwin")
    monkeypatch.setitem(sys.modules, "fcntl", fake_fcntl)
    descriptor = os.open(source, os.O_RDONLY)
    try:
        assert identity_module.descriptor_path(descriptor) == expected
    finally:
        os.close(descriptor)


def test_descriptor_path_resolves_a_real_open_file(tmp_path: Path) -> None:
    source = tmp_path / "opened.txt"
    source.write_text("content\n", encoding="utf-8")
    descriptor = os.open(source, os.O_RDONLY)
    try:
        opened_path = descriptor_path(descriptor)
        assert opened_path is not None
        assert opened_path.samefile(source)
    finally:
        os.close(descriptor)


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


@pytest.mark.parametrize(
    ("kind", "source", "secret"),
    [
        (
            "private_key",
            "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----",
            "YWJjZA==",
        ),
        ("aws_access_key", "ASIA1234567890ABCDEF", "ASIA1234567890ABCDEF"),
        (
            "github_token",
            "ghp_abcdefghijklmnopqrstuvwxyz123456",
            "ghp_abcdefghijklmnopqrstuvwxyz123456",
        ),
        (
            "github_fine_grained_token",
            "github_pat_abcdefghijklmnopqrstuvwxyz123456",
            "github_pat_abcdefghijklmnopqrstuvwxyz123456",
        ),
        ("gitlab_token", "glpat-1234567890abcdefghij", "glpat-1234567890abcdefghij"),
        ("slack_token", "xoxb-1234567890-abcdefghij", "xoxb-1234567890-abcdefghij"),
        (
            "google_api_key",
            "AIza1234567890abcdefghijklmnopqrstuvwxyz",
            "AIza1234567890abcdefghijklmnopqrstuvwxyz",
        ),
        (
            "provider_api_key",
            "sk-proj-abcdefghijklmnopqrstuvwxyz",
            "sk-proj-abcdefghijklmnopqrstuvwxyz",
        ),
        (
            "hugging_face_token",
            "hf_abcdefghijklmnopqrstuvwxyz123456",
            "hf_abcdefghijklmnopqrstuvwxyz123456",
        ),
        ("stripe_live_key", "sk_live_1234567890abcdef", "sk_live_1234567890abcdef"),
        (
            "jwt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
        ),
        (
            "url_password",
            "postgresql://alice:correct-horse@example.invalid/app",
            "correct-horse",
        ),
        ("bearer_token", "Bearer abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
        (
            "credential_assignment",
            'api_key = "v3ry-long-random-value-827364"',
            "v3ry-long-random-value-827364",
        ),
    ],
)
def test_scanner_and_transport_secret_rules_have_parity(
    kind: str,
    source: str,
    secret: str,
) -> None:
    assert scanner_detects_likely_secret(source)
    matches = find_likely_secrets(source)
    assert any(match.kind == kind and match.confidence == "high" for match in matches)

    redacted, count = redact_secrets(source)

    assert count == 1
    assert secret not in redacted
    assert not scanner_detects_likely_secret(redacted)


def test_overlapping_assignment_and_typed_token_count_as_one_secret() -> None:
    source = 'api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz"'

    redacted, count = redact_secrets(source)
    repeated, repeated_count = redact_secrets(redacted)

    assert redacted == 'api_key = "[REDACTED]"'
    assert count == 1
    assert repeated == redacted
    assert repeated_count == 0


def test_privacy_store_remembers_per_repo_provider_outside_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    state_path = tmp_path / "state" / "privacy.json"
    store = PrivacyStore(state_path)

    assert store.is_allowed(repo, "ollama/qwen3-coder") is True
    assert store.is_allowed(repo, "openai/gpt-test") is False

    store.grant(repo, "openai/gpt-test", OPENAI_ENDPOINT)

    assert store.status(repo) == {"openai": True}
    assert store.grant_details(repo) == {
        "openai": ("https://api.openai.com:443/v1/chat/completions",)
    }
    assert store.is_allowed(repo, "openai/another-model", OPENAI_ENDPOINT) is True
    assert (
        store.is_allowed(
            repo,
            "openai/another-model",
            "https://compatible.example.invalid/v1/chat/completions",
        )
        is False
    )
    raw_state = state_path.read_text(encoding="utf-8")
    assert "gpt-test" not in raw_state

    store.revoke(repo, "openai")
    assert store.status(repo) == {}


def test_pre_rename_consent_is_not_inherited(tmp_path: Path, isolated_user_dirs: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    legacy_path = Path(user_state_dir("devpilot", appauthor=False)) / "privacy.json"
    current_path = Path(user_state_dir("repolocus", appauthor=False)) / "privacy.json"
    PrivacyStore(legacy_path).grant(repo, "openai", OPENAI_ENDPOINT)

    current_store = PrivacyStore()

    assert legacy_path != current_path
    assert current_store.path == current_path
    assert current_store.is_allowed(repo, "openai") is False


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

    store.grant(repo, "openai", OPENAI_ENDPOINT)

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

    store.grant(repo, "openai", OPENAI_ENDPOINT)

    assert stat.S_IMODE(state_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(state_path.with_suffix(".json.lock").stat().st_mode) == 0o600


def test_privacy_store_revoke_all_is_repository_scoped(tmp_path: Path) -> None:
    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    repo_a.mkdir()
    repo_b.mkdir()
    store = PrivacyStore(tmp_path / "state" / "privacy.json")
    store.grant(repo_a, "openai", OPENAI_ENDPOINT)
    store.grant(repo_a, "anthropic", ANTHROPIC_ENDPOINT)
    store.grant(repo_b, "openai", OPENAI_ENDPOINT)

    store.revoke(repo_a)

    assert store.status(repo_a) == {}
    assert store.status(repo_b) == {"openai": True}


def test_remembered_consent_does_not_follow_a_replaced_repository(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    state_path = tmp_path / "state" / "privacy.json"
    store = PrivacyStore(state_path)
    store.grant(repo, "openai", OPENAI_ENDPOINT)

    repo.rename(tmp_path / "old-repo")
    repo.mkdir()

    assert store.status(repo) == {}
    assert store.is_allowed(repo, "openai", OPENAI_ENDPOINT) is False


def test_consent_read_fails_if_repository_changes_during_state_lookup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    store = PrivacyStore(tmp_path / "state" / "privacy.json")
    store.grant(repo, "openai", OPENAI_ENDPOINT)
    original_read = store._read

    def replace_repository() -> dict[str, object]:
        state = original_read()
        repo.rename(tmp_path / "old-repo")
        repo.mkdir()
        return state

    monkeypatch.setattr(store, "_read", replace_repository)

    with pytest.raises(PrivacyStoreError, match="identity changed"):
        store.is_allowed(repo, "openai", OPENAI_ENDPOINT)


def test_privacy_store_refuses_state_inside_repository(tmp_path: Path) -> None:
    store = PrivacyStore(tmp_path / ".repolocus-privacy.json")

    with pytest.raises(PrivacyStoreError, match="outside the repository"):
        store.grant(tmp_path, "openai", OPENAI_ENDPOINT)


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
        require_provider_consent(
            repo,
            "anthropic/model",
            store,
            endpoint=ANTHROPIC_ENDPOINT,
        )
    require_provider_consent(
        repo,
        "anthropic/model",
        store,
        allow_once=True,
        endpoint=ANTHROPIC_ENDPOINT,
    )


def test_canonical_endpoint_binds_scheme_host_port_and_path() -> None:
    assert (
        canonical_endpoint("HTTPS://API.OPENAI.COM/v1/chat/completions")
        == "https://api.openai.com:443/v1/chat/completions"
    )
    assert canonical_endpoint("https://[::1]/v1") == "https://[::1]:443/v1"
    assert canonical_endpoint("https://api.openai.com:8443/v1") != canonical_endpoint(
        "https://api.openai.com/v1"
    )


def test_canonical_endpoint_rejects_empty_hostname_after_normalization() -> None:
    with pytest.raises(ValueError, match="invalid hostname"):
        canonical_endpoint("https://./v1/chat")


def test_family_only_v1_grants_are_migrated_fail_closed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    state_path = tmp_path / "privacy.json"
    repository_id = hashlib.sha256(str(repo.resolve()).encode()).hexdigest()
    state_path.write_text(
        json.dumps(
            {
                "version": 1,
                "repositories": {
                    repository_id: {
                        "path": str(repo.resolve()),
                        "providers": {"openai": {"granted_at": "2026-01-01T00:00:00Z"}},
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    store = PrivacyStore(state_path)

    assert store.status(repo) == {}
    assert store.is_allowed(repo, "openai", OPENAI_ENDPOINT) is False


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
