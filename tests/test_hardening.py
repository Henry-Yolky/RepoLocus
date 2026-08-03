from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from repolocus.config import Settings
from repolocus.core import RepoLocusService
from repolocus.index import IndexFormatError, RepositoryIndex, index_path_for
from repolocus.models import Chunk, Dependency, ScannedFile, ScanResult, ScanStats, Symbol
from repolocus.parsers import ParseResult, ParserRegistry
from repolocus.scanner import RepositoryScanner
from repolocus.security import (
    PathSecurityError,
    PrivacyStore,
    PrivacyStoreError,
    build_cloud_send_preview,
    is_loopback_url,
    is_within_root,
    resolve_within_root,
)


def _file(path: str, text: str, *, symbol: str = "") -> ScannedFile:
    line_count = len(text.splitlines())
    symbols = (
        (Symbol(symbol, "function", path, 1, max(1, line_count), f"def {symbol}()"),)
        if symbol
        else ()
    )
    chunks = (Chunk(path, 1, max(1, line_count), text, "python", symbol),) if text else ()
    return ScannedFile(
        path=path,
        language="python",
        size_bytes=len(text.encode()),
        sha256=hashlib.sha256(text.encode()).hexdigest(),
        line_count=line_count,
        text=text,
        symbols=symbols,
        chunks=chunks,
    )


def _scan(root: Path, *files: ScannedFile) -> ScanResult:
    return ScanResult(root, list(files), ScanStats())


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://localhost:11434", True),
        ("https://worker.localhost/api", True),
        ("http://127.0.0.2:11434", True),
        ("http://[::1]:11434", True),
        ("ftp://127.0.0.1/model", False),
        ("http://example.invalid", False),
        ("http://[::1", False),
        ("/relative/path", False),
    ],
)
def test_loopback_detection_rejects_malformed_or_remote_urls(url: str, expected: bool) -> None:
    assert is_loopback_url(url) is expected


def test_path_boundary_handles_missing_roots_and_required_leaves(tmp_path: Path) -> None:
    missing_root = tmp_path / "missing-root"
    with pytest.raises(PathSecurityError, match="repository root cannot be resolved"):
        resolve_within_root(missing_root, "child.py")

    root = tmp_path / "repo"
    root.mkdir()
    with pytest.raises(PathSecurityError, match="path cannot be resolved"):
        resolve_within_root(root, "missing.py", must_exist=True)

    assert is_within_root(root, "future/output.md")
    assert not is_within_root(root, tmp_path / "outside.py")


def test_path_boundary_rejects_a_regular_file_as_root(tmp_path: Path) -> None:
    regular_file = tmp_path / "not-a-repository"
    regular_file.write_text("text", encoding="utf-8")

    with pytest.raises(PathSecurityError, match="not a directory"):
        resolve_within_root(regular_file, ".")


@pytest.mark.parametrize(
    "state",
    [
        {"version": 2, "repositories": {}},
        {"version": 1, "repositories": []},
    ],
)
def test_privacy_store_rejects_unsupported_state_shapes(tmp_path: Path, state: object) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    state_path = tmp_path / "privacy.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(PrivacyStoreError):
        PrivacyStore(state_path).status(repository)


def test_privacy_store_rejects_malformed_provider_table(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    state_path = tmp_path / "privacy.json"
    store = PrivacyStore(state_path)
    store.grant(repository, "openai")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    only_repository = next(iter(state["repositories"].values()))
    only_repository["providers"] = ["openai"]
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(PrivacyStoreError, match="invalid providers table"):
        store.status(repository)


def test_privacy_store_rejects_missing_and_non_directory_roots(tmp_path: Path) -> None:
    store = PrivacyStore(tmp_path / "state" / "privacy.json")
    regular_file = tmp_path / "file"
    regular_file.write_text("not a directory", encoding="utf-8")

    with pytest.raises(PrivacyStoreError, match="cannot be resolved"):
        store.status(tmp_path / "missing")
    with pytest.raises(PrivacyStoreError, match="not a directory"):
        store.status(regular_file)


def test_cloud_preview_rejects_fragments_without_string_source_fields() -> None:
    with pytest.raises(TypeError, match="string path and content"):
        build_cloud_send_preview("openai", [{"path": "src/app.py", "content": None}])


def test_scanner_detects_a_file_replaced_during_its_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "app.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    from repolocus.scanner import repository as scanner_repository

    original_safe_read = scanner_repository._safe_read

    def mutate_after_read(path: Path, limit: int) -> tuple[bytes | None, str | None]:
        payload, error = original_safe_read(path, limit)
        if path == source:
            path.write_text("VALUE = 200\n", encoding="utf-8")
        return payload, error

    monkeypatch.setattr(scanner_repository, "_safe_read", mutate_after_read)

    result = RepositoryScanner().scan(tmp_path)

    assert result.files == []
    assert result.stats.skipped == {"changed_during_scan": 1}
    assert result.warnings == ["file changed during scan: app.py"]


def test_oversize_ignore_file_is_not_applied_and_is_reported(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("*.py\n", encoding="utf-8")
    (tmp_path / "kept.py").write_text("def kept():\n    return True\n", encoding="utf-8")

    result = RepositoryScanner(max_ignore_bytes=2).scan(tmp_path)

    assert "kept.py" in {file.path for file in result.files}
    assert any("could not load ignore file (oversize)" in warning for warning in result.warnings)


@pytest.mark.parametrize("invalid_fact", ["symbol", "dependency", "language", "content"])
def test_parser_plugins_cannot_cross_source_boundaries(tmp_path: Path, invalid_fact: str) -> None:
    class InvalidParser:
        languages = frozenset({"python"})

        def parse(self, path: str, text: str, language: str, **kwargs: object) -> ParseResult:
            if invalid_fact == "symbol":
                return ParseResult(symbols=(Symbol("bad", "function", "other.py", 1, 1),))
            if invalid_fact == "dependency":
                return ParseResult(dependencies=(Dependency(path, "module", "import", 99),))
            if invalid_fact == "language":
                return ParseResult(chunks=(Chunk(path, 1, 1, text, "javascript"),))
            return ParseResult(chunks=(Chunk(path, 1, 1, "fabricated", language),))

    registry = ParserRegistry()
    registry.register(InvalidParser())
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")

    result = RepositoryScanner(parser_registry=registry).scan(tmp_path)

    assert result.files == []
    assert result.stats.skipped == {"parse_error": 1}
    assert result.warnings == ["parse failed (ValueError) for file: app.py"]


def test_unversioned_foreign_database_is_not_overwritten(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"
    database = index_path_for(repository, cache)
    database.parent.mkdir(parents=True)
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE valuable_data(value TEXT)")
    connection.execute("INSERT INTO valuable_data VALUES ('keep-me')")
    connection.commit()
    connection.close()

    with pytest.raises(IndexFormatError, match="refusing to overwrite an unversioned database"):
        RepositoryIndex.open(repository, cache)

    connection = sqlite3.connect(database)
    assert connection.execute("SELECT value FROM valuable_data").fetchone()[0] == "keep-me"
    connection.close()


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        ("application", "not a RepoLocus index"),
        ("identity", "identity does not match"),
        ("format", "format version is incompatible"),
        ("table", "schema is incomplete"),
    ],
)
def test_existing_index_tampering_is_rejected(tmp_path: Path, tamper: str, message: str) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    cache = tmp_path / "cache"
    with RepositoryIndex.open(repository, cache) as index:
        database = index.db_path

    connection = sqlite3.connect(database)
    if tamper == "application":
        connection.execute("PRAGMA application_id = 0")
    elif tamper == "identity":
        connection.execute("UPDATE meta SET value = '/wrong/root' WHERE key = 'repository_root'")
    elif tamper == "format":
        connection.execute("UPDATE meta SET value = '999' WHERE key = 'index_format_version'")
    else:
        connection.execute("DROP TABLE dependencies")
    connection.commit()
    connection.close()

    with pytest.raises(IndexFormatError, match=message):
        RepositoryIndex.open(repository, cache)


def test_failed_index_insert_rolls_back_the_complete_update(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    original = _file("original.py", "ORIGINAL = True\n")
    malformed = replace(
        _file("malformed.py", "def broken():\n    pass\n"),
        symbols=(
            Symbol(
                None,  # type: ignore[arg-type]
                "function",
                "malformed.py",
                1,
                2,
            ),
        ),
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(_scan(repository, original))

        with pytest.raises(sqlite3.IntegrityError):
            index.update(_scan(repository, malformed))

        assert [file.path for file in index.get_files()] == ["original.py"]
        assert index.get_files()[0].text == original.text


def test_cloud_model_success_can_remember_repository_scoped_consent(
    sample_repo: Path,
    isolated_user_dirs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProvider:
        name = "openai"

        def generate(self, system_prompt: str, user_prompt: str) -> str:
            return "Configuration is loaded here [[src/demo/config.py:1-2]]."

    monkeypatch.setattr("repolocus.core.service.create_provider", lambda *_args: FakeProvider())
    privacy = PrivacyStore(isolated_user_dirs / "privacy.json")
    service = RepoLocusService(Settings(model="openai/test-model"), privacy=privacy)

    answer, _operation, _preview = service.ask(
        "Where is load_config defined?",
        sample_repo,
        allow_cloud=True,
        remember_consent=True,
    )

    assert answer.provider == "openai"
    assert answer.confidence == "inferred"
    assert "src/demo/config.py#L1" in answer.text
    assert privacy.status(sample_repo) == {"openai": True}


def test_unverifiable_model_response_falls_back_to_source_evidence(
    sample_repo: Path,
    isolated_user_dirs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProvider:
        name = "openai"

        def generate(self, system_prompt: str, user_prompt: str) -> str:
            return "Trust me: configuration is definitely uploaded elsewhere."

    monkeypatch.setattr("repolocus.core.service.create_provider", lambda *_args: FakeProvider())
    service = RepoLocusService(
        Settings(model="openai/test-model"),
        privacy=PrivacyStore(isolated_user_dirs / "privacy.json"),
    )

    answer, _operation, _preview = service.ask(
        "Where is load_config defined?", sample_repo, allow_cloud=True
    )

    assert answer.provider == "openai"
    assert answer.confidence == "needs_review"
    assert answer.text.startswith("The model response was withheld")
    assert "uploaded elsewhere" not in answer.text
    assert any(item.path == "src/demo/config.py" for item in answer.evidence)


def test_no_evidence_returns_without_cloud_consent_or_provider_call(
    tmp_path: Path,
    isolated_user_dirs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "empty"
    repository.mkdir()

    def unexpected_provider(*args: object, **kwargs: object) -> object:
        raise AssertionError("a provider must not be called without evidence")

    monkeypatch.setattr("repolocus.core.service.create_provider", unexpected_provider)
    service = RepoLocusService(
        Settings(model="openai/test-model"),
        privacy=PrivacyStore(isolated_user_dirs / "privacy.json"),
    )

    answer, _operation, preview = service.ask("Where is the entry point?", repository)

    assert answer.provider == "extractive"
    assert answer.confidence == "needs_review"
    assert answer.evidence == ()
    assert preview.fragment_count == 0


def test_remote_ollama_can_use_explicitly_remembered_remote_scope(
    sample_repo: Path,
    isolated_user_dirs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProvider:
        name = "ollama"

        def generate(self, system_prompt: str, user_prompt: str) -> str:
            return "Configuration is loaded here [[src/demo/config.py:1]]."

    monkeypatch.setattr("repolocus.core.service.create_provider", lambda *_args: FakeProvider())
    privacy = PrivacyStore(isolated_user_dirs / "privacy.json")
    privacy.grant(sample_repo, "ollama-remote")
    service = RepoLocusService(
        Settings(
            model="ollama/test-model",
            ollama_base_url="https://ollama.example.invalid",
        ),
        privacy=privacy,
    )

    answer, _operation, preview = service.ask("Where is load_config defined?", sample_repo)

    assert preview.provider == "ollama-remote"
    assert answer.provider == "ollama"
    assert answer.confidence == "inferred"
