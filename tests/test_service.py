from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import pytest

from repolocus.config import Settings
from repolocus.core import PrivacyRequiredError, RepoLocusService
from repolocus.index import RepositoryIndex, StaleScanError
from repolocus.models import Evidence, ScannedFile, ScanResult, ScanStats
from repolocus.scanner import RepositoryScanner
from repolocus.security import CloudSendPreview, PrivacyStore


def _service(root: Path, state: Path, *, model: str = "local") -> RepoLocusService:
    settings = Settings(model=model)
    return RepoLocusService(settings, privacy=PrivacyStore(state / "privacy.json"))


class RecordingScanner(RepositoryScanner):
    def __init__(self, *, analysis_version: str = "service-test") -> None:
        super().__init__(analysis_version=analysis_version)
        self.calls: list[tuple[int | None, tuple[str, ...]]] = []

    def scan(
        self,
        root: Path | str,
        *,
        cached_files: Mapping[str, ScannedFile] | None = None,
        trusted_cache: bool = False,
        base_generation: int | None = None,
    ) -> ScanResult:
        self.calls.append((base_generation, tuple(sorted((cached_files or {}).keys()))))
        return super().scan(
            root,
            cached_files=cached_files,
            trusted_cache=trusted_cache,
            base_generation=base_generation,
        )


def test_end_to_end_local_workflow_is_incremental(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    service = _service(sample_repo, isolated_user_dirs)

    first = service.scan(sample_repo)
    second = service.scan(sample_repo)
    project_map, _ = service.map(sample_repo)
    diagram, _ = service.diagram(sample_repo)
    answer, _, preview = service.ask("Where is load_config defined?", sample_repo)

    assert first.update.added >= 4
    assert second.update.unchanged == first.result.stats.indexed_files
    assert first.index_path.is_file()
    assert sample_repo not in first.index_path.parents
    assert "## Main entry points" in project_map
    assert "src/demo/main.py" in project_map
    assert "```mermaid" in diagram
    assert answer.provider == "extractive"
    assert answer.confidence == "confirmed"
    assert any(item.path == "src/demo/config.py" for item in answer.evidence)
    assert preview.fragment_count == len(answer.evidence)
    assert not (sample_repo / ".repolocus").exists()


def test_evidence_refresh_uses_metadata_manifest_instead_of_full_snapshot(
    sample_repo: Path,
    isolated_user_dirs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(sample_repo, isolated_user_dirs)
    service.scan(sample_repo)

    def unexpected_full_materialization(_index: RepositoryIndex) -> list[ScannedFile]:
        raise AssertionError("evidence refresh must not load every indexed source and parser fact")

    monkeypatch.setattr(RepositoryIndex, "get_files", unexpected_full_materialization)

    evidence, operation = service.evidence("Where is load_config defined?", sample_repo)

    assert any(item.path == "src/demo/config.py" for item in evidence)
    assert operation.update.unchanged > 0
    assert all(file.text == "" for file in operation.result.files)


def test_explicit_scan_refresh_uses_metadata_manifest(
    sample_repo: Path,
    isolated_user_dirs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(sample_repo, isolated_user_dirs)
    service.scan(sample_repo)

    def unexpected_full_materialization(_index: RepositoryIndex) -> list[ScannedFile]:
        raise AssertionError("incremental scan must not load every stored source body")

    monkeypatch.setattr(RepositoryIndex, "get_files", unexpected_full_materialization)

    operation = service.scan(sample_repo)

    assert operation.update.unchanged > 0
    assert all(file.text == "" for file in operation.result.files)


def test_changed_file_updates_only_changed_content(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    service = _service(sample_repo, isolated_user_dirs)
    initial = service.scan(sample_repo)
    config = sample_repo / "src" / "demo" / "config.py"
    config.write_text(config.read_text(encoding="utf-8") + "\nVALUE = 1\n", encoding="utf-8")

    update = service.scan(sample_repo)

    assert initial.update.added > 0
    assert update.update.changed == 1
    assert update.update.added == 0


def test_scan_seeds_cache_and_cas_from_one_index_snapshot(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    scanner = RecordingScanner()
    service = RepoLocusService(
        Settings(model="local"),
        scanner=scanner,
        privacy=PrivacyStore(isolated_user_dirs / "privacy.json"),
    )

    first = service.scan(sample_repo)
    second = service.scan(sample_repo)

    assert scanner.calls[0] == (0, ())
    assert scanner.calls[1][0] == first.update.generation
    assert "src/demo/config.py" in scanner.calls[1][1]
    assert second.update.generation == first.update.generation + 1
    assert second.update.unchanged == first.result.stats.indexed_files


def test_scan_retries_an_unpinned_stale_generation(
    sample_repo: Path,
    isolated_user_dirs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = RecordingScanner()
    service = RepoLocusService(
        Settings(model="local"),
        scanner=scanner,
        privacy=PrivacyStore(isolated_user_dirs / "privacy.json"),
    )
    original_update = RepositoryIndex.update
    first_call = True

    def commit_then_report_stale(index: RepositoryIndex, result: ScanResult):
        nonlocal first_call
        update = original_update(index, result)
        if first_call:
            first_call = False
            raise StaleScanError("simulated competing scan")
        return update

    monkeypatch.setattr(RepositoryIndex, "update", commit_then_report_stale)

    operation = service.scan(sample_repo)

    assert len(scanner.calls) == 2
    assert scanner.calls[0][0] == 0
    assert scanner.calls[1][0] == 1
    assert operation.update.generation == 2


def test_refresh_modes_are_shared_by_generation_and_question_workflows(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    scanner = RecordingScanner()
    service = RepoLocusService(
        Settings(model="local"),
        scanner=scanner,
        privacy=PrivacyStore(isolated_user_dirs / "privacy.json"),
    )

    with pytest.raises(RuntimeError, match="no valid index snapshot"):
        service.map(sample_repo, refresh="never")
    assert scanner.calls == []

    _project_map, auto = service.map(sample_repo, refresh="auto")
    generation = auto.update.generation
    assert len(scanner.calls) == 1

    service.diagram(sample_repo, refresh="never", expected_generation=generation)
    service.evidence(
        "Where is load_config defined?",
        sample_repo,
        refresh="never",
        expected_generation=generation,
    )
    service.preview(
        "Where is load_config defined?",
        sample_repo,
        refresh="never",
        expected_generation=generation,
    )
    service.prepare_ask(
        "Where is load_config defined?",
        sample_repo,
        refresh="never",
        expected_generation=generation,
    )
    service.ask(
        "Where is load_config defined?",
        sample_repo,
        refresh="never",
        expected_generation=generation,
    )
    assert len(scanner.calls) == 1

    _refreshed_map, refreshed = service.map(sample_repo, refresh="always")
    assert len(scanner.calls) == 2
    assert refreshed.update.generation == generation + 1

    with pytest.raises(StaleScanError, match="expected index generation"):
        service.ask(
            "Where is load_config defined?",
            sample_repo,
            refresh="never",
            expected_generation=generation,
        )
    with pytest.raises(ValueError, match="refresh must be one of"):
        service.map(sample_repo, refresh="sometimes")  # type: ignore[arg-type]


def test_never_rejects_an_incompatible_snapshot_and_auto_rebuilds_it(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    original = _service(sample_repo, isolated_user_dirs)
    original.scan(sample_repo)
    scanner = RecordingScanner(analysis_version="future-parser")
    upgraded = RepoLocusService(
        Settings(model="local"),
        scanner=scanner,
        privacy=PrivacyStore(isolated_user_dirs / "privacy.json"),
    )

    with pytest.raises(RuntimeError, match="no valid index snapshot"):
        upgraded.map(sample_repo, refresh="never")

    _document, operation = upgraded.map(sample_repo, refresh="auto")

    assert len(scanner.calls) == 1
    assert scanner.calls[0][1] == ()
    assert operation.result.analysis_version == scanner.analysis_version


def test_snapshot_operation_contains_only_fresh_source_files(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    service = _service(sample_repo, isolated_user_dirs)
    service.scan(sample_repo)

    with RepositoryIndex.open(sample_repo) as index:
        snapshot = index.snapshot()
        reclassified = [
            replace(file, provenance="generated") if file.path == "README.md" else file
            for file in snapshot.files
        ]
        first = index.update(
            ScanResult(
                sample_repo,
                reclassified,
                ScanStats(),
                analysis_version=snapshot.analysis_version,
                base_generation=snapshot.generation,
            )
        )
        second = index.update(
            ScanResult(
                sample_repo,
                [file for file in reclassified if file.path != "pyproject.toml"],
                ScanStats(),
                analysis_version=snapshot.analysis_version,
                temporarily_unreadable=("pyproject.toml",),
                base_generation=first.generation,
            )
        )

    _document, operation = service.map(
        sample_repo,
        refresh="never",
        expected_generation=second.generation,
    )
    paths = {file.path for file in operation.result.files}

    assert "README.md" not in paths
    assert "pyproject.toml" not in paths
    assert paths
    assert all(file.provenance == "source" and not file.stale for file in operation.result.files)
    assert operation.result.stats.indexed_files == len(paths)
    assert operation.result.temporarily_unreadable == ("pyproject.toml",)
    assert operation.update.stale == 1
    assert any("excludes 1 stale file" in warning for warning in operation.result.warnings)

    _document, refreshed = service.map(
        sample_repo,
        refresh="auto",
        expected_generation=second.generation,
    )
    readme = next(file for file in refreshed.result.files if file.path == "README.md")
    assert readme.provenance == "source"
    assert readme.text
    assert readme.chunks


def test_service_rejects_a_symlink_repository_root(
    sample_repo: Path, isolated_user_dirs: Path, tmp_path: Path
) -> None:
    linked = tmp_path / "linked-repository"
    linked.symlink_to(sample_repo, target_is_directory=True)
    service = _service(sample_repo, isolated_user_dirs)

    with pytest.raises(ValueError, match="symbolic link or reparse point"):
        service.scan(linked)


def test_auto_refresh_scans_even_when_committed_snapshot_is_empty(
    tmp_path: Path, isolated_user_dirs: Path
) -> None:
    repository = tmp_path / "empty"
    repository.mkdir()
    scanner = RecordingScanner()
    service = RepoLocusService(
        Settings(model="local"),
        scanner=scanner,
        privacy=PrivacyStore(isolated_user_dirs / "privacy.json"),
    )

    first = service.scan(repository)
    _document, cached = service.map(repository, refresh="auto")

    assert len(scanner.calls) == 2
    assert cached.update.generation == first.update.generation + 1


def test_auto_refresh_observes_edits_while_never_is_explicit_snapshot_reuse(
    tmp_path: Path, isolated_user_dirs: Path
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "value.py"
    source.write_text("OLD_SYMBOL = 1\n", encoding="utf-8")
    scanner = RecordingScanner()
    service = RepoLocusService(
        Settings(model="local"),
        scanner=scanner,
        privacy=PrivacyStore(isolated_user_dirs / "privacy.json"),
    )

    first, initial = service.evidence("OLD_SYMBOL", repository, refresh="auto")
    source.write_text("NEW_SYMBOL = 2\n", encoding="utf-8")
    stale, reused = service.evidence("OLD_SYMBOL", repository, refresh="never")
    fresh, refreshed = service.evidence("NEW_SYMBOL", repository, refresh="auto")

    assert first and stale
    assert reused.update.generation == initial.update.generation
    assert fresh
    assert refreshed.update.generation == initial.update.generation + 1
    assert len(scanner.calls) == 2


def test_service_does_not_seed_scanner_cache_with_stale_files(
    tmp_path: Path, isolated_user_dirs: Path
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "value.py").write_text("VALUE = 1\n", encoding="utf-8")
    scanner = RecordingScanner()
    service = RepoLocusService(
        Settings(model="local"),
        scanner=scanner,
        privacy=PrivacyStore(isolated_user_dirs / "privacy.json"),
    )
    first = service.scan(repository)
    with RepositoryIndex.open(repository) as index:
        index.update(
            ScanResult(
                repository,
                [],
                ScanStats(),
                analysis_version=scanner.analysis_version,
                temporarily_unreadable=("value.py",),
                base_generation=first.update.generation,
            )
        )

    service.scan(repository)

    assert scanner.calls[-1][1] == ()


def test_cloud_call_is_stopped_before_provider_creation(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    service = _service(sample_repo, isolated_user_dirs, model="openai/test-model")

    with pytest.raises(PrivacyRequiredError) as raised:
        service.ask("Where is load_config defined?", sample_repo)

    assert raised.value.preview.provider == "openai"
    assert raised.value.preview.model == "openai/test-model"
    assert raised.value.preview.endpoint == "https://api.openai.com:443/v1/chat/completions"
    assert raised.value.preview.payload_bytes > 0
    assert "src/demo/config.py" in raised.value.preview.paths
    assert not service.privacy.is_allowed(sample_repo, "openai")


def test_remote_ollama_requires_cloud_consent(sample_repo: Path, isolated_user_dirs: Path) -> None:
    settings = Settings(
        model="ollama/test-model",
        ollama_base_url="https://ollama.example.invalid",
    )
    service = RepoLocusService(
        settings,
        privacy=PrivacyStore(isolated_user_dirs / "privacy.json"),
    )

    with pytest.raises(PrivacyRequiredError) as raised:
        service.ask("Where is load_config defined?", sample_repo)

    assert raised.value.preview.provider == "ollama-remote"
    assert raised.value.preview.endpoint == "https://ollama.example.invalid:443/api/chat"


def test_remembered_consent_does_not_follow_changed_compatible_endpoint(
    sample_repo: Path,
    isolated_user_dirs: Path,
) -> None:
    privacy = PrivacyStore(isolated_user_dirs / "privacy.json")
    privacy.grant(
        sample_repo,
        "openai",
        "https://api.openai.com/v1/chat/completions",
    )
    service = RepoLocusService(
        Settings(
            model="openai/test-model",
            openai_base_url="https://compatible.example.invalid/v1",
        ),
        privacy=privacy,
    )

    with pytest.raises(PrivacyRequiredError) as raised:
        service.ask("Where is load_config defined?", sample_repo)

    assert raised.value.preview.endpoint == (
        "https://compatible.example.invalid:443/v1/chat/completions"
    )


def test_cloud_send_uses_the_exact_evidence_shown_in_preview(
    sample_repo: Path,
    isolated_user_dirs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, str] = {}

    class FakeProvider:
        name = "openai"

        def generate(self, system_prompt: str, user_prompt: str) -> str:
            captured["prompt"] = user_prompt
            return (
                "The function is defined here [[src/demo/config.py:1]].\n"
                'Evidence quote: "def load_config(path: str) -> dict:" '
                "[[src/demo/config.py:1]]"
            )

    monkeypatch.setattr(
        "repolocus.core.service.create_provider",
        lambda model, settings: FakeProvider(),
    )
    service = _service(sample_repo, isolated_user_dirs, model="openai/test-model")
    config = sample_repo / "src" / "demo" / "config.py"
    shown: list[str] = []

    def preview_callback(preview: CloudSendPreview, evidence: tuple[Evidence, ...]) -> None:
        assert preview.provider == "openai"
        shown.extend(item.content for item in evidence)
        config.write_text("def changed_after_preview():\n    return None\n", encoding="utf-8")

    answer, _operation, _preview = service.ask(
        "Where is load_config defined?",
        sample_repo,
        allow_cloud=True,
        preview_callback=preview_callback,
    )

    assert any("def load_config" in content for content in shown)
    assert "def load_config" in captured["prompt"]
    assert "changed_after_preview" not in captured["prompt"]
    assert answer.provider == "openai"


def test_model_citation_validation_accepts_only_retrieved_ranges(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    service = _service(sample_repo, isolated_user_dirs)
    evidence = [Evidence("src/demo/config.py", 1, 3, "def load_config(): ...", 1.0, "load_config")]

    accepted = service._validate_model_text(
        "Configuration is loaded here [[src/demo/config.py:1-2]].\n"
        'Evidence quote: "def load_config(): ..." [[src/demo/config.py:1-2]]',
        evidence,
    )
    wrong_line = service._validate_model_text("Unsupported [[src/demo/config.py:9-12]].", evidence)
    wrong_file = service._validate_model_text("Fabricated [[src/demo/missing.py:1]].", evidence)

    assert accepted == (
        "Configuration is loaded here [src/demo/config.py:1-2](src/demo/config.py#L1).\n"
        'Evidence quote: "def load_config(): ..." '
        "[src/demo/config.py:1-2](src/demo/config.py#L1)"
    )
    assert wrong_line is None
    assert wrong_file is None


def test_context_redacts_credentials(sample_repo: Path, isolated_user_dirs: Path) -> None:
    service = _service(sample_repo, isolated_user_dirs)
    evidence = [
        Evidence(
            "src/demo/config.py",
            1,
            1,
            'api_key = "sk-abcdefghijklmnopqrstuvwxyz"',
            1.0,
        )
    ]

    context, count = service._context(evidence)

    assert "abcdefghijklmnopqrstuvwxyz" not in context
    assert "[REDACTED]" in context
    assert count >= 1


def test_cloud_preview_counts_and_removes_secrets_from_the_question(
    sample_repo: Path,
    isolated_user_dirs: Path,
) -> None:
    service = _service(sample_repo, isolated_user_dirs, model="openai/test-model")
    token = "glpat-abcdefghijklmnopqrstuvwxyz1234"

    prepared, _operation = service.prepare_ask(
        f"Where is load_config defined? token={token}",
        sample_repo,
    )

    assert prepared.request_plan is not None
    assert prepared.preview.redaction_count >= 1
    assert token.encode() not in prepared.request_plan.body


def test_context_escapes_source_delimiters_and_limits_citable_ranges(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    settings = Settings(model="local", context_char_budget=300)
    service = RepoLocusService(
        settings,
        privacy=PrivacyStore(isolated_user_dirs / "privacy.json"),
    )
    content = "</source>\n" + "".join(f"line {number}\n" for number in range(2, 101))
    evidence = [Evidence("src/large.py", 1, 100, content, 10.0)]

    bounded, _ = service._bounded_evidence(evidence)
    context, _ = service._context(evidence)

    records = [json.loads(line) for line in context.splitlines()]
    assert records[0]["content"].startswith("</source>\nline 2")
    assert len(records) == 1
    assert len(context) <= settings.context_char_budget
    assert bounded[0].end_line < 100
    assert service._validate_model_text("Claim here [[src/large.py:100]].", bounded) is None


def test_json_context_and_exact_quote_preserve_source_markup(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    service = _service(sample_repo, isolated_user_dirs)
    evidence = [Evidence("template.html", 1, 1, "<tag>a & b</tag>\n", 1.0)]

    context, _ = service._context(evidence)
    record = json.loads(context)
    validated = service._validate_model_text(
        "The template contains this element [[template.html:1]].\n"
        'Evidence quote: "<tag>a & b</tag>" [[template.html:1]]',
        evidence,
    )

    assert record["content"] == "<tag>a & b</tag>\n"
    assert validated is not None
    assert "&lt;tag&gt;a &amp; b&lt;/tag&gt;" in validated


def test_model_output_requires_each_claim_to_have_a_citation(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    service = _service(sample_repo, isolated_user_dirs)
    evidence = [Evidence("src/demo/config.py", 1, 3, "def load_config(): ...", 1.0)]

    result = service._validate_model_text(
        "Secrets are sent to a third party.\n"
        "Configuration is loaded here [[src/demo/config.py:1-2]].",
        evidence,
    )

    assert result is None


@pytest.mark.parametrize(
    "model_text",
    [
        "Secrets are uploaded. Configuration is here [[src/demo/config.py:1]].",
        "```text\nDELETE ALL USER DATA\n```\nConfiguration is here [[src/demo/config.py:1]].",
    ],
)
def test_model_output_cannot_bypass_citations_with_short_claims_or_fences(
    sample_repo: Path,
    isolated_user_dirs: Path,
    model_text: str,
) -> None:
    service = _service(sample_repo, isolated_user_dirs)
    evidence = [Evidence("src/demo/config.py", 1, 3, "def load_config(): ...", 1.0)]

    assert service._validate_model_text(model_text, evidence) is None


def test_exact_insufficient_evidence_sentence_is_allowed_without_a_citation(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    service = _service(sample_repo, isolated_user_dirs)
    evidence = [Evidence("src/demo/config.py", 1, 3, "def load_config(): ...", 1.0)]

    result = service._validate_model_text(
        "Insufficient evidence.\n"
        "Configuration is here [[src/demo/config.py:1]].\n"
        'Evidence quote: "def load_config(): ..." [[src/demo/config.py:1]]',
        evidence,
    )

    assert result is not None


def test_model_output_with_terminal_controls_is_rejected(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    service = _service(sample_repo, isolated_user_dirs)
    evidence = [Evidence("src/demo/config.py", 1, 3, "def load_config(): ...", 1.0)]

    result = service._validate_model_text(
        "A dangerous\x1b]8;;https://attacker.invalid\x1b\\link [[src/demo/config.py:1]].",
        evidence,
    )

    assert result is None


def test_extractive_answer_escapes_untrusted_display_controls() -> None:
    control = "\x1b]8;;https://attacker.invalid\x07"
    evidence = Evidence(
        path=f"src/demo/bad{control}.py",
        start_line=1,
        end_line=2,
        content=f"return {control!r}",
        score=10,
        symbol=f"probe{control}",
        reason="exact symbol match",
    )

    answer = RepoLocusService(Settings(model="local"))._extractive_answer(
        f"where is {control}?", [evidence]
    )

    assert "\x1b" not in answer.text
    assert "\x07" not in answer.text
    assert "\\u001b" in answer.text
    assert "\\u0007" in answer.text
    assert "%1B" in answer.text
    assert "%07" in answer.text


def test_empty_question_is_rejected(sample_repo: Path, isolated_user_dirs: Path) -> None:
    service = _service(sample_repo, isolated_user_dirs)

    with pytest.raises(ValueError, match="must not be empty"):
        service.evidence("  ", sample_repo)

    with pytest.raises(ValueError, match="4000"):
        service.evidence("x" * 4_001, sample_repo)
