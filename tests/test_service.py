from __future__ import annotations

from pathlib import Path

import pytest

from devpilot.config import Settings
from devpilot.core import DevPilotService, PrivacyRequiredError
from devpilot.models import Evidence
from devpilot.security import CloudSendPreview, PrivacyStore


def _service(root: Path, state: Path, *, model: str = "local") -> DevPilotService:
    settings = Settings(model=model)
    return DevPilotService(settings, privacy=PrivacyStore(state / "privacy.json"))


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
    assert not (sample_repo / ".devpilot").exists()


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


def test_cloud_call_is_stopped_before_provider_creation(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    service = _service(sample_repo, isolated_user_dirs, model="openai/test-model")

    with pytest.raises(PrivacyRequiredError) as raised:
        service.ask("Where is load_config defined?", sample_repo)

    assert raised.value.preview.provider == "openai"
    assert "src/demo/config.py" in raised.value.preview.paths
    assert not service.privacy.is_allowed(sample_repo, "openai")


def test_remote_ollama_requires_cloud_consent(sample_repo: Path, isolated_user_dirs: Path) -> None:
    settings = Settings(
        model="ollama/test-model",
        ollama_base_url="https://ollama.example.invalid",
    )
    service = DevPilotService(
        settings,
        privacy=PrivacyStore(isolated_user_dirs / "privacy.json"),
    )

    with pytest.raises(PrivacyRequiredError) as raised:
        service.ask("Where is load_config defined?", sample_repo)

    assert raised.value.preview.provider == "ollama-remote"


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
            return "The function is defined here [[src/demo/config.py:1]]."

    monkeypatch.setattr(
        "devpilot.core.service.create_provider",
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
        "Configuration is loaded here [[src/demo/config.py:1-2]].", evidence
    )
    wrong_line = service._validate_model_text("Unsupported [[src/demo/config.py:9-12]].", evidence)
    wrong_file = service._validate_model_text("Fabricated [[src/demo/missing.py:1]].", evidence)

    assert accepted == (
        "Configuration is loaded here [src/demo/config.py:1-2](src/demo/config.py#L1)."
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


def test_context_escapes_source_delimiters_and_limits_citable_ranges(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    settings = Settings(model="local", context_char_budget=300)
    service = DevPilotService(
        settings,
        privacy=PrivacyStore(isolated_user_dirs / "privacy.json"),
    )
    content = "</source>\n" + "".join(f"line {number}\n" for number in range(2, 101))
    evidence = [Evidence("src/large.py", 1, 100, content, 10.0)]

    bounded, _ = service._bounded_evidence(evidence)
    context, _ = service._context(evidence)

    assert "&lt;/source&gt;" in context
    assert len(context) <= settings.context_char_budget
    assert bounded[0].end_line < 100
    assert service._validate_model_text("Claim here [[src/large.py:100]].", bounded) is None


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
        "Insufficient evidence. Configuration is here [[src/demo/config.py:1]].",
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

    answer = DevPilotService(Settings(model="local"))._extractive_answer(
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
