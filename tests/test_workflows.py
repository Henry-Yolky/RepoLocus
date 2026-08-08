from __future__ import annotations

import re
from pathlib import Path

_ACTION = re.compile(r"^\s*(?:-\s*)?uses:\s*([^#\s]+)(?:\s+#\s+(\S+))?\s*$", re.MULTILINE)
_FULL_SHA = re.compile(r"[0-9a-f]{40}")
_READABLE_VERSION = re.compile(r"v\d+(?:\.\d+){0,2}")
_UV_VERSION = "0.9.18"


def _repository() -> Path:
    return Path(__file__).resolve().parents[1]


def _workflow(name: str) -> str:
    return (_repository() / ".github" / "workflows" / name).read_text(encoding="utf-8")


def test_third_party_actions_are_pinned_with_readable_versions() -> None:
    for name in ("ci.yml", "release.yml"):
        references = _ACTION.findall(_workflow(name))
        assert references
        for reference, readable_version in references:
            if reference.startswith("./"):
                continue
            action, separator, revision = reference.rpartition("@")
            assert action and separator
            assert _FULL_SHA.fullmatch(revision), reference
            assert _READABLE_VERSION.fullmatch(readable_version), reference


def test_ci_and_release_use_the_same_exact_uv_version() -> None:
    workflows = [_workflow("ci.yml"), _workflow("release.yml")]
    setup_count = sum(workflow.count("uses: astral-sh/setup-uv@") for workflow in workflows)
    pinned_version_count = sum(
        workflow.count(f'version: "{_UV_VERSION}"') for workflow in workflows
    )

    assert setup_count > 0
    assert pinned_version_count == setup_count


def test_external_evaluation_blocks_packaging() -> None:
    workflow = _workflow("ci.yml")

    assert "external-evaluation:" in workflow
    assert "scripts/evaluate_external_repositories.py evaluation" in workflow
    assert "--minimum-citation-recall 1.0" in workflow
    assert "--minimum-qrels 100" in workflow
    assert "--minimum-answerable-qrels 60" in workflow
    assert "--minimum-no-answer-qrels 20" in workflow
    assert "--minimum-citation-qrels 60" in workflow
    external_job = workflow.split("  external-evaluation:", 1)[1].split(
        "  performance-benchmark:", 1
    )[0]
    assert "timeout-minutes: 20" in external_job
    assert "performance-benchmark:" in workflow
    assert "--manifest benchmarks/v0.2-gates.json" in workflow
    assert "benchmarks/v0.2-scale-gates.json" not in workflow
    assert (
        "needs: [test, coverage, security, external-evaluation, performance-benchmark]" in workflow
    )
    assert "if: ${{ always() }}" in workflow
    assert "EVALUATION_RESULT: ${{ needs.external-evaluation.result }}" in workflow
    assert "PERFORMANCE_RESULT: ${{ needs.performance-benchmark.result }}" in workflow
    assert 'if [[ "$result" != "success" ]]' in workflow
    assert 'python-version: ["3.10", "3.12", "3.14"]' in workflow


def test_release_attests_and_verifies_every_asset_before_publish() -> None:
    workflow = _workflow("release.yml")

    assert "scripts/evaluate_external_repositories.py evaluation" in workflow
    assert "--minimum-citation-recall 1.0" in workflow
    assert "--minimum-qrels 100" in workflow
    assert "benchmarks/v0.2-scale-gates.json" in workflow
    assert "repolocus-${PROJECT_VERSION}.scale-benchmark.json" in workflow
    assert "timeout-minutes: 45" in workflow
    assert "timeout-minutes: 20" in workflow
    assert "repolocus-${PROJECT_VERSION}.external-evaluation.json" in workflow
    assert "attestations: write" in workflow
    assert "subject-path: release-assets/*" in workflow
    assert "verify-provenance:" in workflow
    assert "sha256sum -c SHA256SUMS" in workflow
    assert 'gh attestation verify "$asset" --repo "$GITHUB_REPOSITORY"' in workflow
    assert "needs: [build, verify-provenance]" in workflow
    assert "repolocus doctor --security --json" in workflow


def test_core_and_treesitter_wheels_are_smoke_tested_separately() -> None:
    ci = _workflow("ci.yml")
    release = _workflow("release.yml")

    assert ci.count("--extra api --extra treesitter") >= 2
    assert "--extra api --extra treesitter" in release
    for workflow in (ci, release):
        core_install = re.search(
            r'uv pip install --python (\S+/bin/python) "\$\{wheel\}"', workflow
        )
        treesitter_install = re.search(
            r'uv pip install --python (\S+/bin/python) "\$\{wheel\}\[api,treesitter\]"',
            workflow,
        )
        assert core_install is not None
        assert treesitter_install is not None
        assert core_install.group(1) != treesitter_install.group(1)
        assert "assert TreeSitterParser.discover() is None" in workflow
        assert "result = parse_source(" in workflow
        assert 'expected_languages = {"c", "cpp", "javascript", "typescript", "rust"}' in workflow
        assert "assert parser.languages == expected_languages" in workflow
        assert "parser._parser(language, path=path).parse(source_bytes).root_node" in workflow
        assert "assert root.has_error is False" in workflow
        assert "native_symbols = parser._symbols(" in workflow
        assert "result = parser.parse(" in workflow
        assert "assert result.chunks" in workflow
        for fixture in (
            "fixture.c",
            "fixture.cpp",
            "fixture.js",
            "fixture.ts",
            "fixture.tsx",
            "fixture.rs",
        ):
            assert fixture in workflow


def test_dependabot_updates_github_actions() -> None:
    configuration = (_repository() / ".github" / "dependabot.yml").read_text(encoding="utf-8")

    assert "version: 2" in configuration
    assert "package-ecosystem: github-actions" in configuration
    assert "interval: weekly" in configuration


def test_build_backend_is_exactly_pinned() -> None:
    configuration = (_repository() / "pyproject.toml").read_text(encoding="utf-8")

    assert 'requires = ["hatchling==1.31.0"]' in configuration
