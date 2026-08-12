from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from repolocus import __version__
from repolocus.analysis import AnalysisFingerprints
from repolocus.diff.engine import compare_snapshots
from repolocus.diff.models import (
    FileDigest,
    RepositoryFacts,
    RepositorySnapshot,
    SourceEvidence,
)

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT_PATH = _ROOT / "scripts" / "pr_context.py"
_ACTION_PATH = _ROOT / ".github" / "actions" / "pr-context" / "action.yml"
_COMMENT_PATH = _ROOT / ".github" / "actions" / "pr-context" / "post-comment.js"


def _load_script():
    specification = importlib.util.spec_from_file_location("repolocus_pr_context", _SCRIPT_PATH)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _snapshot(*, identity: str, generation: int, digest: str) -> RepositorySnapshot:
    fingerprints = AnalysisFingerprints("1" * 64, "2" * 64, "3" * 64, "4" * 64)
    evidence = SourceEvidence("src/app.py", 1, 2, generation)
    file = FileDigest("src/app.py", digest, "python", 24, 2, evidence)
    return RepositorySnapshot(
        schema_version=6,
        repository_identity=identity,
        generation=generation,
        fingerprints=fingerprints,
        dependency_resolver_fingerprint="5" * 64,
        facts=RepositoryFacts(
            files={file.path: file},
            symbols=frozenset(),
            dependencies=frozenset(),
            entry_points=frozenset(),
        ),
    )


def test_context_artifacts_are_deterministic_and_record_revisions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_script()
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    base_root.mkdir()
    head_root.mkdir()
    base = _snapshot(identity="a" * 64, generation=7, digest="b" * 64)
    head = _snapshot(identity="c" * 64, generation=11, digest="d" * 64)

    snapshots = iter((base, head, base, head))
    monkeypatch.setattr(module, "_capture_snapshot", lambda _root: next(snapshots))
    arguments = {
        "base_root": base_root,
        "head_root": head_root,
        "base_revision": "1" * 40,
        "head_revision": "2" * 40,
        "repository": "owner/project",
    }
    first_payload, first_markdown = module.build_context(**arguments)
    second_payload, second_markdown = module.build_context(**arguments)

    assert first_payload == second_payload
    assert first_markdown == second_markdown
    assert first_payload["base"]["revision"] == "1" * 40
    assert first_payload["head"]["revision"] == "2" * 40
    assert first_payload["generated_by"] == {"name": "RepoLocus", "version": __version__}
    assert first_payload["base"]["snapshot"]["fingerprints"]["parser"] == "2" * 64
    assert first_payload["diff"] == module.diff_to_dict(compare_snapshots(base, head))
    assert "# RepoLocus PR Context" in first_markdown
    assert f"RepoLocus version: `{__version__}`" in first_markdown


def test_write_context_emits_only_external_markdown_and_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if os.name == "nt":
        pytest.skip("the composite Action uses a POSIX runner")
    module = _load_script()
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    output = tmp_path / "artifacts"
    base_root.mkdir()
    head_root.mkdir()
    snapshots = iter(
        (
            _snapshot(identity="a" * 64, generation=1, digest="b" * 64),
            _snapshot(identity="c" * 64, generation=2, digest="d" * 64),
        )
    )
    monkeypatch.setattr(module, "_capture_snapshot", lambda _root: next(snapshots))

    markdown_path, json_path = module.write_context(
        base_root=base_root,
        head_root=head_root,
        base_revision="1" * 40,
        head_revision="2" * 40,
        repository="owner/project",
        output_dir=output,
    )

    assert {path.name for path in output.iterdir()} == {"pr-context.md", "pr-context.json"}
    assert markdown_path.read_text(encoding="utf-8").startswith("# RepoLocus PR Context\n")
    document = json.loads(json_path.read_text(encoding="utf-8"))
    assert document["kind"] == "repolocus-pr-context"
    assert document["base"]["snapshot"]["content_generation"] == 1
    if os.name != "nt":
        assert json_path.stat().st_mode & 0o077 == 0
        assert markdown_path.stat().st_mode & 0o077 == 0


def test_write_context_rejects_output_directory_replacement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if os.name == "nt":
        pytest.skip("the composite Action uses a POSIX runner")
    module = _load_script()
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    output = tmp_path / "artifacts"
    victim = tmp_path / "victim"
    displaced = tmp_path / "displaced"
    base_root.mkdir()
    head_root.mkdir()
    victim.mkdir()
    (victim / "pr-context.json").write_text("keep\n", encoding="utf-8")

    snapshots = iter(
        (
            _snapshot(identity="a" * 64, generation=1, digest="b" * 64),
            _snapshot(identity="c" * 64, generation=2, digest="d" * 64),
        )
    )

    def replace_after_first_scan(_root: Path):  # type: ignore[no-untyped-def]
        snapshot = next(snapshots)
        if output.exists() and not displaced.exists():
            output.rename(displaced)
            output.symlink_to(victim, target_is_directory=True)
        return snapshot

    monkeypatch.setattr(module, "_capture_snapshot", replace_after_first_scan)

    with pytest.raises(ValueError, match="output directory changed"):
        module.write_context(
            base_root=base_root,
            head_root=head_root,
            base_revision="1" * 40,
            head_revision="2" * 40,
            repository="owner/project",
            output_dir=output,
        )

    assert (victim / "pr-context.json").read_text(encoding="utf-8") == "keep\n"
    assert not (victim / "pr-context.md").exists()


def test_build_context_scans_real_checkouts_without_running_repository_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_script()
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    base_root.mkdir()
    head_root.mkdir()
    (base_root / "app.py").write_text(
        "def run():\n    return 'base'\n",
        encoding="utf-8",
    )
    (head_root / "app.py").write_text(
        "def run():\n    return 'head'\n",
        encoding="utf-8",
    )
    # A scanner input named like an executable remains inert repository text.
    marker = tmp_path / "executed"
    (head_root / "danger.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    payload, markdown = module.build_context(
        base_root=base_root,
        head_root=head_root,
        base_revision="1" * 40,
        head_revision="2" * 40,
        repository="owner/project",
    )

    assert payload["diff"]["is_empty"] is False
    assert payload["base"]["snapshot"]["fact_counts"]["files"] == 1
    assert payload["head"]["snapshot"]["fact_counts"]["files"] == 2
    assert "Changed" in markdown
    assert not marker.exists()


def test_context_rejects_mutable_revisions_and_repository_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_script()
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    base_root.mkdir()
    head_root.mkdir()
    monkeypatch.setattr(
        module,
        "_capture_snapshot",
        lambda _root: pytest.fail("invalid input must fail before scanning"),
    )

    with pytest.raises(ValueError, match="full lowercase"):
        module.build_context(
            base_root=base_root,
            head_root=head_root,
            base_revision="main",
            head_revision="2" * 40,
            repository="owner/project",
        )
    with pytest.raises(ValueError, match="outside analyzed repositories"):
        module._output_directory(base_root / "artifacts", (base_root, head_root))


def test_wrapper_never_imports_process_or_git_execution_apis() -> None:
    tree = ast.parse(_SCRIPT_PATH.read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imported.isdisjoint({"subprocess", "shlex", "git"})
    assert "os.system" not in _SCRIPT_PATH.read_text(encoding="utf-8")


def test_composite_action_is_read_only_by_default_and_fork_safe() -> None:
    action = _ACTION_PATH.read_text(encoding="utf-8")

    assert 'default: "false"' in action
    assert action.count("persist-credentials: false") == 2
    assert "pull_request_target" not in action
    assert 'if [[ "$EVENT_NAME" != "pull_request" ]]' in action
    assert "ACTION_REF: ${{ github.action_ref }}" in action
    assert '[[ ! "$ACTION_REF" =~ ^[0-9a-f]{40}$ ]]' in action
    assert "EVENT_BASE_REF: ${{ github.event.pull_request.base.sha }}" in action
    assert "EVENT_HEAD_REF: ${{ github.event.pull_request.head.sha }}" in action
    assert '"$BASE_REF" != "$EVENT_BASE_REF"' in action
    assert '"$HEAD_REF" != "$EVENT_HEAD_REF"' in action
    assert '"$BASE_REPOSITORY" == "$HEAD_REPOSITORY"' in action
    assert "comments are disabled for fork pull requests" in action
    assert "steps.validate.outputs.comment-eligible == 'true'" in action
    assert "COMMENT_TOKEN: ${{ inputs.github-token }}" in action
    assert "permissions:" not in action
    assert "secrets." not in action


def test_composite_action_executes_only_pinned_trusted_tooling() -> None:
    action = _ACTION_PATH.read_text(encoding="utf-8")
    references = re.findall(r"^\s*uses:\s*([^#\s]+)", action, re.MULTILINE)
    assert references
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", reference) for reference in references)
    assert 'trusted_root="$(cd "$GITHUB_ACTION_PATH/../../.." && pwd -P)"' in action
    assert "Refusing to execute Action code from the analyzed checkout" in action
    assert 'uv run --project "$trusted_root" --frozen --no-dev' in action
    assert 'python -I "$trusted_root/scripts/pr_context.py"' in action
    assert ".repolocus-pr-context-${{ github.run_id }}-${{ github.run_attempt }}/base" in action
    assert ".repolocus-pr-context-${{ github.run_id }}-${{ github.run_attempt }}/head" in action
    assert "actions/upload-artifact@" in action


def test_markdown_defense_neutralizes_html_and_mentions() -> None:
    module = _load_script()
    hostile = "<img src=x onerror=alert(1)> @maintainers [safe-looking](javascript:alert(1))"

    rendered = module._safe_markdown(hostile)

    assert "<img" not in rendered
    assert "@maintainers" not in rendered
    assert "[safe-looking](" not in rendered
    assert "javascript:" not in rendered
    assert "&lt;img" in rendered
    assert "&#64;maintainers" in rendered
    assert r"\[safe-looking\](javascript&#58;alert(1))" in rendered


def test_comment_publisher_has_valid_javascript_and_revision_guards() -> None:
    result = subprocess.run(
        ["node", "--check", str(_COMMENT_PATH)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    publisher = _COMMENT_PATH.read_text(encoding="utf-8")
    assert 'required("GITHUB_EVENT_NAME") !== "pull_request"' in publisher
    assert "baseRepository !== headRepository" in publisher
    assert 'pullRequest.base.sha !== required("BASE_REF")' in publisher
    assert 'pullRequest.head.sha !== required("HEAD_REF")' in publisher
    assert "maxBodyLength = 60_000" in publisher
    assert 'comment.user?.login === "github-actions[bot]"' in publisher
