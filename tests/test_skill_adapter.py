from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ADAPTER = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "repolocus-analyze-repo"
    / "scripts"
    / "run_repolocus.py"
)


def _run_adapter(
    *arguments: str, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ADAPTER), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_skill_adapter_forces_local_json_answers(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    environment = dict(os.environ)
    environment["REPOLOCUS_MODEL"] = "openai/must-not-run"

    result = _run_adapter(
        "ask",
        "Where is load_config defined?",
        str(sample_repo),
        environment=environment,
    )

    assert result.returncode == 0, result.stderr
    answer = json.loads(result.stdout)
    assert answer["provider"] == "extractive"
    assert any(item["path"] == "src/demo/config.py" for item in answer["evidence"])


@pytest.mark.parametrize(
    ("operation", "output_name", "marker"),
    [
        ("map", "PROJECT_MAP.md", "Generator: RepoLocus"),
        ("diagram", "ARCHITECTURE.md", "```mermaid"),
    ],
)
def test_skill_adapter_returns_documents_without_writing_repository(
    sample_repo: Path,
    isolated_user_dirs: Path,
    operation: str,
    output_name: str,
    marker: str,
) -> None:
    result = _run_adapter(operation, str(sample_repo), environment=dict(os.environ))

    assert result.returncode == 0, result.stderr
    assert marker in result.stdout
    assert not (sample_repo / output_name).exists()
