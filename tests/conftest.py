from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def isolated_user_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = tmp_path / "user"
    monkeypatch.setenv("XDG_CACHE_HOME", str(state / "cache"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(state / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(state / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(state / "state"))
    return state


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    root = tmp_path / "sample"
    (root / "src" / "demo").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "README.md").write_text(
        "# Sample\n\nSample loads configuration and runs a worker.\n", encoding="utf-8"
    )
    (root / "pyproject.toml").write_text(
        "[project]\nname = 'sample'\nversion = '0.1.0'\n", encoding="utf-8"
    )
    (root / "src" / "demo" / "config.py").write_text(
        "def load_config(path: str) -> dict:\n"
        '    """Load one local configuration file."""\n'
        "    return {'path': path}\n",
        encoding="utf-8",
    )
    (root / "src" / "demo" / "main.py").write_text(
        "from demo.config import load_config\n\n"
        "def main() -> None:\n"
        "    load_config('settings.toml')\n\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )
    (root / "tests" / "test_config.py").write_text(
        "from demo.config import load_config\n\n"
        "def test_load_config():\n"
        "    assert load_config('x')['path'] == 'x'\n",
        encoding="utf-8",
    )
    (root / ".env").write_text("OPENAI_API_KEY=never-index-this\n", encoding="utf-8")
    return root
