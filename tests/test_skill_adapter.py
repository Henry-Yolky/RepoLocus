from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

ADAPTER = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "repolocus-analyze-repo"
    / "scripts"
    / "run_repolocus.py"
)


def _load_adapter() -> ModuleType:
    spec = importlib.util.spec_from_file_location("repolocus_skill_adapter", ADAPTER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_adapter(
    *arguments: str,
    environment: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    clean_environment = dict(os.environ if environment is None else environment)
    clean_environment.pop("COVERAGE_FILE", None)
    clean_environment.pop("COVERAGE_PROCESS_START", None)
    for name in tuple(clean_environment):
        if name.startswith("COV_CORE_"):
            clean_environment.pop(name)
    return subprocess.run(
        [sys.executable, "-I", str(ADAPTER), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=clean_environment,
        cwd=cwd,
    )


def _write_path_hijack(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        executable = directory / "repolocus.cmd"
        executable.write_text("@echo off\r\necho PATH_HIJACKED\r\n", encoding="utf-8")
        return executable

    executable = directory / "repolocus"
    executable.write_text("#!/bin/sh\necho PATH_HIJACKED\n", encoding="utf-8")
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable


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


def test_skill_adapter_ignores_target_path_and_module_hijacks(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    package = sample_repo / "repolocus"
    package.mkdir()
    (package / "__main__.py").write_text("print('MODULE_HIJACKED')\n", encoding="utf-8")
    executable_directory = sample_repo / "bin"
    _write_path_hijack(executable_directory)

    environment = dict(os.environ)
    environment["PATH"] = os.pathsep.join(
        (str(executable_directory), environment.get("PATH", os.defpath))
    )
    environment["PYTHONPATH"] = str(sample_repo)
    environment["VIRTUAL_ENV"] = str(sample_repo / ".venv")

    result = _run_adapter(
        "scan",
        ".",
        environment=environment,
        cwd=sample_repo,
    )

    assert result.returncode == 0, result.stderr
    assert "PATH_HIJACKED" not in result.stdout
    assert "MODULE_HIJACKED" not in result.stdout
    assert json.loads(result.stdout)["root"] == str(sample_repo.resolve())


def test_skill_adapter_rejects_explicit_binary_inside_target(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    executable = _write_path_hijack(sample_repo / "bin")

    result = _run_adapter(
        "--binary",
        str(executable),
        "scan",
        ".",
        environment=dict(os.environ),
        cwd=sample_repo,
    )

    assert result.returncode == 2
    assert "outside the target repository" in result.stderr
    assert "PATH_HIJACKED" not in result.stdout


def test_skill_adapter_ignores_path_hijack_under_parent_cwd(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    invocation_cwd = sample_repo.parent
    executable_directory = invocation_cwd / ".local" / "bin"
    _write_path_hijack(executable_directory)
    environment = dict(os.environ)
    environment["HOME"] = str(invocation_cwd)
    environment["USERPROFILE"] = str(invocation_cwd)
    environment["PATH"] = os.pathsep.join(
        (str(executable_directory), environment.get("PATH", os.defpath))
    )

    result = _run_adapter(
        "scan",
        str(sample_repo),
        environment=environment,
        cwd=invocation_cwd,
    )

    assert result.returncode == 0, result.stderr
    assert "PATH_HIJACKED" not in result.stdout
    assert json.loads(result.stdout)["root"] == str(sample_repo.resolve())


def test_skill_adapter_does_not_trust_an_unrelated_path_runtime(
    sample_repo: Path, isolated_user_dirs: Path
) -> None:
    stale_directory = sample_repo.parent / "stale-runtime"
    _write_path_hijack(stale_directory)
    environment = dict(os.environ)
    environment["PATH"] = os.pathsep.join(
        (str(stale_directory), environment.get("PATH", os.defpath))
    )

    result = _run_adapter("scan", str(sample_repo), environment=environment)

    assert result.returncode == 0, result.stderr
    assert "PATH_HIJACKED" not in result.stdout
    assert json.loads(result.stdout)["root"] == str(sample_repo.resolve())


def test_skill_adapter_rejects_python_interpreter_inside_target(
    sample_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _load_adapter()
    target_interpreter = sample_repo / ".venv" / "bin" / "python"
    monkeypatch.setattr(adapter.sys, "executable", str(target_interpreter))

    with pytest.raises(adapter.AdapterError, match="Python interpreter inside the target"):
        adapter._trusted_interpreter(sample_repo.resolve())


def test_skill_adapter_keeps_absolute_user_bin_while_sanitizing_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _load_adapter()
    invocation_cwd = tmp_path / "home"
    user_bin = invocation_cwd / ".local" / "bin"
    target = invocation_cwd / "projects" / "target"
    target_bin = target / "bin"
    for directory in (user_bin, target_bin):
        directory.mkdir(parents=True)
    monkeypatch.chdir(invocation_cwd)
    monkeypatch.setattr(adapter, "_account_home", lambda: invocation_cwd.resolve())
    monkeypatch.setenv(
        "PATH",
        os.pathsep.join((str(user_bin), ".", "relative-bin", str(target_bin), os.defpath)),
    )
    for name in (*adapter._PYTHON_IMPORT_ENVIRONMENT, *adapter._UV_ENVIRONMENT):
        monkeypatch.setenv(name, str(target))
    monkeypatch.setenv("COVERAGE_PROCESS_START", str(target / "coverage.ini"))
    monkeypatch.setenv("COV_CORE_SOURCE", "repolocus")

    interpreter = adapter._trusted_interpreter(target.resolve())
    trusted_roots = adapter._trusted_roots(target.resolve(), interpreter)

    environment = adapter._execution_environment(
        invocation_cwd=invocation_cwd.resolve(),
        untrusted_roots=(target.resolve(), invocation_cwd.resolve()),
        trusted_roots=trusted_roots,
    )

    path_entries = set(environment["PATH"].split(os.pathsep))
    assert str(user_bin.resolve()) in path_entries
    assert str(invocation_cwd.resolve()) not in path_entries
    assert str((invocation_cwd / "relative-bin").resolve()) not in path_entries
    assert str(target_bin.resolve()) not in path_entries
    assert all(name not in environment for name in adapter._PYTHON_IMPORT_ENVIRONMENT)
    assert all(name not in environment for name in adapter._UV_ENVIRONMENT)
    assert "COVERAGE_PROCESS_START" not in environment
    assert "COV_CORE_SOURCE" not in environment


def test_skill_adapter_uses_an_environment_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _load_adapter()
    invocation_cwd = tmp_path / "work"
    target = tmp_path / "target"
    user_cache = tmp_path / "user-cache"
    invocation_cwd.mkdir()
    target.mkdir()
    user_cache.mkdir()
    monkeypatch.chdir(invocation_cwd)
    monkeypatch.setenv("XDG_CACHE_HOME", str(user_cache))
    monkeypatch.setenv("LANG", "C.UTF-8")
    forbidden = (
        "ALL_PROXY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "OPENAI_API_KEY",
        "SSH_AUTH_SOCK",
    )
    for name in forbidden:
        monkeypatch.setenv(name, "must-not-leak")

    interpreter = adapter._trusted_interpreter(target.resolve())
    trusted_roots = adapter._trusted_roots(target.resolve(), interpreter)
    environment = adapter._execution_environment(
        invocation_cwd=invocation_cwd.resolve(),
        untrusted_roots=(target.resolve(), invocation_cwd.resolve()),
        trusted_roots=trusted_roots,
    )

    assert environment["LANG"] == "C.UTF-8"
    assert environment["XDG_CACHE_HOME"] == str(user_cache.resolve())
    assert environment["REPOLOCUS_MODEL"] == "local"
    assert environment["UV_OFFLINE"] == "1"
    assert environment["UV_NO_SYNC"] == "1"
    assert all(name not in environment for name in forbidden)
    assert all("must-not-leak" not in value for value in environment.values())


def test_source_checkout_runtime_is_forced_offline_and_no_sync(tmp_path: Path) -> None:
    adapter = _load_adapter()
    prefix = adapter._source_runtime_prefix(tmp_path / "uv", tmp_path / "source")

    assert "--offline" in prefix
    assert "--no-sync" in prefix
    assert "--locked" in prefix
    assert "--no-env-file" in prefix
    assert prefix[-2:] == ["python", "-I"]


def test_runtime_probe_validates_module_origin_and_compatible_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _load_adapter()
    runtime_root = tmp_path / "runtime"
    origin = runtime_root / "repolocus" / "__init__.py"
    origin.parent.mkdir(parents=True)
    origin.write_text("", encoding="utf-8")

    monkeypatch.setattr(
        adapter.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"origin": str(origin), "version": "0.1.2"}),
            stderr="",
        ),
    )

    runtime = adapter._probe_runtime(
        [str(tmp_path / "python"), "-I"],
        environment={},
        untrusted_roots=(tmp_path / "target",),
        trusted_roots=(runtime_root,),
        source="test",
        expected_origin_root=runtime_root,
    )

    assert runtime.origin == origin.resolve()
    assert runtime.version == "0.1.2"
    assert runtime.prefix[-2:] == ("-m", "repolocus")


@pytest.mark.parametrize("version", ["0.1.1", "0.2.0", "not-a-version"])
def test_runtime_probe_rejects_incompatible_versions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    adapter = _load_adapter()
    runtime_root = tmp_path / "runtime"
    origin = runtime_root / "repolocus" / "__init__.py"
    origin.parent.mkdir(parents=True)
    origin.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        adapter.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"origin": str(origin), "version": version}),
            stderr="",
        ),
    )

    with pytest.raises(adapter.AdapterError, match=r"requires >=0\.1\.2,<0\.2\.0"):
        adapter._probe_runtime(
            [str(tmp_path / "python"), "-I"],
            environment={},
            untrusted_roots=(tmp_path / "target",),
            trusted_roots=(runtime_root,),
            source="test",
        )


def test_bootstrap_doctor_reports_runtime_failure_without_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    adapter = _load_adapter()
    repository = tmp_path / "repository"
    repository.mkdir()

    def unavailable(*args: object, **kwargs: object) -> object:
        raise adapter.AdapterError("compatible runtime missing")

    monkeypatch.setattr(adapter, "_runtime_command", unavailable)
    monkeypatch.setattr(adapter.sys, "argv", [str(ADAPTER), "doctor", str(repository)])

    assert adapter.main() == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["bootstrap"] is True
    runtime = next(check for check in payload["checks"] if check["name"] == "bootstrap_runtime")
    assert runtime["ok"] is False
    assert "compatible runtime missing" in runtime["detail"]


def test_bootstrap_doctor_reports_path_resolution_failure_as_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    adapter = _load_adapter()
    repository = tmp_path / "repository"
    repository.mkdir()

    def cannot_resolve(*args: object, **kwargs: object) -> object:
        raise OSError("filesystem lookup failed")

    monkeypatch.setattr(adapter.Path, "resolve", cannot_resolve)
    monkeypatch.setattr(adapter.sys, "argv", [str(ADAPTER), "doctor", str(repository)])

    assert adapter.main() == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["bootstrap"] is True
    runtime = next(check for check in payload["checks"] if check["name"] == "bootstrap_runtime")
    assert runtime["ok"] is False
    assert "filesystem lookup failed" in runtime["detail"]
