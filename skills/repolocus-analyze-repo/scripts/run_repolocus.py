#!/usr/bin/env python3
"""Local-only, read-only RepoLocus adapter for AI agents."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

_TRUSTED_WORKING_DIRECTORY = Path(__file__).resolve().parent
_PYTHON_IMPORT_ENVIRONMENT = (
    "PYTHONCASEOK",
    "PYTHONEXECUTABLE",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONPATH",
    "PYTHONPLATLIBDIR",
    "PYTHONSTARTUP",
    "PYTHONUSERBASE",
    "__PYVENV_LAUNCHER__",
)
_UV_ENVIRONMENT = (
    "UV_CONFIG_FILE",
    "UV_PROJECT",
    "UV_PROJECT_ENVIRONMENT",
    "UV_PYTHON",
    "UV_WORKING_DIRECTORY",
    "VIRTUAL_ENV",
)
_COVERAGE_ENVIRONMENT = ("COVERAGE_FILE", "COVERAGE_PROCESS_START")


class AdapterError(RuntimeError):
    """Raised when the RepoLocus runtime cannot be located."""


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _source_checkout() -> Path | None:
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "pyproject.toml").is_file() and (candidate / "src" / "repolocus").is_dir():
            return candidate
    return None


def _overlaps(path: Path, other: Path) -> bool:
    return _is_within(path, other) or _is_within(other, path)


def _account_home() -> Path | None:
    if os.name == "nt":
        try:
            import ctypes

            profile = ctypes.create_unicode_buffer(32_768)
            result = ctypes.windll.shell32.SHGetFolderPathW(None, 0x0028, None, 0, profile)
            return Path(profile.value).resolve() if result == 0 and profile.value else None
        except (AttributeError, OSError):
            return None
    try:
        import pwd

        return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    except (ImportError, KeyError, OSError):
        return None


def _trusted_roots(repository: Path, interpreter: Path) -> tuple[Path, ...]:
    candidates = [interpreter.parent, _source_checkout()]
    account_home = _account_home()
    if account_home is not None:
        candidates.append(account_home / ".local" / "bin")

    roots: list[Path] = []
    for candidate in candidates:
        if candidate is None:
            continue
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if not resolved.is_dir() or _overlaps(resolved, repository) or resolved in roots:
            continue
        roots.append(resolved)
    return tuple(roots)


def _trusted_interpreter(repository: Path) -> Path:
    interpreter = Path(os.path.abspath(Path(sys.executable).expanduser()))
    try:
        resolved = interpreter.resolve()
    except OSError as exc:
        raise AdapterError(f"Cannot resolve the Python interpreter: {exc}") from exc
    if _is_within(interpreter, repository) or _is_within(resolved, repository):
        raise AdapterError(
            "The adapter is running with a Python interpreter inside the target repository; "
            "rerun it with a trusted Python interpreter outside the target repository"
        )
    return interpreter


def _path_is_trusted(
    path: Path,
    *,
    untrusted_roots: tuple[Path, ...],
    trusted_roots: tuple[Path, ...],
) -> bool:
    if any(_is_within(path, root) for root in trusted_roots):
        return True
    return not any(_is_within(path, root) for root in untrusted_roots)


def _resolved_executable(
    command: str,
    *,
    path_value: str,
    untrusted_roots: tuple[Path, ...],
    trusted_roots: tuple[Path, ...],
) -> Path | None:
    requested_path = Path(command).expanduser()
    expanded = str(requested_path)
    if os.path.dirname(expanded):
        candidate = shutil.which(expanded)
        if candidate is None:
            return None
        try:
            resolved = Path(candidate).resolve()
        except (OSError, RuntimeError):
            return None
        from_trusted_root = any(_is_within(resolved, root) for root in trusted_roots)
        if not requested_path.is_absolute() and not from_trusted_root:
            return None
        if _path_is_trusted(resolved, untrusted_roots=untrusted_roots, trusted_roots=trusted_roots):
            return resolved
        return None

    seen: set[Path] = set()
    for raw_entry in path_value.split(os.pathsep):
        entry = raw_entry or os.curdir
        candidate = shutil.which(command, path=entry)
        if candidate is None:
            continue
        try:
            resolved = Path(candidate).resolve()
        except (OSError, RuntimeError):
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if _path_is_trusted(resolved, untrusted_roots=untrusted_roots, trusted_roots=trusted_roots):
            return resolved
    return None


def _safe_path(
    path_value: str,
    *,
    invocation_cwd: Path,
    untrusted_roots: tuple[Path, ...],
    trusted_roots: tuple[Path, ...],
) -> str:
    entries: list[str] = []
    for raw_entry in path_value.split(os.pathsep):
        raw_path = Path(raw_entry or os.curdir).expanduser()
        try:
            entry = raw_path.resolve()
        except (OSError, RuntimeError):
            continue
        from_trusted_root = any(_is_within(entry, root) for root in trusted_roots)
        if not from_trusted_root and (not raw_path.is_absolute() or entry == invocation_cwd):
            continue
        if _path_is_trusted(entry, untrusted_roots=untrusted_roots, trusted_roots=trusted_roots):
            entries.append(str(entry))
    return os.pathsep.join(entries)


def _execution_environment(
    *,
    invocation_cwd: Path,
    untrusted_roots: tuple[Path, ...],
    trusted_roots: tuple[Path, ...],
) -> dict[str, str]:
    environment = dict(os.environ)
    for name in (*_PYTHON_IMPORT_ENVIRONMENT, *_UV_ENVIRONMENT, *_COVERAGE_ENVIRONMENT):
        environment.pop(name, None)
    for name in tuple(environment):
        if name.startswith("COV_CORE_"):
            environment.pop(name)
    environment["PATH"] = _safe_path(
        environment.get("PATH", os.defpath),
        invocation_cwd=invocation_cwd,
        untrusted_roots=untrusted_roots,
        trusted_roots=trusted_roots,
    )
    environment["PYTHONSAFEPATH"] = "1"
    environment["REPOLOCUS_MODEL"] = "local"
    environment["REPOLOCUS_TELEMETRY"] = "false"
    return environment


def _isolated_module_origin(environment: dict[str, str], interpreter: Path) -> Path | None:
    probe = (
        "import importlib.util; "
        "spec = importlib.util.find_spec('repolocus'); "
        "print(spec.origin if spec and spec.origin else '')"
    )
    try:
        completed = subprocess.run(
            [str(interpreter), "-I", "-c", probe],
            cwd=_TRUSTED_WORKING_DIRECTORY,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    try:
        return Path(completed.stdout.strip()).resolve()
    except (OSError, RuntimeError):
        return None


def _command_prefix(
    explicit_binary: str | None,
    *,
    environment: dict[str, str],
    interpreter: Path,
    untrusted_roots: tuple[Path, ...],
    trusted_roots: tuple[Path, ...],
) -> list[str]:
    requested = explicit_binary or os.environ.get("REPOLOCUS_BIN")
    if requested:
        resolved = _resolved_executable(
            requested,
            path_value=environment["PATH"],
            untrusted_roots=untrusted_roots,
            trusted_roots=trusted_roots,
        )
        if resolved is not None:
            return [str(resolved)]
        raise AdapterError(
            f"RepoLocus executable not found outside the target repository: {requested}"
        )

    installed = _resolved_executable(
        "repolocus",
        path_value=environment["PATH"],
        untrusted_roots=untrusted_roots,
        trusted_roots=trusted_roots,
    )
    if installed is not None:
        return [str(installed)]

    module_origin = _isolated_module_origin(environment, interpreter)
    if module_origin is not None and _path_is_trusted(
        module_origin, untrusted_roots=untrusted_roots, trusted_roots=trusted_roots
    ):
        return [str(interpreter), "-I", "-m", "repolocus"]

    source_checkout = _source_checkout()
    uv = _resolved_executable(
        "uv",
        path_value=environment["PATH"],
        untrusted_roots=untrusted_roots,
        trusted_roots=trusted_roots,
    )
    if source_checkout is not None and source_checkout in trusted_roots and uv is not None:
        return [
            str(uv),
            "run",
            "--project",
            str(source_checkout),
            "--locked",
            "repolocus",
        ]

    raise AdapterError(
        "RepoLocus is unavailable; install it with 'pipx install repolocus' or run this "
        "Skill from a RepoLocus source checkout with uv installed"
    )


def _limit(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 20:
        raise argparse.ArgumentTypeError("limit must be between 1 and 20")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run RepoLocus through a local-only, repository-read-only agent boundary."
    )
    parser.add_argument(
        "--binary",
        help="Explicit RepoLocus executable path; defaults to REPOLOCUS_BIN or discovery.",
    )
    commands = parser.add_subparsers(dest="operation", required=True)

    for operation in ("doctor", "scan", "map", "diagram"):
        command = commands.add_parser(operation)
        command.add_argument("repository", nargs="?", default=".")

    ask = commands.add_parser("ask")
    ask.add_argument("question")
    ask.add_argument("repository", nargs="?", default=".")
    ask.add_argument("--limit", type=_limit, default=8)
    return parser


def _operation_arguments(arguments: argparse.Namespace, repository: Path) -> list[str]:
    repository_argument = str(repository)
    if arguments.operation == "doctor":
        return ["doctor", repository_argument, "--security", "--json"]
    if arguments.operation == "scan":
        return ["scan", repository_argument, "--json"]
    if arguments.operation in {"map", "diagram"}:
        return [arguments.operation, repository_argument, "--stdout"]
    if arguments.operation == "ask":
        return [
            "ask",
            arguments.question,
            repository_argument,
            "--model",
            "local",
            "--limit",
            str(arguments.limit),
            "--json",
        ]
    raise AssertionError(f"unsupported operation: {arguments.operation}")


def main() -> int:
    parser = _parser()
    arguments = parser.parse_args()
    try:
        repository = Path(arguments.repository).expanduser().resolve()
        invocation_cwd = Path.cwd().resolve()
        interpreter = _trusted_interpreter(repository)
        untrusted_roots = (repository, invocation_cwd)
        trusted_roots = _trusted_roots(repository, interpreter)
        environment = _execution_environment(
            invocation_cwd=invocation_cwd,
            untrusted_roots=untrusted_roots,
            trusted_roots=trusted_roots,
        )
        command = _command_prefix(
            arguments.binary,
            environment=environment,
            interpreter=interpreter,
            untrusted_roots=untrusted_roots,
            trusted_roots=trusted_roots,
        ) + _operation_arguments(arguments, repository)
    except AdapterError as exc:
        parser.error(str(exc))

    try:
        completed = subprocess.run(
            command,
            cwd=_TRUSTED_WORKING_DIRECTORY,
            env=environment,
            check=False,
        )
    except FileNotFoundError as exc:
        print(f"RepoLocus execution failed: {exc}", file=sys.stderr)
        return 127
    except KeyboardInterrupt:
        return 130
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
