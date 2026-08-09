#!/usr/bin/env python3
"""Local-only, read-only RepoLocus adapter for AI agents."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

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
_PASSTHROUGH_ENVIRONMENT = (
    "APPDATA",
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOCALAPPDATA",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "TZ",
    "USERPROFILE",
    "WINDIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
)
_PATH_ENVIRONMENT = frozenset(
    {
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
    }
)
_MINIMUM_RUNTIME_VERSION = (0, 2, 0)
_MAXIMUM_RUNTIME_VERSION = (0, 3, 0)
_RUNTIME_REQUIREMENT = ">=0.2.0,<0.3.0"
_VERSION = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_RUNTIME_PROBE = (
    "import importlib.metadata as metadata, importlib.util as util, json; "
    "spec = util.find_spec('repolocus'); "
    "origin = spec.origin if spec and spec.origin else ''; "
    "\ntry:\n version = metadata.version('repolocus')\n"
    "except metadata.PackageNotFoundError:\n version = ''\n"
    "print(json.dumps({'origin': origin, 'version': version}))"
)


class AdapterError(RuntimeError):
    """Raised when the RepoLocus runtime cannot be located."""


class RuntimeCommand(NamedTuple):
    """A RepoLocus module whose origin and version were checked without importing it."""

    prefix: tuple[str, ...]
    origin: Path
    version: str
    source: str


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
        candidates.extend(
            (
                account_home / ".local" / "bin",
                account_home / ".local" / "share" / "pipx" / "venvs" / "repolocus",
                account_home / ".local" / "pipx" / "venvs" / "repolocus",
            )
        )

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
    require_trusted_root: bool = False,
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
        if require_trusted_root and not from_trusted_root:
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
        if require_trusted_root and not any(_is_within(resolved, root) for root in trusted_roots):
            continue
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


def _safe_passthrough_path(value: str, untrusted_roots: tuple[Path, ...]) -> str | None:
    """Keep a user-directory setting only when it is absolute and outside the target."""

    raw = Path(value).expanduser()
    if not raw.is_absolute():
        return None
    try:
        resolved = raw.resolve()
    except (OSError, RuntimeError):
        return None
    if any(_is_within(resolved, root) for root in untrusted_roots):
        return None
    return str(resolved)


def _execution_environment(
    *,
    invocation_cwd: Path,
    untrusted_roots: tuple[Path, ...],
    trusted_roots: tuple[Path, ...],
) -> dict[str, str]:
    # Start empty rather than trying to enumerate every possible credential,
    # proxy, shell hook, cloud setting, or language-specific injection knob.
    environment: dict[str, str] = {}
    for name in _PASSTHROUGH_ENVIRONMENT:
        value = os.environ.get(name)
        if value is None:
            continue
        if name in _PATH_ENVIRONMENT:
            value = _safe_passthrough_path(value, untrusted_roots)
            if value is None:
                continue
        environment[name] = value

    account_home = _account_home()
    if account_home is not None and not any(
        _is_within(account_home, root) for root in untrusted_roots
    ):
        environment["USERPROFILE" if os.name == "nt" else "HOME"] = str(account_home)
    environment["PATH"] = _safe_path(
        os.environ.get("PATH", os.defpath),
        invocation_cwd=invocation_cwd,
        untrusted_roots=untrusted_roots,
        trusted_roots=trusted_roots,
    )
    environment["PYTHONSAFEPATH"] = "1"
    environment["PYTHONUTF8"] = "1"
    environment["REPOLOCUS_MODEL"] = "local"
    environment["REPOLOCUS_TELEMETRY"] = "false"
    environment["UV_LOCKED"] = "1"
    environment["UV_NO_ENV_FILE"] = "1"
    environment["UV_NO_PROGRESS"] = "1"
    environment["UV_NO_SYNC"] = "1"
    environment["UV_OFFLINE"] = "1"
    return environment


def _runtime_version(value: str) -> tuple[int, int, int] | None:
    match = _VERSION.fullmatch(value.strip())
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _probe_runtime(
    python_prefix: list[str],
    *,
    environment: dict[str, str],
    untrusted_roots: tuple[Path, ...],
    trusted_roots: tuple[Path, ...],
    source: str,
    expected_origin_root: Path | None = None,
) -> RuntimeCommand:
    """Resolve module metadata in isolated mode before executing RepoLocus itself."""

    try:
        completed = subprocess.run(
            [*python_prefix, "-c", _RUNTIME_PROBE],
            cwd=_TRUSTED_WORKING_DIRECTORY,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise AdapterError(f"could not probe the {source} RepoLocus runtime: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else "failed"
        raise AdapterError(f"could not probe the {source} RepoLocus runtime: {detail}")
    try:
        payload = json.loads(completed.stdout)
        origin_text = payload["origin"]
        version = payload["version"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise AdapterError(
            f"the {source} RepoLocus runtime returned invalid probe metadata"
        ) from exc
    if not isinstance(origin_text, str) or not origin_text:
        raise AdapterError(f"RepoLocus is not importable from the {source} runtime")
    if not isinstance(version, str) or not version:
        raise AdapterError(f"the {source} RepoLocus runtime has no distribution version metadata")
    parsed_version = _runtime_version(version)
    if (
        parsed_version is None
        or parsed_version < _MINIMUM_RUNTIME_VERSION
        or parsed_version >= _MAXIMUM_RUNTIME_VERSION
    ):
        raise AdapterError(
            f"the {source} RepoLocus runtime is version {version!r}; "
            f"this Skill requires {_RUNTIME_REQUIREMENT}"
        )
    try:
        origin = Path(origin_text).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise AdapterError(f"cannot resolve the {source} RepoLocus module origin") from exc
    if origin.parent.name != "repolocus" or origin.name not in {"__init__.py", "__init__.pyc"}:
        raise AdapterError(f"unexpected RepoLocus module origin from {source}: {origin}")
    if not _path_is_trusted(
        origin,
        untrusted_roots=untrusted_roots,
        trusted_roots=trusted_roots,
    ):
        raise AdapterError(f"RepoLocus module origin is inside an untrusted directory: {origin}")
    if expected_origin_root is not None and not _is_within(origin, expected_origin_root):
        raise AdapterError(
            f"the {source} runtime resolved RepoLocus outside {expected_origin_root}: {origin}"
        )
    return RuntimeCommand(
        prefix=tuple([*python_prefix, "-m", "repolocus"]),
        origin=origin,
        version=version,
        source=source,
    )


def _launcher_interpreter(
    launcher: Path,
    *,
    path_value: str,
    untrusted_roots: tuple[Path, ...],
    trusted_roots: tuple[Path, ...],
) -> Path | None:
    """Resolve a Python interpreter from a console launcher without executing it."""

    candidates: list[Path] = []
    if os.name == "nt":
        candidates.extend((launcher.parent / "python.exe", launcher.parent / "python3.exe"))
    else:
        try:
            first_line = launcher.open("rb").readline(4096).decode("utf-8", errors="strict").strip()
        except (OSError, UnicodeDecodeError):
            return None
        if not first_line.startswith("#!"):
            return None
        try:
            words = shlex.split(first_line[2:].strip())
        except ValueError:
            return None
        if not words:
            return None
        requested = Path(words[0]).name.casefold()
        if requested == "env":
            if len(words) != 2:
                return None
            resolved = _resolved_executable(
                words[1],
                path_value=path_value,
                untrusted_roots=untrusted_roots,
                trusted_roots=trusted_roots,
                require_trusted_root=True,
            )
            if resolved is not None:
                candidates.append(resolved)
        else:
            candidates.append(Path(words[0]))

    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not resolved.is_file() or not _path_is_trusted(
            resolved,
            untrusted_roots=untrusted_roots,
            trusted_roots=trusted_roots,
        ):
            continue
        return resolved
    return None


def _source_runtime_prefix(uv: Path, source_checkout: Path) -> list[str]:
    return [
        str(uv),
        "run",
        "--project",
        str(source_checkout),
        "--offline",
        "--no-sync",
        "--locked",
        "--no-env-file",
        "--no-progress",
        "python",
        "-I",
    ]


def _runtime_command(
    explicit_binary: str | None,
    *,
    environment: dict[str, str],
    interpreter: Path,
    untrusted_roots: tuple[Path, ...],
    trusted_roots: tuple[Path, ...],
) -> RuntimeCommand:
    requested = explicit_binary or os.environ.get("REPOLOCUS_BIN")
    if requested:
        launcher = _resolved_executable(
            requested,
            path_value=environment["PATH"],
            untrusted_roots=untrusted_roots,
            trusted_roots=trusted_roots,
        )
        if launcher is None:
            raise AdapterError(
                f"RepoLocus executable not found outside the target repository: {requested}"
            )
        requested_interpreter = _launcher_interpreter(
            launcher,
            path_value=environment["PATH"],
            untrusted_roots=untrusted_roots,
            trusted_roots=trusted_roots,
        )
        if requested_interpreter is None:
            raise AdapterError(
                f"cannot validate a Python module origin for RepoLocus executable: {launcher}"
            )
        return _probe_runtime(
            [str(requested_interpreter), "-I"],
            environment=environment,
            untrusted_roots=untrusted_roots,
            trusted_roots=trusted_roots,
            source="explicit executable",
        )

    failures: list[str] = []
    try:
        return _probe_runtime(
            [str(interpreter), "-I"],
            environment=environment,
            untrusted_roots=untrusted_roots,
            trusted_roots=trusted_roots,
            source="adapter interpreter",
        )
    except AdapterError as exc:
        failures.append(str(exc))

    installed = _resolved_executable(
        "repolocus",
        path_value=environment["PATH"],
        untrusted_roots=untrusted_roots,
        trusted_roots=trusted_roots,
        require_trusted_root=True,
    )
    if installed is not None:
        installed_interpreter = _launcher_interpreter(
            installed,
            path_value=environment["PATH"],
            untrusted_roots=untrusted_roots,
            trusted_roots=trusted_roots,
        )
        if installed_interpreter is not None:
            try:
                return _probe_runtime(
                    [str(installed_interpreter), "-I"],
                    environment=environment,
                    untrusted_roots=untrusted_roots,
                    trusted_roots=trusted_roots,
                    source="installed executable",
                )
            except AdapterError as exc:
                failures.append(str(exc))
        else:
            failures.append(f"cannot validate a Python interpreter for {installed}")

    source_checkout = _source_checkout()
    uv = _resolved_executable(
        "uv",
        path_value=environment["PATH"],
        untrusted_roots=untrusted_roots,
        trusted_roots=trusted_roots,
        require_trusted_root=True,
    )
    if source_checkout is not None and source_checkout in trusted_roots and uv is not None:
        try:
            return _probe_runtime(
                _source_runtime_prefix(uv, source_checkout),
                environment=environment,
                untrusted_roots=untrusted_roots,
                trusted_roots=trusted_roots,
                source="offline source checkout",
                expected_origin_root=source_checkout / "src",
            )
        except AdapterError as exc:
            failures.append(str(exc))

    detail = "; ".join(failures[-3:])
    suffix = f" Details: {detail}" if detail else ""
    raise AdapterError(
        "RepoLocus is unavailable. Install a compatible runtime "
        f"({_RUNTIME_REQUIREMENT}) or pre-sync the trusted source checkout; the Skill never "
        f"downloads or syncs dependencies.{suffix}"
    )


def _command_prefix(
    explicit_binary: str | None,
    *,
    environment: dict[str, str],
    interpreter: Path,
    untrusted_roots: tuple[Path, ...],
    trusted_roots: tuple[Path, ...],
) -> list[str]:
    runtime = _runtime_command(
        explicit_binary,
        environment=environment,
        interpreter=interpreter,
        untrusted_roots=untrusted_roots,
        trusted_roots=trusted_roots,
    )
    return list(runtime.prefix)


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


def _bootstrap_doctor_failure(
    repository: Path,
    interpreter: Path,
    error: AdapterError,
) -> dict[str, object]:
    """Return useful diagnostics even when RepoLocus itself cannot start."""

    checks = [
        {
            "name": "bootstrap_python",
            "ok": sys.version_info >= (3, 10),
            "detail": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "required": True,
        },
        {
            "name": "bootstrap_repository",
            "ok": repository.is_dir(),
            "detail": str(repository),
            "required": True,
        },
        {
            "name": "bootstrap_interpreter",
            "ok": interpreter.is_file(),
            "detail": str(interpreter),
            "required": True,
        },
        {
            "name": "bootstrap_runtime",
            "ok": False,
            "detail": str(error),
            "required": True,
        },
        {
            "name": "bootstrap_offline",
            "ok": True,
            "detail": "runtime discovery uses offline, no-sync mode",
            "required": True,
        },
    ]
    return {"ok": False, "bootstrap": True, "checks": checks}


def _diagnostic_path(value: str | os.PathLike[str], fallback: str) -> Path:
    """Build a display-only absolute path without resolving filesystem links."""

    try:
        return Path(os.path.abspath(Path(value).expanduser()))
    except (OSError, RuntimeError, ValueError):
        return Path(fallback)


def main() -> int:
    parser = _parser()
    arguments = parser.parse_args()
    repository = _diagnostic_path(arguments.repository, ".")
    interpreter = _diagnostic_path(sys.executable, "python")
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
        runtime = _runtime_command(
            arguments.binary,
            environment=environment,
            interpreter=interpreter,
            untrusted_roots=untrusted_roots,
            trusted_roots=trusted_roots,
        )
        command = list(runtime.prefix) + _operation_arguments(arguments, repository)
    except (OSError, RuntimeError, ValueError) as exc:
        error = exc if isinstance(exc, AdapterError) else AdapterError(f"Bootstrap failed: {exc}")
        if arguments.operation == "doctor":
            print(json.dumps(_bootstrap_doctor_failure(repository, interpreter, error)))
            return 1
        parser.error(str(error))

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
