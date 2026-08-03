#!/usr/bin/env python3
"""Local-only, read-only RepoLocus adapter for AI agents."""

from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path


class AdapterError(RuntimeError):
    """Raised when the RepoLocus runtime cannot be located."""


def _command_prefix(explicit_binary: str | None) -> list[str]:
    requested = explicit_binary or os.environ.get("REPOLOCUS_BIN")
    if requested:
        resolved = shutil.which(requested)
        if resolved:
            return [resolved]
        raise AdapterError(f"RepoLocus executable not found: {requested}")

    installed = shutil.which("repolocus")
    if installed:
        return [installed]

    if importlib.util.find_spec("repolocus") is not None:
        return [sys.executable, "-m", "repolocus"]

    uv = shutil.which("uv")
    if uv:
        for candidate in Path(__file__).resolve().parents:
            if (candidate / "pyproject.toml").is_file() and (
                candidate / "src" / "repolocus"
            ).is_dir():
                return [
                    uv,
                    "run",
                    "--project",
                    str(candidate),
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


def _operation_arguments(arguments: argparse.Namespace) -> list[str]:
    repository = str(Path(arguments.repository).expanduser())
    if arguments.operation == "doctor":
        return ["doctor", repository, "--security", "--json"]
    if arguments.operation == "scan":
        return ["scan", repository, "--json"]
    if arguments.operation in {"map", "diagram"}:
        return [arguments.operation, repository, "--stdout"]
    if arguments.operation == "ask":
        return [
            "ask",
            arguments.question,
            repository,
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
        command = _command_prefix(arguments.binary) + _operation_arguments(arguments)
    except AdapterError as exc:
        parser.error(str(exc))

    environment = dict(os.environ)
    environment["REPOLOCUS_MODEL"] = "local"
    environment["REPOLOCUS_TELEMETRY"] = "false"
    try:
        completed = subprocess.run(command, env=environment, check=False)
    except FileNotFoundError as exc:
        print(f"RepoLocus execution failed: {exc}", file=sys.stderr)
        return 127
    except KeyboardInterrupt:
        return 130
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
