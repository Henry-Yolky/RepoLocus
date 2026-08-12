#!/usr/bin/env python3
"""Build deterministic PR-context artifacts from two checked-out repositories.

Git checkout and optional comment publication deliberately stay outside this
wrapper.  The repositories are treated as untrusted input: RepoLocus scans
their files, but never imports them or executes their commands.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from contextlib import suppress
from pathlib import Path
from typing import Any

from repolocus import __version__
from repolocus.config import Settings
from repolocus.core import RepoLocusService
from repolocus.diff import (
    compare_snapshots,
    diff_to_dict,
    render_diff_markdown,
    snapshot_from_index,
)
from repolocus.index import RepositoryIndex

_REVISION = re.compile(r"[0-9a-f]{40}")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_FORMAT_VERSION = 1
_JSON_NAME = "pr-context.json"
_MARKDOWN_NAME = "pr-context.md"
_ACTIVE_SCHEME = re.compile(r"(?i)(?<![A-Za-z0-9+.-])(https?|javascript|mailto):")


def _safe_markdown(document: str) -> str:
    """Neutralize active HTML and mentions in core-rendered Markdown."""

    escaped = (
        document.replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("@", "&#64;")
        .replace("[", r"\[")
        .replace("]", r"\]")
    )
    return _ACTIVE_SCHEME.sub(lambda match: match.group(1) + "&#58;", escaped)


def _revision(value: str, field: str) -> str:
    if not _REVISION.fullmatch(value):
        raise ValueError(f"{field} must be a full lowercase 40-character Git commit SHA")
    return value


def _repository_name(value: str) -> str:
    if not _REPOSITORY.fullmatch(value):
        raise ValueError("repository must use the owner/name form")
    return value


def _repository_path(value: Path, field: str) -> Path:
    candidate = Path(value).expanduser()
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{field} repository does not exist: {candidate}") from exc
    resolved_metadata = resolved.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino)
        != (resolved_metadata.st_dev, resolved_metadata.st_ino)
    ):
        raise ValueError(f"{field} repository must be a stable, non-symlink directory")
    return resolved


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _output_directory(value: Path, repositories: tuple[Path, Path]) -> Path:
    candidate = Path(value).expanduser()
    if candidate.exists() and candidate.is_symlink():
        raise ValueError("output directory must not be a symlink")
    resolved = candidate.resolve(strict=False)
    if any(_is_within(resolved, repository) for repository in repositories):
        raise ValueError("PR-context artifacts must be written outside analyzed repositories")
    if resolved.exists() and any(resolved.iterdir()):
        raise ValueError("output directory must be empty")
    resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
    if resolved.is_symlink() or not resolved.is_dir():
        raise ValueError("output directory must be a stable, non-symlink directory")
    if os.name != "nt":
        resolved.chmod(0o700)
    return resolved


def _open_output_directory(path: Path) -> tuple[int, os.stat_result]:
    """Pin the Action's output directory across the potentially long scans."""

    if os.name == "nt":  # pragma: no cover - the composite Action is Linux-only
        raise ValueError("descriptor-bound PR-context output requires a POSIX runner")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    before = path.lstat()
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise ValueError("output directory changed while it was opened")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _write_new_at(directory: int, name: str, payload: bytes) -> None:
    """Create one private artifact relative to a pinned directory descriptor."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    descriptor = os.open(name, flags, 0o600, dir_fd=directory)
    try:
        try:
            view = memoryview(payload)
            offset = 0
            while offset < len(view):
                written = os.write(descriptor, view[offset:])
                if written <= 0:
                    raise OSError("short write while creating PR-context artifact")
                offset += written
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        except BaseException:
            with suppress(OSError):
                os.unlink(name, dir_fd=directory)
            raise
    finally:
        os.close(descriptor)


def _attest_output_directory(path: Path, opened: os.stat_result) -> None:
    try:
        current = path.lstat()
    except OSError as exc:
        raise ValueError("output directory changed while artifacts were generated") from exc
    if (
        not stat.S_ISDIR(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise ValueError("output directory changed while artifacts were generated")


def _capture_snapshot(root: Path):
    """Scan one checkout and capture its committed projection-only facts."""

    operation = RepoLocusService(Settings()).scan(root, refresh="rebuild")
    with RepositoryIndex.open(root) as index:
        return snapshot_from_index(index, expected_generation=operation.update.content_generation)


def _fingerprints(snapshot: Any) -> dict[str, str] | None:
    value = snapshot.fingerprints
    if value is None:
        return None
    return {
        "scan": value.scan,
        "parser": value.parser,
        "term_index": value.term_index,
        "retrieval": value.retrieval,
    }


def _snapshot_metadata(snapshot: Any) -> dict[str, object]:
    facts = snapshot.facts
    return {
        "format_version": snapshot.format_version,
        "schema_version": snapshot.schema_version,
        "repository_identity": snapshot.repository_identity,
        "content_generation": snapshot.generation,
        "fingerprints": _fingerprints(snapshot),
        "dependency_resolver_fingerprint": snapshot.dependency_resolver_fingerprint,
        "fact_counts": {
            "files": len(facts.files),
            "symbols": len(facts.symbols),
            "dependencies": len(facts.dependencies),
            "entry_points": len(facts.entry_points),
        },
    }


def build_context(
    *,
    base_root: Path,
    head_root: Path,
    base_revision: str,
    head_revision: str,
    repository: str,
) -> tuple[dict[str, object], str]:
    """Scan both checkouts, run the pure diff, and render portable artifacts."""

    base = _repository_path(base_root, "base")
    head = _repository_path(head_root, "head")
    if base == head:
        raise ValueError("base and head must be separate checkout directories")
    base_sha = _revision(base_revision, "base revision")
    head_sha = _revision(head_revision, "head revision")
    repository_name = _repository_name(repository)

    base_snapshot = _capture_snapshot(base)
    head_snapshot = _capture_snapshot(head)
    difference = compare_snapshots(base_snapshot, head_snapshot)
    payload: dict[str, object] = {
        "format_version": _FORMAT_VERSION,
        "kind": "repolocus-pr-context",
        "repository": repository_name,
        "generated_by": {"name": "RepoLocus", "version": __version__},
        "base": {
            "revision": base_sha,
            "snapshot": _snapshot_metadata(base_snapshot),
        },
        "head": {
            "revision": head_sha,
            "snapshot": _snapshot_metadata(head_snapshot),
        },
        "diff": diff_to_dict(difference),
    }
    markdown = "\n".join(
        (
            "# RepoLocus PR Context",
            "",
            f"- Repository: `{repository_name}`",
            f"- Base revision: `{base_sha}`",
            f"- Head revision: `{head_sha}`",
            f"- RepoLocus version: `{__version__}`",
            "",
            _safe_markdown(render_diff_markdown(difference).rstrip()),
            "",
        )
    )
    return payload, markdown


def write_context(
    *,
    base_root: Path,
    head_root: Path,
    base_revision: str,
    head_revision: str,
    repository: str,
    output_dir: Path,
) -> tuple[Path, Path]:
    base = _repository_path(base_root, "base")
    head = _repository_path(head_root, "head")
    output = _output_directory(output_dir, (base, head))
    directory, opened = _open_output_directory(output)
    created: list[str] = []
    try:
        payload, markdown = build_context(
            base_root=base,
            head_root=head,
            base_revision=base_revision,
            head_revision=head_revision,
            repository=repository,
        )
        _attest_output_directory(output, opened)
        encoded_json = (
            json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        for name, content in (
            (_JSON_NAME, encoded_json),
            (_MARKDOWN_NAME, markdown.encode("utf-8")),
        ):
            _write_new_at(directory, name, content)
            created.append(name)
        os.fsync(directory)
        _attest_output_directory(output, opened)
    except BaseException:
        for name in created:
            with suppress(OSError):
                os.unlink(name, dir_fd=directory)
        raise
    finally:
        os.close(directory)
    json_path = output / _JSON_NAME
    markdown_path = output / _MARKDOWN_NAME
    return markdown_path, json_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--head", required=True, type=Path)
    parser.add_argument("--base-revision", required=True)
    parser.add_argument("--head-revision", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    markdown_path, json_path = write_context(
        base_root=arguments.base,
        head_root=arguments.head,
        base_revision=arguments.base_revision,
        head_revision=arguments.head_revision,
        repository=arguments.repository,
        output_dir=arguments.output_dir,
    )
    print(
        json.dumps(
            {"markdown_path": str(markdown_path), "json_path": str(json_path)},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
