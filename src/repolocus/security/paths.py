"""Canonical repository path checks."""

from __future__ import annotations

from pathlib import Path


class PathSecurityError(ValueError):
    """Raised when a requested path leaves the selected repository root."""


def resolve_within_root(
    root: Path | str,
    candidate: Path | str,
    *,
    must_exist: bool = False,
) -> Path:
    """Return a canonical candidate path, rejecting traversal and symlink escape.

    Relative candidates are interpreted below ``root``.  ``Path.resolve`` also
    follows every existing symlink in the path, including an existing parent of
    a not-yet-created leaf.
    """

    try:
        root_path = Path(root).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PathSecurityError(f"repository root cannot be resolved: {root}") from exc
    if not root_path.is_dir():
        raise PathSecurityError(f"repository root is not a directory: {root_path}")

    requested = Path(candidate).expanduser()
    if not requested.is_absolute():
        requested = root_path / requested
    try:
        resolved = requested.resolve(strict=must_exist)
    except (OSError, RuntimeError) as exc:
        raise PathSecurityError(f"path cannot be resolved: {candidate}") from exc
    try:
        resolved.relative_to(root_path)
    except ValueError as exc:
        raise PathSecurityError(f"path escapes repository root: {candidate}") from exc
    return resolved


def ensure_within_root(
    root: Path | str,
    candidate: Path | str,
    *,
    must_exist: bool = False,
) -> Path:
    """Alias with an imperative name for callers enforcing the boundary."""

    return resolve_within_root(root, candidate, must_exist=must_exist)


def is_within_root(root: Path | str, candidate: Path | str, *, must_exist: bool = False) -> bool:
    """Return whether ``candidate`` resolves within ``root``."""

    try:
        resolve_within_root(root, candidate, must_exist=must_exist)
    except PathSecurityError:
        return False
    return True
