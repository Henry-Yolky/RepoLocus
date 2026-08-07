"""Secure, deterministic repository traversal."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path, PurePosixPath

from repolocus.analysis import build_analysis_fingerprints
from repolocus.models import ScannedFile, ScanResult, ScanStats
from repolocus.parsers import DEFAULT_REGISTRY, ParserRegistry
from repolocus.scanner.budget import FactCounts, ScanBudget, deadline_after
from repolocus.scanner.filters import (
    contains_likely_secret,
    detect_language,
    is_binary,
    is_default_ignored,
    is_generated_document,
    is_sensitive_path,
)
from repolocus.scanner.ignore import IgnoreRules
from repolocus.scanner.validation import (
    DEFAULT_MAX_CHUNKS_PER_FILE,
    DEFAULT_MAX_DEPENDENCIES_PER_FILE,
    DEFAULT_MAX_REPOSITORY_DEPENDENCIES,
    DEFAULT_MAX_SYMBOLS_PER_FILE,
    HARD_MAX_REPOSITORY_DEPENDENCIES,
    ParseLimits,
    finalize_parse_result,
)
from repolocus.security.identity import descriptor_path, filesystem_identity

DEFAULT_MAX_FILE_BYTES = 1_000_000
DEFAULT_MAX_IGNORE_BYTES = 256_000
DEFAULT_MAX_REPOSITORY_FILES = 100_000
DEFAULT_MAX_REPOSITORY_BYTES = 512_000_000
DEFAULT_MAX_DIRECTORY_DEPTH = 64
DEFAULT_MAX_REPOSITORY_CHUNKS = 500_000
DEFAULT_MAX_REPOSITORY_SYMBOLS = 500_000
DEFAULT_MAX_SCAN_SECONDS = 120

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_IS_WINDOWS = os.name == "nt"
_USE_DIRECTORY_FDS = (
    os.name == "posix"
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.scandir in os.supports_fd
)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _is_reparse_point(metadata: os.stat_result) -> bool:
    """Return whether Windows reports an entry as a reparse point."""

    return bool(getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT)


def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _same_content_state(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        _same_identity(first, second)
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
    )


def _same_file_state(first: os.stat_result, second: os.stat_result) -> bool:
    return _same_content_state(first, second) and first.st_ctime_ns == second.st_ctime_ns


def _is_stable_unpinned_directory(
    directory: Path,
    root: Path,
    expected: os.stat_result,
) -> bool:
    """Validate a path-based directory traversal against its enumerated identity."""

    try:
        before = directory.lstat()
    except OSError:
        return False
    if (
        not stat.S_ISDIR(before.st_mode)
        or _is_reparse_point(before)
        or not _same_identity(expected, before)
    ):
        return False
    try:
        resolved = directory.resolve(strict=True)
        after = directory.lstat()
    except (OSError, RuntimeError):
        return False
    return (
        _is_within(resolved, root)
        and stat.S_ISDIR(after.st_mode)
        and not _is_reparse_point(after)
        and _same_identity(expected, after)
        and _same_identity(before, after)
    )


def _read_descriptor(descriptor: int, limit: int) -> tuple[bytes | None, str | None]:
    blocks: list[bytes] = []
    remaining = limit + 1
    try:
        while remaining:
            block = os.read(descriptor, min(65_536, remaining))
            if not block:
                break
            blocks.append(block)
            remaining -= len(block)
    except OSError:
        return None, "unreadable"
    payload = b"".join(blocks)
    return (None, "oversize") if len(payload) > limit else (payload, None)


def _safe_read_at(
    name: str,
    limit: int,
    expected: os.stat_result,
    *,
    directory: Path,
    directory_fd: int | None,
    root: Path | None = None,
) -> tuple[bytes | None, os.stat_result | None, str | None]:
    """Open and read one enumerated file without resolving a path component twice."""

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    target: str | Path = name if directory_fd is not None else directory / name
    try:
        if directory_fd is None:
            descriptor = os.open(target, flags)
        else:
            descriptor = os.open(target, flags, dir_fd=directory_fd)
    except OSError as exc:
        reason = (
            "changed_during_scan"
            if exc.errno in {errno.ELOOP, errno.ENOENT, errno.ENOTDIR}
            else "unreadable"
        )
        return None, None, reason
    accepted_payload: bytes | None = None
    preclose_path: os.stat_result | None = None
    try:
        try:
            opened = os.fstat(descriptor)
        except OSError:
            return None, None, "unreadable"
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_point(opened)
            or not _same_identity(expected, opened)
        ):
            return None, None, "changed_during_scan"
        # A pinned directory descriptor already confines POSIX openat reads.
        # Descriptor-path attestation is required only for the path-based
        # fallback (and on Windows), where it closes the final open race.
        if root is not None and directory_fd is None:
            opened_path = descriptor_path(descriptor)
            if opened_path is None or not _is_within(opened_path, root):
                return None, None, "changed_during_scan"
        if opened.st_size > limit:
            return None, None, "oversize"
        payload, reason = _read_descriptor(descriptor, limit)
        if payload is None:
            return None, None, reason
        try:
            finished = os.fstat(descriptor)
            if directory_fd is None:
                current = os.stat(target, follow_symlinks=False)
            else:
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            return None, None, "changed_during_scan"
        # Keep ctime comparisons within matching metadata sources on Windows 3.12.
        if (
            _is_reparse_point(current)
            or not _same_file_state(opened, finished)
            or not _same_content_state(finished, current)
            or not _same_file_state(expected, current)
        ):
            return None, None, "changed_during_scan"
        accepted_payload = payload
        preclose_path = current
    finally:
        os.close(descriptor)

    if accepted_payload is None or preclose_path is None:  # pragma: no cover - control flow
        raise RuntimeError("safe read completed without an accepted snapshot")
    try:
        if directory_fd is None:
            persisted = os.stat(target, follow_symlinks=False)
        else:
            persisted = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return None, None, "changed_during_scan"
    if (
        not stat.S_ISREG(persisted.st_mode)
        or _is_reparse_point(persisted)
        or not _same_file_state(preclose_path, persisted)
    ):
        return None, None, "changed_during_scan"
    return accepted_payload, persisted, None


def _safe_read(path: Path, limit: int) -> tuple[bytes | None, str | None]:
    """Compatibility wrapper for securely reading one standalone path."""

    try:
        expected = path.lstat()
    except OSError:
        return None, "unreadable"
    if not stat.S_ISREG(expected.st_mode) or _is_reparse_point(expected):
        return None, "special_file"
    payload, _metadata, reason = _safe_read_at(
        path.name,
        limit,
        expected,
        directory=path.parent,
        directory_fd=None,
    )
    return payload, reason


def _metadata_still_matches_at(
    name: str,
    expected: os.stat_result,
    *,
    directory: Path,
    directory_fd: int | None,
) -> bool:
    """Revalidate one metadata-only cache hit without opening its contents."""

    try:
        if directory_fd is None:
            current = os.stat(directory / name, follow_symlinks=False)
        else:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISREG(current.st_mode)
        and not _is_reparse_point(current)
        and _same_file_state(expected, current)
    )


def _open_directory_at(
    name: str,
    expected: os.stat_result,
    directory_fd: int,
) -> tuple[int | None, str | None]:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        reason = (
            "changed_during_scan"
            if exc.errno in {errno.ELOOP, errno.ENOENT, errno.ENOTDIR}
            else "unreadable"
        )
        return None, reason
    try:
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        os.close(descriptor)
        return None, "changed_during_scan"
    if (
        not stat.S_ISDIR(opened.st_mode)
        or _is_reparse_point(opened)
        or _is_reparse_point(current)
        or not _same_identity(expected, opened)
        or not _same_identity(opened, current)
    ):
        os.close(descriptor)
        return None, "changed_during_scan"
    return descriptor, None


class RepositoryScanner:
    """Scan supported repository text without following links or running code."""

    def __init__(
        self,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        *,
        max_chunk_lines: int = 160,
        max_chunk_chars: int = 16_000,
        max_ignore_bytes: int = DEFAULT_MAX_IGNORE_BYTES,
        max_repository_files: int = DEFAULT_MAX_REPOSITORY_FILES,
        max_repository_bytes: int = DEFAULT_MAX_REPOSITORY_BYTES,
        max_directory_depth: int = DEFAULT_MAX_DIRECTORY_DEPTH,
        max_repository_chunks: int = DEFAULT_MAX_REPOSITORY_CHUNKS,
        max_repository_symbols: int = DEFAULT_MAX_REPOSITORY_SYMBOLS,
        max_repository_dependencies: int = DEFAULT_MAX_REPOSITORY_DEPENDENCIES,
        max_dependencies_per_file: int = DEFAULT_MAX_DEPENDENCIES_PER_FILE,
        max_symbols_per_file: int = DEFAULT_MAX_SYMBOLS_PER_FILE,
        max_chunks_per_file: int = DEFAULT_MAX_CHUNKS_PER_FILE,
        max_scan_seconds: int = DEFAULT_MAX_SCAN_SECONDS,
        parser_registry: ParserRegistry | None = None,
        analysis_version: str | None = None,
    ) -> None:
        if max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be positive")
        if max_ignore_bytes <= 0:
            raise ValueError("max_ignore_bytes must be positive")
        if max_chunk_lines <= 0 or max_chunk_chars <= 0:
            raise ValueError("chunk limits must be positive")
        for name, value in (
            ("max_repository_files", max_repository_files),
            ("max_repository_bytes", max_repository_bytes),
            ("max_directory_depth", max_directory_depth),
            ("max_repository_chunks", max_repository_chunks),
            ("max_repository_symbols", max_repository_symbols),
            ("max_repository_dependencies", max_repository_dependencies),
            ("max_dependencies_per_file", max_dependencies_per_file),
            ("max_symbols_per_file", max_symbols_per_file),
            ("max_chunks_per_file", max_chunks_per_file),
            ("max_scan_seconds", max_scan_seconds),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if max_repository_dependencies > HARD_MAX_REPOSITORY_DEPENDENCIES:
            raise ValueError(
                "max_repository_dependencies exceeds the global safety ceiling of "
                f"{HARD_MAX_REPOSITORY_DEPENDENCIES}"
            )
        if analysis_version is not None and (not analysis_version or len(analysis_version) > 96):
            raise ValueError("analysis_version must be a short non-empty string")
        self.max_file_bytes = max_file_bytes
        self.max_ignore_bytes = max_ignore_bytes
        self.max_chunk_lines = max_chunk_lines
        self.max_chunk_chars = max_chunk_chars
        self.max_repository_files = max_repository_files
        self.max_repository_bytes = max_repository_bytes
        self.max_directory_depth = max_directory_depth
        self.max_repository_chunks = max_repository_chunks
        self.max_repository_symbols = max_repository_symbols
        self.max_repository_dependencies = max_repository_dependencies
        self.parse_limits = ParseLimits(
            max_chunk_lines=max_chunk_lines,
            max_chunk_chars=max_chunk_chars,
            max_dependencies_per_file=max_dependencies_per_file,
            max_symbols_per_file=max_symbols_per_file,
            max_chunks_per_file=max_chunks_per_file,
        )
        self.max_scan_seconds = max_scan_seconds
        self.parser_registry = (parser_registry or DEFAULT_REGISTRY).frozen_copy()
        self.fingerprints = build_analysis_fingerprints(
            parser_manifest=self.parser_registry.cache_manifest(),
            scan_limits={
                "max_directory_depth": max_directory_depth,
                "max_file_bytes": max_file_bytes,
                "max_ignore_bytes": max_ignore_bytes,
                "max_repository_bytes": max_repository_bytes,
                "max_repository_files": max_repository_files,
                "max_scan_seconds": max_scan_seconds,
            },
            chunk_limits={
                "max_chunk_chars": max_chunk_chars,
                "max_chunk_lines": max_chunk_lines,
                "max_repository_chunks": max_repository_chunks,
                "max_repository_symbols": max_repository_symbols,
                "max_repository_dependencies": max_repository_dependencies,
                "max_dependencies_per_file": max_dependencies_per_file,
                "max_symbols_per_file": max_symbols_per_file,
                "max_chunks_per_file": max_chunks_per_file,
            },
            legacy_cache_key=analysis_version or "",
        )
        self.analysis_version = (
            f"{analysis_version}:lines={max_chunk_lines}:chars={max_chunk_chars}"
            if analysis_version is not None
            else (
                f"components-v1:scan={self.fingerprints.scan[:16]}:"
                f"parser={self.fingerprints.parser[:16]}:"
                f"terms={self.fingerprints.term_index[:16]}"
            )
        )

    def scan(
        self,
        root: Path | str,
        *,
        cached_files: Mapping[str, ScannedFile] | None = None,
        trusted_cache: bool = False,
        base_generation: int | None = None,
        base_scan_revision: int | None = None,
        refresh_mode: str = "auto",
    ) -> ScanResult:
        """Return a stable scan of *root*.

        The root itself must be a real directory.  Links encountered beneath
        it are reported and never opened, even when their target is inside the
        repository.
        """

        if base_generation is not None and (
            isinstance(base_generation, bool) or base_generation < 0
        ):
            raise ValueError("base_generation must be a non-negative integer or None")
        if base_scan_revision is not None and (
            isinstance(base_scan_revision, bool) or base_scan_revision < 0
        ):
            raise ValueError("base_scan_revision must be a non-negative integer or None")
        if refresh_mode not in {"auto", "always", "rebuild"}:
            raise ValueError("scanner refresh_mode must be auto, always, or rebuild")
        if not isinstance(trusted_cache, bool):
            raise ValueError("trusted_cache must be true or false")
        self.parser_registry.require_stable()
        supplied_root = Path(root).expanduser().absolute()
        try:
            root_metadata = supplied_root.lstat()
        except OSError as exc:
            raise ValueError(f"repository root is not accessible: {supplied_root}") from exc
        if stat.S_ISLNK(root_metadata.st_mode) or _is_reparse_point(root_metadata):
            raise ValueError("repository root must not be a symbolic link or reparse point")
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise ValueError("repository root must be a directory")
        resolved_root = supplied_root.resolve(strict=True)
        try:
            root_identity = filesystem_identity(root_metadata)
        except ValueError as exc:
            raise ValueError("repository root has no stable filesystem identity") from exc

        files: list[ScannedFile] = []
        stats = ScanStats()
        warnings: list[str] = []
        temporarily_unreadable: set[str] = set()
        reusable = cached_files or {}
        budget = ScanBudget(
            max_entries=self.max_repository_files,
            max_bytes=self.max_repository_bytes,
            max_chunks=self.max_repository_chunks,
            max_symbols=self.max_repository_symbols,
            max_dependencies=self.max_repository_dependencies,
            deadline=deadline_after(self.max_scan_seconds),
        )
        root_fd: int | None = None
        if _USE_DIRECTORY_FDS:
            flags = os.O_RDONLY
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_DIRECTORY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                root_fd = os.open(supplied_root, flags)
                opened_root = os.fstat(root_fd)
            except OSError as exc:
                if root_fd is not None:
                    os.close(root_fd)
                raise ValueError(f"repository root is not accessible: {supplied_root}") from exc
            if (
                not stat.S_ISDIR(opened_root.st_mode)
                or _is_reparse_point(opened_root)
                or not _same_identity(root_metadata, opened_root)
            ):
                os.close(root_fd)
                raise ValueError("repository root changed while it was being opened")
        try:
            self._walk(
                resolved_root,
                resolved_root,
                root_fd,
                root_metadata,
                PurePosixPath(),
                IgnoreRules(),
                files,
                stats,
                warnings,
                temporarily_unreadable,
                reusable,
                trusted_cache,
                refresh_mode,
                budget,
            )
        finally:
            if root_fd is not None:
                os.close(root_fd)
        try:
            final_root_metadata = supplied_root.lstat()
        except OSError:
            final_root_metadata = None
        if (
            final_root_metadata is None
            or not stat.S_ISDIR(final_root_metadata.st_mode)
            or _is_reparse_point(final_root_metadata)
            or not _same_identity(root_metadata, final_root_metadata)
        ):
            files.clear()
            stats = ScanStats(skipped={"changed_during_scan": 1})
            warnings = ["repository root changed during scan"]
            temporarily_unreadable = {"."}
        files.sort(key=lambda item: item.path)
        warnings.sort()
        self.parser_registry.require_stable()
        return ScanResult(
            root=resolved_root,
            files=files,
            stats=stats,
            warnings=warnings,
            analysis_version=self.analysis_version,
            temporarily_unreadable=tuple(sorted(temporarily_unreadable)),
            base_generation=base_generation,
            repository_identity=root_identity,
            base_scan_revision=base_scan_revision,
            fingerprints=self.fingerprints,
            refresh_mode=refresh_mode,  # type: ignore[arg-type]
        )

    def _load_local_ignore(
        self,
        root: Path,
        directory: Path,
        directory_fd: int | None,
        relative_directory: PurePosixPath,
        rules: IgnoreRules,
        warnings: list[str],
        temporarily_unreadable: set[str],
    ) -> IgnoreRules | None:
        ignore_path = directory / ".gitignore"
        directory_location = relative_directory.as_posix() or "."
        try:
            if directory_fd is None:
                metadata = ignore_path.lstat()
            else:
                metadata = os.stat(".gitignore", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return rules
        except OSError:
            location = (relative_directory / ".gitignore").as_posix()
            warnings.append(f"could not inspect ignore file: {location}")
            temporarily_unreadable.add(directory_location)
            return None
        if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(metadata):
            location = (relative_directory / ".gitignore").as_posix()
            warnings.append(f"unsafe ignore file prevents scanning: {location}")
            temporarily_unreadable.add(directory_location)
            return None
        payload, _post_metadata, reason = _safe_read_at(
            ".gitignore",
            self.max_ignore_bytes,
            metadata,
            directory=directory,
            directory_fd=directory_fd,
            root=root,
        )
        if payload is None:
            location = (relative_directory / ".gitignore").as_posix()
            warnings.append(f"could not load ignore file ({reason}): {location}")
            temporarily_unreadable.add(directory_location)
            return None
        contents = payload.decode("utf-8-sig", errors="replace")
        try:
            return rules.extend(relative_directory, contents)
        except (TypeError, ValueError) as exc:
            location = (relative_directory / ".gitignore").as_posix()
            warnings.append(f"invalid ignore file ({type(exc).__name__}): {location}")
            temporarily_unreadable.add(directory_location)
            return None

    def _walk(
        self,
        root: Path,
        directory: Path,
        directory_fd: int | None,
        expected_directory: os.stat_result,
        relative_directory: PurePosixPath,
        inherited_rules: IgnoreRules,
        files: list[ScannedFile],
        stats: ScanStats,
        warnings: list[str],
        temporarily_unreadable: set[str],
        cached_files: Mapping[str, ScannedFile],
        trusted_cache: bool,
        refresh_mode: str,
        budget: ScanBudget,
    ) -> None:
        file_checkpoint = len(files)
        warning_checkpoint = len(warnings)
        unreadable_checkpoint = set(temporarily_unreadable)
        budget_checkpoint = budget.checkpoint()
        stats_checkpoint = (
            stats.discovered_files,
            stats.indexed_files,
            stats.indexed_bytes,
            dict(stats.languages),
            dict(stats.skipped),
            stats.content_reads,
            stats.parsed_files,
        )
        directory_location = relative_directory.as_posix() or "."

        def stop_for_global_budget() -> None:
            temporarily_unreadable.add(".")
            if not budget.reported:
                budget.reported = True
                stats.skip("repository_budget")
                warnings.append(
                    f"repository scan stopped at {budget.exhausted_reason or 'a hard limit'}"
                )

        def discard_changed_directory() -> None:
            del files[file_checkpoint:]
            del warnings[warning_checkpoint:]
            temporarily_unreadable.clear()
            temporarily_unreadable.update(unreadable_checkpoint)
            (
                stats.discovered_files,
                stats.indexed_files,
                stats.indexed_bytes,
                languages,
                skipped,
                stats.content_reads,
                stats.parsed_files,
            ) = stats_checkpoint
            stats.languages.clear()
            stats.languages.update(languages)
            stats.skipped.clear()
            stats.skipped.update(skipped)
            budget.restore(budget_checkpoint)
            stats.skip("changed_during_scan")
            warnings.append(f"directory changed during scan: {directory_location}")
            temporarily_unreadable.add(directory_location)
            if budget.exhausted_reason is not None:
                # A rollback removes the first budget diagnostic as well. Let
                # the global marker be emitted again so callers retain both
                # independent reasons that this scan is incomplete.
                budget.reported = False
                stop_for_global_budget()

        def directory_is_stable() -> bool:
            # A descriptor pins the opened directory object, but it does not
            # prove that the repository-relative path still names that object.
            # Revalidate the path binding as well so a rename followed by a
            # replacement cannot make facts from the detached directory fresh.
            if not _is_stable_unpinned_directory(directory, root, expected_directory):
                return False
            if directory_fd is None:
                return True
            try:
                opened_directory = os.fstat(directory_fd)
            except OSError:
                return False
            return (
                stat.S_ISDIR(opened_directory.st_mode)
                and not _is_reparse_point(opened_directory)
                and _same_identity(expected_directory, opened_directory)
            )

        # A path-based traversal must validate the identity and root boundary
        # before opening a local ignore file or enumerating any children.
        if len(relative_directory.parts) > self.max_directory_depth:
            stats.skip("max_directory_depth")
            warnings.append(f"maximum directory depth reached: {directory_location}")
            temporarily_unreadable.add(directory_location)
            return
        if not budget.check_deadline():
            stop_for_global_budget()
            return
        if not directory_is_stable():
            discard_changed_directory()
            return
        rules = self._load_local_ignore(
            root,
            directory,
            directory_fd,
            relative_directory,
            inherited_rules,
            warnings,
            temporarily_unreadable,
        )
        if not directory_is_stable():
            discard_changed_directory()
            return
        if rules is None:
            stats.skip("unreadable_ignore")
            return
        try:
            scan_target: int | Path = directory_fd if directory_fd is not None else directory
            with os.scandir(scan_target) as iterator:
                entries = []
                for entry in iterator:
                    if not budget.observe_entry():
                        stop_for_global_budget()
                        return
                    entries.append(entry)
                entries.sort(key=lambda entry: entry.name)
        except OSError:
            if not directory_is_stable():
                discard_changed_directory()
                return
            stats.skip("unreadable")
            warnings.append(f"could not list directory: {directory_location}")
            temporarily_unreadable.add(directory_location)
            return
        if not directory_is_stable():
            discard_changed_directory()
            return
        if not budget.check_deadline():
            stop_for_global_budget()
            return

        for entry in entries:
            if not budget.check_deadline():
                stop_for_global_budget()
                return
            if not directory_is_stable():
                discard_changed_directory()
                return
            relative_path = relative_directory / entry.name
            display_path = relative_path.as_posix()
            absolute_path = directory / entry.name
            try:
                if directory_fd is None:
                    # Windows DirEntry.stat() may reuse find data without a stable file ID.
                    metadata = absolute_path.lstat()
                else:
                    metadata = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                if not directory_is_stable():
                    discard_changed_directory()
                    return
                stats.discovered_files += 1
                stats.skip("unreadable")
                warnings.append(f"could not inspect path: {display_path}")
                temporarily_unreadable.add(display_path)
                continue

            if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
                stats.discovered_files += 1
                reason = self._symlink_reason(absolute_path, root)
                stats.skip(reason)
                if reason == "outside_root":
                    warnings.append(f"outside-root symlink skipped: {display_path}")
                else:
                    warnings.append(f"symlink skipped: {display_path}")
                # The entry may have replaced a previously indexed file or
                # directory. Never interpret that old subtree as a confirmed
                # deletion when the current object cannot be traversed.
                temporarily_unreadable.add(display_path)
                continue

            if stat.S_ISDIR(metadata.st_mode):
                if is_default_ignored(relative_path, is_dir=True):
                    stats.skip("default_ignored")
                    continue
                if rules.is_ignored(relative_path, is_dir=True):
                    stats.skip("gitignored")
                    continue
                child_fd: int | None = None
                if directory_fd is not None:
                    child_fd, reason = _open_directory_at(entry.name, metadata, directory_fd)
                    if child_fd is None:
                        stats.skip(reason or "unreadable")
                        warnings.append(f"could not safely open directory: {display_path}")
                        temporarily_unreadable.add(display_path)
                        continue
                try:
                    self._walk(
                        root,
                        absolute_path,
                        child_fd,
                        metadata,
                        relative_path,
                        rules,
                        files,
                        stats,
                        warnings,
                        temporarily_unreadable,
                        cached_files,
                        trusted_cache,
                        refresh_mode,
                        budget,
                    )
                finally:
                    if child_fd is not None:
                        os.close(child_fd)
                if not directory_is_stable():
                    discard_changed_directory()
                    return
                if budget.exhausted_reason is not None:
                    stop_for_global_budget()
                    return
                continue

            stats.discovered_files += 1
            if not stat.S_ISREG(metadata.st_mode):
                stats.skip("special_file")
                warnings.append(f"special file skipped: {display_path}")
                continue
            if is_default_ignored(relative_path):
                stats.skip("default_ignored")
                continue
            if rules.is_ignored(relative_path):
                stats.skip("gitignored")
                continue
            if is_sensitive_path(relative_path):
                stats.skip("sensitive_filename")
                warnings.append(f"sensitive filename skipped: {display_path}")
                continue
            language = detect_language(relative_path)
            if language is None:
                stats.skip("unsupported")
                continue
            if metadata.st_size > self.max_file_bytes:
                stats.skip("oversize")
                warnings.append(f"oversize file skipped: {display_path}")
                continue
            if directory_fd is None:
                try:
                    resolved_file = absolute_path.resolve(strict=True)
                except OSError:
                    stats.skip("unreadable")
                    warnings.append(f"could not resolve file: {display_path}")
                    temporarily_unreadable.add(display_path)
                    continue
                if not directory_is_stable():
                    discard_changed_directory()
                    return
                if not _is_within(resolved_file, root):
                    stats.skip("changed_during_scan")
                    warnings.append(f"file changed during scan: {display_path}")
                    temporarily_unreadable.add(display_path)
                    continue

            cached = cached_files.get(display_path)
            if not budget.observe_bytes(metadata.st_size):
                stop_for_global_budget()
                return
            # Service-provided cache entries are bound to the same repository
            # identity and analysis version. Exact metadata matches can therefore
            # reuse parser facts without reading and hashing unchanged contents.
            if (
                trusted_cache
                and cached is not None
                and cached.provenance == "source"
                and not cached.stale
                and cached.language == language
                and cached.size_bytes == metadata.st_size
                and cached.mtime_ns == metadata.st_mtime_ns
                and cached.ctime_ns == metadata.st_ctime_ns
                and _metadata_still_matches_at(
                    entry.name,
                    metadata,
                    directory=directory,
                    directory_fd=directory_fd,
                )
            ):
                cached_counts = FactCounts(
                    chunks=len(cached.chunks) or cached.cached_chunk_count,
                    symbols=len(cached.symbols) or cached.cached_symbol_count,
                    dependencies=(len(cached.dependencies) or cached.cached_dependency_count),
                )
                if not budget.require_capacity(cached_counts):
                    stop_for_global_budget()
                    return
                budget.commit_facts(cached_counts)
                if not directory_is_stable():
                    discard_changed_directory()
                    return
                files.append(replace(cached, provenance="source", stale=False))
                stats.indexed_files += 1
                stats.indexed_bytes += cached.size_bytes
                stats.languages[language] = stats.languages.get(language, 0) + 1
                continue
            payload, post_read_metadata, read_error = _safe_read_at(
                entry.name,
                self.max_file_bytes,
                metadata,
                directory=directory,
                directory_fd=directory_fd,
                root=root,
            )
            if not directory_is_stable():
                discard_changed_directory()
                return
            if not budget.check_deadline():
                stop_for_global_budget()
                return
            if payload is None:
                stats.skip(read_error or "unreadable")
                if read_error == "changed_during_scan":
                    warnings.append(f"file changed during scan: {display_path}")
                else:
                    warnings.append(f"file skipped ({read_error or 'unreadable'}): {display_path}")
                if read_error in {"unreadable", "changed_during_scan"}:
                    temporarily_unreadable.add(display_path)
                continue
            stats.content_reads += 1
            if post_read_metadata is None:  # pragma: no cover - helper invariant
                raise RuntimeError("safe read returned no metadata")
            digest = hashlib.sha256(payload).hexdigest()
            if is_binary(payload):
                stats.skip("binary")
                warnings.append(f"binary file skipped: {display_path}")
                continue
            try:
                text = payload.decode("utf-8-sig", errors="strict")
            except UnicodeDecodeError:
                stats.skip("binary")
                warnings.append(f"non-UTF-8 file skipped: {display_path}")
                continue
            # Binary descriptor reads preserve on-disk bytes for size, hashing,
            # and binary detection. Detector- and parser-facing decoded text uses
            # one cross-platform newline convention; a bare CR remains untouched
            # and is still rejected by parser postcondition checks.
            text = text.replace("\r\n", "\n")
            if is_generated_document(text, language):
                stats.skip("generated")
                continue
            # Re-run the current detector even for parser-fact cache hits. A
            # detector update must be able to evict content accepted by an
            # older release without requiring the source bytes to change.
            if contains_likely_secret(text):
                stats.skip("likely_secret")
                warnings.append(f"file with likely secret skipped: {display_path}")
                continue
            if (
                refresh_mode != "rebuild"
                and cached is not None
                and cached.provenance == "source"
                and not cached.stale
                and cached.language == language
                and cached.size_bytes == len(payload)
                and cached.sha256.casefold() == digest
            ):
                cached_counts = FactCounts(
                    chunks=len(cached.chunks) or cached.cached_chunk_count,
                    symbols=len(cached.symbols) or cached.cached_symbol_count,
                    dependencies=(len(cached.dependencies) or cached.cached_dependency_count),
                )
                if not budget.require_capacity(cached_counts):
                    stop_for_global_budget()
                    return
                budget.commit_facts(cached_counts)
                files.append(
                    replace(
                        cached,
                        mtime_ns=post_read_metadata.st_mtime_ns,
                        ctime_ns=post_read_metadata.st_ctime_ns,
                        provenance="source",
                        stale=False,
                    )
                )
                stats.indexed_files += 1
                stats.indexed_bytes += cached.size_bytes
                stats.languages[language] = stats.languages.get(language, 0) + 1
                continue

            try:
                parsed = self.parser_registry.parse(
                    display_path,
                    text,
                    language,
                    max_chunk_lines=self.max_chunk_lines,
                    max_chunk_chars=self.max_chunk_chars,
                )
                stats.parsed_files += 1
                parsed, parsed_counts = finalize_parse_result(
                    parsed,
                    path=display_path,
                    text=text,
                    language=language,
                    limits=self.parse_limits,
                )
            except Exception as exc:  # Parser plugins are an isolation boundary.
                stats.skip("parse_error")
                warnings.append(f"parse failed ({type(exc).__name__}) for file: {display_path}")
                temporarily_unreadable.add(display_path)
                continue

            if not budget.check_deadline():
                stop_for_global_budget()
                return
            if not budget.require_capacity(parsed_counts):
                stop_for_global_budget()
                return
            budget.commit_facts(parsed_counts)

            scanned = ScannedFile(
                path=display_path,
                language=language,
                size_bytes=len(payload),
                sha256=digest,
                line_count=len(text.splitlines()),
                text=text,
                symbols=parsed.symbols,
                dependencies=parsed.dependencies,
                chunks=parsed.chunks,
                is_entry_point=parsed.is_entry_point,
                mtime_ns=post_read_metadata.st_mtime_ns,
                ctime_ns=post_read_metadata.st_ctime_ns,
                provenance="source",
                stale=False,
            )
            files.append(scanned)
            stats.indexed_files += 1
            stats.indexed_bytes += len(payload)
            stats.languages[language] = stats.languages.get(language, 0) + 1

        if not directory_is_stable():
            discard_changed_directory()
            return
        if not budget.check_deadline():
            stop_for_global_budget()

    @staticmethod
    def _symlink_reason(path: Path, root: Path) -> str:
        try:
            target = path.resolve(strict=False)
        except (OSError, RuntimeError):
            return "symlink"
        return "symlink" if _is_within(target, root) else "outside_root"
