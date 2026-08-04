"""Secure, deterministic repository traversal."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path, PurePosixPath

from repolocus.models import ANALYSIS_VERSION, ScannedFile, ScanResult, ScanStats
from repolocus.parsers import DEFAULT_REGISTRY, ParseResult, ParserRegistry
from repolocus.scanner.filters import (
    contains_likely_secret,
    detect_language,
    is_binary,
    is_default_ignored,
    is_generated_document,
    is_sensitive_path,
)
from repolocus.scanner.ignore import IgnoreRules

DEFAULT_MAX_FILE_BYTES = 1_000_000
DEFAULT_MAX_IGNORE_BYTES = 256_000

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
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
) -> tuple[bytes | None, os.stat_result | None, str | None]:
    """Open and read one enumerated file without resolving a path component twice."""

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
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
        return payload, finished, None
    finally:
        os.close(descriptor)


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


def _validate_parse_result(
    parsed: ParseResult,
    *,
    path: str,
    text: str,
    language: str,
    max_chunk_lines: int,
    max_chunk_chars: int,
) -> None:
    """Reject plugin facts that cannot be traced to the supplied source."""

    source_lines = text.splitlines(keepends=True)
    line_count = len(source_lines)

    def valid_range(start: int, end: int) -> bool:
        return 1 <= start <= end <= line_count

    for symbol in parsed.symbols:
        if symbol.path != path or not valid_range(symbol.start_line, symbol.end_line):
            raise ValueError("parser emitted an invalid symbol source range")
    for dependency in parsed.dependencies:
        if dependency.source_path != path or not 1 <= dependency.line <= line_count:
            raise ValueError("parser emitted an invalid dependency source line")
    for chunk in parsed.chunks:
        if chunk.path != path or chunk.language != language:
            raise ValueError("parser emitted a chunk for a different source")
        if not valid_range(chunk.start_line, chunk.end_line):
            raise ValueError("parser emitted an invalid chunk source range")
        if chunk.end_line - chunk.start_line + 1 > max_chunk_lines:
            raise ValueError("parser emitted a chunk beyond the line budget")
        if len(chunk.content) > max_chunk_chars:
            raise ValueError("parser emitted a chunk beyond the character budget")
        source_region = "".join(source_lines[chunk.start_line - 1 : chunk.end_line])
        if chunk.content not in source_region:
            raise ValueError("parser emitted chunk content not present in its source range")


class RepositoryScanner:
    """Scan supported repository text without following links or running code."""

    def __init__(
        self,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        *,
        max_chunk_lines: int = 160,
        max_chunk_chars: int = 16_000,
        max_ignore_bytes: int = DEFAULT_MAX_IGNORE_BYTES,
        parser_registry: ParserRegistry | None = None,
        analysis_version: str = ANALYSIS_VERSION,
    ) -> None:
        if max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be positive")
        if max_ignore_bytes <= 0:
            raise ValueError("max_ignore_bytes must be positive")
        if max_chunk_lines <= 0 or max_chunk_chars <= 0:
            raise ValueError("chunk limits must be positive")
        if not analysis_version or len(analysis_version) > 96:
            raise ValueError("analysis_version must be a short non-empty string")
        self.max_file_bytes = max_file_bytes
        self.max_ignore_bytes = max_ignore_bytes
        self.max_chunk_lines = max_chunk_lines
        self.max_chunk_chars = max_chunk_chars
        self.parser_registry = parser_registry or DEFAULT_REGISTRY
        self.analysis_version = (
            f"{analysis_version}:lines={max_chunk_lines}:chars={max_chunk_chars}"
        )

    def scan(
        self,
        root: Path | str,
        *,
        cached_files: Mapping[str, ScannedFile] | None = None,
        base_generation: int | None = None,
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

        files: list[ScannedFile] = []
        stats = ScanStats()
        warnings: list[str] = []
        temporarily_unreadable: set[str] = set()
        reusable = cached_files or {}
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
                PurePosixPath(),
                IgnoreRules(),
                files,
                stats,
                warnings,
                temporarily_unreadable,
                reusable,
            )
        finally:
            if root_fd is not None:
                os.close(root_fd)
        files.sort(key=lambda item: item.path)
        warnings.sort()
        return ScanResult(
            root=resolved_root,
            files=files,
            stats=stats,
            warnings=warnings,
            analysis_version=self.analysis_version,
            temporarily_unreadable=tuple(sorted(temporarily_unreadable)),
            base_generation=base_generation,
        )

    def _load_local_ignore(
        self,
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
        relative_directory: PurePosixPath,
        inherited_rules: IgnoreRules,
        files: list[ScannedFile],
        stats: ScanStats,
        warnings: list[str],
        temporarily_unreadable: set[str],
        cached_files: Mapping[str, ScannedFile],
    ) -> None:
        rules = self._load_local_ignore(
            directory,
            directory_fd,
            relative_directory,
            inherited_rules,
            warnings,
            temporarily_unreadable,
        )
        if rules is None:
            stats.skip("unreadable_ignore")
            return
        try:
            scan_target: int | Path = directory_fd if directory_fd is not None else directory
            with os.scandir(scan_target) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError:
            location = relative_directory.as_posix() or "."
            stats.skip("unreadable")
            warnings.append(f"could not list directory: {location}")
            temporarily_unreadable.add(location)
            return

        for entry in entries:
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
                else:
                    try:
                        resolved_directory = absolute_path.resolve(strict=True)
                    except OSError:
                        stats.skip("unreadable")
                        warnings.append(f"could not resolve directory: {display_path}")
                        temporarily_unreadable.add(display_path)
                        continue
                    if not _is_within(resolved_directory, root):
                        stats.skip("outside_root")
                        warnings.append(f"outside-root directory skipped: {display_path}")
                        continue
                try:
                    self._walk(
                        root,
                        absolute_path,
                        child_fd,
                        relative_path,
                        rules,
                        files,
                        stats,
                        warnings,
                        temporarily_unreadable,
                        cached_files,
                    )
                finally:
                    if child_fd is not None:
                        os.close(child_fd)
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
                if not _is_within(resolved_file, root):
                    stats.skip("outside_root")
                    warnings.append(f"outside-root file skipped: {display_path}")
                    continue

            cached = cached_files.get(display_path)
            payload, post_read_metadata, read_error = _safe_read_at(
                entry.name,
                self.max_file_bytes,
                metadata,
                directory=directory,
                directory_fd=directory_fd,
            )
            if payload is None:
                stats.skip(read_error or "unreadable")
                if read_error == "changed_during_scan":
                    warnings.append(f"file changed during scan: {display_path}")
                else:
                    warnings.append(f"file skipped ({read_error or 'unreadable'}): {display_path}")
                if read_error in {"unreadable", "changed_during_scan"}:
                    temporarily_unreadable.add(display_path)
                continue
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
                cached is not None
                and cached.language == language
                and cached.size_bytes == len(payload)
                and cached.sha256.casefold() == digest
            ):
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
                _validate_parse_result(
                    parsed,
                    path=display_path,
                    text=text,
                    language=language,
                    max_chunk_lines=self.max_chunk_lines,
                    max_chunk_chars=self.max_chunk_chars,
                )
            except Exception as exc:  # Parser plugins are an isolation boundary.
                stats.skip("parse_error")
                warnings.append(f"parse failed ({type(exc).__name__}) for file: {display_path}")
                temporarily_unreadable.add(display_path)
                continue

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

    @staticmethod
    def _symlink_reason(path: Path, root: Path) -> str:
        try:
            target = path.resolve(strict=False)
        except (OSError, RuntimeError):
            return "symlink"
        return "symlink" if _is_within(target, root) else "outside_root"
