"""Secure, deterministic repository traversal."""

from __future__ import annotations

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
    is_sensitive_path,
)
from repolocus.scanner.ignore import IgnoreRules

DEFAULT_MAX_FILE_BYTES = 1_000_000
DEFAULT_MAX_IGNORE_BYTES = 256_000


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _safe_read(path: Path, limit: int) -> tuple[bytes | None, str | None]:
    """Read a regular file once without following its final path component."""

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, "unreadable"
    try:
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                return None, "special_file"
            if metadata.st_size > limit:
                return None, "oversize"
            blocks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                block = os.read(descriptor, min(65_536, remaining))
                if not block:
                    break
                blocks.append(block)
                remaining -= len(block)
            payload = b"".join(blocks)
            if len(payload) > limit:
                return None, "oversize"
            return payload, None
        except OSError:
            return None, "unreadable"
    finally:
        os.close(descriptor)


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
    ) -> ScanResult:
        """Return a stable scan of *root*.

        The root itself must be a real directory.  Links encountered beneath
        it are reported and never opened, even when their target is inside the
        repository.
        """

        supplied_root = Path(root)
        try:
            root_metadata = supplied_root.lstat()
        except OSError as exc:
            raise ValueError(f"repository root is not accessible: {supplied_root}") from exc
        if stat.S_ISLNK(root_metadata.st_mode):
            raise ValueError("repository root must not be a symbolic link")
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise ValueError("repository root must be a directory")
        resolved_root = supplied_root.resolve(strict=True)

        files: list[ScannedFile] = []
        stats = ScanStats()
        warnings: list[str] = []
        reusable = cached_files or {}
        self._walk(
            resolved_root,
            resolved_root,
            PurePosixPath(),
            IgnoreRules(),
            files,
            stats,
            warnings,
            reusable,
        )
        files.sort(key=lambda item: item.path)
        warnings.sort()
        return ScanResult(
            root=resolved_root,
            files=files,
            stats=stats,
            warnings=warnings,
            analysis_version=self.analysis_version,
        )

    def _load_local_ignore(
        self,
        directory: Path,
        relative_directory: PurePosixPath,
        rules: IgnoreRules,
        warnings: list[str],
    ) -> IgnoreRules:
        ignore_path = directory / ".gitignore"
        try:
            metadata = ignore_path.lstat()
        except FileNotFoundError:
            return rules
        except OSError:
            location = (relative_directory / ".gitignore").as_posix()
            warnings.append(f"could not inspect ignore file: {location}")
            return rules
        if not stat.S_ISREG(metadata.st_mode):
            return rules
        payload, reason = _safe_read(ignore_path, self.max_ignore_bytes)
        if payload is None:
            location = (relative_directory / ".gitignore").as_posix()
            warnings.append(f"could not load ignore file ({reason}): {location}")
            return rules
        contents = payload.decode("utf-8-sig", errors="replace")
        try:
            return rules.extend(relative_directory, contents)
        except (TypeError, ValueError) as exc:
            location = (relative_directory / ".gitignore").as_posix()
            warnings.append(f"invalid ignore file ({type(exc).__name__}): {location}")
            return rules

    def _walk(
        self,
        root: Path,
        directory: Path,
        relative_directory: PurePosixPath,
        inherited_rules: IgnoreRules,
        files: list[ScannedFile],
        stats: ScanStats,
        warnings: list[str],
        cached_files: Mapping[str, ScannedFile],
    ) -> None:
        rules = self._load_local_ignore(directory, relative_directory, inherited_rules, warnings)
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError:
            location = relative_directory.as_posix() or "."
            stats.skip("unreadable")
            warnings.append(f"could not list directory: {location}")
            return

        for entry in entries:
            relative_path = relative_directory / entry.name
            display_path = relative_path.as_posix()
            absolute_path = directory / entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError:
                stats.discovered_files += 1
                stats.skip("unreadable")
                warnings.append(f"could not inspect path: {display_path}")
                continue

            if stat.S_ISLNK(metadata.st_mode):
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
                try:
                    resolved_directory = absolute_path.resolve(strict=True)
                except OSError:
                    stats.skip("unreadable")
                    warnings.append(f"could not resolve directory: {display_path}")
                    continue
                if not _is_within(resolved_directory, root):
                    stats.skip("outside_root")
                    warnings.append(f"outside-root directory skipped: {display_path}")
                    continue
                self._walk(
                    root,
                    absolute_path,
                    relative_path,
                    rules,
                    files,
                    stats,
                    warnings,
                    cached_files,
                )
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
            try:
                resolved_file = absolute_path.resolve(strict=True)
            except OSError:
                stats.skip("unreadable")
                warnings.append(f"could not resolve file: {display_path}")
                continue
            if not _is_within(resolved_file, root):
                stats.skip("outside_root")
                warnings.append(f"outside-root file skipped: {display_path}")
                continue

            cached = cached_files.get(display_path)
            payload, read_error = _safe_read(absolute_path, self.max_file_bytes)
            if payload is None:
                stats.skip(read_error or "unreadable")
                warnings.append(f"file skipped ({read_error or 'unreadable'}): {display_path}")
                continue
            try:
                post_read_metadata = absolute_path.stat(follow_symlinks=False)
            except OSError:
                stats.skip("changed_during_scan")
                warnings.append(f"file changed during scan: {display_path}")
                continue
            if (
                not stat.S_ISREG(post_read_metadata.st_mode)
                or metadata.st_size != post_read_metadata.st_size
                or metadata.st_mtime_ns != post_read_metadata.st_mtime_ns
                or metadata.st_ctime_ns != post_read_metadata.st_ctime_ns
            ):
                stats.skip("changed_during_scan")
                warnings.append(f"file changed during scan: {display_path}")
                continue
            digest = hashlib.sha256(payload).hexdigest()
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
                    )
                )
                stats.indexed_files += 1
                stats.indexed_bytes += cached.size_bytes
                stats.languages[language] = stats.languages.get(language, 0) + 1
                continue
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
            if contains_likely_secret(text):
                stats.skip("likely_secret")
                warnings.append(f"file with likely secret skipped: {display_path}")
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
