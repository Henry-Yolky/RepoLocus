"""Descriptor-bound atomic writes for generated repository documents."""

from __future__ import annotations

import os
import secrets
import stat
import sys
from contextlib import suppress
from pathlib import Path, PurePosixPath

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_MARKER_READ_LIMIT = 4096


class AtomicWriteError(ValueError):
    """Raised when a repository output cannot be written without escaping its root."""


def _checkpoint(stage: str, root: Path, relative_path: PurePosixPath) -> None:
    """Race-test seam; production calls intentionally do nothing."""

    del stage, root, relative_path


def _is_reparse_point(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT)


def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _same_file_state(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        _same_identity(first, second)
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
        and stat.S_IFMT(first.st_mode) == stat.S_IFMT(second.st_mode)
    )


def _same_published_file(first: os.stat_result, second: os.stat_result) -> bool:
    """Compare an inode across link/rename operations that may update ctime."""

    return (
        _same_identity(first, second)
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and stat.S_IFMT(first.st_mode) == stat.S_IFMT(second.st_mode)
    )


def _validated_relative_path(relative_path: PurePosixPath) -> PurePosixPath:
    if not isinstance(relative_path, PurePosixPath):
        raise TypeError("relative_path must be a PurePosixPath")
    rendered = str(relative_path)
    if (
        not rendered
        or rendered == "."
        or "\\" in rendered
        or "\x00" in rendered
        or relative_path.is_absolute()
        or any(part in {"", ".", ".."} for part in relative_path.parts)
    ):
        raise AtomicWriteError("output path must be normalized repository-relative POSIX text")
    return relative_path


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError("short write while creating generated output")
        offset += written


def _generated_marker(payload: bytes) -> bool:
    from repolocus.scanner.filters import is_generated_document

    return is_generated_document(payload.decode("utf-8", errors="replace"))


def _target_state_at(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AtomicWriteError(f"cannot inspect generated output target: {name}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
    ):
        raise AtomicWriteError(f"refusing to replace non-regular output: {name}")
    return metadata


def _raw_state_at(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _rename_exchange_at(parent_fd: int, first: str, second: str) -> None:
    """Atomically exchange two names without discarding either object."""

    import ctypes

    library = ctypes.CDLL(None, use_errno=True)
    first_bytes = os.fsencode(first)
    second_bytes = os.fsencode(second)
    if sys.platform.startswith("linux"):
        rename = getattr(library, "renameat2", None)
        flag = 0x2  # RENAME_EXCHANGE
    elif sys.platform == "darwin":
        rename = getattr(library, "renameatx_np", None)
        flag = 0x00000002  # RENAME_SWAP
    else:
        rename = None
        flag = 0
    if rename is None:
        raise AtomicWriteError(
            "atomic generated-output replacement is unavailable on this platform"
        )
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    if rename(parent_fd, first_bytes, parent_fd, second_bytes, flag) != 0:
        error = ctypes.get_errno()
        raise AtomicWriteError(
            "the filesystem does not support atomic generated-output replacement"
        ) from OSError(error, os.strerror(error))


def _cleanup_owned_temporary_at(
    parent_fd: int,
    temporary_name: str,
    temporary_fd: int,
    *,
    required: bool,
) -> bool:
    """Unlink *temporary_name* only while it still names our open inode."""

    try:
        expected = os.fstat(temporary_fd)
        current = _raw_state_at(parent_fd, temporary_name)
    except OSError as exc:
        if required:
            raise AtomicWriteError(
                f"generated output cleanup could not be verified; preserved: {temporary_name}"
            ) from exc
        return False
    if current is None:
        return True
    if not _same_identity(expected, current):
        if required:
            raise AtomicWriteError(
                f"generated output cleanup raced; preserved unverified object: {temporary_name}"
            )
        return False
    try:
        os.unlink(temporary_name, dir_fd=parent_fd)
    except OSError as exc:
        if required:
            raise AtomicWriteError(
                f"generated output cleanup failed; preserved: {temporary_name}"
            ) from exc
        return False
    return True


def _cleanup_displaced_at(
    parent_fd: int,
    temporary_name: str,
    expected: os.stat_result,
) -> None:
    """Remove a verified displaced target, preserving any later competitor."""

    current = _raw_state_at(parent_fd, temporary_name)
    if current is None:
        return
    if not _same_published_file(expected, current):
        raise AtomicWriteError(
            f"generated output cleanup raced; preserved unverified object: {temporary_name}"
        )
    try:
        os.unlink(temporary_name, dir_fd=parent_fd)
    except OSError as exc:
        raise AtomicWriteError(
            f"generated output cleanup failed; preserved: {temporary_name}"
        ) from exc


def _commit_new_at(
    parent_fd: int,
    temporary_name: str,
    name: str,
    expected_temporary: os.stat_result,
) -> None:
    """Publish a new output with create-if-absent semantics."""

    try:
        os.link(
            temporary_name,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise AtomicWriteError("generated output appeared before it could be created") from exc
    installed = _raw_state_at(parent_fd, name)
    if (
        installed is not None
        and stat.S_ISREG(installed.st_mode)
        and _same_published_file(expected_temporary, installed)
    ):
        return
    raise AtomicWriteError(
        f"generated output temporary changed during publication; preserved target: {name}"
    )


def _commit_exchange_at(
    parent_fd: int,
    temporary_name: str,
    name: str,
    expected_temporary: os.stat_result,
    expected_target: os.stat_result,
) -> None:
    """Publish over one exact target, preserving it until CAS validation succeeds."""

    _rename_exchange_at(parent_fd, temporary_name, name)
    try:
        installed = _raw_state_at(parent_fd, name)
        displaced = _raw_state_at(parent_fd, temporary_name)
    except OSError as exc:
        raise AtomicWriteError(
            "generated-output replacement could not be verified; preserved target and "
            f"backup names: {name}, {temporary_name}"
        ) from exc
    installed_matches = (
        installed is not None
        and stat.S_ISREG(installed.st_mode)
        and _same_published_file(expected_temporary, installed)
    )
    displaced_matches = (
        displaced is not None
        and stat.S_ISREG(displaced.st_mode)
        and _same_published_file(expected_target, displaced)
    )
    if installed_matches and displaced_matches:
        return
    raise AtomicWriteError(
        "generated output or target changed during atomic replacement; "
        f"preserved recoverable names: {name}, {temporary_name}"
    )


def _validate_generated_at(parent_fd: int, name: str, expected: os.stat_result) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise AtomicWriteError(f"generated output changed while it was inspected: {name}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file_state(expected, opened):
            raise AtomicWriteError(f"generated output changed while it was inspected: {name}")
        payload = os.read(descriptor, _MARKER_READ_LIMIT)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = _target_state_at(parent_fd, name)
    if (
        current is None
        or not _same_file_state(opened, finished)
        or not _same_file_state(finished, current)
    ):
        raise AtomicWriteError(f"generated output changed while it was inspected: {name}")
    if not _generated_marker(payload):
        raise AtomicWriteError(
            f"output already exists and is not recognized as generated: {name}; "
            "pass --force to replace it"
        )


def _open_directory_at(parent_fd: int, name: str, *, create: bool) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise
        with suppress(FileExistsError):
            os.mkdir(name, 0o755, dir_fd=parent_fd)
        return os.open(name, flags, dir_fd=parent_fd)


def _attest_posix_chain(
    root: Path,
    parent_parts: tuple[str, ...],
    expected_root: os.stat_result,
    expected_parent: os.stat_result,
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    try:
        descriptor = os.open(root, flags)
        descriptors.append(descriptor)
        opened_root = os.fstat(descriptor)
        if not _same_identity(expected_root, opened_root):
            raise AtomicWriteError("repository root changed during generated output write")
        for part in parent_parts:
            descriptor = os.open(part, flags, dir_fd=descriptor)
            descriptors.append(descriptor)
        if not _same_identity(expected_parent, os.fstat(descriptor)):
            raise AtomicWriteError("output parent changed during generated output write")
    except AtomicWriteError:
        raise
    except OSError as exc:
        raise AtomicWriteError(
            "output directory tree changed during generated output write"
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            with suppress(OSError):
                os.close(descriptor)


def _atomic_write_posix(
    root: Path,
    relative_path: PurePosixPath,
    content: bytes,
    *,
    replace_generated_only: bool,
) -> None:
    root_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    root_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    temporary_name: str | None = None
    temporary_fd: int | None = None
    parent_fd: int | None = None
    try:
        supplied_root = root.lstat()
        if (
            not stat.S_ISDIR(supplied_root.st_mode)
            or stat.S_ISLNK(supplied_root.st_mode)
            or _is_reparse_point(supplied_root)
        ):
            raise AtomicWriteError("repository root must be a real directory")
        root_fd = os.open(root, root_flags)
        descriptors.append(root_fd)
        opened_root = os.fstat(root_fd)
        if not _same_identity(supplied_root, opened_root):
            raise AtomicWriteError("repository root changed while it was opened")
        parent_fd = root_fd
        for part in relative_path.parts[:-1]:
            parent_fd = _open_directory_at(parent_fd, part, create=True)
            descriptors.append(parent_fd)
            metadata = os.fstat(parent_fd)
            if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_point(metadata):
                raise AtomicWriteError("output parent is not a safe directory")
        parent_state = os.fstat(parent_fd)
        name = relative_path.name
        initial_target = _target_state_at(parent_fd, name)
        if initial_target is not None and replace_generated_only:
            _validate_generated_at(parent_fd, name, initial_target)

        for _attempt in range(128):
            candidate = f".{name}.{secrets.token_hex(12)}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            flags |= getattr(os, "O_BINARY", 0)
            try:
                temporary_fd = os.open(candidate, flags, 0o600, dir_fd=parent_fd)
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        else:  # pragma: no cover - cryptographically improbable collision exhaustion
            raise AtomicWriteError("could not allocate a temporary generated output")
        _write_all(temporary_fd, content)
        os.fsync(temporary_fd)
        temporary_state = os.fstat(temporary_fd)

        _checkpoint("temporary-synced", root, relative_path)
        _attest_posix_chain(
            root,
            tuple(relative_path.parts[:-1]),
            opened_root,
            parent_state,
        )
        current_target = _target_state_at(parent_fd, name)
        if (initial_target is None) != (current_target is None) or (
            initial_target is not None
            and current_target is not None
            and not _same_file_state(initial_target, current_target)
        ):
            raise AtomicWriteError("generated output target changed before replacement")
        if current_target is not None and replace_generated_only:
            _validate_generated_at(parent_fd, name, current_target)
        _checkpoint("target-validated", root, relative_path)
        _attest_posix_chain(
            root,
            tuple(relative_path.parts[:-1]),
            opened_root,
            parent_state,
        )
        final_target = _target_state_at(parent_fd, name)
        if (current_target is None) != (final_target is None) or (
            current_target is not None
            and final_target is not None
            and not _same_file_state(current_target, final_target)
        ):
            raise AtomicWriteError("generated output target changed before replacement")
        temporary_path_state = _target_state_at(parent_fd, temporary_name)
        if temporary_path_state is None or not _same_file_state(
            temporary_state, temporary_path_state
        ):
            raise AtomicWriteError("generated output temporary changed before replacement")
        _checkpoint("commit-ready", root, relative_path)
        if final_target is None:
            _commit_new_at(parent_fd, temporary_name, name, temporary_state)
            _cleanup_owned_temporary_at(
                parent_fd,
                temporary_name,
                temporary_fd,
                required=True,
            )
        else:
            _commit_exchange_at(
                parent_fd,
                temporary_name,
                name,
                temporary_state,
                final_target,
            )
            _cleanup_displaced_at(parent_fd, temporary_name, final_target)
        temporary_name = None
        os.fsync(parent_fd)
        _attest_posix_chain(
            root,
            tuple(relative_path.parts[:-1]),
            opened_root,
            parent_state,
        )
    except AtomicWriteError:
        raise
    except (OSError, ValueError) as exc:
        raise AtomicWriteError(
            f"cannot safely write generated output {relative_path}: {exc}"
        ) from exc
    finally:
        if temporary_name is not None and parent_fd is not None and temporary_fd is not None:
            _cleanup_owned_temporary_at(
                parent_fd,
                temporary_name,
                temporary_fd,
                required=False,
            )
        if temporary_fd is not None:
            with suppress(OSError):
                os.close(temporary_fd)
        for descriptor in reversed(descriptors):
            with suppress(OSError):
                os.close(descriptor)


def _safe_fallback_state(path: Path, *, directory: bool) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AtomicWriteError(f"cannot inspect output path: {path}") from exc
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not expected or stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        kind = "directory" if directory else "regular file"
        raise AtomicWriteError(f"output path is not a safe {kind}: {path}")
    return metadata


def _read_fallback_marker(path: Path, expected: os.stat_result) -> bytes:
    """Read only the bounded marker prefix from the exact validated file."""

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AtomicWriteError("cannot validate existing generated output") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_point(opened)
            or not _same_file_state(expected, opened)
        ):
            raise AtomicWriteError("generated output changed while it was inspected")
        payload = os.read(descriptor, _MARKER_READ_LIMIT)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = _safe_fallback_state(path, directory=False)
    if not _same_file_state(opened, finished) or not _same_file_state(finished, current):
        raise AtomicWriteError("generated output changed while it was inspected")
    return payload


def _attest_fallback_chain(  # pragma: no cover - exercised by Windows CI
    root: Path,
    parent_parts: tuple[str, ...],
    expected_root: os.stat_result,
    expected_parent: os.stat_result,
) -> None:
    current = _safe_fallback_state(root, directory=True)
    if not _same_identity(current, expected_root):
        raise AtomicWriteError("repository root changed during generated output write")
    parent = root
    for part in parent_parts:
        parent /= part
        current = _safe_fallback_state(parent, directory=True)
    if not _same_identity(current, expected_parent):
        raise AtomicWriteError("output parent changed during generated output write")


def _open_fallback_temporary(  # pragma: no cover - exercised by Windows CI
    path: Path,
    *,
    replace_existing: bool,
) -> int:
    if os.name != "nt":
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        return os.open(path, flags, 0o600)

    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    desired_access = 0x40000000 | 0x00010000  # GENERIC_WRITE | DELETE
    del replace_existing
    share_mode = 0x00000001 | 0x00000004  # FILE_SHARE_READ | FILE_SHARE_DELETE
    handle = create_file(
        str(path),
        desired_access,
        share_mode,
        None,
        1,  # CREATE_NEW
        0x00000100,  # FILE_ATTRIBUTE_TEMPORARY
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return msvcrt.open_osfhandle(handle, os.O_WRONLY | getattr(os, "O_BINARY", 0))
    except BaseException:
        kernel32.CloseHandle(handle)
        raise


def _replace_file_windows(  # pragma: no cover - exercised by Windows CI
    destination: Path,
    replacement: Path,
    backup: Path,
) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    replace_file = kernel32.ReplaceFileW
    replace_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    replace_file.restype = wintypes.BOOL
    if not replace_file(str(destination), str(replacement), str(backup), 0, None, None):
        raise ctypes.WinError(ctypes.get_last_error())


def _move_file_windows(  # pragma: no cover - exercised by Windows CI
    source: Path,
    destination: Path,
) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    move_file = kernel32.MoveFileExW
    move_file.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move_file.restype = wintypes.BOOL
    if not move_file(str(source), str(destination), 0x00000008):  # MOVEFILE_WRITE_THROUGH
        raise ctypes.WinError(ctypes.get_last_error())


def _cleanup_owned_fallback_temporary(  # pragma: no cover - exercised by Windows CI
    temporary: Path,
    descriptor: int,
    *,
    required: bool,
) -> bool:
    """Remove a fallback temporary only while its open handle proves ownership."""

    try:
        expected = os.fstat(descriptor)
        current = temporary.lstat()
    except FileNotFoundError:
        return True
    except OSError as exc:
        if required:
            raise AtomicWriteError(
                f"generated output cleanup could not be verified; preserved: {temporary}"
            ) from exc
        return False
    if not _same_identity(expected, current):
        if required:
            raise AtomicWriteError(
                f"generated output cleanup raced; preserved unverified object: {temporary}"
            )
        return False
    try:
        temporary.unlink()
    except OSError as exc:
        if required:
            raise AtomicWriteError(
                f"generated output cleanup failed; preserved: {temporary}"
            ) from exc
        return False
    return True


def _cleanup_displaced_fallback(  # pragma: no cover - exercised by Windows CI
    path: Path,
    expected: os.stat_result,
) -> None:
    """Remove only the exact displaced object verified after publication."""

    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if not _same_published_file(expected, current):
        raise AtomicWriteError(
            f"generated output cleanup raced; preserved unverified object: {path}"
        )
    try:
        path.unlink()
    except OSError as exc:
        raise AtomicWriteError(f"generated output cleanup failed; preserved: {path}") from exc


def _windows_commit_new(  # pragma: no cover - exercised by Windows CI
    temporary: Path,
    destination: Path,
    expected_temporary: os.stat_result,
) -> None:
    """Publish one pinned Windows temporary without replacing an existing name."""

    try:
        _move_file_windows(temporary, destination)
    except OSError as exc:
        raise AtomicWriteError("generated output appeared before it could be created") from exc
    try:
        installed = destination.lstat()
    except OSError:
        installed = None
    installed_matches = (
        installed is not None
        and stat.S_ISREG(installed.st_mode)
        and not _is_reparse_point(installed)
        and _same_published_file(expected_temporary, installed)
    )
    if installed_matches:
        return
    raise AtomicWriteError(
        f"generated output temporary changed during publication; preserved: {destination}"
    )


def _windows_commit_exchange(  # pragma: no cover - exercised by Windows CI
    destination: Path,
    temporary: Path,
    expected_temporary: os.stat_result,
    expected_target: os.stat_result,
) -> None:
    """Use ReplaceFileW's backup as a recoverable compare-and-swap witness."""

    backup = destination.parent / f".{destination.name}.{secrets.token_hex(12)}.rollback"
    try:
        _replace_file_windows(destination, temporary, backup)
        try:
            installed = destination.lstat()
        except OSError:
            installed = None
        try:
            displaced = backup.lstat()
        except OSError:
            displaced = None
        installed_matches = (
            installed is not None
            and stat.S_ISREG(installed.st_mode)
            and not _is_reparse_point(installed)
            and _same_published_file(expected_temporary, installed)
        )
        displaced_matches = (
            displaced is not None
            and stat.S_ISREG(displaced.st_mode)
            and not _is_reparse_point(displaced)
            and _same_published_file(expected_target, displaced)
        )
        if installed_matches and displaced_matches:
            _cleanup_displaced_fallback(backup, expected_target)
            return
        raise AtomicWriteError(
            "generated output or target changed during atomic replacement; "
            f"preserved recoverable names: {destination}, {backup}"
        )
    except AtomicWriteError:
        raise
    except OSError as exc:
        raise AtomicWriteError("Windows could not atomically replace the generated output") from exc


def _fallback_commit_new(  # pragma: no cover - exercised by Windows CI
    temporary: Path,
    destination: Path,
    expected_temporary: os.stat_result,
) -> None:
    try:
        os.link(temporary, destination, follow_symlinks=False)
    except OSError as exc:
        raise AtomicWriteError("generated output appeared before it could be created") from exc
    installed = destination.lstat()
    if stat.S_ISREG(installed.st_mode) and _same_published_file(expected_temporary, installed):
        return
    raise AtomicWriteError(
        f"generated output temporary changed during publication; preserved: {destination}"
    )


def _atomic_write_fallback(  # pragma: no cover - exercised by Windows CI
    root: Path,
    relative_path: PurePosixPath,
    content: bytes,
    *,
    replace_generated_only: bool,
) -> None:
    """Handle-validated Windows fallback; every component rejects reparse points."""

    root_state = _safe_fallback_state(root, directory=True)
    parent = root
    for part in relative_path.parts[:-1]:
        parent /= part
        with suppress(FileExistsError):
            parent.mkdir(mode=0o755)
        _safe_fallback_state(parent, directory=True)
    parent_state = _safe_fallback_state(parent, directory=True)
    destination = parent / relative_path.name
    try:
        initial_target = destination.lstat()
    except FileNotFoundError:
        initial_target = None
    if initial_target is not None:
        initial_target = _safe_fallback_state(destination, directory=False)
        if replace_generated_only:
            payload = _read_fallback_marker(destination, initial_target)
            if not _generated_marker(payload):
                raise AtomicWriteError(
                    f"output already exists and is not recognized as generated: {destination}; "
                    "pass --force to replace it"
                )
    temporary: Path | None = None
    descriptor: int | None = None
    try:
        for _attempt in range(128):
            temporary = parent / f".{destination.name}.{secrets.token_hex(12)}.tmp"
            try:
                descriptor = _open_fallback_temporary(
                    temporary,
                    replace_existing=initial_target is not None,
                )
            except FileExistsError:
                continue
            break
        else:  # pragma: no cover - cryptographically improbable collision exhaustion
            raise AtomicWriteError("could not allocate a temporary generated output")
        _write_all(descriptor, content)
        os.fsync(descriptor)
        temporary_state = os.fstat(descriptor)
        _checkpoint("temporary-synced", root, relative_path)
        _attest_fallback_chain(
            root,
            tuple(relative_path.parts[:-1]),
            root_state,
            parent_state,
        )
        try:
            current_target = destination.lstat()
        except FileNotFoundError:
            current_target = None
        if current_target is not None:
            current_target = _safe_fallback_state(destination, directory=False)
        if (initial_target is None) != (current_target is None) or (
            initial_target is not None
            and current_target is not None
            and not _same_file_state(initial_target, current_target)
        ):
            raise AtomicWriteError("generated output target changed before replacement")
        _checkpoint("target-validated", root, relative_path)
        _attest_fallback_chain(
            root,
            tuple(relative_path.parts[:-1]),
            root_state,
            parent_state,
        )
        try:
            final_target = destination.lstat()
        except FileNotFoundError:
            final_target = None
        if final_target is not None:
            final_target = _safe_fallback_state(destination, directory=False)
        if (current_target is None) != (final_target is None) or (
            current_target is not None
            and final_target is not None
            and not _same_file_state(current_target, final_target)
        ):
            raise AtomicWriteError("generated output target changed before replacement")
        temporary_path_state = _safe_fallback_state(temporary, directory=False)
        if not _same_file_state(temporary_state, temporary_path_state):
            raise AtomicWriteError("generated output temporary changed before replacement")
        _checkpoint("commit-ready", root, relative_path)
        if final_target is None:
            if os.name == "nt":
                _windows_commit_new(temporary, destination, temporary_state)
            else:
                _fallback_commit_new(temporary, destination, temporary_state)
                _cleanup_owned_fallback_temporary(
                    temporary,
                    descriptor,
                    required=True,
                )
        elif os.name == "nt":
            _windows_commit_exchange(
                destination,
                temporary,
                temporary_state,
                final_target,
            )
        else:
            raise AtomicWriteError(
                "atomic generated-output replacement is unavailable on this platform"
            )
        temporary = None
        _attest_fallback_chain(
            root,
            tuple(relative_path.parts[:-1]),
            root_state,
            parent_state,
        )
    except AtomicWriteError:
        raise
    except OSError as exc:
        raise AtomicWriteError(
            f"cannot safely write generated output {relative_path}: {exc}"
        ) from exc
    finally:
        if temporary is not None and descriptor is not None:
            _cleanup_owned_fallback_temporary(
                temporary,
                descriptor,
                required=False,
            )
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)


def atomic_write_within_root(
    root: Path,
    relative_path: PurePosixPath,
    content: bytes,
    *,
    replace_generated_only: bool,
) -> None:
    """Atomically write bytes below a pinned repository root.

    POSIX uses descriptor-relative traversal and replacement. Windows and other
    platforms without the required ``dir_fd`` operations use a conservative
    component-by-component identity/reparse validation path.
    """

    if not isinstance(root, Path):
        raise TypeError("root must be a Path")
    relative = _validated_relative_path(relative_path)
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    if not isinstance(replace_generated_only, bool):
        raise TypeError("replace_generated_only must be true or false")
    root_path = root.expanduser().absolute()
    supports_descriptor_write = (
        os.name != "nt"
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and os.open in os.supports_dir_fd
        and os.mkdir in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.link in os.supports_dir_fd
        and os.link in os.supports_follow_symlinks
        and os.unlink in os.supports_dir_fd
    )
    if supports_descriptor_write:
        _atomic_write_posix(
            root_path,
            relative,
            content,
            replace_generated_only=replace_generated_only,
        )
    else:  # pragma: no cover - exercised by Windows CI
        _atomic_write_fallback(
            root_path,
            relative,
            content,
            replace_generated_only=replace_generated_only,
        )
