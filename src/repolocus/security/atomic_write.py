"""Descriptor-bound atomic writes for generated repository documents."""

from __future__ import annotations

import errno
import hashlib
import os
import secrets
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from repolocus.security.display import has_unsafe_display_controls

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_MARKER_READ_LIMIT = 4096
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{number}" for number in range(1, 10)}
    | {f"LPT{number}" for number in range(1, 10)}
    | {f"COM{number}" for number in "¹²³"}
    | {f"LPT{number}" for number in "¹²³"}
)


class AtomicWriteError(ValueError):
    """Raised when a repository output cannot be written without escaping its root."""


@dataclass(frozen=True, slots=True)
class AtomicWriteResult:
    """Outcome of an atomic write, including any intentionally retained recovery file."""

    recovery_path: Path | None = None


@dataclass(frozen=True, slots=True)
class _WindowsFileState:
    """Stable state read through a Windows file handle, not CRT stat variants."""

    volume_serial: int
    file_id: bytes
    size: int
    last_write: int
    type_attributes: int


_FallbackState = os.stat_result | _WindowsFileState


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
    unsafe_windows_component = any(
        part.endswith((" ", "."))
        or part.split(".", 1)[0].rstrip(" ").upper() in _WINDOWS_RESERVED_NAMES
        for part in relative_path.parts
    )
    if (
        not rendered
        or rendered == "."
        or "\\" in rendered
        or ":" in rendered
        or "\x00" in rendered
        or any(character in '<>"|?*' for character in rendered)
        or has_unsafe_display_controls(rendered)
        or relative_path.is_absolute()
        or any(part in {"", ".", ".."} for part in relative_path.parts)
        or unsafe_windows_component
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


def _rename_noreplace_at(parent_fd: int, source: str, destination: str) -> None:
    """Atomically consume *source* only when *destination* is absent."""

    import ctypes

    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform.startswith("linux"):
        rename = getattr(library, "renameat2", None)
        flag = 0x1  # RENAME_NOREPLACE
    elif sys.platform == "darwin":
        rename = getattr(library, "renameatx_np", None)
        flag = 0x00000004  # RENAME_EXCL
    else:
        rename = None
        flag = 0
    if rename is None:
        raise AtomicWriteError(
            "atomic create-if-absent generated-output publication is unavailable"
        )
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    if rename(parent_fd, source_bytes, parent_fd, destination_bytes, flag) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            message = "generated output appeared before it could be created"
        else:
            message = "the filesystem does not support safe create-if-absent publication"
        raise AtomicWriteError(message) from OSError(error, os.strerror(error))


def _commit_new_at(
    parent_fd: int,
    temporary_name: str,
    name: str,
    expected_temporary: os.stat_result,
) -> None:
    """Publish a new output with create-if-absent semantics."""

    _rename_noreplace_at(parent_fd, temporary_name, name)
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
) -> AtomicWriteResult:
    root_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    root_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    temporary_name: str | None = None
    temporary_fd: int | None = None
    parent_fd: int | None = None
    recovery_path: Path | None = None
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
            suffix = "rollback" if initial_target is not None else "tmp"
            candidate = f".{name}.{secrets.token_hex(12)}.{suffix}"
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
            temporary_name = None
        else:
            _commit_exchange_at(
                parent_fd,
                temporary_name,
                name,
                temporary_state,
                final_target,
            )
            recovery_path = root.joinpath(
                *relative_path.parts[:-1],
                temporary_name,
            )
            temporary_name = None
        os.fsync(parent_fd)
        _attest_posix_chain(
            root,
            tuple(relative_path.parts[:-1]),
            opened_root,
            parent_state,
        )
        return AtomicWriteResult(recovery_path=recovery_path)
    except AtomicWriteError as exc:
        if temporary_name is not None:
            preserved = root.joinpath(*relative_path.parts[:-1], temporary_name)
            raise AtomicWriteError(
                f"{exc}; generated temporary preserved if present: {preserved}"
            ) from exc
        if recovery_path is not None:
            raise AtomicWriteError(
                f"{exc}; previous output preserved for recovery: {recovery_path}"
            ) from exc
        raise
    except (OSError, ValueError) as exc:
        preserved_detail = ""
        if temporary_name is not None:
            preserved = root.joinpath(*relative_path.parts[:-1], temporary_name)
            preserved_detail = f"; generated temporary preserved if present: {preserved}"
        elif recovery_path is not None:
            preserved_detail = f"; previous output preserved for recovery: {recovery_path}"
        raise AtomicWriteError(
            f"cannot safely write generated output {relative_path}: {exc}{preserved_detail}"
        ) from exc
    finally:
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


def _windows_file_state_from_handle(  # pragma: no cover - exercised by Windows CI
    handle: int,
) -> _WindowsFileState:
    import ctypes
    from ctypes import wintypes

    class _FileTime(ctypes.Structure):
        _fields_ = [
            ("low", wintypes.DWORD),
            ("high", wintypes.DWORD),
        ]

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation_time", _FileTime),
            ("last_access_time", _FileTime),
            ("last_write_time", _FileTime),
            ("volume_serial", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("link_count", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    class _FileId128(ctypes.Structure):
        _fields_ = [("identifier", wintypes.BYTE * 16)]

    class _FileIdInformation(ctypes.Structure):
        _fields_ = [
            ("volume_serial", ctypes.c_ulonglong),
            ("file_id", _FileId128),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    get_information.restype = wintypes.BOOL
    information = _ByHandleFileInformation()
    if not get_information(wintypes.HANDLE(handle), ctypes.byref(information)):
        raise ctypes.WinError(ctypes.get_last_error())
    get_information_ex = kernel32.GetFileInformationByHandleEx
    get_information_ex.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    get_information_ex.restype = wintypes.BOOL
    file_id = _FileIdInformation()
    if not get_information_ex(
        wintypes.HANDLE(handle),
        18,  # FileIdInfo
        ctypes.byref(file_id),
        ctypes.sizeof(file_id),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    type_mask = 0x00000010 | _REPARSE_POINT  # FILE_ATTRIBUTE_DIRECTORY | reparse
    return _WindowsFileState(
        volume_serial=int(file_id.volume_serial),
        file_id=bytes(file_id.file_id.identifier),
        size=(int(information.size_high) << 32) | int(information.size_low),
        last_write=(int(information.last_write_time.high) << 32)
        | int(information.last_write_time.low),
        type_attributes=int(information.attributes) & type_mask,
    )


def _windows_file_state_from_descriptor(  # pragma: no cover - exercised by Windows CI
    descriptor: int,
) -> _WindowsFileState:
    import msvcrt

    return _windows_file_state_from_handle(msvcrt.get_osfhandle(descriptor))


def _windows_open_path_handle(  # pragma: no cover - exercised by Windows CI
    path: Path,
    *,
    desired_access: int,
    share_mode: int,
) -> int:
    import ctypes
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
    handle = create_file(
        str(path),
        desired_access,
        share_mode,
        None,
        3,  # OPEN_EXISTING
        0x00200000 | 0x02000000,  # OPEN_REPARSE_POINT | BACKUP_SEMANTICS
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    return int(handle)


def _windows_close_handle(  # pragma: no cover - exercised by Windows CI
    handle: int,
) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    if not close_handle(wintypes.HANDLE(handle)):
        raise ctypes.WinError(ctypes.get_last_error())


def _windows_file_state_from_path(  # pragma: no cover - exercised by Windows CI
    path: Path,
) -> _WindowsFileState:
    handle = _windows_open_path_handle(
        path,
        desired_access=0x00000080,  # FILE_READ_ATTRIBUTES
        share_mode=0x00000001 | 0x00000002 | 0x00000004,
    )
    try:
        return _windows_file_state_from_handle(handle)
    finally:
        _windows_close_handle(handle)


def _windows_digest_from_handle(  # pragma: no cover - exercised by Windows CI
    handle: int,
) -> bytes:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    read_file = kernel32.ReadFile
    read_file.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    read_file.restype = wintypes.BOOL
    digest = hashlib.sha256()
    buffer = ctypes.create_string_buffer(64 * 1024)
    while True:
        count = wintypes.DWORD()
        if not read_file(
            wintypes.HANDLE(handle),
            buffer,
            len(buffer),
            ctypes.byref(count),
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if count.value == 0:
            return digest.digest()
        digest.update(buffer.raw[: count.value])


def _windows_hash_path(  # pragma: no cover - exercised by Windows CI
    path: Path,
    expected: _WindowsFileState,
    *,
    allow_last_write_settle: bool = False,
) -> tuple[_WindowsFileState, bytes]:
    handle = _windows_open_path_handle(
        path,
        desired_access=0x80000000 | 0x00000080,  # GENERIC_READ | READ_ATTRIBUTES
        share_mode=0x00000001,  # share read only; deny writers and name deletion
    )
    try:
        opened = _windows_file_state_from_handle(handle)
        if opened.type_attributes & (0x00000010 | _REPARSE_POINT):
            raise AtomicWriteError(f"output path is not a safe regular file: {path}")
        matches = (
            _same_fallback_object_after_close(expected, opened)
            if allow_last_write_settle
            else _same_fallback_state(expected, opened)
        )
        if not matches:
            raise AtomicWriteError(f"output file changed before it could be hashed: {path}")
        digest = _windows_digest_from_handle(handle)
        finished = _windows_file_state_from_handle(handle)
        if not _same_fallback_state(opened, finished):
            raise AtomicWriteError(f"output file changed while it was hashed: {path}")
        return finished, digest
    finally:
        _windows_close_handle(handle)


def _windows_set_delete_disposition(  # pragma: no cover - exercised by Windows CI
    handle: int,
) -> None:
    import ctypes
    from ctypes import wintypes

    class _FileDispositionInformation(ctypes.Structure):
        _fields_ = [("delete_file", wintypes.BYTE)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    set_information.restype = wintypes.BOOL
    disposition = _FileDispositionInformation(1)
    if not set_information(
        wintypes.HANDLE(handle),
        4,  # FileDispositionInfo
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        raise ctypes.WinError(ctypes.get_last_error())


def _windows_delete_verified_path(  # pragma: no cover - exercised by Windows CI
    path: Path,
    expected: _WindowsFileState,
    *,
    expected_digest: bytes,
) -> None:
    handle = _windows_open_path_handle(
        path,
        desired_access=0x80000000 | 0x00010000 | 0x00000080,
        share_mode=0x00000001,  # deny share-write/delete until disposition is set
    )
    try:
        opened = _windows_file_state_from_handle(handle)
        if not _same_fallback_state(expected, opened):
            raise AtomicWriteError(
                f"generated output cleanup raced; preserved unverified object: {path}"
            )
        digest = _windows_digest_from_handle(handle)
        finished = _windows_file_state_from_handle(handle)
        if digest != expected_digest or not _same_fallback_state(opened, finished):
            raise AtomicWriteError(
                f"generated output cleanup raced; preserved unverified object: {path}"
            )
        _windows_set_delete_disposition(handle)
    finally:
        _windows_close_handle(handle)


def _capture_fallback_state(path: Path, *, directory: bool) -> _FallbackState:
    metadata = _safe_fallback_state(path, directory=directory)
    if os.name != "nt":
        return metadata
    try:
        state = _windows_file_state_from_path(path)
    except OSError as exc:
        raise AtomicWriteError(f"cannot inspect output path: {path}") from exc
    is_directory = bool(state.type_attributes & 0x00000010)
    if is_directory != directory or bool(state.type_attributes & _REPARSE_POINT):
        kind = "directory" if directory else "regular file"
        raise AtomicWriteError(f"output path is not a safe {kind}: {path}")
    return state


def _capture_fallback_descriptor_state(descriptor: int) -> _FallbackState:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
    ):
        raise AtomicWriteError("generated output handle is not a safe regular file")
    if os.name == "nt":
        return _windows_file_state_from_descriptor(descriptor)
    return metadata


def _same_fallback_identity(first: _FallbackState, second: _FallbackState) -> bool:
    if isinstance(first, _WindowsFileState) or isinstance(second, _WindowsFileState):
        return (
            isinstance(first, _WindowsFileState)
            and isinstance(second, _WindowsFileState)
            and first.volume_serial == second.volume_serial
            and first.file_id == second.file_id
        )
    return _same_identity(first, second)


def _same_fallback_state(
    first: _FallbackState,
    second: _FallbackState,
    *,
    published: bool = False,
) -> bool:
    if isinstance(first, _WindowsFileState) or isinstance(second, _WindowsFileState):
        return (
            isinstance(first, _WindowsFileState)
            and isinstance(second, _WindowsFileState)
            and first == second
        )
    if published:
        return _same_published_file(first, second)
    return _same_file_state(first, second)


def _same_fallback_object_after_close(
    opened: _FallbackState,
    closed: _FallbackState,
) -> bool:
    """Allow only the last-write timestamp to settle when a Windows writer closes."""

    if isinstance(opened, _WindowsFileState) or isinstance(closed, _WindowsFileState):
        return (
            isinstance(opened, _WindowsFileState)
            and isinstance(closed, _WindowsFileState)
            and opened.volume_serial == closed.volume_serial
            and opened.file_id == closed.file_id
            and opened.size == closed.size
            and opened.type_attributes == closed.type_attributes
        )
    return _same_file_state(opened, closed)


def _read_fallback_marker(path: Path, expected: _FallbackState) -> bytes:
    """Read only the bounded marker prefix from the exact validated file."""

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AtomicWriteError("cannot validate existing generated output") from exc
    try:
        opened = _capture_fallback_descriptor_state(descriptor)
        if not _same_fallback_state(expected, opened):
            raise AtomicWriteError("generated output changed while it was inspected")
        payload = os.read(descriptor, _MARKER_READ_LIMIT)
        finished = _capture_fallback_descriptor_state(descriptor)
    finally:
        os.close(descriptor)
    current = _capture_fallback_state(path, directory=False)
    if not _same_fallback_state(opened, finished) or not _same_fallback_state(finished, current):
        raise AtomicWriteError("generated output changed while it was inspected")
    return payload


def _attest_fallback_chain(  # pragma: no cover - exercised by Windows CI
    root: Path,
    parent_parts: tuple[str, ...],
    expected_root: _FallbackState,
    expected_parent: _FallbackState,
) -> None:
    current = _capture_fallback_state(root, directory=True)
    if not _same_fallback_identity(current, expected_root):
        raise AtomicWriteError("repository root changed during generated output write")
    parent = root
    for part in parent_parts:
        parent /= part
        current = _capture_fallback_state(parent, directory=True)
    if not _same_fallback_identity(current, expected_parent):
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
        _windows_close_handle(int(handle))
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
    descriptor: int | None,
    *,
    expected: _FallbackState | None = None,
    expected_digest: bytes | None = None,
    required: bool,
) -> bool:
    """Remove a fallback temporary only while a handle-derived identity proves ownership."""

    try:
        if descriptor is not None:
            expected = _capture_fallback_descriptor_state(descriptor)
        if expected is None:
            raise AtomicWriteError("generated output cleanup has no ownership witness")
        if os.name == "nt":
            import msvcrt

            if not isinstance(expected, _WindowsFileState):
                raise AtomicWriteError("Windows cleanup has no native ownership witness")
            if descriptor is not None:
                current = _windows_file_state_from_path(temporary)
                if not _same_fallback_identity(expected, current):
                    raise AtomicWriteError(
                        f"generated output cleanup raced; preserved: {temporary}"
                    )
                _windows_set_delete_disposition(msvcrt.get_osfhandle(descriptor))
            else:
                if expected_digest is None:
                    raise AtomicWriteError("Windows cleanup has no content witness")
                _windows_delete_verified_path(
                    temporary,
                    expected,
                    expected_digest=expected_digest,
                )
            return True
        current = _capture_fallback_state(temporary, directory=False)
    except FileNotFoundError:
        return True
    except (AtomicWriteError, OSError) as exc:
        if required:
            raise AtomicWriteError(
                f"generated output cleanup could not be verified; preserved: {temporary}"
            ) from exc
        return False
    if not _same_fallback_identity(expected, current):
        if required:
            raise AtomicWriteError(
                f"generated output cleanup raced; preserved unverified object: {temporary}"
            )
        return False
    # POSIX has no portable unlink-by-handle primitive. Preserve the verified
    # object instead of reopening a check-then-unlink race.
    return False


def _cleanup_displaced_fallback(  # pragma: no cover - exercised by Windows CI
    path: Path,
    expected: _FallbackState,
    *,
    expected_digest: bytes,
) -> None:
    """Remove only the exact displaced object verified after publication."""

    if os.name == "nt":
        if not isinstance(expected, _WindowsFileState):
            raise AtomicWriteError("Windows cleanup has no native ownership witness")
        _windows_delete_verified_path(path, expected, expected_digest=expected_digest)
        return
    try:
        current = _capture_fallback_state(path, directory=False)
    except FileNotFoundError:
        return
    if not _same_fallback_state(expected, current, published=True):
        raise AtomicWriteError(
            f"generated output cleanup raced; preserved unverified object: {path}"
        )
    raise AtomicWriteError(f"safe generated output cleanup is unavailable; preserved: {path}")


def _windows_commit_new(  # pragma: no cover - exercised by Windows CI
    temporary: Path,
    destination: Path,
    expected_temporary: _FallbackState,
    expected_digest: bytes,
) -> None:
    """Publish one pinned Windows temporary without replacing an existing name."""

    try:
        _move_file_windows(temporary, destination)
    except OSError as exc:
        raise AtomicWriteError("generated output appeared before it could be created") from exc
    if not isinstance(expected_temporary, _WindowsFileState):
        raise AtomicWriteError("Windows publication has no native ownership witness")
    try:
        installed, installed_digest = _windows_hash_path(
            destination,
            expected_temporary,
        )
    except (AtomicWriteError, OSError):
        installed = None
        installed_digest = None
    if (
        installed is not None
        and _same_fallback_state(expected_temporary, installed, published=True)
        and installed_digest == expected_digest
    ):
        return
    raise AtomicWriteError(
        f"generated output temporary changed during publication; preserved: {destination}"
    )


def _windows_commit_exchange(  # pragma: no cover - exercised by Windows CI
    destination: Path,
    temporary: Path,
    expected_temporary: _FallbackState,
    expected_target: _FallbackState,
    expected_temporary_digest: bytes,
    expected_target_digest: bytes,
) -> None:
    """Use ReplaceFileW's backup as a recoverable compare-and-swap witness."""

    backup = destination.parent / f".{destination.name}.{secrets.token_hex(12)}.rollback"
    if not isinstance(expected_temporary, _WindowsFileState) or not isinstance(
        expected_target, _WindowsFileState
    ):
        raise AtomicWriteError("Windows replacement has no native ownership witness")
    try:
        _replace_file_windows(destination, temporary, backup)
        try:
            installed, installed_digest = _windows_hash_path(
                destination,
                expected_temporary,
            )
        except (AtomicWriteError, OSError):
            installed = None
            installed_digest = None
        try:
            displaced, displaced_digest = _windows_hash_path(backup, expected_target)
        except (AtomicWriteError, OSError):
            displaced = None
            displaced_digest = None
        installed_matches = (
            installed is not None
            and _same_fallback_state(expected_temporary, installed, published=True)
            and installed_digest == expected_temporary_digest
        )
        displaced_matches = (
            displaced is not None
            and _same_fallback_state(expected_target, displaced, published=True)
            and displaced_digest == expected_target_digest
        )
        if installed_matches and displaced_matches:
            _cleanup_displaced_fallback(
                backup,
                expected_target,
                expected_digest=expected_target_digest,
            )
            return
        raise AtomicWriteError(
            "generated output or target changed during atomic replacement; "
            f"preserved recoverable names: {destination}, {backup}"
        )
    except AtomicWriteError:
        raise
    except OSError as exc:
        raise AtomicWriteError("Windows could not atomically replace the generated output") from exc


def _atomic_write_fallback(  # pragma: no cover - exercised by Windows CI
    root: Path,
    relative_path: PurePosixPath,
    content: bytes,
    *,
    replace_generated_only: bool,
) -> AtomicWriteResult:
    """Handle-validated Windows fallback; every component rejects reparse points."""

    if os.name != "nt":
        raise AtomicWriteError("Windows generated-output writer called on another platform")
    root_state = _capture_fallback_state(root, directory=True)
    parent = root
    for part in relative_path.parts[:-1]:
        parent /= part
        with suppress(FileExistsError):
            parent.mkdir(mode=0o755)
        _capture_fallback_state(parent, directory=True)
    parent_state = _capture_fallback_state(parent, directory=True)
    destination = parent / relative_path.name
    try:
        initial_target = destination.lstat()
    except FileNotFoundError:
        initial_target = None
    if initial_target is not None:
        initial_target = _capture_fallback_state(destination, directory=False)
        if replace_generated_only:
            payload = _read_fallback_marker(destination, initial_target)
            if not _generated_marker(payload):
                raise AtomicWriteError(
                    f"output already exists and is not recognized as generated: {destination}; "
                    "pass --force to replace it"
                )
    temporary: Path | None = None
    descriptor: int | None = None
    temporary_state: _FallbackState | None = None
    target_digest: bytes | None = None
    content_digest = hashlib.sha256(content).digest()
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
        temporary_state = _capture_fallback_descriptor_state(descriptor)
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
            current_target = _capture_fallback_state(destination, directory=False)
        if (initial_target is None) != (current_target is None) or (
            initial_target is not None
            and current_target is not None
            and not _same_fallback_state(initial_target, current_target)
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
            final_target = _capture_fallback_state(destination, directory=False)
        if (current_target is None) != (final_target is None) or (
            current_target is not None
            and final_target is not None
            and not _same_fallback_state(current_target, final_target)
        ):
            raise AtomicWriteError("generated output target changed before replacement")
        temporary_path_state = _capture_fallback_state(temporary, directory=False)
        if not _same_fallback_state(temporary_state, temporary_path_state):
            raise AtomicWriteError("generated output temporary changed before replacement")
        _checkpoint("commit-ready", root, relative_path)
        if os.name == "nt":
            # ReplaceFileW opens its replacement with no sharing. Close our writer,
            # then pin the exact path state used as the publication witness.
            pre_close_state = _capture_fallback_descriptor_state(descriptor)
            os.close(descriptor)
            descriptor = None
            if not isinstance(pre_close_state, _WindowsFileState):
                raise AtomicWriteError("Windows temporary has no native ownership witness")
            closed_path_state, closed_digest = _windows_hash_path(
                temporary,
                pre_close_state,
                allow_last_write_settle=True,
            )
            if closed_digest != content_digest:
                raise AtomicWriteError("generated output temporary changed before replacement")
            temporary_state = closed_path_state
            if final_target is not None:
                if not isinstance(final_target, _WindowsFileState):
                    raise AtomicWriteError("Windows target has no native ownership witness")
                final_target, target_digest = _windows_hash_path(
                    destination,
                    final_target,
                )
            _attest_fallback_chain(
                root,
                tuple(relative_path.parts[:-1]),
                root_state,
                parent_state,
            )
        if final_target is None:
            _windows_commit_new(
                temporary,
                destination,
                temporary_state,
                content_digest,
            )
        else:
            if target_digest is None:
                raise AtomicWriteError("Windows target has no content witness")
            _windows_commit_exchange(
                destination,
                temporary,
                temporary_state,
                final_target,
                content_digest,
                target_digest,
            )
        temporary = None
        _attest_fallback_chain(
            root,
            tuple(relative_path.parts[:-1]),
            root_state,
            parent_state,
        )
        return AtomicWriteResult()
    except AtomicWriteError:
        raise
    except OSError as exc:
        raise AtomicWriteError(
            f"cannot safely write generated output {relative_path}: {exc}"
        ) from exc
    finally:
        if temporary is not None and (descriptor is not None or temporary_state is not None):
            _cleanup_owned_fallback_temporary(
                temporary,
                descriptor,
                expected=temporary_state,
                expected_digest=content_digest,
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
) -> AtomicWriteResult:
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
    )
    if supports_descriptor_write:
        return _atomic_write_posix(
            root_path,
            relative,
            content,
            replace_generated_only=replace_generated_only,
        )
    if os.name != "nt":
        raise AtomicWriteError(
            "descriptor-bound generated-output writes are unavailable on this platform"
        )
    return _atomic_write_fallback(  # pragma: no cover - exercised by Windows CI
        root_path,
        relative,
        content,
        replace_generated_only=replace_generated_only,
    )
