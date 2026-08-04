"""Stable filesystem identities shared by scanning and indexing."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

_FILESYSTEM_IDENTITY_VERSION = "1"


def filesystem_identity(metadata: os.stat_result) -> str:
    """Return a versioned opaque identity for one opened filesystem object."""

    device = int(metadata.st_dev)
    inode = int(metadata.st_ino)
    if device == 0 and inode == 0:
        raise ValueError("the filesystem does not expose a stable object identity")
    payload = f"{_FILESYSTEM_IDENTITY_VERSION}\0{device}\0{inode}".encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def descriptor_path(descriptor: int) -> Path | None:
    """Resolve the filesystem object actually opened by a descriptor."""

    if os.name == "nt":  # pragma: no cover - exercised on Windows CI
        try:
            import ctypes
            import msvcrt
            from ctypes import wintypes

            function = ctypes.windll.kernel32.GetFinalPathNameByHandleW  # type: ignore[attr-defined]
            function.argtypes = (
                wintypes.HANDLE,
                wintypes.LPWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
            )
            function.restype = wintypes.DWORD
            handle = wintypes.HANDLE(msvcrt.get_osfhandle(descriptor))
            buffer = ctypes.create_unicode_buffer(32_768)
            length = function(handle, buffer, len(buffer), 0)
            if not length or length >= len(buffer):
                return None
            value = buffer.value
            if value.startswith("\\\\?\\UNC\\"):
                value = "\\\\" + value[8:]
            elif value.startswith("\\\\?\\"):
                value = value[4:]
            return Path(value)
        except (ImportError, OSError, ValueError):
            return None
    proc_path = Path(f"/proc/self/fd/{descriptor}")
    try:
        return proc_path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None


__all__ = ["descriptor_path", "filesystem_identity"]
