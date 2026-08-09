"""Persistent, repository-scoped source indexes."""

from .store import (
    IndexClosedError,
    IndexFormatError,
    RepositoryIndex,
    StaleScanError,
    cache_root,
    index_path_for,
)
from .view import AreaSummary, EntryPoint, FileSummary, RepositoryView, SQLiteRepositoryView

__all__ = [
    "AreaSummary",
    "EntryPoint",
    "FileSummary",
    "IndexClosedError",
    "IndexFormatError",
    "RepositoryIndex",
    "RepositoryView",
    "SQLiteRepositoryView",
    "StaleScanError",
    "cache_root",
    "index_path_for",
]
