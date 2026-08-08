"""Stable dependency resolution shared by indexes and consumers."""

from .resolver import (
    ResolutionConfidence,
    ResolvedDependency,
    build_alias_index,
    go_module_roots,
    path_aliases,
    resolve_dependencies,
    resolve_dependency,
)

__all__ = [
    "ResolutionConfidence",
    "ResolvedDependency",
    "build_alias_index",
    "go_module_roots",
    "path_aliases",
    "resolve_dependencies",
    "resolve_dependency",
]
