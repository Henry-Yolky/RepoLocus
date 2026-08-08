"""Language-neutral, deterministic dependency resolution.

The resolver is deliberately lexical.  It never imports a project module or
executes build metadata.  Ambiguous aliases stay ambiguous so every consumer
observes the same fail-closed graph.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal, cast

from repolocus.models import Dependency

ResolutionConfidence = Literal["exact", "probable", "ambiguous", "unresolved"]

_SOURCE_SUFFIXES = tuple(
    sorted(
        {
            ".d.mts",
            ".d.cts",
            ".d.ts",
            ".cjs",
            ".cts",
            ".mjs",
            ".mts",
            ".cxx",
            ".hh",
            ".hxx",
            ".ipp",
            ".py",
            ".pyi",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".go",
            ".rs",
            ".java",
            ".c",
            ".cc",
            ".cpp",
            ".h",
            ".hpp",
        },
        key=lambda suffix: (-len(suffix), suffix),
    )
)
_PYTHON_SUFFIXES = frozenset({".py", ".pyi"})
_SOURCE_ROOT_NAMES = frozenset({"lib", "source", "src"})
_PACKAGE_MODULE_NAMES = frozenset({"__init__", "index", "mod"})
_CASEFOLD_ALIAS_PREFIX = "@repolocus-casefold/"
_MAX_PATH_ALIASES = 12
_MAX_ALIAS_RECORDS = 2_000_000
_MAX_ALIAS_CHARS = 64_000_000
_GO_MODULE_RE = re.compile(
    r"^[ \t]*module[ \t]+(?P<target>[^\s\"`]+|\"[^\"\r\n]+\"|`[^`\r\n]+`)"
    r"[ \t]*(?://.*)?$"
)


@dataclass(frozen=True, slots=True)
class ResolvedDependency:
    """A dependency edge with an explicit resolution outcome."""

    source_path: str
    raw_target: str
    target_path: str | None
    target_symbol: str | None
    kind: str
    line: int
    confidence: ResolutionConfidence
    candidates: tuple[str, ...] = ()


class _AliasIndex(dict[str, object]):
    """Alias mapping with non-persisted language-boundary metadata."""

    def __init__(self) -> None:
        super().__init__()
        self.python_package_roots: dict[str, tuple[str, ...]] = {}


def _source_suffix(path: str) -> str:
    lowered = path.casefold()
    return next((suffix for suffix in _SOURCE_SUFFIXES if lowered.endswith(suffix)), "")


def _without_source_suffix(path: str) -> str:
    suffix = _source_suffix(path)
    return path[: -len(suffix)] if suffix else path


def _logical_tail(parts: list[str]) -> list[str] | None:
    roots = [
        index for index, part in enumerate(parts[:-1]) if part.casefold() in _SOURCE_ROOT_NAMES
    ]
    if roots and roots[-1] + 1 < len(parts):
        return parts[roots[-1] + 1 :]
    if len(parts) > 1:
        return parts[1:]
    return None


def _java_source_tail(parts: list[str]) -> list[str] | None:
    for index in range(len(parts) - 3, -1, -1):
        prefix = tuple(part.casefold() for part in parts[index : index + 3])
        if prefix in {("src", "main", "java"), ("src", "test", "java")}:
            tail = parts[index + 3 :]
            return tail or None
    return None


def path_aliases(path: str) -> tuple[str, ...]:
    """Return a constant-size set of repository-relative aliases for one path."""

    without_suffix = _without_source_suffix(path)
    aliases = {
        path,
        PurePosixPath(path).name,
        without_suffix,
        PurePosixPath(without_suffix).name,
        without_suffix.replace("/", "."),
    }
    parts = without_suffix.split("/")
    tail = _logical_tail(parts)
    if tail:
        aliases.update({"/".join(tail), ".".join(tail)})
    if _source_suffix(path) == ".java" and (java_tail := _java_source_tail(parts)):
        aliases.update({"/".join(java_tail), ".".join(java_tail)})
    if parts and parts[-1].casefold() in _PACKAGE_MODULE_NAMES:
        package_parts = parts[:-1]
        if package_parts:
            aliases.update(
                {
                    "/".join(package_parts),
                    ".".join(package_parts),
                    package_parts[-1],
                }
            )
    ordered = tuple(sorted(alias for alias in aliases if alias))
    if len(ordered) > _MAX_PATH_ALIASES:  # pragma: no cover - fixed construction invariant
        raise RuntimeError("path alias construction exceeded its fixed bound")
    return ordered


def _indexed_path_aliases(path: str) -> tuple[str, ...]:
    aliases = set(path_aliases(path))
    aliases.update(f"{_CASEFOLD_ALIAS_PREFIX}{alias.casefold()}" for alias in tuple(aliases))
    return tuple(sorted(aliases))


def _python_package_root(path: str, paths: set[str]) -> tuple[str, ...]:
    parent = list(PurePosixPath(path).parent.parts)
    current = list(parent)
    found_regular_package = False
    while current:
        package = "/".join((*current, "__init__.py"))
        typed_package = "/".join((*current, "__init__.pyi"))
        if package not in paths and typed_package not in paths:
            break
        found_regular_package = True
        current.pop()
    if found_regular_package:
        return tuple(current)
    roots = [index for index, part in enumerate(parent) if part.casefold() in _SOURCE_ROOT_NAMES]
    if roots:
        return tuple(parent[: roots[-1] + 1])
    return ()


def _valid_go_module_path(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 1_024
        and not value.startswith(("/", "."))
        and not value.endswith("/")
        and "//" not in value
        and "\\" not in value
        and all(character.isprintable() and not character.isspace() for character in value)
    )


def go_module_roots(files: Iterable[tuple[str, str]]) -> dict[str, str]:
    """Extract explicit ``go.mod`` module identities without creating graph edges."""

    modules: dict[str, str] = {}
    for path, text in sorted(files, key=lambda item: item[0]):
        parsed = PurePosixPath(path)
        if parsed.name.casefold() != "go.mod" or not isinstance(text, str):
            continue
        match = next(
            (candidate for line in text.splitlines() if (candidate := _GO_MODULE_RE.match(line))),
            None,
        )
        if match is None:
            continue
        target = match.group("target")
        if target[:1] in {'"', "`"} and target[-1:] == target[:1]:
            target = target[1:-1]
        if not _valid_go_module_path(target):
            continue
        root = parsed.parent.as_posix()
        modules["" if root == "." else root] = target
    return modules


def _validated_go_modules(go_modules: Mapping[str, str] | None) -> tuple[tuple[str, str], ...]:
    values: list[tuple[str, str]] = []
    for root, module in (go_modules or {}).items():
        if not isinstance(root, str) or not isinstance(module, str):
            raise ValueError("Go module aliases must map repository paths to module names")
        if root:
            parsed = PurePosixPath(root)
            if parsed.is_absolute() or parsed.as_posix() != root or ".." in parsed.parts:
                raise ValueError("Go module roots must be normalized repository-relative paths")
        if not _valid_go_module_path(module):
            raise ValueError("Go module names must be bounded normalized import paths")
        values.append((root, module))
    return tuple(
        sorted(values, key=lambda item: (-len(PurePosixPath(item[0]).parts), item[0], item[1]))
    )


def _go_package_alias(path: str, modules: tuple[tuple[str, str], ...]) -> str | None:
    if _source_suffix(path) != ".go":
        return None
    parsed = PurePosixPath(path)
    for root, module in modules:
        try:
            relative = parsed.relative_to(root) if root else parsed
        except ValueError:
            continue
        package = relative.parent.as_posix()
        return module if package == "." else f"{module}/{package}"
    return None


def build_alias_index(
    paths: Iterable[str],
    *,
    go_modules: Mapping[str, str] | None = None,
) -> dict[str, tuple[str, ...]]:
    """Build the bounded alias -> candidate-path relation."""

    ordered_paths = sorted(set(paths))
    path_set = set(ordered_paths)
    module_roots = _validated_go_modules(go_modules)
    aliases = _AliasIndex()
    alias_records = 0
    alias_characters = 0
    for path in ordered_paths:
        if _source_suffix(path) in _PYTHON_SUFFIXES:
            aliases.python_package_roots[path] = _python_package_root(path, path_set)
        indexed_aliases = set(_indexed_path_aliases(path))
        if package_alias := _go_package_alias(path, module_roots):
            indexed_aliases.update(
                {
                    package_alias,
                    f"{_CASEFOLD_ALIAS_PREFIX}{package_alias.casefold()}",
                }
            )
        for alias in sorted(indexed_aliases):
            candidates = aliases.get(alias)
            if candidates is None:
                alias_characters += len(alias)
                if alias_characters > _MAX_ALIAS_CHARS:
                    raise ValueError("dependency alias character budget exceeded")
                mutable_candidates: list[str] = []
                aliases[alias] = mutable_candidates
            else:
                mutable_candidates = cast(list[str], candidates)
            alias_records += 1
            if alias_records > _MAX_ALIAS_RECORDS:
                raise ValueError("dependency alias record budget exceeded")
            mutable_candidates.append(path)
    for alias, candidates in aliases.items():
        aliases[alias] = tuple(cast(list[str], candidates))
    return cast(dict[str, tuple[str, ...]], aliases)


def _normalize_relative(
    source_path: str,
    target: str,
    *,
    python_package_root: tuple[str, ...] | None = None,
) -> str | None:
    base = list(PurePosixPath(source_path).parent.parts)
    if target.startswith("./") or target.startswith("../"):
        raw_parts = target.split("/")
    else:
        level = len(target) - len(target.lstrip("."))
        if level == 0:
            return None
        parent_levels = level - 1
        if python_package_root is not None and parent_levels:
            package_depth = len(base) - len(python_package_root)
            if parent_levels >= package_depth:
                return None
        if parent_levels and parent_levels >= len(base):
            return None
        if parent_levels:
            base = base[:-parent_levels]
        module = target[level:].replace(".", "/")
        raw_parts = module.split("/")
    normalized = list(base)
    for part in raw_parts:
        if not part or part == ".":
            continue
        if part == "..":
            if not normalized:
                return None
            normalized.pop()
            continue
        normalized.append(part)
    return "/".join(normalized) or None


def _rust_crate_root(source_path: str) -> tuple[str, ...] | None:
    """Infer the conventional Cargo source root without crossing the repository root."""

    path = PurePosixPath(source_path)
    parent = path.parent.parts
    source_roots = [index for index, part in enumerate(parent) if part.casefold() == "src"]
    if source_roots:
        source_root = source_roots[-1]
        if len(parent) > source_root + 1 and parent[source_root + 1].casefold() == "bin":
            binary_root = parent[: source_root + 2]
            if len(path.parts) == source_root + 3:
                return binary_root
            return parent[: source_root + 3]
        return parent[: source_root + 1]
    target_roots = [
        index
        for index, part in enumerate(parent)
        if part.casefold() in {"benches", "examples", "tests"}
    ]
    if target_roots:
        target_root = target_roots[-1]
        conventional_root = parent[: target_root + 1]
        if len(path.parts) == target_root + 2:
            return conventional_root
        return parent[: target_root + 2]
    if path.name.casefold() in {"lib.rs", "main.rs", "mod.rs"}:
        return parent
    return None


def _rust_module_base(source_path: str) -> tuple[str, ...] | None:
    path = PurePosixPath(source_path)
    root = _rust_crate_root(source_path)
    if root is None:
        return None
    conventional_target = bool(root) and root[-1].casefold() in {
        "benches",
        "bin",
        "examples",
        "tests",
    }
    if path.name.casefold() in {"lib.rs", "main.rs", "mod.rs"} or (
        conventional_target and path.parent.parts == root
    ):
        return path.parent.parts
    return (*path.parent.parts, path.stem)


def _rust_scoped_target(source_path: str, scope: str, remainder: str) -> str | None:
    root = _rust_crate_root(source_path)
    module = _rust_module_base(source_path)
    if root is None or module is None:
        return None
    if scope == "crate":
        base = list(root)
    elif scope == "self":
        base = list(module)
    else:
        levels = int(scope)
        if levels > len(module) - len(root):
            return None
        base = list(module[:-levels]) if levels else list(module)
    base.extend(part for part in remainder.split("/") if part)
    return "/".join(base) or None


def _relative_aliases(relative: str) -> set[str]:
    aliases = {relative, relative.replace("/", ".")}
    aliases.update(_without_source_suffix(alias) for alias in tuple(aliases))
    return aliases


def _clean_target(raw_target: str) -> str:
    return raw_target.strip().strip("'\"").replace("\\", "/").replace("::", "/")


def _python_root_for(
    aliases: Mapping[str, tuple[str, ...]], source_path: str
) -> tuple[str, ...] | None:
    roots = getattr(aliases, "python_package_roots", None)
    if roots is None or _source_suffix(source_path) not in _PYTHON_SUFFIXES:
        return None
    return roots.get(source_path)


def _target_aliases(
    source_path: str,
    raw_target: str,
    *,
    python_package_root: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    cleaned = _clean_target(raw_target)
    if not cleaned:
        return ()
    aliases: set[str] = set()
    if cleaned.startswith("crate/"):
        relative = _rust_scoped_target(source_path, "crate", cleaned[6:])
    elif cleaned.startswith("self/"):
        relative = _rust_scoped_target(source_path, "self", cleaned[5:])
    elif cleaned.startswith("super/"):
        levels = 0
        remainder = cleaned
        while remainder.startswith("super/"):
            levels += 1
            remainder = remainder[6:]
        relative = _rust_scoped_target(source_path, str(levels), remainder)
    elif cleaned.startswith("."):
        relative = _normalize_relative(
            source_path,
            cleaned,
            python_package_root=python_package_root,
        )
    else:
        aliases.update({cleaned, cleaned.replace("/", "."), cleaned.replace(".", "/")})
        relative = None
    if relative:
        aliases.update(_relative_aliases(relative))
    aliases.update(_without_source_suffix(alias) for alias in tuple(aliases))
    return tuple(sorted(alias for alias in aliases if alias))


def _target_path_is_valid(
    source_path: str,
    raw_target: str,
    *,
    python_package_root: tuple[str, ...] | None = None,
) -> bool:
    """Reject relative/scoped targets that cross their lexical analysis root."""

    cleaned = _clean_target(raw_target)
    if cleaned.startswith("crate/"):
        return _rust_scoped_target(source_path, "crate", cleaned[6:]) is not None
    if cleaned.startswith("self/"):
        return _rust_scoped_target(source_path, "self", cleaned[5:]) is not None
    if cleaned.startswith("super/"):
        levels = 0
        remainder = cleaned
        while remainder.startswith("super/"):
            levels += 1
            remainder = remainder[6:]
        return _rust_scoped_target(source_path, str(levels), remainder) is not None
    if cleaned.startswith("."):
        return (
            _normalize_relative(
                source_path,
                cleaned,
                python_package_root=python_package_root,
            )
            is not None
        )
    return True


def _lookup_candidates(
    aliases: Mapping[str, tuple[str, ...]],
    target_aliases: Iterable[str],
    source_path: str,
) -> tuple[set[str], bool]:
    exact = {
        candidate
        for alias in target_aliases
        for candidate in aliases.get(alias, ())
        if candidate != source_path
    }
    if exact:
        return exact, False
    folded = {
        candidate
        for alias in target_aliases
        for candidate in aliases.get(f"{_CASEFOLD_ALIAS_PREFIX}{alias.casefold()}", ())
        if candidate != source_path
    }
    return folded, bool(folded)


def _preferred_target_aliases(dependency: Dependency) -> tuple[str, ...]:
    cleaned = _clean_target(dependency.target)
    if (
        dependency.kind == "module"
        and _source_suffix(dependency.source_path) == ".rs"
        and cleaned.isidentifier()
    ):
        relative = _rust_scoped_target(dependency.source_path, "self", cleaned)
        if relative:
            return tuple(sorted(_relative_aliases(relative)))
    return ()


def _allows_parent_symbol_fallback(dependency: Dependency) -> bool:
    suffix = _source_suffix(dependency.source_path)
    cleaned = _clean_target(dependency.target)
    if dependency.kind == "call":
        return True
    if suffix == ".java":
        return not cleaned.startswith(".") and "." in dependency.target
    if suffix == ".rs":
        return cleaned.startswith(("crate/", "self/", "super/"))
    return False


def resolve_dependency(
    dependency: Dependency,
    aliases: Mapping[str, tuple[str, ...]],
) -> ResolvedDependency:
    """Resolve one edge without guessing when an alias has multiple owners."""

    python_package_root = _python_root_for(aliases, dependency.source_path)
    preferred_aliases = _preferred_target_aliases(dependency)
    candidates: set[str] = set()
    casefold_match = False
    if preferred_aliases:
        candidates, casefold_match = _lookup_candidates(
            aliases, preferred_aliases, dependency.source_path
        )
    if not candidates:
        target_aliases = _target_aliases(
            dependency.source_path,
            dependency.target,
            python_package_root=python_package_root,
        )
        candidates, casefold_match = _lookup_candidates(
            aliases, target_aliases, dependency.source_path
        )
    target_symbol: str | None = None
    confidence: ResolutionConfidence
    if len(candidates) == 1:
        confidence = "probable" if casefold_match else "exact"
    elif len(candidates) > 1:
        confidence = "ambiguous"
    elif not _target_path_is_valid(
        dependency.source_path,
        dependency.target,
        python_package_root=python_package_root,
    ) or not _allows_parent_symbol_fallback(dependency):
        confidence = "unresolved"
    else:
        # Some ecosystems include a symbol/class after the module path.  A
        # unique parent module is useful, but remains explicitly probable.
        cleaned = _clean_target(dependency.target)
        if "/" in cleaned:
            parts = [part for part in cleaned.split("/") if part]

            def parent_target(values: list[str]) -> str:
                return "/".join(values)

        else:
            level = len(cleaned) - len(cleaned.lstrip("."))
            parts = [part for part in cleaned.lstrip(".").split(".") if part]

            def parent_target(values: list[str]) -> str:
                return "." * level + ".".join(values)

        parent_candidates: set[str] = set()
        symbol_parts: list[str] = []
        while len(parts) > 1 and not parent_candidates:
            symbol_parts.insert(0, parts.pop())
            target_symbol = ".".join(symbol_parts)
            if len(parts) == 1 and parts[0] in {"crate", "self", "super"}:
                break
            parent_aliases = _target_aliases(
                dependency.source_path,
                parent_target(parts),
                python_package_root=python_package_root,
            )
            parent_candidates, _folded = _lookup_candidates(
                aliases, parent_aliases, dependency.source_path
            )
        candidates = parent_candidates
        if len(candidates) == 1:
            confidence = "probable"
        elif len(candidates) > 1:
            confidence = "ambiguous"
        else:
            confidence = "unresolved"
            target_symbol = None
    ordered = tuple(sorted(candidates))
    return ResolvedDependency(
        source_path=dependency.source_path,
        raw_target=dependency.target,
        target_path=ordered[0] if len(ordered) == 1 else None,
        target_symbol=target_symbol if len(ordered) == 1 else None,
        kind=dependency.kind,
        line=dependency.line,
        confidence=confidence,
        candidates=ordered,
    )


def resolve_dependencies(
    paths: Iterable[str],
    dependencies: Iterable[Dependency],
    *,
    go_modules: Mapping[str, str] | None = None,
) -> tuple[ResolvedDependency, ...]:
    """Resolve a dependency projection in deterministic source order."""

    aliases = build_alias_index(paths, go_modules=go_modules)
    resolved = (resolve_dependency(dependency, aliases) for dependency in dependencies)
    return tuple(
        sorted(
            resolved,
            key=lambda item: (
                item.source_path,
                item.line,
                item.raw_target,
                item.kind,
                item.candidates,
            ),
        )
    )
