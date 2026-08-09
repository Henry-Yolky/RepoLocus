"""Generate a stable PROJECT_MAP.md directly from scanner evidence."""

from __future__ import annotations

import os
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from html import escape as html_escape
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from repolocus import __version__
from repolocus.graph import ResolvedDependency, go_module_roots, resolve_dependencies
from repolocus.index.view import AreaSummary, EntryPoint, FileSummary, RepositoryView
from repolocus.models import ScannedFile, ScanResult
from repolocus.security.display import escape_untrusted_display

_README_NAMES = ("README.md", "README.rst", "README.txt", "README")
_CONFIG_NAMES = {
    "cargo.toml",
    "dockerfile",
    "go.mod",
    "makefile",
    "package.json",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
    "tsconfig.json",
}


@dataclass(frozen=True, slots=True)
class _SourceLinks:
    """Translate repository paths into links from one generated document."""

    prefix: str = ""
    destination_supplied: bool = False

    @classmethod
    def for_output(cls, root: Path, destination: Path | str | None) -> _SourceLinks:
        if destination is None:
            return cls()
        requested = Path(destination).expanduser()
        if not requested.is_absolute():
            requested = root / requested
        requested = requested.resolve(strict=False)
        relative_root = Path(os.path.relpath(root, start=requested.parent)).as_posix()
        return cls("" if relative_root == "." else relative_root, True)

    def citation(self, path: str, line: int, label: str | None = None) -> str:
        visible = _markdown_text(label or f"{path}:{line}")
        target = PurePosixPath(path)
        if self.prefix:
            target = PurePosixPath(self.prefix) / target
        escaped = quote(target.as_posix(), safe="/._-")
        return f"[{visible}]({escaped}#L{line})"

    @property
    def description(self) -> str:
        if self.destination_supplied:
            return "generated-document-relative"
        return "repository-root-relative"


def _markdown_text(value: str) -> str:
    """Escape untrusted text for a Markdown link label or table cell."""

    escaped = html_escape(escape_untrusted_display(value), quote=False).replace("\\", "\\\\")
    for marker in ("[", "]", "|"):
        escaped = escaped.replace(marker, f"\\{marker}")
    return escaped


def _code(value: str) -> str:
    """Render an untrusted identifier without allowing Markdown structure injection."""

    visible = html_escape(escape_untrusted_display(value), quote=False)
    visible = visible.replace("`", "'").replace("|", "¦")
    return f"`{visible}`"


def _first_content_paragraph(text_value: str) -> tuple[str, int] | None:
    lines = text_value.splitlines()
    paragraph: list[str] = []
    start = 1
    fenced = False
    for number, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if stripped.startswith("```"):
            fenced = not fenced
            continue
        if fenced or stripped.startswith(("#", "!", "[!", "<")):
            continue
        if not stripped:
            if paragraph:
                break
            continue
        if not paragraph:
            start = number
        paragraph.append(stripped)
        if len(" ".join(paragraph)) >= 280:
            break
    if not paragraph:
        return None
    text = escape_untrusted_display(re.sub(r"\s+", " ", " ".join(paragraph)).strip())
    text = html_escape(text, quote=False)
    for marker in ("\\", "`", "*", "_", "[", "]"):
        text = text.replace(marker, f"\\{marker}")
    return text[:400], start


def _top_group(path: str) -> str:
    parts = PurePosixPath(path).parts
    if len(parts) == 1:
        return "(repository root)"
    return parts[0]


def _is_test(path: str) -> bool:
    lowered = path.lower()
    parts = PurePosixPath(lowered).parts
    name = PurePosixPath(lowered).name
    return (
        any(part in {"test", "tests", "spec", "specs", "__tests__"} for part in parts)
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.ts", ".test.js", ".spec.ts", ".spec.js"))
    )


def _is_config(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return name in _CONFIG_NAMES or name.endswith((".yaml", ".yml", ".toml"))


def _first_line_for(file: ScannedFile) -> int:
    for number, line in enumerate(file.text.splitlines(), 1):
        if line.strip():
            return number
    return 1


@dataclass(frozen=True, slots=True)
class _MapStats:
    indexed_files: int
    indexed_bytes: int
    languages: Mapping[str, int]
    skipped: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class _DependencyFacts:
    runtime: Mapping[str, tuple[ResolvedDependency, ...]]
    external_counts: Counter[str]
    external_first: Mapping[str, ResolvedDependency]


class ProjectMapGenerator:
    """Render a conservative map from facts observed during a repository scan."""

    def generate(
        self,
        result: ScanResult,
        *,
        destination: Path | str | None = None,
    ) -> str:
        """Render the map, defaulting to repository-root-relative source links."""

        dependencies = resolve_dependencies(
            (file.path for file in result.files),
            (dependency for file in result.files for dependency in file.dependencies),
            go_modules=go_module_roots((file.path, file.text) for file in result.files),
        )
        summaries = [_file_summary(file) for file in result.files]
        return self._generate_projection(
            root=result.root,
            summaries=summaries,
            areas=_area_summaries(summaries),
            entry_points=_entry_points(result.files),
            dependencies=dependencies,
            stats=_MapStats(
                result.stats.indexed_files,
                result.stats.indexed_bytes,
                result.stats.languages,
                result.stats.skipped,
            ),
            readme_texts={
                file.path: file.text for file in result.files if file.path in _README_NAMES
            },
            destination=destination,
        )

    def generate_view(
        self,
        view: RepositoryView,
        *,
        destination: Path | str | None = None,
    ) -> str:
        """Render from bounded index projections without loading repository text."""

        summaries = sorted(view.file_summaries(), key=lambda item: item.path)
        available_paths = {item.path for item in summaries}
        readme_path = next((name for name in _README_NAMES if name in available_paths), None)
        metadata = view.stats()
        return self._generate_projection(
            root=view.root,
            summaries=summaries,
            areas=view.symbols_by_area(),
            entry_points=view.entry_points(),
            dependencies=view.dependencies(),
            stats=_MapStats(
                int(metadata["files"]),
                int(metadata["indexed_bytes"]),
                dict(metadata["languages"]),  # type: ignore[arg-type]
                dict(metadata["skipped"]),  # type: ignore[arg-type]
            ),
            readme_texts=(
                {readme_path: view.read_text_prefix(readme_path, 8_000)} if readme_path else {}
            ),
            destination=destination,
        )

    def _generate_projection(
        self,
        *,
        root: Path,
        summaries: Sequence[FileSummary],
        areas: Iterable[AreaSummary],
        entry_points: Iterable[EntryPoint],
        dependencies: Iterable[ResolvedDependency],
        stats: _MapStats,
        readme_texts: Mapping[str, str],
        destination: Path | str | None,
    ) -> str:
        links = _SourceLinks.for_output(root, destination)
        files = sorted(summaries, key=lambda item: item.path)
        area_list = sorted(areas, key=lambda item: item.area)
        entries = sorted(entry_points, key=lambda item: item.path)
        dependency_facts = self._dependency_facts(files, entries, dependencies)
        lines: list[str] = [
            "# Project Map",
            "",
            f"<!-- Generator: RepoLocus {__version__}; deterministic source map. -->",
            "",
        ]
        lines.extend(self._overview(files, readme_texts, links))
        lines.extend(self._quick_start(files, links))
        lines.extend(self._layout(area_list, links))
        lines.extend(self._entry_point_section(entries, links))
        lines.extend(self._modules(area_list, links))
        lines.extend(self._runtime_flow(entries, dependency_facts.runtime, links))
        lines.extend(self._dependencies(dependency_facts, links))
        lines.extend(self._configuration(files, links))
        lines.extend(self._tests(files, links))
        lines.extend(self._risks(stats, files, links))
        lines.extend(self._reading_order(files, {item.path for item in entries}, links))
        lines.extend(self._metadata(root, stats, links))
        return "\n".join(lines).rstrip() + "\n"

    def _overview(
        self,
        files: Sequence[FileSummary],
        readme_texts: Mapping[str, str],
        links: _SourceLinks,
    ) -> list[str]:
        readme_path = next((name for name in _README_NAMES if name in readme_texts), None)
        if readme_path:
            paragraph = _first_content_paragraph(readme_texts[readme_path])
            if paragraph:
                text, line = paragraph
                return [
                    "## What this repository does",
                    "",
                    f"**Confirmed:** {text} ({links.citation(readme_path, line)})",
                    "",
                ]
        languages = Counter(file.language for file in files if file.language != "Text")
        top = ", ".join(name for name, _ in languages.most_common(3)) or "text"
        return [
            "## What this repository does",
            "",
            f"**Needs review:** No descriptive README paragraph was found. The scanned files "
            f"primarily use {top}; inspect the entry points below before assigning a purpose.",
            "",
        ]

    def _quick_start(self, files: Sequence[FileSummary], links: _SourceLinks) -> list[str]:
        candidates = [
            file
            for file in files
            if PurePosixPath(file.path).name.lower()
            in {"readme.md", "contributing.md", "package.json", "pyproject.toml", "makefile"}
        ]
        output = ["## Quick start for readers", ""]
        if not candidates:
            output.extend(["**Needs review:** No conventional onboarding file was indexed.", ""])
            return output
        for file in candidates[:5]:
            output.append(
                f"- **Confirmed:** Start with {links.citation(file.path, file.first_line)}."
            )
        output.append("")
        return output

    def _layout(self, areas: Sequence[AreaSummary], links: _SourceLinks) -> list[str]:
        output = [
            "## Repository layout",
            "",
            "| Area | Files | Main languages | Evidence |",
            "|---|---:|---|---|",
        ]
        for area in areas:
            language_text = ", ".join(name for name, _ in area.languages[:3])
            output.append(
                f"| {_code(area.area)} | {area.file_count} | {_markdown_text(language_text)} | "
                f"{links.citation(area.representative_path, area.representative_line)} |"
            )
        output.append("")
        return output

    def _entry_point_section(self, entries: Sequence[EntryPoint], links: _SourceLinks) -> list[str]:
        output = ["## Main entry points", ""]
        if not entries:
            output.extend(
                [
                    "**Needs review:** No conventional executable entry point was confirmed by "
                    "the static scanner.",
                    "",
                ]
            )
            return output
        for entry in entries[:20]:
            output.append(
                f"- **Confirmed:** {_code(entry.path)} matches an entry-point convention "
                f"({links.citation(entry.path, entry.line)})."
            )
        output.append("")
        return output

    def _modules(self, areas: Sequence[AreaSummary], links: _SourceLinks) -> list[str]:
        output = ["## Core modules", ""]
        ranked = sorted(areas, key=lambda item: (-item.file_count, item.area))
        for area in ranked[:12]:
            output.append(
                f"- **Inferred:** {_code(area.area)} is a module area with "
                f"{area.file_count} indexed files "
                f"and {area.symbol_count} extracted symbols; representative source: "
                f"{links.citation(area.representative_path, area.representative_line)}."
            )
        if not ranked:
            output.append("**Needs review:** The scan did not index any source modules.")
        output.append("")
        return output

    def _runtime_flow(
        self,
        entries: Sequence[EntryPoint],
        dependencies_by_source: Mapping[str, tuple[ResolvedDependency, ...]],
        links: _SourceLinks,
    ) -> list[str]:
        output = ["## Runtime and data flow", ""]
        flows = 0
        for entry in entries[:8]:
            deps = dependencies_by_source.get(entry.path, ())
            if not deps:
                continue
            targets = ", ".join(_code(dep.target_path or dep.raw_target) for dep in deps[:4])
            output.append(
                f"- **Inferred:** {_code(entry.path)} begins a static dependency flow toward "
                f"{targets} "
                f"({links.citation(entry.path, deps[0].line)})."
            )
            flows += 1
        if not flows:
            output.append(
                "**Needs review:** Static imports did not establish a reliable end-to-end runtime "
                "flow. Dynamic dispatch and runtime configuration are outside this heuristic scan."
            )
        output.append("")
        return output

    def _dependencies(
        self,
        facts: _DependencyFacts,
        links: _SourceLinks,
    ) -> list[str]:
        target_counts = facts.external_counts
        first = facts.external_first
        output = ["## External dependencies", ""]
        if not target_counts:
            output.extend(
                ["**Needs review:** No static dependency declarations were extracted.", ""]
            )
            return output
        output.extend(["| Dependency | References | Evidence |", "|---|---:|---|"])
        for target, count in target_counts.most_common(20):
            dep = first[target]
            output.append(
                f"| {_code(target)} | {count} | {links.citation(dep.source_path, dep.line)} |"
            )
        output.append("")
        return output

    def _dependency_facts(
        self,
        files: Sequence[FileSummary],
        entries: Sequence[EntryPoint],
        dependencies: Iterable[ResolvedDependency],
    ) -> _DependencyFacts:
        local_roots: set[str] = set()
        for file in files:
            parts = PurePosixPath(file.path).parts
            if parts and parts[0] in {"src", "lib"} and len(parts) > 1:
                local_roots.add(parts[1].casefold())
            elif parts:
                local_roots.add(PurePosixPath(parts[0]).stem.casefold())
        standard_library = {name.casefold() for name in getattr(sys, "stdlib_module_names", ())}
        runtime_paths = {entry.path for entry in entries[:8]}
        runtime: dict[str, list[ResolvedDependency]] = defaultdict(list)
        target_counts: Counter[str] = Counter()
        first: dict[str, ResolvedDependency] = {}
        for dependency in dependencies:
            if dependency.source_path in runtime_paths:
                candidates = runtime[dependency.source_path]
                candidates.append(dependency)
                candidates.sort(key=lambda item: (item.line, item.raw_target, item.kind))
                del candidates[4:]
            if (
                dependency.target_path is None
                and not dependency.candidates
                and self._is_external_target(dependency.raw_target, local_roots, standard_library)
            ):
                target_counts[dependency.raw_target] += 1
                current = first.get(dependency.raw_target)
                if current is None or (
                    dependency.source_path,
                    dependency.line,
                    dependency.kind,
                ) < (current.source_path, current.line, current.kind):
                    first[dependency.raw_target] = dependency
        return _DependencyFacts(
            {path: tuple(values) for path, values in runtime.items()},
            target_counts,
            first,
        )

    @staticmethod
    def _is_external_target(
        target: str,
        local_roots: set[str],
        standard_library: set[str],
    ) -> bool:
        target = target.strip().strip("'\"")
        if not target or target.startswith((".", "/")):
            return False
        root = re.split(r"[./]", target, maxsplit=1)[0].casefold()
        return bool(root and root not in local_roots and root not in standard_library)

    def _configuration(self, files: Sequence[FileSummary], links: _SourceLinks) -> list[str]:
        configs = [file for file in files if _is_config(file.path)]
        output = ["## Configuration and environment", ""]
        if not configs:
            output.extend(["**Needs review:** No conventional configuration file was indexed.", ""])
            return output
        for file in configs[:20]:
            output.append(
                f"- **Confirmed:** {_code(file.path)} is a configuration or build file "
                f"({links.citation(file.path, file.first_line)})."
            )
        output.append("")
        return output

    def _tests(self, files: Sequence[FileSummary], links: _SourceLinks) -> list[str]:
        tests = [file for file in files if _is_test(file.path)]
        output = ["## Tests and quality gates", ""]
        if not tests:
            output.extend(["**Needs review:** No conventional test path was indexed.", ""])
            return output
        by_group = Counter(_top_group(file.path) for file in tests)
        witness_by_group: dict[str, FileSummary] = {}
        for file in tests:
            witness_by_group.setdefault(_top_group(file.path), file)
        for group, count in sorted(by_group.items()):
            witness = witness_by_group[group]
            output.append(
                f"- **Confirmed:** {_code(group)} contains {count} test-like files; example: "
                f"{links.citation(witness.path, witness.first_line)}."
            )
        output.append("")
        return output

    def _risks(
        self,
        stats: _MapStats,
        files: Sequence[FileSummary],
        links: _SourceLinks,
    ) -> list[str]:
        output = ["## High-change or high-risk areas", ""]
        largest = sorted(files, key=lambda file: (-file.line_count, file.path))[:5]
        for file in largest:
            output.append(
                f"- **Inferred:** {_code(file.path)} is relatively large "
                f"({file.line_count} lines) and "
                f"may deserve focused review "
                f"({links.citation(file.path, file.first_line)})."
            )
        if stats.skipped:
            detail = ", ".join(
                f"{reason}={count}" for reason, count in sorted(stats.skipped.items())
            )
            output.append(
                f"- **Needs review:** The scanner intentionally skipped files ({detail}); "
                "conclusions do not cover excluded content."
            )
        output.append(
            "- **Needs review:** Import and call relationships are static approximations; "
            "reflection, generated code, dependency injection, and runtime plugins may change "
            "actual behavior."
        )
        output.append("")
        return output

    def _reading_order(
        self,
        files: Sequence[FileSummary],
        entry_paths: set[str],
        links: _SourceLinks,
    ) -> list[str]:
        readmes = [
            file for file in files if PurePosixPath(file.path).name.lower().startswith("readme")
        ]
        configs = [
            file
            for file in files
            if PurePosixPath(file.path).name.lower() in _CONFIG_NAMES
            and not PurePosixPath(file.path).name.lower().endswith(".lock")
        ]
        entries = [file for file in files if file.path in entry_paths]
        symbol_rich = sorted(
            (
                file
                for file in files
                if not _is_test(file.path)
                and _top_group(file.path) not in {".github", "docs"}
                and not _is_config(file.path)
            ),
            key=lambda file: (-file.symbol_count, file.path),
        )
        selected: list[FileSummary] = []
        seen: set[str] = set()
        for file in [*readmes, *configs, *entries, *symbol_rich]:
            if file.path not in seen:
                seen.add(file.path)
                selected.append(file)
            if len(selected) >= 12:
                break
        output = ["## Suggested reading order", ""]
        for number, file in enumerate(selected, 1):
            reason = "documentation/build context"
            if file.path in entry_paths:
                reason = "entry-point behavior"
            elif file.symbol_count:
                reason = "core symbols and module boundaries"
            output.append(
                f"{number}. **Inferred:** Read "
                f"{links.citation(file.path, file.first_line)} for "
                f"{reason}."
            )
        if not selected:
            output.append("**Needs review:** No reading order can be proposed from an empty index.")
        output.append("")
        return output

    def _metadata(self, root: Path, stats: _MapStats, links: _SourceLinks) -> list[str]:
        language_text = ", ".join(
            f"{name} ({count})" for name, count in sorted(stats.languages.items())
        )
        return [
            "## Generated metadata",
            "",
            f"- Generator: RepoLocus {__version__}",
            f"- Repository: {_code(root.name)}",
            f"- Indexed files: {stats.indexed_files}",
            f"- Indexed bytes: {stats.indexed_bytes}",
            f"- Languages: {language_text or 'none'}",
            f"- Source link base: {links.description}",
            "- Evidence labels: **Confirmed** = direct source fact; **Inferred** = deterministic "
            "static-analysis inference; **Needs review** = insufficient or incomplete evidence.",
            "",
        ]


def _file_summary(file: ScannedFile) -> FileSummary:
    return FileSummary(
        path=file.path,
        language=file.language,
        size_bytes=file.size_bytes,
        line_count=file.line_count,
        is_entry_point=file.is_entry_point,
        symbol_count=max(len(file.symbols), file.cached_symbol_count),
        first_line=_first_line_for(file),
    )


def _area_summaries(summaries: Sequence[FileSummary]) -> list[AreaSummary]:
    grouped: dict[str, list[FileSummary]] = defaultdict(list)
    for summary in summaries:
        grouped[_top_group(summary.path)].append(summary)
    output: list[AreaSummary] = []
    for area, files in sorted(grouped.items()):
        languages = Counter(file.language for file in files)
        representative = min(files, key=lambda item: item.path)
        output.append(
            AreaSummary(
                area=area,
                file_count=len(files),
                symbol_count=sum(file.symbol_count for file in files),
                languages=tuple(sorted(languages.items())),
                representative_path=representative.path,
                representative_line=representative.first_line,
            )
        )
    return output


def _entry_points(files: Iterable[ScannedFile]) -> list[EntryPoint]:
    output: list[EntryPoint] = []
    for file in files:
        if not file.is_entry_point:
            continue
        symbol = next(
            (
                item
                for item in file.symbols
                if item.name.casefold() in {"main", "__main__"}
                or item.name.casefold().endswith(".main")
            ),
            None,
        )
        output.append(EntryPoint(file.path, symbol.start_line if symbol else _first_line_for(file)))
    return sorted(output, key=lambda item: item.path)
