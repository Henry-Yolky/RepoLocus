"""Generate a stable PROJECT_MAP.md directly from scanner evidence."""

from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from html import escape as html_escape
from pathlib import PurePosixPath
from urllib.parse import quote

from devpilot import __version__
from devpilot.models import Dependency, ScannedFile, ScanResult
from devpilot.security.display import escape_untrusted_display

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


def _citation(path: str, line: int, label: str | None = None) -> str:
    """Return a repository-relative Markdown line link."""

    visible = _markdown_text(label or f"{path}:{line}")
    escaped = quote(path, safe="/._-")
    return f"[{visible}]({escaped}#L{line})"


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


def _first_content_paragraph(file: ScannedFile) -> tuple[str, int] | None:
    lines = file.text.splitlines()
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


class ProjectMapGenerator:
    """Render a conservative map from facts observed during a repository scan."""

    def generate(self, result: ScanResult) -> str:
        files = sorted(result.files, key=lambda item: item.path)
        by_path = {item.path: item for item in files}
        lines: list[str] = [
            "# Project Map",
            "",
            f"<!-- Generator: DevPilot {__version__}; deterministic source map. -->",
            "",
        ]
        lines.extend(self._overview(result, by_path))
        lines.extend(self._quick_start(files))
        lines.extend(self._layout(files))
        lines.extend(self._entry_points(files))
        lines.extend(self._modules(files))
        lines.extend(self._runtime_flow(files))
        lines.extend(self._dependencies(files))
        lines.extend(self._configuration(files))
        lines.extend(self._tests(files))
        lines.extend(self._risks(result, files))
        lines.extend(self._reading_order(files))
        lines.extend(self._metadata(result))
        return "\n".join(lines).rstrip() + "\n"

    def _overview(self, result: ScanResult, by_path: dict[str, ScannedFile]) -> list[str]:
        readme = next((by_path[name] for name in _README_NAMES if name in by_path), None)
        if readme:
            paragraph = _first_content_paragraph(readme)
            if paragraph:
                text, line = paragraph
                return [
                    "## What this repository does",
                    "",
                    f"**Confirmed:** {text} ({_citation(readme.path, line)})",
                    "",
                ]
        languages = Counter(file.language for file in result.files if file.language != "Text")
        top = ", ".join(name for name, _ in languages.most_common(3)) or "text"
        return [
            "## What this repository does",
            "",
            f"**Needs review:** No descriptive README paragraph was found. The scanned files "
            f"primarily use {top}; inspect the entry points below before assigning a purpose.",
            "",
        ]

    def _quick_start(self, files: list[ScannedFile]) -> list[str]:
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
            line = _first_line_for(file)
            output.append(f"- **Confirmed:** Start with {_citation(file.path, line)}.")
        output.append("")
        return output

    def _layout(self, files: list[ScannedFile]) -> list[str]:
        groups: dict[str, list[ScannedFile]] = defaultdict(list)
        for file in files:
            groups[_top_group(file.path)].append(file)
        output = [
            "## Repository layout",
            "",
            "| Area | Files | Main languages | Evidence |",
            "|---|---:|---|---|",
        ]
        for group in sorted(groups):
            grouped = groups[group]
            languages = Counter(item.language for item in grouped)
            language_text = ", ".join(name for name, _ in languages.most_common(3))
            witness = min(grouped, key=lambda item: item.path)
            output.append(
                f"| {_code(group)} | {len(grouped)} | {_markdown_text(language_text)} | "
                f"{_citation(witness.path, _first_line_for(witness))} |"
            )
        output.append("")
        return output

    def _entry_points(self, files: list[ScannedFile]) -> list[str]:
        entries = [file for file in files if file.is_entry_point]
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
        for file in entries[:20]:
            symbol = next(
                (item for item in file.symbols if item.name in {"main", "__main__"}), None
            )
            line = symbol.start_line if symbol else _first_line_for(file)
            output.append(
                f"- **Confirmed:** {_code(file.path)} matches an entry-point convention "
                f"({_citation(file.path, line)})."
            )
        output.append("")
        return output

    def _modules(self, files: list[ScannedFile]) -> list[str]:
        groups: dict[str, list[ScannedFile]] = defaultdict(list)
        for file in files:
            groups[_top_group(file.path)].append(file)
        output = ["## Core modules", ""]
        ranked = sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))
        for group, grouped in ranked[:12]:
            symbol_count = sum(len(file.symbols) for file in grouped)
            witness = max(grouped, key=lambda file: (len(file.symbols), -len(file.path)))
            output.append(
                f"- **Inferred:** {_code(group)} is a module area with "
                f"{len(grouped)} indexed files "
                f"and {symbol_count} extracted symbols; representative source: "
                f"{_citation(witness.path, _first_line_for(witness))}."
            )
        if not ranked:
            output.append("**Needs review:** The scan did not index any source modules.")
        output.append("")
        return output

    def _runtime_flow(self, files: list[ScannedFile]) -> list[str]:
        entries = [file for file in files if file.is_entry_point]
        output = ["## Runtime and data flow", ""]
        flows = 0
        for entry in entries[:8]:
            deps = sorted(entry.dependencies, key=lambda item: (item.line, item.target))
            if not deps:
                continue
            targets = ", ".join(_code(dep.target) for dep in deps[:4])
            output.append(
                f"- **Inferred:** {_code(entry.path)} begins a static dependency flow toward "
                f"{targets} "
                f"({_citation(entry.path, deps[0].line)})."
            )
            flows += 1
        if not flows:
            output.append(
                "**Needs review:** Static imports did not establish a reliable end-to-end runtime "
                "flow. Dynamic dispatch and runtime configuration are outside this heuristic scan."
            )
        output.append("")
        return output

    def _dependencies(self, files: list[ScannedFile]) -> list[str]:
        dependencies: list[Dependency] = [dep for file in files for dep in file.dependencies]
        local_roots: set[str] = set()
        for file in files:
            parts = PurePosixPath(file.path).parts
            if parts and parts[0] in {"src", "lib"} and len(parts) > 1:
                local_roots.add(parts[1].casefold())
            elif parts:
                local_roots.add(PurePosixPath(parts[0]).stem.casefold())
        standard_library = {name.casefold() for name in getattr(sys, "stdlib_module_names", ())}
        dependencies = [
            dep
            for dep in dependencies
            if self._is_external_dependency(dep, local_roots, standard_library)
        ]
        target_counts = Counter(dep.target for dep in dependencies)
        first: dict[str, Dependency] = {}
        for dep in sorted(
            dependencies, key=lambda item: (item.target, item.source_path, item.line)
        ):
            first.setdefault(dep.target, dep)
        output = ["## External dependencies", ""]
        if not target_counts:
            output.extend(
                ["**Needs review:** No static dependency declarations were extracted.", ""]
            )
            return output
        output.extend(["| Dependency | References | Evidence |", "|---|---:|---|"])
        for target, count in target_counts.most_common(20):
            dep = first[target]
            output.append(f"| {_code(target)} | {count} | {_citation(dep.source_path, dep.line)} |")
        output.append("")
        return output

    @staticmethod
    def _is_external_dependency(
        dependency: Dependency,
        local_roots: set[str],
        standard_library: set[str],
    ) -> bool:
        target = dependency.target.strip().strip("'\"")
        if not target or target.startswith((".", "/")):
            return False
        root = re.split(r"[./]", target, maxsplit=1)[0].casefold()
        return bool(root and root not in local_roots and root not in standard_library)

    def _configuration(self, files: list[ScannedFile]) -> list[str]:
        configs = [file for file in files if _is_config(file.path)]
        output = ["## Configuration and environment", ""]
        if not configs:
            output.extend(["**Needs review:** No conventional configuration file was indexed.", ""])
            return output
        for file in configs[:20]:
            output.append(
                f"- **Confirmed:** {_code(file.path)} is a configuration or build file "
                f"({_citation(file.path, _first_line_for(file))})."
            )
        output.append("")
        return output

    def _tests(self, files: list[ScannedFile]) -> list[str]:
        tests = [file for file in files if _is_test(file.path)]
        output = ["## Tests and quality gates", ""]
        if not tests:
            output.extend(["**Needs review:** No conventional test path was indexed.", ""])
            return output
        by_group = Counter(_top_group(file.path) for file in tests)
        witness_by_group: dict[str, ScannedFile] = {}
        for file in tests:
            witness_by_group.setdefault(_top_group(file.path), file)
        for group, count in sorted(by_group.items()):
            witness = witness_by_group[group]
            output.append(
                f"- **Confirmed:** {_code(group)} contains {count} test-like files; example: "
                f"{_citation(witness.path, _first_line_for(witness))}."
            )
        output.append("")
        return output

    def _risks(self, result: ScanResult, files: list[ScannedFile]) -> list[str]:
        output = ["## High-change or high-risk areas", ""]
        largest = sorted(files, key=lambda file: (-file.line_count, file.path))[:5]
        for file in largest:
            output.append(
                f"- **Inferred:** {_code(file.path)} is relatively large "
                f"({file.line_count} lines) and "
                f"may deserve focused review ({_citation(file.path, _first_line_for(file))})."
            )
        if result.stats.skipped:
            detail = ", ".join(
                f"{reason}={count}" for reason, count in sorted(result.stats.skipped.items())
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

    def _reading_order(self, files: list[ScannedFile]) -> list[str]:
        readmes = [
            file for file in files if PurePosixPath(file.path).name.lower().startswith("readme")
        ]
        configs = [
            file
            for file in files
            if PurePosixPath(file.path).name.lower() in _CONFIG_NAMES
            and not PurePosixPath(file.path).name.lower().endswith(".lock")
        ]
        entries = [file for file in files if file.is_entry_point]
        symbol_rich = sorted(
            (
                file
                for file in files
                if not _is_test(file.path)
                and _top_group(file.path) not in {".github", "docs"}
                and not _is_config(file.path)
            ),
            key=lambda file: (-len(file.symbols), file.path),
        )
        selected: list[ScannedFile] = []
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
            if file.is_entry_point:
                reason = "entry-point behavior"
            elif file.symbols:
                reason = "core symbols and module boundaries"
            output.append(
                f"{number}. **Inferred:** Read {_citation(file.path, _first_line_for(file))} for "
                f"{reason}."
            )
        if not selected:
            output.append("**Needs review:** No reading order can be proposed from an empty index.")
        output.append("")
        return output

    def _metadata(self, result: ScanResult) -> list[str]:
        language_text = ", ".join(
            f"{name} ({count})" for name, count in sorted(result.stats.languages.items())
        )
        return [
            "## Generated metadata",
            "",
            f"- Generator: DevPilot {__version__}",
            f"- Repository: {_code(result.root.name)}",
            f"- Indexed files: {result.stats.indexed_files}",
            f"- Indexed bytes: {result.stats.indexed_bytes}",
            f"- Languages: {language_text or 'none'}",
            "- Evidence labels: **Confirmed** = direct source fact; **Inferred** = deterministic "
            "static-analysis inference; **Needs review** = insufficient or incomplete evidence.",
            "",
        ]
