"""Deterministic module graph generation with strict output validation."""

from __future__ import annotations

import hashlib
import html
import os
import re
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from repolocus.models import Dependency, ScannedFile, ScanResult
from repolocus.security.display import escape_untrusted_display

_NODE_RE = re.compile(r'^\s{4}(n_[a-f0-9]{10})\["([^"\\]|\\.)*"\]$')
_EDGE_RE = re.compile(r"^\s{4}(n_[a-f0-9]{10}) --> (n_[a-f0-9]{10})$")


def _group(path: str) -> str:
    parts = PurePosixPath(path).parts
    if not parts:
        return "(root)"
    if len(parts) == 1:
        return "(root)"
    if parts[0] in {"src", "lib"} and len(parts) >= 3:
        package = parts[1]
        if len(parts) >= 4:
            return f"{package}.{parts[2]}"
        return package
    return parts[0]


def _node_id(label: str) -> str:
    return "n_" + hashlib.sha1(label.encode("utf-8"), usedforsecurity=False).hexdigest()[:10]


def _escape_label(label: str) -> str:
    escaped = html.escape(escape_untrusted_display(label), quote=False)
    return escaped.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _markdown_cell(value: str) -> str:
    """Escape repository-controlled text for a Markdown table cell."""

    return (
        html.escape(escape_untrusted_display(value), quote=False)
        .replace("`", "'")
        .replace("|", "¦")
    )


def _source_link(path: str, line: int, prefix: str = "") -> str:
    target = PurePosixPath(path)
    if prefix:
        target = PurePosixPath(prefix) / target
    escaped = quote(target.as_posix(), safe="/._-")
    visible = html.escape(escape_untrusted_display(f"{path}:{line}"), quote=False)
    visible = visible.replace("\\", "\\\\")
    for marker in ("[", "]", "|"):
        visible = visible.replace(marker, f"\\{marker}")
    return f"[{visible}]({escaped}#L{line})"


def validate_mermaid(source: str) -> tuple[bool, str]:
    """Validate the deliberately small Mermaid subset emitted by this module."""

    lines = source.rstrip().splitlines()
    if not lines or lines[0] != "flowchart LR":
        return False, "diagram must start with 'flowchart LR'"
    nodes: set[str] = set()
    edges: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        node_match = _NODE_RE.fullmatch(line)
        if node_match:
            if node_match.group(1) in nodes:
                return False, f"duplicate node: {node_match.group(1)}"
            nodes.add(node_match.group(1))
            continue
        edge_match = _EDGE_RE.fullmatch(line)
        if edge_match:
            edges.append((edge_match.group(1), edge_match.group(2)))
            continue
        return False, f"unsupported Mermaid statement: {line.strip()}"
    if not nodes:
        return False, "diagram has no nodes"
    for source_id, target_id in edges:
        if source_id not in nodes or target_id not in nodes:
            return False, "edge references an unknown node"
    return True, "ok"


class MermaidGenerator:
    """Turn top-level module dependencies into a reproducible Mermaid document."""

    def __init__(self, max_nodes: int = 20, max_edges: int = 40) -> None:
        self.max_nodes = max(2, max_nodes)
        self.max_edges = max(1, max_edges)

    def generate(
        self,
        result: ScanResult,
        *,
        destination: Path | str | None = None,
    ) -> str:
        """Render a graph with repository-root-relative links by default."""

        link_prefix = self._link_prefix(result.root, destination)
        source = self.generate_source(result)
        valid, reason = validate_mermaid(source)
        if not valid:
            source = self._fallback_source(result)
            valid, fallback_reason = validate_mermaid(source)
            if not valid:  # pragma: no cover - defensive invariant
                raise ValueError(f"could not produce valid Mermaid: {reason}; {fallback_reason}")
        evidence = self._evidence_table(result, link_prefix)
        link_contract = (
            "Source links are relative to this generated document."
            if destination is not None
            else "Source links are repository-root-relative."
        )
        return "\n".join(
            [
                "# Architecture",
                "",
                "<!-- Generator: RepoLocus; deterministic static graph. -->",
                "",
                "This graph is a static approximation. Nodes and edges are derived from "
                "indexed paths and import statements; runtime dispatch may differ.",
                link_contract,
                "",
                "```mermaid",
                source.rstrip(),
                "```",
                "",
                "## Source evidence",
                "",
                evidence,
                "",
            ]
        )

    @staticmethod
    def _link_prefix(root: Path, destination: Path | str | None) -> str:
        if destination is None:
            return ""
        requested = Path(destination).expanduser()
        if not requested.is_absolute():
            requested = root / requested
        requested = requested.resolve(strict=False)
        relative_root = Path(os.path.relpath(root, start=requested.parent)).as_posix()
        return "" if relative_root == "." else relative_root

    def generate_source(self, result: ScanResult) -> str:
        selected, ranked_edges = self._graph_facts(result)
        lines = ["flowchart LR"]
        for group in sorted(selected):
            lines.append(f'    {_node_id(group)}["{_escape_label(group)}"]')
        for source_group, target_group, _count, _dependency in ranked_edges:
            lines.append(f"    {_node_id(source_group)} --> {_node_id(target_group)}")
        return "\n".join(lines) + "\n"

    def _graph_facts(
        self, result: ScanResult
    ) -> tuple[set[str], list[tuple[str, str, int, Dependency]]]:
        """Return the selected nodes and an import witness for every emitted edge."""

        groups: dict[str, list[ScannedFile]] = defaultdict(list)
        for file in result.files:
            groups[_group(file.path)].append(file)
        ranked_groups = sorted(groups, key=lambda key: (-len(groups[key]), key))[: self.max_nodes]
        selected = set(ranked_groups)
        aliases = self._aliases(groups)
        edges: Counter[tuple[str, str]] = Counter()
        witnesses: dict[tuple[str, str], Dependency] = {}
        for file in result.files:
            source_group = _group(file.path)
            if source_group not in selected:
                continue
            for dep in file.dependencies:
                target_group = self._resolve_target(dep.target, aliases)
                if target_group and target_group in selected and target_group != source_group:
                    edge = (source_group, target_group)
                    edges[edge] += 1
                    witness = witnesses.get(edge)
                    if witness is None or (dep.source_path, dep.line, dep.target) < (
                        witness.source_path,
                        witness.line,
                        witness.target,
                    ):
                        witnesses[edge] = dep
        ranked_edges = [
            (source_group, target_group, count, witnesses[(source_group, target_group)])
            for (source_group, target_group), count in sorted(
                edges.items(), key=lambda item: (-item[1], item[0])
            )[: self.max_edges]
        ]
        return selected, ranked_edges

    def _aliases(self, groups: dict[str, list[ScannedFile]]) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for group, files in groups.items():
            for file in files:
                path = PurePosixPath(file.path)
                parts = list(path.with_suffix("").parts)
                if parts and parts[0] in {"src", "lib"}:
                    parts = parts[1:]
                if parts and parts[-1] == "__init__":
                    parts = parts[:-1]
                if not parts or path.suffix.lower() not in {
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
                }:
                    continue
                module = ".".join(part.lower().replace("-", "_") for part in parts)
                aliases.setdefault(module, group)
        return aliases

    def _resolve_target(self, target: str, aliases: dict[str, str]) -> str | None:
        normalized = target.strip().lstrip(".").replace("/", ".").replace("-", "_").lower()
        for candidate in sorted(aliases, key=len, reverse=True):
            if normalized == candidate or normalized.startswith(candidate + "."):
                return aliases[candidate]
        return None

    def _fallback_source(self, result: ScanResult) -> str:
        groups = Counter(_group(file.path) for file in result.files)
        if not groups:
            return 'flowchart LR\n    n_0000000000["empty repository"]\n'
        selected = [group for group, _ in groups.most_common(min(8, self.max_nodes))]
        lines = ["flowchart LR"]
        for group in sorted(selected):
            lines.append(f'    {_node_id(group)}["{_escape_label(group)}"]')
        return "\n".join(lines) + "\n"

    def _evidence_table(self, result: ScanResult, link_prefix: str = "") -> str:
        witnesses: dict[str, tuple[str, int]] = {}
        for file in sorted(result.files, key=lambda item: item.path):
            group = _group(file.path)
            line = next(
                (i for i, value in enumerate(file.text.splitlines(), 1) if value.strip()), 1
            )
            witnesses.setdefault(group, (file.path, line))
        if not witnesses:
            return "No source files were indexed."
        lines = ["### Node evidence", "", "| Node | Representative source |", "|---|---|"]
        for group, (path, line) in sorted(witnesses.items()):
            lines.append(f"| `{_markdown_cell(group)}` | {_source_link(path, line, link_prefix)} |")
        _selected, ranked_edges = self._graph_facts(result)
        lines.extend(
            [
                "",
                "### Edge evidence",
                "",
                "| Edge | Import target | Import evidence | Observations |",
                "|---|---|---|---:|",
            ]
        )
        if not ranked_edges:
            lines.append("| (no resolved cross-node edges) | — | — | 0 |")
        for source_group, target_group, count, dependency in ranked_edges:
            edge = f"{source_group} -> {target_group}"
            lines.append(
                f"| `{_markdown_cell(edge)}` | `{_markdown_cell(dependency.target)}` | "
                f"{_source_link(dependency.source_path, dependency.line, link_prefix)} | "
                f"{count} |"
            )
        return "\n".join(lines)
