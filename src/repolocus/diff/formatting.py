"""Deterministic, untrusted-text-safe Architecture Diff Markdown."""

from __future__ import annotations

from html import escape as html_escape

from repolocus.security.display import escape_untrusted_display

from .models import RepositoryDiff, SourceEvidence


def _visible(value: str) -> str:
    escaped = html_escape(escape_untrusted_display(value), quote=False)
    for marker in ("\\", "`", "*", "_", "[", "]", "<", ">", "|"):
        escaped = escaped.replace(marker, f"\\{marker}")
    return escaped.replace("@", "&#64;")


def _code(value: str) -> str:
    safe = _visible(value).replace("`", "'")
    return f"`{safe}`"


def _citation(evidence: SourceEvidence | None) -> str:
    return "-" if evidence is None else _code(evidence.citation)


def _section(lines: list[str], title: str, items: list[str]) -> None:
    lines.extend([f"## {title}", ""])
    lines.extend(items or ["None."])
    lines.append("")


def render_diff_markdown(
    diff: RepositoryDiff,
    old_label: str = "old",
    new_label: str = "new",
) -> str:
    """Render a shared CLI/Action report without links or raw untrusted markup."""

    if not isinstance(diff, RepositoryDiff):
        raise TypeError("diff must be a RepositoryDiff")
    if not isinstance(old_label, str) or not old_label:
        raise ValueError("old_label must not be empty")
    if not isinstance(new_label, str) or not new_label:
        raise ValueError("new_label must not be empty")
    status = "degraded" if diff.compatibility.degraded else "compatible"
    lines = [
        f"# Architecture Diff: {_visible(old_label)} to {_visible(new_label)}",
        "",
        f"- Generations: {_code(str(diff.old_generation))} to {_code(str(diff.new_generation))}",
        f"- Comparison: **{status}**",
        f"- Empty: {_code(str(diff.is_empty).lower())}",
        "",
    ]
    if diff.compatibility.reasons:
        lines.extend(["## Compatibility notes", ""])
        lines.extend(f"- {_visible(reason)}" for reason in diff.compatibility.reasons)
        lines.append("")

    lines.extend(
        [
            "## Summary",
            "",
            "| Area | Added | Removed | Changed or moved |",
            "|---|---:|---:|---:|",
            f"| Files | {len(diff.added_files)} | {len(diff.removed_files)} | "
            f"{len(diff.changed_files) + len(diff.moved_files)} |",
            f"| Symbols | {len(diff.added_symbols)} | {len(diff.removed_symbols)} | "
            f"{len(diff.moved_symbols)} |",
            f"| Entry points | {len(diff.added_entry_points)} | "
            f"{len(diff.removed_entry_points)} | 0 |",
            f"| Dependency edges | {len(diff.added_dependencies)} | "
            f"{len(diff.removed_dependencies)} | 0 |",
            "",
        ]
    )

    file_items = [f"- Added {_citation(item.evidence)}" for item in diff.added_files] + [
        f"- Removed {_citation(item.evidence)}" for item in diff.removed_files
    ]
    file_items.extend(
        f"- Changed {_citation(item.old.evidence)} to {_citation(item.new.evidence)}"
        for item in diff.changed_files
        if item.old is not None and item.new is not None
    )
    file_items.extend(
        f"- Moved {_citation(item.old.evidence)} to {_citation(item.new.evidence)} "
        f"({_code(item.confidence)})"
        for item in diff.moved_files
    )
    _section(lines, "Files", file_items)

    symbol_items = [
        f"- Added {_code(item.kind)} {_code(item.name)} at {_citation(item.evidence)}"
        for item in diff.added_symbols
    ] + [
        f"- Removed {_code(item.kind)} {_code(item.name)} at {_citation(item.evidence)}"
        for item in diff.removed_symbols
    ]
    symbol_items.extend(
        f"- Moved {_code(item.old.kind)} {_code(item.old.name)} from "
        f"{_citation(item.old.evidence)} to {_citation(item.new.evidence)} "
        f"({_code(item.confidence)})"
        for item in diff.moved_symbols
    )
    _section(lines, "Symbols", symbol_items)

    entry_items = [f"- Added {_citation(item.evidence)}" for item in diff.added_entry_points] + [
        f"- Removed {_citation(item.evidence)}" for item in diff.removed_entry_points
    ]
    _section(lines, "Entry points", entry_items)

    dependency_items: list[str] = []
    for prefix, dependencies in (
        ("Added", diff.added_dependencies),
        ("Removed", diff.removed_dependencies),
    ):
        for dependency in dependencies:
            target = dependency.target_path or dependency.raw_target
            candidates = (
                " candidates=" + ", ".join(_code(candidate) for candidate in dependency.candidates)
                if dependency.candidates
                else ""
            )
            dependency_items.append(
                f"- {prefix} {_code(dependency.kind)} edge {_citation(dependency.evidence)} "
                f"to {_code(target)} ({_code(dependency.confidence)}){candidates}"
            )
    _section(lines, "Dependency edges", dependency_items)

    lines.extend(
        [
            "## Classified file changes",
            "",
            f"- Configuration: {len(diff.configuration_changes)}",
            f"- Security boundary: {len(diff.security_boundary_changes)}",
            f"- Test area: {len(diff.test_area_changes)}",
            "",
        ]
    )
    review_items = [
        f"{number}. P{item.priority} {_code(item.area)}: {_visible(item.reason)}; "
        f"old={_citation(item.old)}, new={_citation(item.new)}"
        for number, item in enumerate(diff.review_order, 1)
    ]
    _section(lines, "Suggested review order", review_items)
    return "\n".join(lines).rstrip() + "\n"
