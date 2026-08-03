"""Scoped, nested ``.gitignore`` evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from pathspec import GitIgnoreSpec


@dataclass(frozen=True, slots=True)
class _ScopedSpec:
    base: PurePosixPath
    spec: GitIgnoreSpec

    def check(self, path: PurePosixPath, *, is_dir: bool) -> bool | None:
        try:
            local = path.relative_to(self.base) if self.base.parts else path
        except ValueError:
            return None
        candidate = local.as_posix()
        if candidate == ".":
            candidate = ""
        if is_dir and candidate and not candidate.endswith("/"):
            candidate += "/"
        result = self.spec.check_file(candidate)
        return result.include


@dataclass(frozen=True, slots=True)
class IgnoreRules:
    """An immutable stack of repository- and directory-scoped ignore rules."""

    scopes: tuple[_ScopedSpec, ...] = ()

    def extend(self, base: PurePosixPath, contents: str) -> IgnoreRules:
        """Return a new stack with rules from one nested ``.gitignore``."""

        lines = contents.splitlines()
        if not lines:
            return self
        scope = _ScopedSpec(base, GitIgnoreSpec.from_lines(lines))
        return IgnoreRules((*self.scopes, scope))

    def is_ignored(self, path: PurePosixPath, *, is_dir: bool = False) -> bool:
        """Evaluate ancestor rules in Git precedence order."""

        ignored = False
        for scope in self.scopes:
            decision = scope.check(path, is_dir=is_dir)
            if decision is not None:
                ignored = decision
        return ignored


__all__ = ["IgnoreRules"]
