"""Python parser backed by the standard-library AST."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath

from devpilot.models import Dependency, Symbol
from devpilot.parsers.base import ParseResult
from devpilot.parsers.chunking import Region, semantic_chunks

_FALLBACK_SYMBOL_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<async>async\s+)?(?P<kind>def|class)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?P<tail>[^\n]*)",
    re.MULTILINE,
)
_FALLBACK_IMPORT_RE = re.compile(
    r"^[ \t]*(?:from\s+(?P<from>[.\w]+)\s+import\s+|import\s+(?P<import>[\w.]+))",
    re.MULTILINE,
)


def _unparse(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return ""


def _function_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    signature = f"{prefix} {node.name}({_unparse(node.args)})"
    if node.returns is not None:
        signature += f" -> {_unparse(node.returns)}"
    return signature


def _class_signature(node: ast.ClassDef) -> str:
    arguments = [_unparse(base) for base in node.bases]
    arguments.extend(
        f"{keyword.arg}={_unparse(keyword.value)}"
        for keyword in node.keywords
        if keyword.arg is not None
    )
    suffix = f"({', '.join(arguments)})" if arguments else ""
    return f"class {node.name}{suffix}"


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.symbols: list[Symbol] = []
        self.dependencies: list[Dependency] = []
        self._scope: list[tuple[str, str]] = []
        self.has_main_guard = False

    def _qualified(self, name: str) -> str:
        return ".".join([*(scope[0] for scope in self._scope), name])

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        name = self._qualified(node.name)
        self.symbols.append(
            Symbol(
                name=name,
                kind="class",
                path=self.path,
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                signature=_class_signature(node),
            )
        )
        self._scope.append((node.name, "class"))
        self.generic_visit(node)
        self._scope.pop()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        name = self._qualified(node.name)
        in_class = any(scope_kind == "class" for _, scope_kind in self._scope)
        kind = "method" if in_class else "function"
        self.symbols.append(
            Symbol(
                name=name,
                kind=kind,
                path=self.path,
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                signature=_function_signature(node),
            )
        )
        self._scope.append((node.name, kind))
        self.generic_visit(node)
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.dependencies.append(Dependency(self.path, alias.name, "import", node.lineno))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        prefix = "." * node.level
        if node.module:
            targets = [f"{prefix}{node.module}"]
        else:
            targets = [f"{prefix}{alias.name}" for alias in node.names]
        for target in targets:
            self.dependencies.append(Dependency(self.path, target, "import", node.lineno))

    def visit_If(self, node: ast.If) -> None:
        if _is_main_guard(node.test):
            self.has_main_guard = True
        self.generic_visit(node)


def _is_main_guard(test: ast.AST) -> bool:
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    left, right = test.left, test.comparators[0]
    pairs = ((left, right), (right, left))
    return any(
        isinstance(name, ast.Name)
        and name.id == "__name__"
        and isinstance(value, ast.Constant)
        and value.value == "__main__"
        for name, value in pairs
    )


def _fallback(path: str, text: str) -> tuple[list[Symbol], list[Dependency], bool]:
    symbols: list[Symbol] = []
    for match in _FALLBACK_SYMBOL_RE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        kind = "class" if match.group("kind") == "class" else "function"
        async_prefix = "async " if match.group("async") else ""
        symbols.append(
            Symbol(
                name=match.group("name"),
                kind=kind,
                path=path,
                start_line=line,
                end_line=line,
                signature=f"{async_prefix}{match.group('kind')} {match.group('name')}"
                f"{match.group('tail').rstrip(':').strip()}",
            )
        )
    dependencies: list[Dependency] = []
    for match in _FALLBACK_IMPORT_RE.finditer(text):
        target = match.group("from") or match.group("import")
        dependencies.append(
            Dependency(path, target, "import", text.count("\n", 0, match.start()) + 1)
        )
    has_main_guard = bool(
        re.search(r"\b__name__\s*==\s*['\"]__main__['\"]", text)
        or re.search(r"['\"]__main__['\"]\s*==\s*\b__name__", text)
    )
    return symbols, dependencies, has_main_guard


class PythonParser:
    """Extract Python symbols and imports without executing the source."""

    languages = frozenset({"python"})

    def parse(
        self,
        path: str,
        text: str,
        language: str,
        *,
        max_chunk_lines: int,
        max_chunk_chars: int,
    ) -> ParseResult:
        try:
            tree = ast.parse(text, filename=path, type_comments=True)
        except (SyntaxError, ValueError, TypeError):
            symbols, dependencies, has_main_guard = _fallback(path, text)
        else:
            visitor = _PythonVisitor(path)
            visitor.visit(tree)
            symbols = visitor.symbols
            dependencies = visitor.dependencies
            has_main_guard = visitor.has_main_guard

        symbols.sort(key=lambda item: (item.start_line, item.end_line, item.kind, item.name))
        dependencies = sorted(
            set(dependencies), key=lambda item: (item.line, item.target, item.kind)
        )
        regions = [Region(item.start_line, item.end_line, item.name) for item in symbols]
        chunks = semantic_chunks(
            path=path,
            text=text,
            language=language,
            regions=regions,
            max_lines=max_chunk_lines,
            max_chars=max_chunk_chars,
        )
        basename = PurePosixPath(path).name.casefold()
        conventional_entry = basename in {
            "__main__.py",
            "main.py",
            "manage.py",
            "wsgi.py",
            "asgi.py",
        }
        return ParseResult(
            symbols=tuple(symbols),
            dependencies=tuple(dependencies),
            chunks=chunks,
            is_entry_point=conventional_entry or has_main_guard,
        )
