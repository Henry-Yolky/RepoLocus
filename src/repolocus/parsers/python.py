"""Python parser backed by the standard-library AST."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from bisect import bisect_right
from pathlib import PurePosixPath

from repolocus.models import Dependency, Symbol
from repolocus.parsers.base import (
    DEFAULT_MAX_CHUNKS_PER_FILE,
    DEFAULT_MAX_DEPENDENCIES_PER_FILE,
    DEFAULT_MAX_SYMBOLS_PER_FILE,
    ParseResult,
)
from repolocus.parsers.chunking import Region, semantic_chunks

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
    def __init__(self, path: str, *, max_symbols: int, max_dependencies: int) -> None:
        self.path = path
        self.symbols: list[Symbol] = []
        self.dependencies: list[Dependency] = []
        self._seen_symbols: set[Symbol] = set()
        self._seen_dependencies: set[Dependency] = set()
        self._max_symbols = max_symbols
        self._max_dependencies = max_dependencies
        self._scope: list[tuple[str, str]] = []
        self.has_main_guard = False

    def _add_symbol(self, symbol: Symbol) -> None:
        if symbol in self._seen_symbols:
            return
        if len(self._seen_symbols) >= self._max_symbols:
            raise ValueError("parser exceeded the configured symbol limit")
        self._seen_symbols.add(symbol)
        self.symbols.append(symbol)

    def _add_dependency(self, dependency: Dependency) -> None:
        if dependency in self._seen_dependencies:
            return
        if len(self._seen_dependencies) >= self._max_dependencies:
            raise ValueError("parser exceeded the configured dependency limit")
        self._seen_dependencies.add(dependency)
        self.dependencies.append(dependency)

    def _qualified(self, name: str) -> str:
        return ".".join([*(scope[0] for scope in self._scope), name])

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        name = self._qualified(node.name)
        self._add_symbol(
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
        self._add_symbol(
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
            self._add_dependency(Dependency(self.path, alias.name, "import", node.lineno))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        prefix = "." * node.level
        if node.module:
            targets = [f"{prefix}{node.module}"]
        else:
            targets = [f"{prefix}{alias.name}" for alias in node.names]
        for target in targets:
            self._add_dependency(Dependency(self.path, target, "import", node.lineno))

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


def _token_offset(line_starts: list[int], text_length: int, position: tuple[int, int]) -> int:
    row, column = position
    if row <= 0:
        return 0
    if row > len(line_starts):
        return text_length
    return min(line_starts[row - 1] + column, text_length)


def _is_main_literal(value: str) -> bool:
    if "__main__" not in value or len(value) > 64:
        return False
    try:
        return ast.literal_eval(value) == "__main__"
    except (SyntaxError, ValueError):
        return False


def _masked_fallback_source(text: str) -> tuple[str, list[int]]:
    """Mask Python strings/comments while retaining token and line positions."""

    line_starts = [0]
    line_starts.extend(index + 1 for index, character in enumerate(text) if character == "\n")
    masked = list(text)

    def mask_range(start: int, end: int) -> None:
        for index in range(start, end):
            if masked[index] not in "\r\n":
                masked[index] = " "

    tokens = tokenize.generate_tokens(io.StringIO(text).readline)
    try:
        for token in tokens:
            if token.type not in {tokenize.STRING, tokenize.COMMENT}:
                continue
            if token.type == tokenize.STRING and _is_main_literal(token.string):
                continue
            start = _token_offset(line_starts, len(text), token.start)
            end = _token_offset(line_starts, len(text), token.end)
            mask_range(start, end)
    except tokenize.TokenError as exc:
        message = str(exc.args[0]) if exc.args else ""
        location = exc.args[1] if len(exc.args) > 1 else None
        if (
            isinstance(location, tuple)
            and len(location) == 2
            and ("multi-line string" in message or "triple-quoted string" in message)
        ):
            row, column = location
            start = _token_offset(
                line_starts,
                len(text),
                (int(row), max(0, int(column) - 1)),
            )
            mask_range(start, len(text))
    except (IndentationError, SyntaxError):
        # Syntax-error fallback intentionally uses every safe token produced
        # before tokenization reached the malformed region.
        pass
    return "".join(masked), line_starts


def _fallback(
    path: str,
    text: str,
    *,
    max_symbols: int,
    max_dependencies: int,
) -> tuple[list[Symbol], list[Dependency], bool]:
    masked, line_starts = _masked_fallback_source(text)

    def line_at(offset: int) -> int:
        return bisect_right(line_starts, min(max(offset, 0), len(text)))

    symbols: list[Symbol] = []
    seen_symbols: set[Symbol] = set()
    for match in _FALLBACK_SYMBOL_RE.finditer(masked):
        line = line_at(match.start())
        kind = "class" if match.group("kind") == "class" else "function"
        async_prefix = "async " if match.group("async") else ""
        symbol = Symbol(
            name=match.group("name"),
            kind=kind,
            path=path,
            start_line=line,
            end_line=line,
            signature=f"{async_prefix}{match.group('kind')} {match.group('name')}"
            f"{match.group('tail').rstrip(':').strip()}",
        )
        if symbol not in seen_symbols:
            if len(symbols) >= max_symbols:
                raise ValueError("parser exceeded the configured symbol limit")
            seen_symbols.add(symbol)
            symbols.append(symbol)
    dependencies: list[Dependency] = []
    seen_dependencies: set[Dependency] = set()
    for match in _FALLBACK_IMPORT_RE.finditer(masked):
        target = match.group("from") or match.group("import")
        dependency = Dependency(path, target, "import", line_at(match.start()))
        if dependency not in seen_dependencies:
            if len(dependencies) >= max_dependencies:
                raise ValueError("parser exceeded the configured dependency limit")
            seen_dependencies.add(dependency)
            dependencies.append(dependency)
    has_main_guard = bool(
        re.search(r"\b__name__\s*==\s*['\"]__main__['\"]", masked)
        or re.search(r"['\"]__main__['\"]\s*==\s*\b__name__", masked)
    )
    return symbols, dependencies, has_main_guard


class PythonParser:
    """Extract Python symbols and imports without executing the source."""

    cache_key = "python-ast:v3"
    priority = 100
    languages = frozenset({"python"})

    def parse(
        self,
        path: str,
        text: str,
        language: str,
        *,
        max_chunk_lines: int,
        max_chunk_chars: int,
        max_dependencies_per_file: int = DEFAULT_MAX_DEPENDENCIES_PER_FILE,
        max_symbols_per_file: int = DEFAULT_MAX_SYMBOLS_PER_FILE,
        max_chunks_per_file: int = DEFAULT_MAX_CHUNKS_PER_FILE,
    ) -> ParseResult:
        try:
            tree = ast.parse(text, filename=path, type_comments=True)
        except (SyntaxError, ValueError, TypeError):
            symbols, dependencies, has_main_guard = _fallback(
                path,
                text,
                max_symbols=max_symbols_per_file,
                max_dependencies=max_dependencies_per_file,
            )
        else:
            visitor = _PythonVisitor(
                path,
                max_symbols=max_symbols_per_file,
                max_dependencies=max_dependencies_per_file,
            )
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
            max_chunks=max_chunks_per_file,
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
