"""Conservative, execution-free parsers for non-Python source languages."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TypeVar

from repolocus.models import Dependency, Symbol
from repolocus.parsers.base import (
    DEFAULT_MAX_CHUNKS_PER_FILE,
    DEFAULT_MAX_DEPENDENCIES_PER_FILE,
    DEFAULT_MAX_SYMBOLS_PER_FILE,
    ParseResult,
)
from repolocus.parsers.chunking import Region, semantic_chunks
from repolocus.parsers.source_layout import SourceLayout


@dataclass(frozen=True, slots=True)
class _SymbolPattern:
    kind: str
    regex: re.Pattern[str]
    braced: bool = True


def _pattern(expression: str) -> re.Pattern[str]:
    return re.compile(expression, re.MULTILINE)


_PATTERNS: dict[str, tuple[_SymbolPattern, ...]] = {
    "javascript": (
        _SymbolPattern(
            "function",
            _pattern(
                r"^[ \t]*(?:(?:export\s+)?default\s+|export\s+)?"
                r"(?:async\s+)?function\s*\*?\s*(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{}]*\)"
                r"[^;{]*\{"
            ),
        ),
        _SymbolPattern(
            "class",
            _pattern(
                r"^[ \t]*(?:(?:export\s+)?default\s+|export\s+)?class\s+"
                r"(?P<name>[A-Za-z_$][\w$]*)[^\n{]*\{"
            ),
        ),
        _SymbolPattern(
            "function",
            _pattern(
                r"^[ \t]*(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)"
                r"\s*=\s*(?:async\s+)?(?:\([^\n)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{?"
            ),
        ),
    ),
    "typescript": (
        _SymbolPattern(
            "function",
            _pattern(
                r"^[ \t]*(?:(?:export\s+)?default\s+|export\s+)?"
                r"(?:declare\s+)?(?:async\s+)?function\s*\*?\s*"
                r"(?P<name>[A-Za-z_$][\w$]*)\s*(?:<[^\n>{}]+>)?\s*\([^;{}]*\)"
                r"[^;{]*\{"
            ),
        ),
        _SymbolPattern(
            "class",
            _pattern(
                r"^[ \t]*(?:(?:export\s+)?default\s+|export\s+)?(?:declare\s+)?class\s+"
                r"(?P<name>[A-Za-z_$][\w$]*)[^\n{]*\{"
            ),
        ),
        _SymbolPattern(
            "interface",
            _pattern(
                r"^[ \t]*(?:export\s+)?(?:declare\s+)?interface\s+"
                r"(?P<name>[A-Za-z_$][\w$]*)[^\n{]*\{"
            ),
        ),
        _SymbolPattern(
            "enum",
            _pattern(
                r"^[ \t]*(?:export\s+)?(?:declare\s+)?(?:const\s+)?enum\s+"
                r"(?P<name>[A-Za-z_$][\w$]*)[^\n{]*\{"
            ),
        ),
        _SymbolPattern(
            "type",
            _pattern(
                r"^[ \t]*(?:export\s+)?(?:declare\s+)?type\s+"
                r"(?P<name>[A-Za-z_$][\w$]*)\s*(?:<[^\n>]+>)?\s*="
            ),
            braced=False,
        ),
        _SymbolPattern(
            "function",
            _pattern(
                r"^[ \t]*(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)"
                r"\s*(?::[^=\n]+)?=\s*(?:async\s+)?(?:\([^\n)]*\)|[A-Za-z_$][\w$]*)"
                r"\s*(?::[^=\n]+)?=>\s*\{?"
            ),
        ),
    ),
    "go": (
        _SymbolPattern(
            "function",
            _pattern(
                r"^[ \t]*func\s+(?:\([^\n)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*"
                r"(?:\[[^\n]]+\])?\s*\([^\n{]*\)[^\n{]*\{"
            ),
        ),
        _SymbolPattern(
            "type",
            _pattern(r"^[ \t]*type\s+(?P<name>[A-Za-z_]\w*)\s+(?:struct|interface)\s*\{"),
        ),
    ),
    "rust": (
        _SymbolPattern(
            "function",
            _pattern(
                r"^[ \t]*(?:pub(?:\([^\n)]*\))?\s+)?"
                r"(?:(?:async|const|unsafe)\s+)*(?:extern\s+\"[^\"]+\"\s+)?fn\s+"
                r"(?P<name>[A-Za-z_]\w*)\s*(?:<[^\n>{}]+>)?\s*\([^\n{;]*\)[^\n{;]*\{"
            ),
        ),
        _SymbolPattern(
            "struct",
            _pattern(
                r"^[ \t]*(?:pub(?:\([^\n)]*\))?\s+)?struct\s+"
                r"(?P<name>[A-Za-z_]\w*)[^\n;{]*\{"
            ),
        ),
        _SymbolPattern(
            "enum",
            _pattern(
                r"^[ \t]*(?:pub(?:\([^\n)]*\))?\s+)?enum\s+"
                r"(?P<name>[A-Za-z_]\w*)[^\n{]*\{"
            ),
        ),
        _SymbolPattern(
            "trait",
            _pattern(
                r"^[ \t]*(?:pub(?:\([^\n)]*\))?\s+)?(?:unsafe\s+)?trait\s+"
                r"(?P<name>[A-Za-z_]\w*)[^\n{]*\{"
            ),
        ),
        _SymbolPattern(
            "impl",
            _pattern(r"^[ \t]*(?:unsafe\s+)?impl(?:<[^\n>]+>)?\s+(?P<name>[^\n{]+?)\s*\{"),
        ),
    ),
    "java": (
        _SymbolPattern(
            "type",
            _pattern(
                r"^[ \t]*(?:(?:public|protected|private|abstract|final|static|sealed|"
                r"non-sealed)\s+)*"
                r"(?:class|interface|enum|record)\s+(?P<name>[A-Za-z_$][\w$]*)[^\n{]*\{"
            ),
        ),
        _SymbolPattern(
            "method",
            _pattern(
                r"^[ \t]*(?:(?:public|protected|private|static|final|native|synchronized|"
                r"abstract|default|strictfp)\s+)*(?:<[^\n>]+>\s*)?"
                r"[A-Za-z_$][\w$<>,.?\[\]]*(?:\s*\[\])?\s+"
                r"(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{}]*\)"
                r"(?:\s+throws\s+[^\n{]+)?\s*\{"
            ),
        ),
    ),
    "c": (
        _SymbolPattern(
            "type",
            _pattern(
                r"^[ \t]*(?:typedef\s+)?(?:struct|union|enum)\s+"
                r"(?P<name>[A-Za-z_]\w*)[^;\n{]*\{"
            ),
        ),
        _SymbolPattern(
            "function",
            _pattern(
                r"^[ \t]*(?:(?:static|extern|inline|const|volatile|unsigned|signed)\s+)*"
                r"[A-Za-z_]\w*(?:[ \t*]+[A-Za-z_]\w*)*[ \t*]+"
                r"(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"
            ),
        ),
    ),
    "cpp": (
        _SymbolPattern(
            "type",
            _pattern(
                r"^[ \t]*(?:template\s*<[^\n>]+>\s*)?(?:class|struct|union|enum(?:\s+class)?)\s+"
                r"(?P<name>[A-Za-z_]\w*)[^;\n{]*\{"
            ),
        ),
        _SymbolPattern(
            "function",
            _pattern(
                r"^[ \t]*(?:template\s*<[^\n>]+>\s*)?"
                r"(?:(?:static|extern|inline|constexpr|consteval|virtual|friend)\s+)*"
                r"[~A-Za-z_]\w*(?:(?:::|[ \t*&<>:,]+)[~A-Za-z_]\w*)*[ \t*&]+"
                r"(?P<name>(?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*\([^;{}]*\)"
                r"(?:\s+(?:const|noexcept|override|final))*\s*(?:->\s*[^\n{]+)?\{"
            ),
        ),
    ),
}


def _signature(text: str, start: int, match_end: int) -> str:
    excerpt = text[start:match_end]
    return " ".join(excerpt.strip().split())[:500]


_Fact = TypeVar("_Fact", Symbol, Dependency)


def _add_bounded(
    values: set[_Fact],
    value: _Fact,
    *,
    maximum: int,
    fact_name: str,
) -> None:
    if value in values:
        return
    if len(values) >= maximum:
        raise ValueError(f"parser exceeded the configured {fact_name} limit")
    values.add(value)


def _source_symbols(
    path: str,
    layout: SourceLayout,
    language: str,
    *,
    max_symbols: int,
) -> list[Symbol]:
    text = layout.text
    symbols: set[Symbol] = set()
    for pattern in _PATTERNS[language]:
        for match in pattern.regex.finditer(text):
            if not layout.is_code(match.start()):
                continue
            name = " ".join(match.group("name").split())
            start_line = layout.line_at_offset(match.start())
            if pattern.braced:
                brace_offset = text.rfind("{", match.start(), match.end())
                end_line = layout.brace_end_line(brace_offset)
            else:
                end_line = start_line
            _add_bounded(
                symbols,
                Symbol(
                    name=name,
                    kind=pattern.kind,
                    path=path,
                    start_line=start_line,
                    end_line=max(start_line, end_line),
                    signature=_signature(text, match.start(), match.end()),
                ),
                maximum=max_symbols,
                fact_name="symbol",
            )
    return sorted(symbols, key=lambda item: (item.start_line, item.end_line, item.kind, item.name))


_JavaScriptToken = tuple[str, str, int]
_JS_LINE_BREAK_CHARACTERS = frozenset("\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")
_JS_REGEX_PREFIXES = frozenset(
    {
        "(",
        "{",
        "[",
        ",",
        ";",
        ":",
        "=",
        "==",
        "===",
        "!=",
        "!==",
        "!",
        "?",
        "??",
        "&&",
        "||",
        "=>",
        "+",
        "-",
        "*",
        "%",
        "&",
        "|",
        "^",
        "~",
        "<",
        ">",
        "<=",
        ">=",
    }
)
_JS_REGEX_KEYWORDS = frozenset(
    {
        "await",
        "case",
        "delete",
        "do",
        "else",
        "in",
        "instanceof",
        "new",
        "of",
        "return",
        "throw",
        "typeof",
        "void",
        "yield",
    }
)
_JS_EXPORT_DECLARATIONS = frozenset(
    {
        "abstract",
        "async",
        "class",
        "const",
        "declare",
        "default",
        "enum",
        "function",
        "interface",
        "let",
        "namespace",
        "var",
    }
)
_JS_DOUBLE_OPERATORS = frozenset(
    {
        "&&",
        "||",
        "??",
        "=>",
        "==",
        "!=",
        "<=",
        ">=",
        "++",
        "--",
        "**",
        "?.",
    }
)


def _javascript_regex_can_start(previous: _JavaScriptToken | None) -> bool:
    if previous is None:
        return True
    kind, value, _offset = previous
    if kind == "identifier":
        return value in _JS_REGEX_KEYWORDS
    return value in _JS_REGEX_PREFIXES


def _javascript_tokens(text: str) -> Iterator[_JavaScriptToken]:
    """Yield dependency-relevant JavaScript tokens in one bounded pass."""

    previous: _JavaScriptToken | None = None
    template_braces: list[int] = []
    template_raw = False
    index = 0

    while index < len(text):
        if template_raw:
            character = text[index]
            if character == "\\":
                index = min(len(text), index + 2)
                continue
            if character == "`":
                template_raw = False
                token = ("value", "", index)
                previous = token
                index += 1
                yield token
                continue
            if character == "$" and index + 1 < len(text) and text[index + 1] == "{":
                template_braces.append(1)
                template_raw = False
                index += 2
                continue
            index += 1
            continue

        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if character.isspace():
            index += 1
            continue
        if character == "/" and following == "/":
            index += 2
            while index < len(text) and text[index] not in _JS_LINE_BREAK_CHARACTERS:
                index += 1
            continue
        if character == "/" and following == "*":
            closing = text.find("*/", index + 2)
            index = len(text) if closing < 0 else closing + 2
            continue
        if character in {'"', "'"}:
            quote = character
            start = index
            index += 1
            escaped = False
            closed = False
            while index < len(text):
                current = text[index]
                if current in _JS_LINE_BREAK_CHARACTERS and not escaped:
                    break
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    index += 1
                    closed = True
                    break
                index += 1
            token = (
                "string" if closed else "value",
                text[start + 1 : index - 1] if closed else "",
                start,
            )
            previous = token
            yield token
            continue
        if character == "`":
            template_raw = True
            index += 1
            continue
        if character == "/" and _javascript_regex_can_start(previous):
            start = index
            index += 1
            escaped = False
            in_character_class = False
            while index < len(text):
                current = text[index]
                if current in _JS_LINE_BREAK_CHARACTERS and not escaped:
                    break
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == "[":
                    in_character_class = True
                elif current == "]":
                    in_character_class = False
                elif current == "/" and not in_character_class:
                    index += 1
                    while index < len(text) and text[index].isalpha():
                        index += 1
                    break
                index += 1
            token = ("value", "", start)
            previous = token
            yield token
            continue
        if character.isalpha() or character in {"_", "$"} or ord(character) >= 128:
            start = index
            index += 1
            while index < len(text):
                current = text[index]
                if not (current.isalnum() or current in {"_", "$"} or ord(current) >= 128):
                    break
                index += 1
            token = ("identifier", text[start:index], start)
            previous = token
            yield token
            continue
        if character.isdigit():
            start = index
            index += 1
            while index < len(text) and (text[index].isalnum() or text[index] in {"_", "."}):
                index += 1
            token = ("value", text[start:index], start)
            previous = token
            yield token
            continue

        if template_braces and character == "{":
            template_braces[-1] += 1
        elif template_braces and character == "}":
            template_braces[-1] -= 1
            if template_braces[-1] == 0:
                template_braces.pop()
                template_raw = True
                index += 1
                continue

        triple = text[index : index + 3]
        pair = text[index : index + 2]
        if triple in {"===", "!=="}:
            value = triple
            index += 3
        elif pair in _JS_DOUBLE_OPERATORS:
            value = pair
            index += 2
        else:
            value = character
            index += 1
        token = ("punctuation", value, index - len(value))
        previous = token
        yield token


def _javascript_dependencies(
    path: str,
    layout: SourceLayout,
    *,
    max_dependencies: int,
) -> list[Dependency]:
    dependencies: set[Dependency] = set()

    def add(target: str, kind: str, offset: int) -> None:
        if not target:
            return
        _add_bounded(
            dependencies,
            Dependency(path, target, kind, layout.line_at_offset(offset)),
            maximum=max_dependencies,
            fact_name="dependency",
        )

    recent: list[_JavaScriptToken] = []
    static_mode: str | None = None
    static_start = 0
    static_tokens = 0
    static_braces = 0
    static_from = False

    for token in _javascript_tokens(layout.text):
        recent.append(token)
        if len(recent) > 5:
            recent.pop(0)
        if token[1] == ")" and len(recent) >= 4:
            function, opening, argument, _closing = recent[-4:]
            preceding = recent[-5] if len(recent) == 5 else None
            if (
                function[0] == "identifier"
                and function[1] in {"import", "require"}
                and opening[1] == "("
                and argument[0] == "string"
                and (preceding is None or preceding[1] != ".")
            ):
                kind = "dynamic_import" if function[1] == "import" else "require"
                add(argument[1], kind, function[2])

        kind, value, offset = token
        if static_mode is None:
            if kind == "identifier" and value in {"import", "export"}:
                static_mode = value
                static_start = offset
                static_tokens = 0
                static_braces = 0
                static_from = False
            continue

        if static_braces == 0 and kind == "identifier" and value in {"import", "export"}:
            static_mode = value
            static_start = offset
            static_tokens = 0
            static_from = False
            continue
        if static_braces == 0 and value == ";":
            static_mode = None
            continue
        if static_tokens == 0 and static_mode == "import" and value in {"(", "."}:
            static_mode = None
            continue
        if (
            static_tokens == 0
            and static_mode == "export"
            and kind == "identifier"
            and value in _JS_EXPORT_DECLARATIONS
        ):
            static_mode = None
            continue
        if value == "{":
            static_braces += 1
        elif value == "}" and static_braces:
            static_braces -= 1
        elif static_braces == 0 and kind == "identifier" and value == "from":
            static_from = True
        elif kind == "string" and (static_from or (static_mode == "import" and static_tokens == 0)):
            add(value, "import", static_start)
            static_mode = None
            continue
        static_tokens += 1
    return list(dependencies)


_GO_SINGLE_IMPORT_RE = re.compile(
    r"^[ \t]*import[ \t]+(?:[._A-Za-z]\w*[ \t]+)?[\"`]"
    r"(?P<target>[^\"`\r\n]+)[\"`]"
)
_GO_BLOCK_START_RE = re.compile(r"^[ \t]*import[ \t]*\(")
_GO_BLOCK_SPEC_RE = re.compile(
    r"(?:^|;)[ \t]*(?:[._A-Za-z]\w*[ \t]+)?[\"`]"
    r"(?P<target>[^\"`\r\n]+)[\"`]"
)


def _go_dependencies(
    path: str,
    layout: SourceLayout,
    *,
    max_dependencies: int,
) -> list[Dependency]:
    dependencies: set[Dependency] = set()
    block_dependencies: set[Dependency] = set()
    in_block = False

    def commit_block() -> None:
        for dependency in block_dependencies:
            _add_bounded(
                dependencies,
                dependency,
                maximum=max_dependencies,
                fact_name="dependency",
            )
        block_dependencies.clear()

    def closing_index(fragment: str, offset: int) -> int | None:
        return next(
            (
                index
                for index, character in enumerate(fragment)
                if character == ")" and layout.is_code(offset + index)
            ),
            None,
        )

    def add_specs(output: set[Dependency], fragment: str, offset: int, line_number: int) -> None:
        for match in _GO_BLOCK_SPEC_RE.finditer(fragment):
            absolute_start = offset + match.start()
            code_probe = absolute_start if layout.is_code(absolute_start) else absolute_start - 1
            if code_probe < 0 or not layout.is_code(code_probe):
                continue
            _add_bounded(
                output,
                Dependency(path, match.group("target"), "import", line_number),
                maximum=max_dependencies,
                fact_name="dependency",
            )

    for line_number, line in enumerate(layout.lines, start=1):
        line_start = layout.line_starts[line_number - 1]
        if in_block:
            closing = closing_index(line, line_start)
            body = line if closing is None else line[:closing]
            add_specs(block_dependencies, body, line_start, line_number)
            if closing is not None:
                commit_block()
                in_block = False
            continue

        single = _GO_SINGLE_IMPORT_RE.match(line)
        if single is not None and layout.is_code(line_start + single.start()):
            _add_bounded(
                dependencies,
                Dependency(path, single.group("target"), "import", line_number),
                maximum=max_dependencies,
                fact_name="dependency",
            )
            continue

        block = _GO_BLOCK_START_RE.match(line)
        if block is None or not layout.is_code(line_start + block.start()):
            continue
        remainder = line[block.end() :]
        remainder_start = line_start + block.end()
        block_dependencies.clear()
        closing = closing_index(remainder, remainder_start)
        body = remainder if closing is None else remainder[:closing]
        add_specs(block_dependencies, body, remainder_start, line_number)
        if closing is None:
            in_block = True
        else:
            commit_block()
    return list(dependencies)


def _source_dependencies(
    path: str,
    layout: SourceLayout,
    language: str,
    *,
    max_dependencies: int,
) -> list[Dependency]:
    text = layout.text
    if language in {"javascript", "typescript"}:
        return _javascript_dependencies(path, layout, max_dependencies=max_dependencies)
    if language == "go":
        return _go_dependencies(path, layout, max_dependencies=max_dependencies)
    if language == "rust":
        dependencies: set[Dependency] = set()
        for match in re.finditer(
            r"^[ \t]*(?:pub\s+)?use\s+(?P<target>[^;\n]+)\s*;", text, re.MULTILINE
        ):
            if not layout.is_code(match.start()):
                continue
            target = match.group("target").strip().split("::{", 1)[0]
            _add_bounded(
                dependencies,
                Dependency(path, target, "import", layout.line_at_offset(match.start())),
                maximum=max_dependencies,
                fact_name="dependency",
            )
        for match in re.finditer(
            r"^[ \t]*extern\s+crate\s+(?P<target>[A-Za-z_]\w*)\s*;", text, re.MULTILINE
        ):
            if not layout.is_code(match.start()):
                continue
            _add_bounded(
                dependencies,
                Dependency(
                    path,
                    match.group("target"),
                    "import",
                    layout.line_at_offset(match.start()),
                ),
                maximum=max_dependencies,
                fact_name="dependency",
            )
        for match in re.finditer(
            r"^[ \t]*(?:pub\s+)?mod\s+(?P<target>[A-Za-z_]\w*)\s*;", text, re.MULTILINE
        ):
            if not layout.is_code(match.start()):
                continue
            _add_bounded(
                dependencies,
                Dependency(
                    path,
                    match.group("target"),
                    "module",
                    layout.line_at_offset(match.start()),
                ),
                maximum=max_dependencies,
                fact_name="dependency",
            )
        return list(dependencies)
    if language == "java":
        dependencies: set[Dependency] = set()
        for match in re.finditer(
            r"^[ \t]*import\s+(?:static\s+)?(?P<target>[\w.*]+)\s*;", text, re.MULTILINE
        ):
            if not layout.is_code(match.start()):
                continue
            _add_bounded(
                dependencies,
                Dependency(
                    path,
                    match.group("target"),
                    "import",
                    layout.line_at_offset(match.start()),
                ),
                maximum=max_dependencies,
                fact_name="dependency",
            )
        return list(dependencies)
    if language in {"c", "cpp"}:
        dependencies: set[Dependency] = set()
        for match in re.finditer(
            r"^[ \t]*#[ \t]*include[ \t]*[<\"](?P<target>[^>\"]+)[>\"]",
            text,
            re.MULTILINE,
        ):
            if not layout.is_code(match.start()):
                continue
            _add_bounded(
                dependencies,
                Dependency(
                    path,
                    match.group("target"),
                    "include",
                    layout.line_at_offset(match.start()),
                ),
                maximum=max_dependencies,
                fact_name="dependency",
            )
        return list(dependencies)
    return []


def _has_code_match(layout: SourceLayout, expression: str, flags: int = 0) -> bool:
    return any(
        layout.is_code(match.start()) for match in re.finditer(expression, layout.text, flags)
    )


def _source_entry_point(path: str, layout: SourceLayout, language: str) -> bool:
    basename = PurePosixPath(path).name.casefold()
    if language in {"javascript", "typescript"}:
        conventional = basename in {
            "main.js",
            "main.jsx",
            "main.ts",
            "main.tsx",
            "server.js",
            "server.ts",
            "index.js",
            "index.ts",
        }
        marker = _has_code_match(
            layout,
            r"\brequire\.main\s*===\s*module\b|\bimport\.meta\.main\b|^#!.*\bnode\b",
            re.MULTILINE,
        )
        return conventional or marker
    if language == "go":
        return _has_code_match(
            layout, r"^[ \t]*package\s+main\b", re.MULTILINE
        ) and _has_code_match(layout, r"^[ \t]*func\s+main\s*\(", re.MULTILINE)
    if language == "rust":
        return basename == "main.rs" or _has_code_match(
            layout, r"^[ \t]*(?:pub\s+)?fn\s+main\s*\(", re.MULTILINE
        )
    if language == "java":
        return _has_code_match(
            layout,
            r"\bpublic\s+static\s+void\s+main\s*\(\s*(?:String(?:\[\]|\.\.\.)|"
            r"String\s*\[\s*\])",
        )
    if language in {"c", "cpp"}:
        return _has_code_match(layout, r"\b(?:int|auto|void)\s+main\s*\(")
    return False


_MD_ATX_HEADING_RE = re.compile(r"^[ \t]{0,3}(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$")
_MD_SETEXT_UNDERLINE_RE = re.compile(r"^[ \t]{0,3}(?:=+|-+)[ \t]*$")


def _markdown_symbols(path: str, layout: SourceLayout, *, max_symbols: int) -> list[Symbol]:
    headings: list[tuple[int, int, str, str]] = []
    lines = layout.lines
    for index, line in enumerate(lines, start=1):
        match = _MD_ATX_HEADING_RE.match(line)
        if match:
            if len(headings) >= max_symbols:
                raise ValueError("parser exceeded the configured symbol limit")
            headings.append((index, len(match.group(1)), match.group(2).strip(), line.strip()))
            continue
        if index > 1 and _MD_SETEXT_UNDERLINE_RE.match(line):
            previous = lines[index - 2].strip()
            if previous:
                if len(headings) >= max_symbols:
                    raise ValueError("parser exceeded the configured symbol limit")
                headings.append((index - 1, 1 if "=" in line else 2, previous, previous))

    symbols: list[Symbol] = []
    for position, (line, level, name, signature) in enumerate(headings):
        end = len(lines)
        for next_line, next_level, _, _ in headings[position + 1 :]:
            if next_level <= level:
                end = next_line - 1
                break
        symbols.append(Symbol(name, "section", path, line, max(line, end), signature))
    return symbols


_CFG_SECTION_RE = re.compile(r"^[ \t]*\[\[?\s*([^\]]+?)\s*\]\]?[ \t]*(?:[#;].*)?$")
_CFG_KEY_RE = re.compile(r'^[ \t]*(?:"(?P<quoted>[^"\n]+)"|(?P<plain>[A-Za-z_][\w.-]*))\s*[:=]')
_CARGO_SECTION_RE = re.compile(r"^\s*\[([^]]+)]")
_CARGO_DEP_RE = re.compile(r"^\s*([A-Za-z_][\w-]*)\s*=")
_GOMOD_REQUIRE_RE = re.compile(r"^\s*(?:require\s+)?([\w./-]+)\s+v\d")
_PACKAGE_DEPENDENCY_FIELDS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
)


def _package_dependency_lines(
    layout: SourceLayout,
    fields: tuple[str, ...],
    *,
    max_dependencies: int,
) -> dict[str, dict[str, int]]:
    """Locate dependency-object keys in one bounded pass over JSON tokens."""

    text = layout.text
    field_names = frozenset(fields)
    lines = {field: {} for field in fields}
    pending_objects: dict[int, str] = {}
    active_objects: dict[int, str] = {}
    ignored = iter(layout.ignored_ranges)
    current_range = next(ignored, None)
    depth = 0
    dependency_count = 0
    index = 0

    while index < len(text):
        if current_range is not None and index == current_range[0]:
            start, end = current_range
            if text[start : start + 1] == '"' and text[end - 1 : end] == '"':
                after = end
                while after < len(text) and text[after].isspace():
                    after += 1
                if after < len(text) and text[after] == ":":
                    try:
                        key = json.loads(text[start:end])
                    except (json.JSONDecodeError, TypeError):
                        key = None
                    if isinstance(key, str):
                        value_start = after + 1
                        while value_start < len(text) and text[value_start].isspace():
                            value_start += 1
                        if (
                            depth == 1
                            and key in field_names
                            and value_start < len(text)
                            and text[value_start] == "{"
                        ):
                            pending_objects[value_start] = key
                        elif depth == 2 and (field := active_objects.get(depth)):
                            if key not in lines[field] and dependency_count >= max_dependencies:
                                raise ValueError("parser exceeded the configured dependency limit")
                            if key not in lines[field]:
                                dependency_count += 1
                            lines[field][key] = layout.line_at_offset(start)
            index = end
            current_range = next(ignored, None)
            continue

        character = text[index]
        if character == "{":
            depth += 1
            field = pending_objects.pop(index, None)
            if field is not None:
                dependency_count -= len(lines[field])
                lines[field] = {}
                active_objects[depth] = field
        elif character == "}":
            active_objects.pop(depth, None)
            depth = max(0, depth - 1)
        index += 1

    return lines


def _config_symbols(path: str, layout: SourceLayout, *, max_symbols: int) -> list[Symbol]:
    candidates: list[tuple[int, str, str]] = []
    for line_number, line in enumerate(layout.lines, start=1):
        section = _CFG_SECTION_RE.match(line)
        if section:
            if len(candidates) >= max_symbols:
                raise ValueError("parser exceeded the configured symbol limit")
            candidates.append((line_number, section.group(1).strip(), "section"))
            continue
        key = _CFG_KEY_RE.match(line)
        if key:
            if len(candidates) >= max_symbols:
                raise ValueError("parser exceeded the configured symbol limit")
            candidates.append((line_number, key.group("quoted") or key.group("plain"), "key"))
    line_count = len(layout.lines)
    symbols = []
    for index, (line, name, kind) in enumerate(candidates):
        end = candidates[index + 1][0] - 1 if index + 1 < len(candidates) else line_count
        symbols.append(
            Symbol(
                name,
                kind,
                path,
                line,
                max(line, end),
                layout.lines[line - 1].strip(),
            )
        )
    return symbols


def _config_dependencies(
    path: str,
    layout: SourceLayout,
    *,
    max_dependencies: int,
) -> list[Dependency]:
    text = layout.text
    basename = PurePosixPath(path).name.casefold()
    dependencies: set[Dependency] = set()
    if basename == "package.json":
        try:
            document = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            document = {}
        if isinstance(document, dict):
            key_lines = _package_dependency_lines(
                layout,
                _PACKAGE_DEPENDENCY_FIELDS,
                max_dependencies=max_dependencies,
            )
            for field in _PACKAGE_DEPENDENCY_FIELDS:
                values = document.get(field, {})
                if not isinstance(values, dict):
                    continue
                targets = sorted(key for key in values if isinstance(key, str))
                for target in targets:
                    _add_bounded(
                        dependencies,
                        Dependency(path, target, "package", key_lines[field].get(target, 1)),
                        maximum=max_dependencies,
                        fact_name="dependency",
                    )
    elif basename.startswith("requirements") and basename.endswith(".txt"):
        for line_number, line in enumerate(layout.lines, start=1):
            value = line.strip()
            if not value or value.startswith(("#", "-")):
                continue
            target = re.split(r"[<>=!~;\s\[]", value, maxsplit=1)[0]
            if target:
                _add_bounded(
                    dependencies,
                    Dependency(path, target, "package", line_number),
                    maximum=max_dependencies,
                    fact_name="dependency",
                )
    elif basename == "cargo.toml":
        in_dependencies = False
        for line_number, line in enumerate(layout.lines, start=1):
            section = _CARGO_SECTION_RE.match(line)
            if section:
                name = section.group(1).strip()
                in_dependencies = name == "dependencies" or name.endswith(".dependencies")
                continue
            if in_dependencies:
                match = _CARGO_DEP_RE.match(line)
                if match:
                    _add_bounded(
                        dependencies,
                        Dependency(path, match.group(1), "package", line_number),
                        maximum=max_dependencies,
                        fact_name="dependency",
                    )
    elif basename == "go.mod":
        for line_number, line in enumerate(layout.lines, start=1):
            match = _GOMOD_REQUIRE_RE.match(line)
            if match:
                _add_bounded(
                    dependencies,
                    Dependency(path, match.group(1), "package", line_number),
                    maximum=max_dependencies,
                    fact_name="dependency",
                )
    return list(dependencies)


class HeuristicParser:
    """Regex/brace parser for source, Markdown, and configuration files."""

    languages = frozenset(
        {"javascript", "typescript", "go", "rust", "java", "c", "cpp", "markdown", "config"}
    )
    cache_key = "heuristic-multilang:v7"
    priority = 10

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
        layout = SourceLayout.build(text, language=language)
        return self._parse_layout(
            path,
            text,
            language,
            layout,
            max_chunk_lines=max_chunk_lines,
            max_chunk_chars=max_chunk_chars,
            max_dependencies_per_file=max_dependencies_per_file,
            max_symbols_per_file=max_symbols_per_file,
            max_chunks_per_file=max_chunks_per_file,
        )

    def _parse_layout(
        self,
        path: str,
        text: str,
        language: str,
        layout: SourceLayout,
        *,
        max_chunk_lines: int,
        max_chunk_chars: int,
        max_dependencies_per_file: int,
        max_symbols_per_file: int,
        max_chunks_per_file: int,
    ) -> ParseResult:
        if language == "markdown":
            symbols = _markdown_symbols(path, layout, max_symbols=max_symbols_per_file)
            dependencies: list[Dependency] = []
            is_entry_point = False
        elif language == "config":
            symbols = _config_symbols(path, layout, max_symbols=max_symbols_per_file)
            dependencies = _config_dependencies(
                path, layout, max_dependencies=max_dependencies_per_file
            )
            is_entry_point = False
        else:
            symbols = _source_symbols(path, layout, language, max_symbols=max_symbols_per_file)
            dependencies = _source_dependencies(
                path,
                layout,
                language,
                max_dependencies=max_dependencies_per_file,
            )
            is_entry_point = _source_entry_point(path, layout, language)

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
            source_lines=layout.source_lines,
        )
        return ParseResult(
            symbols=tuple(symbols),
            dependencies=tuple(dependencies),
            chunks=chunks,
            is_entry_point=is_entry_point,
        )
