"""Conservative, execution-free parsers for non-Python source languages."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from repolocus.models import Dependency, Symbol
from repolocus.parsers.base import ParseResult
from repolocus.parsers.chunking import Region, semantic_chunks


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


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _brace_end_line(text: str, brace_offset: int) -> int:
    """Return the matching brace line while ignoring common strings/comments."""

    depth = 0
    index = brace_offset
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if character == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if character == "*" and following == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            index += 1
            continue
        if character == "/" and following == "/":
            line_comment = True
            index += 2
            continue
        if character == "/" and following == "*":
            block_comment = True
            index += 2
            continue
        if character in {'"', "'", "`"}:
            quote = character
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return _line_number(text, index)
        index += 1
    return _line_number(text, len(text))


def _signature(text: str, start: int, match_end: int) -> str:
    excerpt = text[start:match_end]
    return " ".join(excerpt.strip().split())[:500]


def _source_symbols(path: str, text: str, language: str) -> list[Symbol]:
    symbols: list[Symbol] = []
    for pattern in _PATTERNS[language]:
        for match in pattern.regex.finditer(text):
            name = " ".join(match.group("name").split())
            start_line = _line_number(text, match.start())
            if pattern.braced:
                brace_offset = text.rfind("{", match.start(), match.end())
                end_line = _brace_end_line(text, brace_offset)
            else:
                end_line = start_line
            symbols.append(
                Symbol(
                    name=name,
                    kind=pattern.kind,
                    path=path,
                    start_line=start_line,
                    end_line=max(start_line, end_line),
                    signature=_signature(text, match.start(), match.end()),
                )
            )
    return sorted(
        set(symbols), key=lambda item: (item.start_line, item.end_line, item.kind, item.name)
    )


def _quoted_dependencies(
    path: str, text: str, expressions: tuple[tuple[str, re.Pattern[str]], ...]
) -> list[Dependency]:
    dependencies: list[Dependency] = []
    for kind, expression in expressions:
        for match in expression.finditer(text):
            dependencies.append(
                Dependency(path, match.group("target"), kind, _line_number(text, match.start()))
            )
    return dependencies


_JS_DEPENDENCIES = (
    (
        "import",
        re.compile(
            r"\b(?:import|export)\s+(?:type\s+)?(?:[^;\n]*?\s+from\s+)?"
            r"['\"](?P<target>[^'\"]+)['\"]"
        ),
    ),
    (
        "require",
        re.compile(r"\brequire\s*\(\s*['\"](?P<target>[^'\"]+)['\"]\s*\)"),
    ),
    (
        "dynamic_import",
        re.compile(r"\bimport\s*\(\s*['\"](?P<target>[^'\"]+)['\"]\s*\)"),
    ),
)


def _go_dependencies(path: str, text: str) -> list[Dependency]:
    dependencies = _quoted_dependencies(
        path,
        text,
        (
            (
                "import",
                re.compile(
                    r"^[ \t]*import\s+(?:[._A-Za-z]\w*\s+)?[\"`]"
                    r"(?P<target>[^\"`]+)[\"`]",
                    re.MULTILINE,
                ),
            ),
        ),
    )
    for block in re.finditer(
        r"^[ \t]*import\s*\((?P<body>.*?)^\s*\)", text, re.MULTILINE | re.DOTALL
    ):
        body = block.group("body")
        body_start = block.start("body")
        for match in re.finditer(
            r"^[ \t]*(?:[._A-Za-z]\w*\s+)?[\"`](?P<target>[^\"`]+)[\"`]",
            body,
            re.MULTILINE,
        ):
            dependencies.append(
                Dependency(
                    path,
                    match.group("target"),
                    "import",
                    _line_number(text, body_start + match.start()),
                )
            )
    return dependencies


def _source_dependencies(path: str, text: str, language: str) -> list[Dependency]:
    if language in {"javascript", "typescript"}:
        return _quoted_dependencies(path, text, _JS_DEPENDENCIES)
    if language == "go":
        return _go_dependencies(path, text)
    if language == "rust":
        dependencies: list[Dependency] = []
        for match in re.finditer(
            r"^[ \t]*(?:pub\s+)?use\s+(?P<target>[^;\n]+)\s*;", text, re.MULTILINE
        ):
            target = match.group("target").strip().split("::{", 1)[0]
            dependencies.append(
                Dependency(path, target, "import", _line_number(text, match.start()))
            )
        for match in re.finditer(
            r"^[ \t]*extern\s+crate\s+(?P<target>[A-Za-z_]\w*)\s*;", text, re.MULTILINE
        ):
            dependencies.append(
                Dependency(path, match.group("target"), "import", _line_number(text, match.start()))
            )
        for match in re.finditer(
            r"^[ \t]*(?:pub\s+)?mod\s+(?P<target>[A-Za-z_]\w*)\s*;", text, re.MULTILINE
        ):
            dependencies.append(
                Dependency(path, match.group("target"), "module", _line_number(text, match.start()))
            )
        return dependencies
    if language == "java":
        dependencies = []
        for match in re.finditer(
            r"^[ \t]*import\s+(?:static\s+)?(?P<target>[\w.*]+)\s*;", text, re.MULTILINE
        ):
            dependencies.append(
                Dependency(path, match.group("target"), "import", _line_number(text, match.start()))
            )
        return dependencies
    if language in {"c", "cpp"}:
        dependencies = []
        for match in re.finditer(
            r"^[ \t]*#[ \t]*include[ \t]*[<\"](?P<target>[^>\"]+)[>\"]",
            text,
            re.MULTILINE,
        ):
            dependencies.append(
                Dependency(
                    path,
                    match.group("target"),
                    "include",
                    _line_number(text, match.start()),
                )
            )
        return dependencies
    return []


def _source_entry_point(path: str, text: str, language: str) -> bool:
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
        marker = re.search(
            r"\brequire\.main\s*===\s*module\b|\bimport\.meta\.main\b|^#!.*\bnode\b",
            text,
            re.MULTILINE,
        )
        return conventional or marker is not None
    if language == "go":
        return bool(
            re.search(r"^[ \t]*package\s+main\b", text, re.MULTILINE)
            and re.search(r"^[ \t]*func\s+main\s*\(", text, re.MULTILINE)
        )
    if language == "rust":
        return basename == "main.rs" or bool(
            re.search(r"^[ \t]*(?:pub\s+)?fn\s+main\s*\(", text, re.MULTILINE)
        )
    if language == "java":
        return bool(
            re.search(
                r"\bpublic\s+static\s+void\s+main\s*\(\s*(?:String(?:\[\]|\.\.\.)|"
                r"String\s*\[\s*\])",
                text,
            )
        )
    if language in {"c", "cpp"}:
        return bool(re.search(r"\b(?:int|auto|void)\s+main\s*\(", text))
    return False


def _markdown_symbols(path: str, text: str) -> list[Symbol]:
    headings: list[tuple[int, int, str, str]] = []
    lines = text.splitlines()
    for index, line in enumerate(lines, start=1):
        match = re.match(r"^[ \t]{0,3}(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$", line)
        if match:
            headings.append((index, len(match.group(1)), match.group(2).strip(), line.strip()))
            continue
        if index > 1 and re.match(r"^[ \t]{0,3}(?:=+|-+)[ \t]*$", line):
            previous = lines[index - 2].strip()
            if previous:
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


def _config_symbols(path: str, text: str) -> list[Symbol]:
    candidates: list[tuple[int, str, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        section = re.match(r"^[ \t]*\[\[?\s*([^\]]+?)\s*\]\]?[ \t]*(?:[#;].*)?$", line)
        if section:
            candidates.append((line_number, section.group(1).strip(), "section"))
            continue
        key = re.match(
            r'^[ \t]*(?:"(?P<quoted>[^"\n]+)"|(?P<plain>[A-Za-z_][\w.-]*))\s*[:=]',
            line,
        )
        if key:
            candidates.append((line_number, key.group("quoted") or key.group("plain"), "key"))
    line_count = len(text.splitlines())
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
                text.splitlines()[line - 1].strip(),
            )
        )
    return symbols


def _config_dependencies(path: str, text: str) -> list[Dependency]:
    basename = PurePosixPath(path).name.casefold()
    dependencies: list[Dependency] = []
    if basename == "package.json":
        try:
            document = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            document = {}
        if isinstance(document, dict):
            dependency_fields = (
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            )
            for field in dependency_fields:
                values = document.get(field, {})
                if not isinstance(values, dict):
                    continue
                for target in sorted(key for key in values if isinstance(key, str)):
                    match = re.search(rf'^[ \t]*"{re.escape(target)}"\s*:', text, re.MULTILINE)
                    line = _line_number(text, match.start()) if match else 1
                    dependencies.append(Dependency(path, target, "package", line))
    elif basename.startswith("requirements") and basename.endswith(".txt"):
        for line_number, line in enumerate(text.splitlines(), start=1):
            value = line.strip()
            if not value or value.startswith(("#", "-")):
                continue
            target = re.split(r"[<>=!~;\s\[]", value, maxsplit=1)[0]
            if target:
                dependencies.append(Dependency(path, target, "package", line_number))
    elif basename == "cargo.toml":
        in_dependencies = False
        for line_number, line in enumerate(text.splitlines(), start=1):
            section = re.match(r"^\s*\[([^]]+)]", line)
            if section:
                name = section.group(1).strip()
                in_dependencies = name == "dependencies" or name.endswith(".dependencies")
                continue
            if in_dependencies:
                match = re.match(r"^\s*([A-Za-z_][\w-]*)\s*=", line)
                if match:
                    dependencies.append(Dependency(path, match.group(1), "package", line_number))
    elif basename == "go.mod":
        for line_number, line in enumerate(text.splitlines(), start=1):
            match = re.match(r"^\s*(?:require\s+)?([\w./-]+)\s+v\d", line)
            if match:
                dependencies.append(Dependency(path, match.group(1), "package", line_number))
    return dependencies


class HeuristicParser:
    """Regex/brace parser for source, Markdown, and configuration files."""

    languages = frozenset(
        {"javascript", "typescript", "go", "rust", "java", "c", "cpp", "markdown", "config"}
    )

    def parse(
        self,
        path: str,
        text: str,
        language: str,
        *,
        max_chunk_lines: int,
        max_chunk_chars: int,
    ) -> ParseResult:
        if language == "markdown":
            symbols = _markdown_symbols(path, text)
            dependencies: list[Dependency] = []
            is_entry_point = False
        elif language == "config":
            symbols = _config_symbols(path, text)
            dependencies = _config_dependencies(path, text)
            is_entry_point = False
        else:
            symbols = _source_symbols(path, text, language)
            dependencies = _source_dependencies(path, text, language)
            is_entry_point = _source_entry_point(path, text, language)

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
        return ParseResult(
            symbols=tuple(symbols),
            dependencies=tuple(dependencies),
            chunks=chunks,
            is_entry_point=is_entry_point,
        )
