from __future__ import annotations

from dataclasses import dataclass

import pytest

from devpilot.parsers import (
    HeuristicParser,
    ParseResult,
    ParserRegistry,
    PythonParser,
    parse_source,
)
from devpilot.parsers.chunking import Region, semantic_chunks


def test_python_ast_extracts_qualified_symbols_imports_and_entry_point() -> None:
    source = """import os
from .tools import helper

class Service:
    async def run(self, value: int) -> str:
        return str(value)

def main(argv: list[str]) -> int:
    return len(argv)

if __name__ == "__main__":
    raise SystemExit(main([]))
"""
    result = parse_source("pkg/app.py", source, "python")

    assert [(symbol.name, symbol.kind) for symbol in result.symbols] == [
        ("Service", "class"),
        ("Service.run", "method"),
        ("main", "function"),
    ]
    assert result.symbols[1].signature == "async def run(self, value: int) -> str"
    assert [(item.target, item.line) for item in result.dependencies] == [("os", 1), (".tools", 2)]
    assert result.is_entry_point
    assert all(chunk.path == "pkg/app.py" for chunk in result.chunks)
    assert any(chunk.symbol == "Service.run" for chunk in result.chunks)


def test_python_syntax_error_uses_safe_fallback() -> None:
    source = "import package\ndef still_visible(:\n    pass\n"
    result = parse_source("broken.py", source, "python")

    assert [symbol.name for symbol in result.symbols] == ["still_visible"]
    assert [dependency.target for dependency in result.dependencies] == ["package"]
    assert result.chunks


@pytest.mark.parametrize(
    ("language", "path", "source", "symbol", "dependency", "entry"),
    [
        (
            "javascript",
            "src/index.js",
            "import value from 'library';\nexport function start() { return value; }\n",
            "start",
            "library",
            True,
        ),
        (
            "typescript",
            "src/worker.ts",
            "import type { Job } from './job';\nexport interface Worker { run(): Job }\n",
            "Worker",
            "./job",
            False,
        ),
        (
            "go",
            "cmd/tool/main.go",
            'package main\nimport "fmt"\nfunc main() { fmt.Println("ok") }\n',
            "main",
            "fmt",
            True,
        ),
        (
            "rust",
            "src/main.rs",
            "use std::{fs, io};\npub struct App { ready: bool }\nfn main() {}\n",
            "App",
            "std",
            True,
        ),
        (
            "java",
            "src/Main.java",
            "import java.util.List;\npublic class Main {\n"
            " public static void main(String[] args) {}\n}\n",
            "Main",
            "java.util.List",
            True,
        ),
        (
            "c",
            "src/main.c",
            "#include <stdio.h>\nint main(void) { return 0; }\n",
            "main",
            "stdio.h",
            True,
        ),
        (
            "cpp",
            "src/tool.cpp",
            '#include "tool.hpp"\nclass Tool { public: void run() {} };\n',
            "Tool",
            "tool.hpp",
            False,
        ),
    ],
)
def test_heuristic_language_families(
    language: str,
    path: str,
    source: str,
    symbol: str,
    dependency: str,
    entry: bool,
) -> None:
    result = parse_source(path, source, language)

    assert symbol in {item.name for item in result.symbols}
    assert dependency in {item.target for item in result.dependencies}
    assert result.is_entry_point is entry
    assert result.chunks


def test_brace_matching_ignores_strings_and_comments() -> None:
    source = """export function parse() {
  const literal = "}";
  // }
  /* { ignored } */
  if (true) { return { ok: true }; }
}
export function next() { return 2; }
"""
    result = parse_source("lib.js", source, "javascript")

    symbols = {item.name: item for item in result.symbols}
    assert symbols["parse"].end_line == 6
    assert symbols["next"].start_line == 7
    assert symbols["next"].end_line == 7


def test_go_import_block_aliases_are_extracted_with_lines() -> None:
    source = """package sample
import (
    "fmt"
    alias "example.org/project/pkg"
    _ "example.org/driver"
)
"""
    result = parse_source("sample.go", source, "go")

    assert [(item.target, item.line) for item in result.dependencies] == [
        ("fmt", 3),
        ("example.org/project/pkg", 4),
        ("example.org/driver", 5),
    ]


def test_markdown_sections_define_semantic_chunks() -> None:
    source = "# Overview\nintro\n## Details\nbody\n# Next\nend\n"
    result = parse_source("README.md", source, "markdown")

    assert [(item.name, item.start_line, item.end_line) for item in result.symbols] == [
        ("Overview", 1, 4),
        ("Details", 3, 4),
        ("Next", 5, 6),
    ]
    assert {chunk.symbol for chunk in result.chunks} == {"Overview", "Details", "Next"}


def test_config_sections_and_package_dependencies() -> None:
    package = """{
  "name": "demo",
  "dependencies": {
    "react": "19.0.0",
    "zod": "4.0.0"
  }
}
"""
    result = parse_source("package.json", package, "config")

    assert {item.name for item in result.symbols} >= {"name", "dependencies", "react", "zod"}
    assert [(item.target, item.kind) for item in result.dependencies] == [
        ("react", "package"),
        ("zod", "package"),
    ]

    cargo = parse_source(
        "Cargo.toml",
        '[package]\nname = "demo"\n[dependencies]\nserde = "1"\ntokio = { version = "1" }\n',
        "config",
    )
    assert {item.target for item in cargo.dependencies} == {"serde", "tokio"}


def test_chunks_are_bounded_by_lines_and_characters() -> None:
    text = "# Heading\n" + "abcdefghij" * 5 + "\n" + "line\n" * 8
    chunks = semantic_chunks(
        path="README.md",
        text=text,
        language="markdown",
        regions=[Region(1, 10, "Heading")],
        max_lines=3,
        max_chars=20,
    )

    assert chunks
    assert all(chunk.end_line - chunk.start_line + 1 <= 3 for chunk in chunks)
    assert all(len(chunk.content) <= 20 for chunk in chunks)
    assert all(chunk.symbol == "Heading" for chunk in chunks)


def test_registry_is_deterministic_and_supports_plugins() -> None:
    @dataclass(frozen=True)
    class CustomParser:
        languages = frozenset({"custom"})

        def parse(
            self,
            path: str,
            text: str,
            language: str,
            *,
            max_chunk_lines: int,
            max_chunk_chars: int,
        ) -> ParseResult:
            return ParseResult(is_entry_point=text == "entry")

    registry = ParserRegistry()
    registry.register(CustomParser())
    assert registry.languages == ("custom",)
    assert registry.parse("a.custom", "entry", "custom").is_entry_point
    with pytest.raises(ValueError, match="already registered"):
        registry.register(CustomParser())
    with pytest.raises(ValueError, match="unsupported parser language"):
        registry.parse("a.py", "", "python")
    with pytest.raises(ValueError, match="positive"):
        registry.parse("a.custom", "", "custom", max_chunk_lines=0)


def test_built_in_parser_declarations_do_not_overlap() -> None:
    assert PythonParser.languages.isdisjoint(HeuristicParser.languages)
