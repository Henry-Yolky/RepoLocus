from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from repolocus.parsers import (
    HeuristicParser,
    ParseResult,
    ParserRegistry,
    PythonParser,
    TreeSitterParser,
    parse_source,
)
from repolocus.parsers import heuristic as heuristic_module
from repolocus.parsers.chunking import Region, semantic_chunks


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


@pytest.mark.parametrize(
    ("language", "path", "source"),
    [
        (
            "javascript",
            "src/library.js",
            "/*\nimport hidden from './fake.js';\nexport function hidden() {}\n"
            "require.main === module;\n*/\n"
            "const literal = \"import stringValue from './string.js'\";\n"
            "export function visible() {}\n",
        ),
        (
            "typescript",
            "src/library.ts",
            "/*\nimport hidden from './fake';\nexport function hidden() {}\n"
            "import.meta.main;\n*/\n"
            "const literal: string = \"import value from './string'\";\n"
            "export function visible(): void {}\n",
        ),
        (
            "c",
            "src/library.c",
            '/*\n#include "fake.h"\nint main(void) {}\n*/\n'
            'const char *literal = "int main(void)";\n'
            "int visible(void) { return 0; }\n",
        ),
        (
            "cpp",
            "src/library.cpp",
            '/*\n#include "fake.hpp"\nint main() {}\n*/\n'
            'const char *literal = "int main()";\n'
            "int visible() { return 0; }\n",
        ),
        (
            "rust",
            "src/library.rs",
            "/*\nuse fake::module;\nfn main() {}\n*/\n"
            'const LITERAL: &str = "use string::module;";\n'
            "fn visible() {}\n",
        ),
    ],
)
def test_heuristic_source_facts_ignore_comments_and_strings(
    language: str, path: str, source: str
) -> None:
    result = HeuristicParser().parse(
        path,
        source,
        language,
        max_chunk_lines=160,
        max_chunk_chars=16_000,
    )

    assert [symbol.name for symbol in result.symbols] == ["visible"]
    assert result.dependencies == ()
    assert not result.is_entry_point


def test_rust_lifetime_does_not_hide_following_symbols() -> None:
    result = HeuristicParser().parse(
        "src/library.rs",
        "fn borrow<'a>() {}\nfn visible() {}\n",
        "rust",
        max_chunk_lines=160,
        max_chunk_chars=16_000,
    )

    assert [symbol.name for symbol in result.symbols] == ["borrow", "visible"]


def test_cpp_hex_digit_separator_does_not_hide_following_symbols() -> None:
    result = HeuristicParser().parse(
        "src/library.cpp",
        "constexpr auto mask = 0x1'FF;\n"
        "constexpr auto letter = u8'F';\n"
        "int visible() { return 0; }\n",
        "cpp",
        max_chunk_lines=160,
        max_chunk_chars=16_000,
    )

    assert [symbol.name for symbol in result.symbols] == ["visible"]


def test_heuristic_javascript_dependencies_respect_lexical_context() -> None:
    source = (
        'const pattern = /import value from "fake"/;\n'
        'const rendered = `${require("./template.js")}`;\n'
        "import {\n"
        "  value,\n"
        '} from "./static.js";\n'
    )

    result = HeuristicParser().parse(
        "src/library.js",
        source,
        "javascript",
        max_chunk_lines=160,
        max_chunk_chars=16_000,
    )

    assert [
        (dependency.target, dependency.kind, dependency.line) for dependency in result.dependencies
    ] == [
        ("./template.js", "require", 2),
        ("./static.js", "import", 3),
    ]


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


def test_go_inline_import_block_is_extracted() -> None:
    result = HeuristicParser().parse(
        "sample.go",
        'package sample\nimport ("fmt")\n',
        "go",
        max_chunk_lines=160,
        max_chunk_chars=16_000,
    )

    assert [(dependency.target, dependency.line) for dependency in result.dependencies] == [
        ("fmt", 2)
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
  "scripts": {
    "react": "echo not a dependency"
  },
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
    assert [(item.target, item.line) for item in result.dependencies] == [
        ("react", 7),
        ("zod", 8),
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
        cache_key = "test-custom:v1"
        priority = 0

        def parse(
            self,
            path: str,
            text: str,
            language: str,
            *,
            max_chunk_lines: int,
            max_chunk_chars: int,
            **_limits: int,
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


def test_optional_tree_sitter_adapters_keep_ranges_and_fallback_dependencies() -> None:
    parser = TreeSitterParser.discover()
    if parser is None:
        pytest.skip("Tree-sitter language extras are not installed")

    fixtures = {
        "c": ('#include "config.h"\nint main(void) {\n  return 0;\n}\n', "main"),
        "javascript": (
            "import value from './value.js';\nexport function run() {\n  return value;\n}\n",
            "run",
        ),
        "rust": ("use crate::config;\npub fn run() {\n    config::load();\n}\n", "run"),
        "typescript": (
            "import { value } from './value';\n"
            "export function run(): number {\n  return value;\n}\n",
            "run",
        ),
    }
    for language, (text, expected_symbol) in fixtures.items():
        if language not in parser.languages:
            continue
        result = parser.parse(
            f"src/example.{language}",
            text,
            language,
            max_chunk_lines=160,
            max_chunk_chars=16_000,
        )
        symbol = next(item for item in result.symbols if item.name == expected_symbol)
        assert symbol.start_line == 2
        assert symbol.end_line >= symbol.start_line
        assert result.dependencies
        assert result.chunks


def test_optional_tree_sitter_uses_syntax_names_and_merges_fallback_symbols() -> None:
    parser = TreeSitterParser.discover()
    if parser is None:
        pytest.skip("Tree-sitter language extras are not installed")

    fixtures = {
        "cpp": ("int ns::f() { return 1; }\n", {"ns::f"}),
        "rust": ("impl<'a> Thing<'a> { fn run(&self) {} }\n", {"Thing<'a>", "run"}),
        "typescript": ("function run() {}\nconst helper = () => {};\n", {"run", "helper"}),
    }
    for language, (text, expected_symbols) in fixtures.items():
        if language not in parser.languages:
            continue
        result = parser.parse(
            f"src/example.{language}",
            text,
            language,
            max_chunk_lines=160,
            max_chunk_chars=16_000,
        )

        assert expected_symbols <= {symbol.name for symbol in result.symbols}

    if "rust" in parser.languages:
        trait_impl = parser.parse(
            "src/trait_impl.rs",
            "impl<'a, T> Trait<'a> for Thing<T> { fn run(&self) {} }\n",
            "rust",
            max_chunk_lines=160,
            max_chunk_chars=16_000,
        )
        assert [symbol.name for symbol in trait_impl.symbols if symbol.kind == "impl"] == [
            "Thing<T>"
        ]


def test_tree_sitter_cache_key_tracks_fallback_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    original = TreeSitterParser(object, {"c": object()}).cache_key

    monkeypatch.setattr(HeuristicParser, "cache_key", "heuristic-multilang:test")
    changed = TreeSitterParser(object, {"c": object()}).cache_key

    assert changed != original
    assert len(changed) <= 128


def test_source_layout_uses_the_same_unicode_line_model_as_chunks() -> None:
    source = "const value = 1;\u2028\nexport function visible() {}\n"
    parsers = [HeuristicParser()]
    tree_sitter = TreeSitterParser.discover()
    if tree_sitter is not None and "javascript" in tree_sitter.languages:
        parsers.append(tree_sitter)

    for parser in parsers:
        result = parser.parse(
            "src/example.js",
            source,
            "javascript",
            max_chunk_lines=160,
            max_chunk_chars=16_000,
        )
        visible = next(symbol for symbol in result.symbols if symbol.name == "visible")
        symbol_chunks = [chunk for chunk in result.chunks if chunk.symbol == "visible"]

        assert visible.start_line == 3
        assert symbol_chunks
        assert "export function visible" in "".join(chunk.content for chunk in symbol_chunks)


def test_python_syntax_fallback_ignores_triple_quoted_fake_facts() -> None:
    source = (
        '"""\nimport fake\ndef hidden():\n    pass\n"""\nimport real\ndef visible(:\n    pass\n'
    )

    result = PythonParser().parse(
        "broken.py",
        source,
        "python",
        max_chunk_lines=160,
        max_chunk_chars=16_000,
    )

    assert [symbol.name for symbol in result.symbols] == ["visible"]
    assert [dependency.target for dependency in result.dependencies] == ["real"]


def test_python_syntax_fallback_ignores_unterminated_triple_quoted_text() -> None:
    source = 'import real\n"""\nimport fake\ndef hidden():\n    pass\n'

    result = PythonParser().parse(
        "broken.py",
        source,
        "python",
        max_chunk_lines=160,
        max_chunk_chars=16_000,
    )

    assert result.symbols == ()
    assert [dependency.target for dependency in result.dependencies] == ["real"]


def test_package_dependency_line_lookup_scans_keys_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = {"dependencies": {f"package-{index}": {"version": "1"} for index in range(250)}}
    source = json.dumps(package, indent=2)
    calls = 0
    original = re.finditer

    def counted_finditer(*args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(heuristic_module.re, "finditer", counted_finditer)

    result = HeuristicParser().parse(
        "package.json",
        source,
        "config",
        max_chunk_lines=160,
        max_chunk_chars=16_000,
    )

    assert len(result.dependencies) == 250
    assert calls < 20


def test_tree_sitter_native_facts_do_not_merge_heuristic_literal_matches() -> None:
    parser = TreeSitterParser.discover()
    if parser is None:
        pytest.skip("Tree-sitter language extras are not installed")

    fixtures = {
        "rust": (
            'const TEXT: &str = r#"\n"\nfn fake() {}\n"#;\nfn real() {}\n',
            ["real"],
            [],
        ),
        "cpp": (
            'const char* text = R"tag(\n"\nint fake() {}\n)tag";\nint real() {}\n',
            ["real"],
            [],
        ),
        "javascript": (
            'const pattern = /import value from "fake"/;\n'
            'const actual = `${require("./real")}`;\n'
            "export function visible() {}\n",
            ["visible"],
            ["./real"],
        ),
    }
    for language, (source, expected_symbols, expected_dependencies) in fixtures.items():
        if language not in parser.languages:
            continue
        result = parser.parse(
            f"src/example.{language}",
            source,
            language,
            max_chunk_lines=160,
            max_chunk_chars=16_000,
        )

        assert [symbol.name for symbol in result.symbols] == expected_symbols
        assert [dependency.target for dependency in result.dependencies] == expected_dependencies


def test_tree_sitter_extracts_multiline_javascript_and_grouped_rust_dependencies() -> None:
    parser = TreeSitterParser.discover()
    if parser is None:
        pytest.skip("Tree-sitter language extras are not installed")

    if "javascript" in parser.languages:
        javascript = parser.parse(
            "src/app.js",
            'import {\n  value,\n} from "./dep.js";\nexport function run() {}\n',
            "javascript",
            max_chunk_lines=160,
            max_chunk_chars=16_000,
        )
        assert [dependency.target for dependency in javascript.dependencies] == ["./dep.js"]

    if "rust" in parser.languages:
        rust = parser.parse(
            "src/lib.rs",
            "pub(crate) use crate::foo as local;\n"
            "use crate::{bar, baz};\n"
            "mod external;\n"
            "mod inline { pub fn run() {} }\n",
            "rust",
            max_chunk_lines=160,
            max_chunk_chars=16_000,
        )
        assert [dependency.target for dependency in rust.dependencies] == [
            "crate::foo",
            "crate::bar",
            "crate::baz",
            "external",
        ]


def test_tree_sitter_uses_the_tsx_grammar_variant() -> None:
    parser = TreeSitterParser.discover()
    if parser is None:
        pytest.skip("Tree-sitter language extras are not installed")

    assert "tsx" in parser._language_objects
    result = parser.parse(
        "src/App.tsx",
        "export function App() { return <main>ok</main>; }\n",
        "typescript",
        max_chunk_lines=160,
        max_chunk_chars=16_000,
    )

    assert [symbol.name for symbol in result.symbols] == ["App"]


def test_tree_sitter_discovery_degrades_on_optional_adapter_runtime_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    core = SimpleNamespace(Language=lambda capsule: capsule, Parser=object)

    def import_module(name: str):
        if name == "tree_sitter":
            return core
        raise RuntimeError("broken optional adapter")

    monkeypatch.setattr("repolocus.parsers.treesitter.importlib.import_module", import_module)

    assert TreeSitterParser.discover() is None


@pytest.mark.parametrize(
    ("language", "path", "source"),
    [
        ("javascript", "src/adversarial.js", "import " * 4_000),
        ("javascript", "src/spaces.js", "import " + " " * 1_600 + "x"),
        ("go", "adversarial.go", "package sample\n" + "import (\n" * 4_000),
    ],
)
def test_heuristic_import_scanning_is_bounded_on_unclosed_input(
    language: str,
    path: str,
    source: str,
) -> None:
    started = time.monotonic()

    HeuristicParser().parse(
        path,
        source,
        language,
        max_chunk_lines=160,
        max_chunk_chars=16_000,
    )

    assert time.monotonic() - started < 0.5


def test_tree_sitter_success_does_not_materialize_full_heuristic_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser = TreeSitterParser.discover()
    if parser is None or "javascript" not in parser.languages:
        pytest.skip("Tree-sitter JavaScript extras are not installed")

    def unexpected_baseline(*args: object, **kwargs: object) -> ParseResult:
        raise AssertionError("native success must not build the heuristic baseline")

    monkeypatch.setattr(parser._fallback, "_parse_layout", unexpected_baseline)

    result = parser.parse(
        "src/app.js",
        "export function run() {}\n",
        "javascript",
        max_chunk_lines=160,
        max_chunk_chars=16_000,
    )

    assert [symbol.name for symbol in result.symbols] == ["run"]


def test_tree_sitter_preserves_fallback_only_rust_facts_and_javascript_kinds() -> None:
    parser = TreeSitterParser.discover()
    if parser is None:
        pytest.skip("Tree-sitter language extras are not installed")

    if "rust" in parser.languages:
        rust = parser.parse(
            "src/lib.rs",
            "extern crate alloc;\nuse crate::worker;\n",
            "rust",
            max_chunk_lines=160,
            max_chunk_chars=16_000,
        )
        assert [(item.target, item.kind) for item in rust.dependencies] == [
            ("alloc", "import"),
            ("crate::worker", "import"),
        ]

    if "javascript" in parser.languages:
        javascript = parser.parse(
            "src/app.js",
            'import value from "./static.js";\n'
            'const required = require("./required.js");\n'
            'const lazy = import("./lazy.js");\n',
            "javascript",
            max_chunk_lines=160,
            max_chunk_chars=16_000,
        )
        assert [(item.target, item.kind) for item in javascript.dependencies] == [
            ("./static.js", "import"),
            ("./required.js", "require"),
            ("./lazy.js", "dynamic_import"),
        ]


def test_tree_sitter_fact_limit_does_not_retry_with_heuristic_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser = TreeSitterParser.discover()
    if parser is None or "javascript" not in parser.languages:
        pytest.skip("Tree-sitter JavaScript extras are not installed")

    def unexpected_fallback(*args: object, **kwargs: object) -> ParseResult:
        raise AssertionError("fact budget failures must not trigger fallback")

    monkeypatch.setattr(parser._fallback, "_parse_layout", unexpected_fallback)

    with pytest.raises(ValueError, match="symbol limit"):
        parser.parse(
            "src/many.js",
            "function one() {}\nfunction two() {}\n",
            "javascript",
            max_chunk_lines=160,
            max_chunk_chars=16_000,
            max_symbols_per_file=1,
        )

    if "rust" in parser.languages:
        with pytest.raises(ValueError, match="dependency limit"):
            parser.parse(
                "src/lib.rs",
                "use crate::{one, two};\n",
                "rust",
                max_chunk_lines=160,
                max_chunk_chars=16_000,
                max_dependencies_per_file=1,
            )
        duplicate = parser.parse(
            "src/lib.rs",
            "use crate::{worker, worker};\n",
            "rust",
            max_chunk_lines=160,
            max_chunk_chars=16_000,
            max_dependencies_per_file=1,
        )
        assert [(item.target, item.kind) for item in duplicate.dependencies] == [
            ("crate::worker", "import")
        ]


@pytest.mark.parametrize(
    ("source", "limits", "message"),
    [
        (
            "int one(void) {}\nint two(void) {}\nint three(void) {}\n",
            {"max_symbols_per_file": 2},
            "symbol limit",
        ),
        (
            'import "one"\nimport "two"\nimport "three"\n',
            {"max_dependencies_per_file": 2},
            "dependency limit",
        ),
        (
            "".join(f"int nested_{index}(void) {{\n" for index in range(40)) + "}\n" * 40,
            {"max_chunks_per_file": 2},
            "configured chunk limit",
        ),
    ],
)
def test_heuristic_parser_enforces_fact_limits_before_returning(
    source: str,
    limits: dict[str, int],
    message: str,
) -> None:
    defaults = {
        "max_symbols_per_file": 10_000,
        "max_dependencies_per_file": 10_000,
        "max_chunks_per_file": 10_000,
    }
    defaults.update(limits)

    with pytest.raises(ValueError, match=message):
        HeuristicParser().parse(
            "nested.c" if "int " in source else "imports.go",
            source,
            "c" if "int " in source else "go",
            max_chunk_lines=2,
            max_chunk_chars=16_000,
            **defaults,
        )
