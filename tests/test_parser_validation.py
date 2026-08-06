from __future__ import annotations

from pathlib import Path

import pytest

from repolocus.models import Chunk, Dependency, Symbol
from repolocus.parsers import ParseResult, ParserRegistry
from repolocus.scanner import RepositoryScanner
from repolocus.scanner.validation import ParseLimits, finalize_parse_result


def _limits(**overrides: int) -> ParseLimits:
    values = {
        "max_chunk_lines": 160,
        "max_chunk_chars": 16_000,
        "max_dependencies_per_file": 10_000,
        "max_symbols_per_file": 10_000,
        "max_chunks_per_file": 10_000,
    }
    values.update(overrides)
    return ParseLimits(**values)


def test_empty_plugin_chunks_use_bounded_semantic_chunking_for_near_megabyte_source() -> None:
    text = "".join(f"{index:06d}:" + ("x" * 993) for index in range(1_000))

    normalized, counts = finalize_parse_result(
        ParseResult(),
        text=text,
        path="large.py",
        language="python",
        limits=_limits(),
    )

    assert len(text) == 1_000_000
    assert counts.chunks == len(normalized.chunks)
    assert len(normalized.chunks) > 1
    assert all(chunk.end_line - chunk.start_line + 1 <= 160 for chunk in normalized.chunks)
    assert all(len(chunk.content) <= 16_000 for chunk in normalized.chunks)


def test_empty_plugin_chunk_fallback_stops_at_the_per_file_chunk_limit() -> None:
    with pytest.raises(ValueError, match="configured chunk limit"):
        finalize_parse_result(
            ParseResult(),
            text="x" * 100_000,
            path="large.py",
            language="python",
            limits=_limits(max_chunk_chars=1, max_chunks_per_file=2),
        )


@pytest.mark.parametrize(
    ("parsed", "message"),
    [
        (
            ParseResult(symbols=(Symbol("bad\u202e", "function", "a.py", 1, 1),)),
            "unsafe controls",
        ),
        (
            ParseResult(symbols=(Symbol("name", "function", "a.py", 0, 1),)),
            "invalid symbol source range",
        ),
        (
            ParseResult(dependencies=(Dependency("a.py", "x" * 1_025, "import", 1),)),
            "oversized dependency target",
        ),
        (
            ParseResult(chunks=(Chunk("a.py", 1, 1, "not in source", "python"),)),
            "not present",
        ),
        (
            ParseResult(
                chunks=(
                    Chunk("a.py", 1, 2, "one\ntwo\n", "python"),
                    Chunk("a.py", 2, 3, "two\nthree\n", "python"),
                )
            ),
            "partially overlapping",
        ),
        (
            ParseResult(chunks=(Chunk("a.py", 1, 1, "one\r", "python"),)),
            "unsafe controls",
        ),
    ],
)
def test_parser_postconditions_reject_unsafe_or_inconsistent_facts(
    parsed: ParseResult,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        finalize_parse_result(
            parsed,
            text="one\ntwo\nthree\n",
            path="a.py",
            language="python",
            limits=_limits(),
        )


def test_scanner_accepts_crlf_source_without_weakening_bare_cr_controls(tmp_path: Path) -> None:
    (tmp_path / "value.py").write_bytes(b"VALUE = 1\r\n")

    result = RepositoryScanner().scan(tmp_path)

    assert [file.path for file in result.files] == ["value.py"]
    assert result.stats.skipped.get("parse_error", 0) == 0
    assert result.files[0].chunks[0].content == "VALUE = 1\r\n"


def test_per_file_fact_limits_fail_closed_before_indexing() -> None:
    dependencies = tuple(
        Dependency("a.py", f"dependency-{index}", "import", 1) for index in range(3)
    )

    with pytest.raises(ValueError, match="per-file safety limit"):
        finalize_parse_result(
            ParseResult(dependencies=dependencies),
            text="value = 1\n",
            path="a.py",
            language="python",
            limits=_limits(max_dependencies_per_file=2),
        )


@pytest.mark.parametrize(
    ("field", "fact", "limit_name"),
    [
        ("symbols", Symbol("value", "variable", "a.py", 1, 1), "max_symbols_per_file"),
        (
            "dependencies",
            Dependency("a.py", "target", "import", 1),
            "max_dependencies_per_file",
        ),
        ("chunks", Chunk("a.py", 1, 1, "value = 1\n", "python"), "max_chunks_per_file"),
    ],
)
def test_unbounded_plugin_fact_iterables_stop_at_the_per_file_limit(
    field: str,
    fact: object,
    limit_name: str,
) -> None:
    class InfiniteFacts:
        def __init__(self) -> None:
            self.emitted = 0

        def __iter__(self):  # type: ignore[no-untyped-def]
            while True:
                self.emitted += 1
                yield fact

    emitted = InfiniteFacts()
    values: dict[str, object] = {
        "symbols": (),
        "dependencies": (),
        "chunks": (),
    }
    values[field] = emitted
    parsed = ParseResult(**values)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="per-file safety limit"):
        finalize_parse_result(
            parsed,
            text="value = 1\n",
            path="a.py",
            language="python",
            limits=_limits(**{limit_name: 2}),
        )

    assert emitted.emitted == 3


def test_finite_generator_facts_are_normalized_without_full_materialization() -> None:
    symbols = (Symbol(name, "variable", "a.py", 1, 1) for name in ("first", "second"))

    normalized, counts = finalize_parse_result(
        ParseResult(symbols=symbols),  # type: ignore[arg-type]
        text="value = 1\n",
        path="a.py",
        language="python",
        limits=_limits(max_symbols_per_file=2),
    )

    assert counts.symbols == 2
    assert [symbol.name for symbol in normalized.symbols] == ["first", "second"]


def test_non_iterable_plugin_fact_collection_fails_closed() -> None:
    with pytest.raises(ValueError, match="facts must be iterable"):
        finalize_parse_result(
            ParseResult(symbols=object()),  # type: ignore[arg-type]
            text="value = 1\n",
            path="a.py",
            language="python",
            limits=_limits(),
        )


def test_validation_failure_does_not_consume_repository_fact_budget(tmp_path: Path) -> None:
    class FailingThenValidParser:
        languages = frozenset({"python"})
        cache_key = "test-transactional-budget:v1"
        priority = 0

        def parse(
            self,
            path: str,
            text: str,
            language: str,
            *,
            max_chunk_lines: int,
            max_chunk_chars: int,
        ) -> ParseResult:
            del text, language, max_chunk_lines, max_chunk_chars
            start_line = 0 if path == "a.py" else 1
            return ParseResult(
                symbols=(Symbol("value", "variable", path, start_line, 1),),
            )

    (tmp_path / "a.py").write_text("a = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("b = 2\n", encoding="utf-8")
    registry = ParserRegistry()
    registry.register(FailingThenValidParser())

    result = RepositoryScanner(
        parser_registry=registry,
        max_repository_symbols=1,
    ).scan(tmp_path)

    assert [file.path for file in result.files] == ["b.py"]
    assert result.stats.skipped["parse_error"] == 1
    assert len(result.files[0].symbols) == 1


def test_repository_dependency_budget_is_enforced(tmp_path: Path) -> None:
    class DependencyParser:
        languages = frozenset({"python"})
        cache_key = "test-dependency-budget:v1"
        priority = 0

        def parse(
            self,
            path: str,
            text: str,
            language: str,
            *,
            max_chunk_lines: int,
            max_chunk_chars: int,
        ) -> ParseResult:
            del text, language, max_chunk_lines, max_chunk_chars
            return ParseResult(
                dependencies=(Dependency(path, "target", "import", 1),),
            )

    (tmp_path / "a.py").write_text("a = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("b = 2\n", encoding="utf-8")
    registry = ParserRegistry()
    registry.register(DependencyParser())

    result = RepositoryScanner(
        parser_registry=registry,
        max_repository_dependencies=1,
    ).scan(tmp_path)

    assert [file.path for file in result.files] == ["a.py"]
    assert result.stats.skipped["repository_budget"] == 1
    assert any("dependency count" in warning for warning in result.warnings)
