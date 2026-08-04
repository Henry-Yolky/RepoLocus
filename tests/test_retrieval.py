from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from repolocus.index import RepositoryIndex
from repolocus.models import Chunk, Dependency, ScannedFile, ScanResult, ScanStats, Symbol
from repolocus.retrieval import RetrievalEngine


def _source(
    path: str,
    text: str,
    symbol: str,
    *,
    dependency: str = "",
) -> ScannedFile:
    lines = len(text.splitlines())
    return ScannedFile(
        path=path,
        language="python",
        size_bytes=len(text.encode()),
        sha256=hashlib.sha256(text.encode()).hexdigest(),
        line_count=lines,
        text=text,
        symbols=(Symbol(symbol, "function", path, 1, lines),),
        dependencies=(Dependency(path, dependency, "import", 1),) if dependency else (),
        chunks=(Chunk(path, 1, lines, text, "python", symbol),),
    )


@pytest.fixture
def engine(tmp_path: Path) -> tuple[RetrievalEngine, RepositoryIndex]:
    repository = tmp_path / "repository"
    repository.mkdir()
    service = _source(
        "src/service.py",
        "def authenticate_user(token):\n"
        "    credential_marker = token\n"
        "    return credential_marker\n",
        "authenticate_user",
        dependency="src.store",
    )
    store = _source(
        "src/store.py",
        "def load_record(key):\n"
        "    persistence_layer = {}\n"
        "    return persistence_layer.get(key)\n",
        "load_record",
    )
    helper = _source(
        "src/helper.py",
        "def authenticate_proxy():\n    return False\n",
        "authenticate_proxy",
    )
    index = RepositoryIndex.open(repository, tmp_path / "cache")
    index.update(ScanResult(repository, [helper, store, service], ScanStats()))
    yield RetrievalEngine(index), index
    index.close()


def test_exact_symbol_match_is_boosted_and_source_addressable(
    engine: tuple[RetrievalEngine, RepositoryIndex],
) -> None:
    retrieval, _ = engine

    results = retrieval.search("Where is authenticate_user() implemented?", limit=3)

    assert results[0].path == "src/service.py"
    assert results[0].symbol == "authenticate_user"
    assert results[0].citation == "src/service.py:1-3"
    assert "exact symbol match: authenticate_user" in results[0].reason
    assert results[0].score > results[1].score


def test_partial_symbol_match_is_reported(
    engine: tuple[RetrievalEngine, RepositoryIndex],
) -> None:
    retrieval, _ = engine

    results = retrieval.search("authenticate", limit=3)

    assert {result.symbol for result in results[:2]} == {
        "authenticate_proxy",
        "authenticate_user",
    }
    assert all("partial symbol match" in result.reason for result in results[:2])


def test_query_expansion_does_not_claim_an_exact_user_symbol(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = _source(
        "src/config.py",
        "class Settings:\n    pass\n",
        "Settings",
    )
    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [source], ScanStats()))
        results = RetrievalEngine(
            index,
            synonyms={
                "configuration": ("config", "settings"),
                "validated": ("validate",),
            },
        ).search("Where is configuration validated?", limit=5)

    settings = next(result for result in results if result.symbol == "Settings")
    assert "query-expansion symbol match: Settings" in settings.reason
    assert "exact symbol match" not in settings.reason


def test_cjk_subphrases_and_identifier_parts_are_searchable(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = _source(
        "src/httpClient.py",
        "def loadConfigValue():\n    # \u8fd9\u91cc\u6267\u884c\u914d\u7f6e"
        "\u6821\u9a8c\u903b\u8f91\n    return True\n",
        "loadConfigValue",
    )
    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [source], ScanStats()))
        retrieval = RetrievalEngine(index)

        assert retrieval.search("\u914d\u7f6e", limit=1)[0].path == "src/httpClient.py"
        assert retrieval.search("\u6821\u9a8c", limit=1)[0].path == "src/httpClient.py"
        assert retrieval.search("http client", limit=1)[0].path == "src/httpClient.py"


def test_cjk_rewrite_uses_one_ngram_group_and_keeps_non_cjk_literal_required(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    with_policy = _source(
        "src/primary.py",
        "def verify_policy():\n    # \u8fd9\u91cc\u6267\u884c\u914d\u7f6e"
        "\u6821\u9a8c\u903b\u8f91\n    return policy\n",
        "verify_policy",
    )
    without_policy = _source(
        "src/secondary.py",
        "def verify_value():\n    # \u8fd9\u91cc\u6267\u884c\u914d\u7f6e"
        "\u6821\u9a8c\u903b\u8f91\n    return True\n",
        "verify_value",
    )
    one_overlap_only = _source(
        "src/distractor.py",
        "def load_configuration():\n    # \u8fd9\u91cc\u53ea\u8d1f\u8d23\u914d\u7f6e\u5728"
        "\u52a0\u8f7d\n    return True\n",
        "load_configuration",
    )
    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(
            ScanResult(
                repository,
                [one_overlap_only, with_policy, without_policy],
                ScanStats(),
            )
        )

        cjk_query = "\u914d\u7f6e" + "\u5728\u54ea\u91cc" + "\u6821\u9a8c"
        rewritten = index.search_chunks(cjk_query, limit=10)
        mixed = index.search_chunks(cjk_query + " policy", limit=10)

    assert {hit.chunk.path for hit in rewritten} == {
        "src/primary.py",
        "src/secondary.py",
    }
    assert [hit.chunk.path for hit in mixed] == ["src/primary.py"]


def test_expanded_terms_cannot_substitute_for_literal_coverage(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    literal = _source(
        "src/literal.py",
        "def literal_match():\n    return configuration and validated\n",
        "literal_match",
    )
    expanded_only = _source(
        "src/expanded.py",
        "def expanded_match():\n    return config and validate\n",
        "expanded_match",
    )
    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [literal, expanded_only], ScanStats()))

        hits = index.search_chunks(
            "configuration validated",
            limit=10,
            synonyms={"configuration": ("config",), "validated": ("validate",)},
        )

    assert [hit.chunk.path for hit in hits] == ["src/literal.py"]


def test_dependency_neighbors_expand_in_both_directions(
    engine: tuple[RetrievalEngine, RepositoryIndex],
) -> None:
    retrieval, _ = engine

    outbound = retrieval.search("credential_marker", limit=4)
    reverse = retrieval.search("load_record", limit=4)

    store = next(result for result in outbound if result.path == "src/store.py")
    assert store.reason == "dependency of src/service.py"
    service = next(result for result in reverse if result.path == "src/service.py")
    assert service.reason == "dependent of src/store.py"


def test_punctuation_and_fts_operators_cannot_break_query_parser(
    engine: tuple[RetrievalEngine, RepositoryIndex],
) -> None:
    retrieval, _ = engine

    assert retrieval.search("!@#$%^&*()[]{}") == []
    assert isinstance(retrieval.search('authenticate_user" OR * NOT ('), list)
    assert retrieval.search("credential_marker", limit=0) == []


def test_search_is_deterministic_and_honors_limit(
    engine: tuple[RetrievalEngine, RepositoryIndex],
) -> None:
    retrieval, _ = engine

    first = retrieval.search("authenticate", limit=1)
    second = retrieval.search("authenticate", limit=1)

    assert first == second
    assert len(first) == 1
