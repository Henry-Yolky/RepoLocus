from __future__ import annotations

import hashlib
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

from repolocus.index import RepositoryIndex
from repolocus.index.store import IndexedChunkHit
from repolocus.models import Chunk, Dependency, ScannedFile, ScanResult, ScanStats, Symbol
from repolocus.parsers import PythonParser
from repolocus.retrieval import MAX_RETRIEVAL_LIMIT, RetrievalEngine
from repolocus.retrieval.engine import _MINIMUM_RELEVANCE, _RRF_K, QueryIntent


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
    assert len(results) == 1


def test_exact_definition_stays_top_ranked_among_many_similar_symbols(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    sources: list[ScannedFile] = []
    parser = PythonParser()
    for number in range(60):
        path = f"src/group_0000/module_{number:06d}.py"
        functions: list[str] = []
        for offset in range(5):
            body = f"    return value + {number + offset}\n"
            if offset == 0 and number % 100:
                previous = number - 1
                body = (
                    f"    from .module_{previous:06d} "
                    f"import function_{previous:06d}_0\n"
                    f"    return function_{previous:06d}_0(value) + {number}\n"
                )
            functions.append(
                f"def function_{number:06d}_{offset}(value: int) -> int:\n"
                f'    """Return fixture value {offset} for module {number}. '
                f'{" " * 900}"""\n' + body
            )
        text = "".join(functions)
        parsed = parser.parse(
            path,
            text,
            "python",
            max_chunk_lines=160,
            max_chunk_chars=16_000,
        )
        sources.append(
            ScannedFile(
                path=path,
                language="python",
                size_bytes=len(text.encode()),
                sha256=hashlib.sha256(text.encode()).hexdigest(),
                line_count=len(text.splitlines()),
                text=text,
                symbols=parsed.symbols,
                dependencies=parsed.dependencies,
                chunks=parsed.chunks,
            )
        )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, sources, ScanStats()))
        result = RetrievalEngine(index).search_result(
            "Where is function_000050_0 defined?",
            limit=8,
        )

    assert result.evidence[0].path == "src/group_0000/module_000050.py"
    assert result.evidence[0].symbol == "function_000050_0"


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


def test_full_text_and_term_ranks_are_fused_without_overwriting_bm25(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    alphabetical_first = _source(
        "src/a.py",
        "def first():\n    # alpha beta " + "filler " * 100 + "\n    return True\n",
        "first",
    )
    stronger_fts = _source(
        "src/z.py",
        "def stronger():\n    # " + "alpha beta " * 20 + "\n    return True\n",
        "stronger",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [alphabetical_first, stronger_fts], ScanStats()))
        hits = index.search_chunks("alpha beta", limit=2)

    assert [hit.chunk.path for hit in hits] == [stronger_fts.path, alphabetical_first.path]


def test_dependency_neighbors_expand_in_both_directions(
    engine: tuple[RetrievalEngine, RepositoryIndex],
) -> None:
    retrieval, _ = engine

    outbound = retrieval.search("credential_marker", limit=4)
    reverse = retrieval.search("persistence", limit=4)

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


@pytest.mark.parametrize(
    "invalid_limit",
    [0, -1, True, 1.5, "1", MAX_RETRIEVAL_LIMIT + 1],
)
def test_public_retrieval_apis_reject_invalid_limits(
    engine: tuple[RetrievalEngine, RepositoryIndex],
    invalid_limit: object,
) -> None:
    retrieval, index = engine
    calls = (
        lambda: retrieval.search("authenticate", invalid_limit),
        lambda: retrieval.search_result("authenticate", invalid_limit),
        lambda: index.search_chunks("authenticate", invalid_limit),
        lambda: index.find_symbol_chunks("authenticate", invalid_limit),
        lambda: index.dependency_neighbors(["src/service.py"], invalid_limit),
    )

    for call in calls:
        with pytest.raises(ValueError, match=r"limit must be an integer between 1 and 500"):
            call()


def test_search_is_deterministic_and_honors_limit(
    engine: tuple[RetrievalEngine, RepositoryIndex],
) -> None:
    retrieval, _ = engine

    first = retrieval.search("authenticate", limit=1)
    second = retrieval.search("authenticate", limit=1)

    assert first == second
    assert len(first) == 1


def test_search_does_not_silently_cap_compatibility_limit(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    sources = [
        _source(
            f"src/item_{number:02d}.py",
            f"def item_{number:02d}():\n    shared_marker = {number}\n",
            f"item_{number:02d}",
        )
        for number in range(25)
    ]

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, sources, ScanStats()))
        results = RetrievalEngine(index).search("shared_marker", limit=25)

    assert len(results) == 25


def test_graph_seeds_are_limited_after_path_deduplication(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    lines = [f"calls common marker lookup first {number}\n" for number in range(8)]
    text = "".join(lines)
    first = ScannedFile(
        path="a.py",
        language="python",
        size_bytes=len(text.encode()),
        sha256=hashlib.sha256(text.encode()).hexdigest(),
        line_count=len(lines),
        text=text,
        chunks=tuple(
            Chunk("a.py", number + 1, number + 1, line, "python")
            for number, line in enumerate(lines)
        ),
    )
    second = _source(
        "b.py",
        "def second():\n    # calls common marker lookup\n    return True\n",
        "second",
    )
    neighbor = _source(
        "c.py",
        "def neighbor():\n    return True\n",
        "neighbor",
        dependency="b",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [first, second, neighbor], ScanStats()))
        results = RetrievalEngine(index).search("common marker lookup", limit=10)

    assert neighbor.path in {result.path for result in results}


def test_importer_query_uses_reverse_graph_before_applying_limit(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    outbound = [
        _source(
            f"a{number:02d}.py",
            f"def outbound_{number:02d}():\n    return {number}\n",
            f"outbound_{number:02d}",
        )
        for number in range(40)
    ]
    target = replace(
        _source(
            "target.py",
            "class TargetService:\n    pass\n",
            "TargetService",
        ),
        dependencies=tuple(
            Dependency("target.py", f"a{number:02d}", "import", 1)
            for number in range(len(outbound))
        ),
    )
    caller = _source(
        "zz_caller.py",
        "from target import TargetService\ndef build_service():\n    return TargetService()\n",
        "build_service",
        dependency="target",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [*outbound, target, caller], ScanStats()))
        results = [
            RetrievalEngine(index).search_result(
                f"Which {subject} imports TargetService?",
                limit=3,
            )
            for subject in ("module", "class", "component", "service")
        ]

    for result in results:
        assert result.intent == "dependency"
        assert [evidence.path for evidence in result.evidence] == [caller.path]
        assert "dependent of target.py" in result.evidence[0].reason


def test_caller_phrase_uses_only_the_queried_symbol_as_a_reverse_graph_seed(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    target = _source(
        "target.py",
        "class TargetService:\n    pass\n",
        "TargetService",
    )
    caller = _source(
        "caller.py",
        "from target import TargetService\ndef build_service():\n    return TargetService()\n",
        "build_service",
        dependency="target",
    )
    caller_of_caller = _source(
        "meta.py",
        "from caller import build_service\ndef build_meta():\n    return build_service()\n",
        "build_meta",
        dependency="caller",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [caller, caller_of_caller, target], ScanStats()))
        result = RetrievalEngine(index).search_result(
            "Which class calls TargetService?",
            limit=5,
        )

    assert result.intent == "references"
    assert [evidence.path for evidence in result.evidence] == [caller.path]
    assert "dependent of target.py" in result.evidence[0].reason


@pytest.mark.parametrize(
    "query",
    ("Who calls Missing?", "Who calls missing_config?"),
)
def test_reference_target_without_an_exact_symbol_cannot_use_a_partial_seed(
    tmp_path: Path,
    query: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    target = _source(
        "missing_config.py",
        "class MissingConfig:\n    pass\n",
        "MissingConfig",
    )
    caller = _source(
        "caller.py",
        "from missing_config import MissingConfig\ndef load():\n    return MissingConfig()\n",
        "load",
        dependency="missing_config",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [caller, target], ScanStats()))
        result = RetrievalEngine(index).search_result(query, limit=5)

    assert result.intent == "references"
    assert result.evidence == ()
    assert result.rejected_reason == "no_candidates"


def test_reference_target_can_use_the_exact_leaf_of_a_qualified_symbol(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    target = _source(
        "target.py",
        "class Service:\n    def run(self):\n        return True\n",
        "Service.run",
    )
    caller = _source(
        "caller.py",
        "from target import Service\ndef invoke():\n    return Service().run()\n",
        "invoke",
        dependency="target",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [caller, target], ScanStats()))
        result = RetrievalEngine(index).search_result("Who calls run?", limit=5)

    assert [evidence.path for evidence in result.evidence] == [caller.path]
    assert "dependent of target.py" in result.evidence[0].reason


def test_reference_query_does_not_use_the_question_verb_as_a_graph_seed(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    target = _source("work.py", "def work():\n    return True\n", "work")
    caller = _source(
        "caller.py",
        "from work import work\ndef run():\n    return work()\n",
        "run",
        dependency="work",
    )
    verb = _source("verb.py", "def calls():\n    return True\n", "calls")
    unrelated = _source(
        "unrelated.py",
        "from verb import calls\ndef invoke():\n    return calls()\n",
        "invoke",
        dependency="verb",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [caller, target, unrelated, verb], ScanStats()))
        result = RetrievalEngine(index).search_result("Who calls work?", limit=5)

    assert [evidence.path for evidence in result.evidence] == [caller.path]


def test_explicit_dependency_question_requires_a_resolved_graph_edge(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    alpha = _source("alpha.py", "class Alpha:\n    pass\n", "Alpha")
    beta = _source("beta.py", "class Beta:\n    pass\n", "Beta")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [alpha, beta], ScanStats()))
        result = RetrievalEngine(index).search_result(
            "Which dependency does Alpha have on Beta?",
            limit=5,
        )

    assert result.intent == "dependency"
    assert result.evidence == ()
    assert result.rejected_reason == "no_candidates"


def test_explicit_two_entity_dependency_query_uses_only_the_source_seed(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    alpha = _source(
        "alpha.py",
        "class Alpha:\n    pass\n",
        "Alpha",
        dependency="beta",
    )
    beta = _source(
        "beta.py",
        "class Beta:\n    pass\n",
        "Beta",
        dependency="gamma",
    )
    gamma = _source("gamma.py", "class Gamma:\n    pass\n", "Gamma")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [alpha, beta, gamma], ScanStats()))
        result = RetrievalEngine(index).search_result(
            "Which dependency does Alpha have on Beta?",
            limit=5,
        )

    assert result.intent == "dependency"
    assert [evidence.path for evidence in result.evidence] == [beta.path]
    assert result.evidence[0].reason == "dependency of alpha.py; exact symbol match: Beta"


def test_missing_compound_identifier_cannot_fall_back_to_a_component_symbol(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    config = _source("config.py", "class Config:\n    pass\n", "Config")
    caller = _source(
        "caller.py",
        "from config import Config\ndef load():\n    return Config()\n",
        "load",
        dependency="config",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [caller, config], ScanStats()))
        result = RetrievalEngine(index).search_result("Who calls MissingConfig?", limit=5)

    assert result.intent == "references"
    assert result.evidence == ()
    assert result.rejected_reason == "no_candidates"


@pytest.mark.parametrize(
    "query",
    ("MissingConfig", "Where is MissingConfig defined?"),
)
def test_missing_compound_identifier_does_not_return_its_component_symbol(
    tmp_path: Path,
    query: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    config = _source("config.py", "class Config:\n    pass\n", "Config")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [config], ScanStats()))
        result = RetrievalEngine(index).search_result(query, limit=5)

    assert result.evidence == ()
    assert result.rejected_reason == "no_candidates"


@pytest.mark.parametrize("query", ("MISSING_CONFIG", "missing_config"))
def test_missing_snake_case_identifier_does_not_return_its_component_symbol(
    tmp_path: Path,
    query: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    config = _source("config.py", "class CONFIG:\n    pass\n", "CONFIG")

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [config], ScanStats()))
        result = RetrievalEngine(index).search_result(query, limit=5)

    assert result.intent == "identifier"
    assert result.evidence == ()
    assert result.rejected_reason == "no_candidates"


def test_direct_snake_case_identifier_can_still_find_exact_source_text(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    text = "OLD_SYMBOL = 1\n"
    source = ScannedFile(
        path="value.py",
        language="python",
        size_bytes=len(text.encode()),
        sha256=hashlib.sha256(text.encode()).hexdigest(),
        line_count=1,
        text=text,
        chunks=(Chunk("value.py", 1, 1, text, "python"),),
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [source], ScanStats()))
        result = RetrievalEngine(index).search_result("OLD_SYMBOL", limit=5)

    assert [evidence.path for evidence in result.evidence] == [source.path]


def test_definition_query_cannot_resolve_a_compound_identifier_from_comment_text(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    note = _source(
        "notes.py",
        "def helper():\n    # MissingConfig is defined in another repository.\n    return None\n",
        "helper",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [note], ScanStats()))
        result = RetrievalEngine(index).search_result(
            "Where is MissingConfig defined?",
            limit=5,
        )

    assert result.evidence == ()
    assert result.rejected_reason == "no_candidates"


def test_path_query_with_dotted_filename_does_not_require_an_exact_symbol(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    app = _source(
        "src/App.tsx",
        "export const App = () => null;\n",
        "App",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [app], ScanStats()))
        result = RetrievalEngine(index).search_result("Where is src/App.tsx?", limit=5)

    assert result.intent == "path"
    assert [evidence.path for evidence in result.evidence] == [app.path]


def test_qualified_identifier_can_resolve_through_its_exact_final_symbol(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    config = _source(
        "config.py",
        "def config_path():\n    return 'settings.toml'\n",
        "config_path",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [config], ScanStats()))
        result = RetrievalEngine(index).search_result(
            "Where is config::config_path defined?",
            limit=5,
        )

    assert [evidence.path for evidence in result.evidence] == [config.path]


@pytest.mark.parametrize("intent", tuple(_MINIMUM_RELEVANCE))
def test_each_intent_can_reject_a_weak_rank_one_candidate(intent: QueryIntent) -> None:
    weak_rank_one = RetrievalEngine._weights(intent)["full_text"] / (_RRF_K + 1)

    assert weak_rank_one < _MINIMUM_RELEVANCE[intent]


def test_partial_multiword_match_can_be_rejected_as_below_minimum_relevance(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    weak_match = _source(
        "src/weak.py",
        "def helper():\n    # alpha beta\n    return True\n",
        "helper",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [weak_match], ScanStats()))
        result = RetrievalEngine(index).search_result(
            "alpha beta gamma delta",
            limit=3,
        )

    assert result.hits
    assert result.evidence == ()
    assert result.rejected_reason == "below_minimum_relevance"


def test_partial_symbol_only_cannot_answer_an_unrelated_natural_language_query(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    weak_match = _source(
        "src/auth.py",
        "def authentication_manager():\n    return True\n",
        "authentication_manager",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [weak_match], ScanStats()))
        result = RetrievalEngine(index).search_result(
            "auth terraform vpc module",
            limit=3,
        )

    assert {hit.retriever for hit in result.hits} == {"symbol_partial"}
    assert result.evidence == ()
    assert result.rejected_reason == "below_minimum_relevance"


def test_diversity_selection_does_not_scan_all_selected_paths_for_each_candidate() -> None:
    class CountingPath(str):
        comparisons = 0
        __hash__ = str.__hash__

        def __eq__(self, other: object) -> bool:
            type(self).comparisons += 1
            return bool(super().__eq__(other))

        def __ne__(self, other: object) -> bool:
            type(self).comparisons += 1
            return bool(super().__ne__(other))

    candidate_count = 120
    hits = [
        IndexedChunkHit(
            chunk_id=number,
            chunk=Chunk(
                CountingPath(f"src/item_{number:03d}.py"),
                1,
                1,
                f"shared marker {number}\n",
                "python",
            ),
            rank=-2.0,
        )
        for number in range(candidate_count)
    ]

    class FakeIndex:
        @contextmanager
        def consistent_read(self):  # type: ignore[no-untyped-def]
            yield 1

        def search_chunks(self, _query, limit, *, synonyms=None):  # type: ignore[no-untyped-def]
            return hits[:limit]

        def find_symbol_chunks(self, _query, _limit, *, synonyms=None):  # type: ignore[no-untyped-def]
            return []

        def dependency_neighbors(self, _paths, _limit, *, direction=None):  # type: ignore[no-untyped-def]
            return []

    result = RetrievalEngine(FakeIndex()).search_result(  # type: ignore[arg-type]
        "shared marker",
        limit=candidate_count,
    )

    assert len(result.evidence) == candidate_count
    assert CountingPath.comparisons < candidate_count


def test_graph_candidate_is_scored_once_per_retriever_across_multiple_seeds(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    first = _source(
        "src/first.py",
        "def first():\n    # shared graph marker\n    return True\n",
        "first",
        dependency="src.common",
    )
    second = _source(
        "src/second.py",
        "def second():\n    # shared graph marker\n    return True\n",
        "second",
        dependency="src.common",
    )
    common = _source(
        "src/common.py",
        "def common():\n    return True\n",
        "common",
    )

    with RepositoryIndex.open(repository, tmp_path / "cache") as index:
        index.update(ScanResult(repository, [first, second, common], ScanStats()))
        result = RetrievalEngine(index).search_result("shared graph marker", limit=3)

    shared_neighbor = next(evidence for evidence in result.evidence if evidence.path == common.path)
    expected_score = RetrievalEngine._weights(result.intent)["outbound_dependency"] / (_RRF_K + 1)
    assert shared_neighbor.score == round(expected_score, 6)
    assert shared_neighbor.reason == ("dependency of src/first.py; dependency of src/second.py")
