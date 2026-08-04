from __future__ import annotations

from repolocus.retrieval.terms import (
    document_terms,
    literal_query_term_groups,
    literal_query_terms,
    query_terms,
)


def test_cjk_terms_use_bigrams_and_trigrams() -> None:
    query = "\u914d\u7f6e" + "\u5728\u54ea\u91cc" + "\u6821\u9a8c"
    indexed = document_terms(query)

    assert "\u914d\u7f6e" in indexed
    assert "\u6821\u9a8c" in indexed
    assert "\u914d\u7f6e\u5728" in indexed
    assert "\u7f6e\u5728\u54ea" in indexed
    assert "\u914d" not in indexed


def test_literal_coverage_groups_cjk_alternatives_but_not_non_cjk_terms() -> None:
    cjk_query = "\u914d\u7f6e" + "\u5728\u54ea\u91cc" + "\u6821\u9a8c"
    groups = literal_query_term_groups(cjk_query + " policy")

    assert groups[0][0] == cjk_query
    assert groups[0] == (cjk_query, "\u914d\u7f6e", "\u5728\u54ea", "\u6821\u9a8c")
    assert groups[1] == ("policy",)


def test_identifiers_paths_and_unicode_are_normalized() -> None:
    terms = document_terms("src/httpClient/load_config.py", "HTTPClient", "loadConfigValue")

    assert {"src", "http", "client", "httpclient", "load", "config", "value"} <= set(terms)


def test_query_synonyms_are_explicit_and_do_not_change_literal_terms() -> None:
    synonyms = {"configuration": ("config", "settings")}

    assert literal_query_terms("Where is configuration?") == ("configuration",)
    expanded = query_terms("Where is configuration?", synonyms)

    assert expanded[0] == "configuration"
    assert expanded[-2:] == ("config", "settings")


def test_query_terms_add_only_generic_suffix_variants() -> None:
    assert query_terms("symlinks validated") == (
        "symlinks",
        "validated",
        "symlink",
        "validat",
        "validate",
    )


def test_term_generation_is_deterministic_unique_and_bounded() -> None:
    first = document_terms("Alpha alpha beta gamma", maximum=2)
    second = document_terms("Alpha alpha beta gamma", maximum=2)

    assert first == second == ("alpha", "beta")
