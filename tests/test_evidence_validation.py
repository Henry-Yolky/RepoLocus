from __future__ import annotations

from repolocus.models import Evidence
from repolocus.security.evidence_validation import validate_model_text


def _evidence() -> list[Evidence]:
    return [
        Evidence(
            "src/config.py",
            1,
            2,
            "def load_config():\n    return Settings()\n",
            1.0,
        )
    ]


def test_exact_quote_and_matching_citation_are_required() -> None:
    valid = (
        "Configuration is loaded by this function [[src/config.py:1]].\n"
        'Evidence quote: "def load_config():" [[src/config.py:1]]'
    )

    assert validate_model_text(valid, _evidence()) == (
        "Configuration is loaded by this function [src/config.py:1](src/config.py#L1).\n"
        'Evidence quote: "def load_config():" [src/config.py:1](src/config.py#L1)'
    )
    assert validate_model_text("Configuration is loaded [[src/config.py:1]].", _evidence()) is None


def test_reference_style_links_are_neutralized_outside_validated_citations() -> None:
    text = (
        "[x]: javascript:alert(1) [[src/config.py:1]].\n"
        'Evidence quote: "def load_config():" [[src/config.py:1]]\n'
        "Click [here][x] [[src/config.py:1]].\n"
        'Evidence quote: "def load_config():" [[src/config.py:1]]'
    )

    rendered = validate_model_text(text, _evidence())

    assert rendered is not None
    assert "[here][x]" not in rendered
    assert "\\[here\\]\\[x\\]" in rendered
    assert rendered.count("[src/config.py:1](src/config.py#L1)") == 4


def test_fabricated_or_mismatched_quotes_are_rejected() -> None:
    fabricated = (
        "Configuration is loaded here [[src/config.py:1]].\n"
        'Evidence quote: "def fabricated():" [[src/config.py:1]]'
    )
    wrong_range = (
        "Configuration is loaded here [[src/config.py:1]].\n"
        'Evidence quote: "return Settings()" [[src/config.py:1]]'
    )

    assert validate_model_text(fabricated, _evidence()) is None
    assert validate_model_text(wrong_range, _evidence()) is None

    markup_evidence = [Evidence("template.html", 1, 1, "<tag>value</tag>\n", 1.0)]
    escaped_context = (
        "The template has a tag [[template.html:1]].\n"
        'Evidence quote: "&lt;tag&gt;value&lt;/tag&gt;" [[template.html:1]]'
    )
    raw_context = (
        "The template has a tag [[template.html:1]].\n"
        'Evidence quote: "<tag>value</tag>" [[template.html:1]]'
    )
    assert validate_model_text(escaped_context, markup_evidence) is None
    rendered = validate_model_text(raw_context, markup_evidence)
    assert rendered is not None
    assert "&lt;tag&gt;value&lt;/tag&gt;" in rendered


def test_unquoted_claims_and_multiple_citations_fail_closed() -> None:
    text = (
        "First claim [[src/config.py:1]].\n"
        'Evidence quote: "def load_config():" [[src/config.py:1]]\n'
        "Second unsupported claim."
    )
    multiple = (
        "Combined claim [[src/config.py:1]] [[src/config.py:2]].\n"
        'Evidence quote: "def load_config():" [[src/config.py:1]]'
    )

    assert validate_model_text(text, _evidence()) is None
    assert validate_model_text(multiple, _evidence()) is None
    assert (
        validate_model_text(
            'Evidence quote: "def load_config():" [[src/config.py:1]]',
            _evidence(),
        )
        is None
    )


def test_exact_insufficient_evidence_message_needs_no_quote() -> None:
    text = (
        "Insufficient evidence.\n"
        "The function is here [[src/config.py:1]].\n"
        'Evidence quote: "def load_config():" [[src/config.py:1]]'
    )

    assert validate_model_text(text, _evidence()) is not None
