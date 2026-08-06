from __future__ import annotations

from datetime import date
from pathlib import Path

from repolocus import config as config_module
from repolocus.config import Settings


def test_standard_toml_parser_handles_strings_arrays_dates_comments_and_nested_tables(
    tmp_path: Path,
) -> None:
    path = tmp_path / "standard.toml"
    parsed = config_module._parse_config(
        b"""
title = "hash # stays in string" # real comment
values = [1, 2, 3]
created = 2026-08-06

[outer.inner]
enabled = true
names = ["alpha", "beta"]
""",
        path,
        source="user",
    )

    assert parsed["title"] == "hash # stays in string"
    assert parsed["values"] == [1, 2, 3]
    assert parsed["created"] == date(2026, 8, 6)
    assert parsed["outer"] == {"inner": {"enabled": True, "names": ["alpha", "beta"]}}


def test_standard_nested_toml_table_feeds_query_synonyms_consistently(tmp_path: Path) -> None:
    user_config = tmp_path / "config.toml"
    user_config.write_text(
        """
[query_synonyms]
build = ["compile", "link"] # standard TOML array
""",
        encoding="utf-8",
    )

    settings = Settings.load(user_config_path=user_config, environ={})

    assert settings.query_synonym_map == {"build": ("compile", "link")}


def test_pyproject_accepts_standard_quoted_table_keys(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool."repolocus"]\nmax_file_bytes = 123456\n',
        encoding="utf-8",
    )

    settings = Settings.load(
        tmp_path,
        environ={},
        user_config_path=tmp_path / "missing.toml",
    )

    assert settings.max_file_bytes == 123_456
