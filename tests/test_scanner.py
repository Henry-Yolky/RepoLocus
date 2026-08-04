from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from repolocus.models import Chunk, ScannedFile
from repolocus.parsers import ParseResult, ParserRegistry
from repolocus.scanner import (
    RepositoryScanner,
    contains_likely_secret,
    detect_language,
    is_binary,
    is_sensitive_path,
)


def _write(root: Path, relative: str, content: str | bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("path", "language"),
    [
        ("main.py", "python"),
        ("types.pyi", "python"),
        ("web/app.jsx", "javascript"),
        ("web/app.mjs", "javascript"),
        ("web/app.tsx", "typescript"),
        ("cmd/main.go", "go"),
        ("src/lib.rs", "rust"),
        ("src/Main.java", "java"),
        ("native/a.c", "c"),
        ("native/a.H", "c"),
        ("native/a.cpp", "cpp"),
        ("native/a.HPP", "cpp"),
        ("README", "markdown"),
        ("docs/guide.mdx", "markdown"),
        ("pyproject.toml", "config"),
        ("requirements-dev.txt", "config"),
        (".env.example", "config"),
        ("image.png", None),
    ],
)
def test_language_detection(path: str, language: str | None) -> None:
    assert detect_language(path) == language


def test_scan_is_sorted_deterministic_and_extracts_facts(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "zeta/main.go",
        'package main\nimport "fmt"\nfunc main() { fmt.Println("ok") }\n',
    )
    _write(tmp_path, "alpha.py", "import os\n\ndef answer():\n    return 42\n")
    _write(tmp_path, "docs/README.md", "# Intro\nText\n")
    _write(tmp_path, "unknown.dat", "not source")

    scanner = RepositoryScanner()
    first = scanner.scan(tmp_path)
    second = scanner.scan(tmp_path)

    assert [item.path for item in first.files] == [
        "alpha.py",
        "docs/README.md",
        "zeta/main.go",
    ]
    assert first.files == second.files
    assert first.stats.indexed_files == 3
    assert first.stats.languages == {"python": 1, "markdown": 1, "go": 1}
    python_file = first.files[0]
    assert python_file.sha256 == second.files[0].sha256
    assert [symbol.name for symbol in python_file.symbols] == ["answer"]
    assert [dependency.target for dependency in python_file.dependencies] == ["os"]
    assert first.files[-1].is_entry_point


def test_nested_gitignore_and_negation_are_scoped(tmp_path: Path) -> None:
    _write(tmp_path, ".gitignore", "*.py\nignored/\n/root_only.py\n")
    _write(tmp_path, "drop.py", "print('drop')\n")
    _write(tmp_path, "root_only.py", "print('drop')\n")
    _write(tmp_path, "ignored/never.py", "raise RuntimeError\n")
    _write(tmp_path, "sub/.gitignore", "!keep.py\nlocal.py\n")
    _write(tmp_path, "sub/keep.py", "def kept():\n    pass\n")
    _write(tmp_path, "sub/local.py", "def local():\n    pass\n")
    _write(tmp_path, "sub/drop.py", "def drop():\n    pass\n")

    result = RepositoryScanner().scan(tmp_path)

    assert "sub/keep.py" in {item.path for item in result.files}
    assert "drop.py" not in {item.path for item in result.files}
    assert "sub/local.py" not in {item.path for item in result.files}
    assert "sub/drop.py" not in {item.path for item in result.files}
    assert result.stats.skipped["gitignored"] >= 4


def test_strong_default_ignores_cannot_be_negated(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".gitignore",
        "!node_modules/kept.js\n!build/kept.py\n!.devpilot/legacy.py\n",
    )
    _write(tmp_path, "node_modules/kept.js", "export function no() {}\n")
    _write(tmp_path, "build/kept.py", "def no(): pass\n")
    _write(tmp_path, ".devpilot/legacy.py", "SECRET = 'never index legacy state'\n")
    _write(tmp_path, "src/yes.py", "def yes(): pass\n")

    result = RepositoryScanner().scan(tmp_path)

    assert {item.path for item in result.files} >= {"src/yes.py", ".gitignore"}
    assert not any(item.path.endswith("kept.py") for item in result.files)
    assert not any("node_modules" in item.path for item in result.files)
    assert not any(".devpilot" in item.path for item in result.files)
    assert result.stats.skipped["default_ignored"] == 3


def test_symlinks_are_never_followed_and_outside_target_is_reported(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    outside = _write(tmp_path, "outside.py", "def stolen():\n    return 'outside'\n")
    inside = _write(repository, "inside.py", "def safe():\n    pass\n")
    (repository / "outside-link.py").symlink_to(outside)
    (repository / "inside-link.py").symlink_to(inside)
    (repository / "directory-link").symlink_to(tmp_path, target_is_directory=True)

    result = RepositoryScanner().scan(repository)

    assert [item.path for item in result.files] == ["inside.py"]
    assert result.stats.skipped["outside_root"] == 2
    assert result.stats.skipped["symlink"] == 1
    assert "outside-root symlink skipped: outside-link.py" in result.warnings
    assert "symlink skipped: inside-link.py" in result.warnings
    assert all("stolen" not in item.text for item in result.files)


def test_symlink_root_and_non_directory_root_are_rejected(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(repository, target_is_directory=True)
    regular = _write(tmp_path, "regular.py", "pass\n")

    with pytest.raises(ValueError, match="symbolic link"):
        RepositoryScanner().scan(linked_root)
    with pytest.raises(ValueError, match="directory"):
        RepositoryScanner().scan(regular)
    with pytest.raises(ValueError, match="not accessible"):
        RepositoryScanner().scan(tmp_path / "missing")


def test_repolocus_and_legacy_generated_markdown_are_excluded(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "PROJECT_MAP.md",
        "# Project Map\n\n"
        "<!-- Generator: RepoLocus 0.1.2; deterministic source map. -->\n"
        "self-derived claim\n",
    )
    _write(
        tmp_path,
        "ARCHITECTURE.md",
        "# Architecture\n\n<!-- Generator: RepoLocus; deterministic static graph. -->\n",
    )
    _write(
        tmp_path,
        "OLD_MAP.md",
        "<!-- Generator: DevPilot 0.1.0; deterministic source map. -->\n",
    )
    _write(
        tmp_path,
        "notes.md",
        "# Notes\n\nThis document discusses Generator: RepoLocus in ordinary prose.\n",
    )

    result = RepositoryScanner().scan(tmp_path)

    assert [file.path for file in result.files] == ["notes.md"]
    assert result.files[0].provenance == "source"
    assert result.stats.skipped["generated"] == 3


def test_secret_detection_is_reapplied_before_cached_fact_reuse(tmp_path: Path) -> None:
    text = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz1234"\n'
    source = _write(tmp_path, "settings.py", text)
    metadata = source.stat()
    cached = ScannedFile(
        path="settings.py",
        language="python",
        size_bytes=len(text.encode()),
        sha256=hashlib.sha256(text.encode()).hexdigest(),
        line_count=1,
        text=text,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
    )

    result = RepositoryScanner().scan(tmp_path, cached_files={cached.path: cached})

    assert result.files == []
    assert result.stats.skipped == {"likely_secret": 1}


@pytest.mark.skipif(os.name != "posix", reason="dir_fd/openat is POSIX-only")
def test_directory_swap_to_outside_symlink_is_never_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repo"
    nested = repository / "nested"
    nested.mkdir(parents=True)
    _write(repository, "nested/value.py", "VALUE = 'inside'\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "value.py", "VALUE = 'stolen-outside'\n")
    from repolocus.scanner import repository as scanner_repository

    original_open_directory = scanner_repository._open_directory_at
    swapped = False

    def swap_before_open(
        name: str, expected: os.stat_result, directory_fd: int
    ) -> tuple[int | None, str | None]:
        nonlocal swapped
        if name == "nested" and not swapped:
            swapped = True
            nested.rename(repository / "original-nested")
            nested.symlink_to(outside, target_is_directory=True)
        return original_open_directory(name, expected, directory_fd)

    monkeypatch.setattr(scanner_repository, "_open_directory_at", swap_before_open)

    result = RepositoryScanner().scan(repository)

    assert result.files == []
    assert result.temporarily_unreadable == ("nested",)
    assert all("stolen-outside" not in warning for warning in result.warnings)


def test_windows_reparse_attribute_is_explicitly_recognized() -> None:
    from repolocus.scanner.repository import _is_reparse_point

    assert _is_reparse_point(SimpleNamespace(st_file_attributes=0x400))  # type: ignore[arg-type]
    assert not _is_reparse_point(  # type: ignore[arg-type]
        SimpleNamespace(st_file_attributes=0)
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows file identity semantics")
def test_windows_regular_file_is_not_reported_as_changed(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", "VALUE = 1\n")

    result = RepositoryScanner().scan(tmp_path)

    assert [item.path for item in result.files] == ["app.py"]
    assert result.stats.indexed_files == 1
    assert result.stats.skipped.get("changed_during_scan", 0) == 0
    assert result.temporarily_unreadable == ()


def test_sensitive_binary_oversize_and_likely_secret_files_are_filtered(tmp_path: Path) -> None:
    _write(tmp_path, ".env", "PASSWORD=correct-horse-battery-staple\n")
    _write(tmp_path, "id_rsa", "not actually a key\n")
    _write(tmp_path, "cert.pem", "certificate-ish\n")
    _write(tmp_path, "binary.py", b"print('prefix')\x00hidden")
    _write(tmp_path, "large.py", "x" * 101)
    _write(tmp_path, "cloud.json", '{"region":"x","token":"AKIA1234567890ABCDEF"}\n')
    _write(tmp_path, ".env.example", "PASSWORD=changeme\n")
    _write(tmp_path, "safe.py", "token = os.environ['TOKEN']\n")

    result = RepositoryScanner(max_file_bytes=100).scan(tmp_path)
    paths = {item.path for item in result.files}

    assert paths == {".env.example", "safe.py"}
    assert result.stats.skipped["sensitive_filename"] == 3
    assert result.stats.skipped["binary"] == 1
    assert result.stats.skipped["oversize"] == 1
    assert result.stats.skipped["likely_secret"] == 1
    assert all("correct-horse" not in warning for warning in result.warnings)


def test_special_file_is_not_opened(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO not supported")
    fifo = tmp_path / "messages.py"
    os.mkfifo(fifo)

    result = RepositoryScanner().scan(tmp_path)

    assert result.stats.skipped["special_file"] == 1
    assert result.files == []


@pytest.mark.parametrize(
    "path",
    [".env", ".env.production", "id_ed25519", "keys/server.key", ".ssh/config", "state.tfstate"],
)
def test_sensitive_filename_detection(path: str) -> None:
    assert is_sensitive_path(path)


def test_secret_and_binary_detection_is_conservative() -> None:
    assert contains_likely_secret('api_key = "v3ry-long-random-value-827364"')
    assert contains_likely_secret("-----BEGIN PRIVATE KEY-----\nabc")
    assert not contains_likely_secret("api_key = os.environ['API_KEY']")
    assert not contains_likely_secret('password = "changeme"')
    assert is_binary(b"text\x00payload")
    assert is_binary(b"\xff\xfe\x01")
    assert not is_binary("你好\nsource".encode())


@pytest.mark.parametrize(
    "source",
    [
        'HF_TOKEN = "hf_abcdefghijklmnopqrstuvwxyz123456"',
        'DATABASE_URL = "postgresql://user:password@db.internal/app"',
    ],
)
def test_additional_cloud_and_database_credentials_are_detected(source: str) -> None:
    assert contains_likely_secret(source)


def test_invalid_gitignore_fails_closed_without_scanning_siblings(tmp_path: Path) -> None:
    _write(tmp_path, ".gitignore", "!\n")
    _write(tmp_path, "safe.py", "def safe():\n    return True\n")

    result = RepositoryScanner().scan(tmp_path)

    assert result.files == []
    assert result.temporarily_unreadable == (".",)
    assert result.stats.skipped == {"unreadable_ignore": 1}
    assert any("invalid ignore file" in warning for warning in result.warnings)


def test_parse_plugin_failure_isolated_to_one_file(tmp_path: Path) -> None:
    class BrokenParser:
        languages = frozenset({"python"})

        def parse(self, *args: object, **kwargs: object) -> ParseResult:
            raise RuntimeError("repository content must not escape through errors")

    registry = ParserRegistry()
    registry.register(BrokenParser())
    _write(tmp_path, "bad.py", "def bad(): pass\n")

    result = RepositoryScanner(parser_registry=registry).scan(tmp_path)

    assert result.files == []
    assert result.stats.skipped["parse_error"] == 1
    assert result.warnings == ["parse failed (RuntimeError) for file: bad.py"]
    assert result.temporarily_unreadable == ("bad.py",)


def test_parser_cannot_fabricate_source_ranges_or_content(tmp_path: Path) -> None:
    class FabricatingParser:
        languages = frozenset({"python"})

        def parse(self, *args: object, **kwargs: object) -> ParseResult:
            return ParseResult(chunks=(Chunk("one.py", 99, 100, "fabricated", "python"),))

    registry = ParserRegistry()
    registry.register(FabricatingParser())
    _write(tmp_path, "one.py", "value = 1\n")

    result = RepositoryScanner(parser_registry=registry).scan(tmp_path)

    assert result.files == []
    assert result.stats.skipped["parse_error"] == 1


def test_unchanged_files_reuse_versioned_parser_results(tmp_path: Path) -> None:
    class CountingParser:
        languages = frozenset({"python"})

        def __init__(self) -> None:
            self.calls = 0

        def parse(
            self,
            path: str,
            text: str,
            language: str,
            **kwargs: object,
        ) -> ParseResult:
            self.calls += 1
            return ParseResult(chunks=(Chunk(path, 1, 1, text.rstrip(), language),))

    parser = CountingParser()
    registry = ParserRegistry()
    registry.register(parser)
    source = _write(tmp_path, "one.py", "value=1\n")
    scanner = RepositoryScanner(parser_registry=registry, analysis_version="counting-v1")

    first = scanner.scan(tmp_path)
    second = scanner.scan(tmp_path, cached_files={file.path: file for file in first.files})
    source.write_text("value=2\n", encoding="utf-8")
    third = scanner.scan(tmp_path, cached_files={file.path: file for file in second.files})

    assert parser.calls == 2
    assert second.files == first.files
    assert third.files[0].text == "value=2\n"
    assert first.analysis_version == "counting-v1:lines=160:chars=16000"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_file_bytes": 0},
        {"max_file_bytes": 1, "max_ignore_bytes": 0},
        {"max_file_bytes": 1, "max_chunk_lines": 0},
        {"max_file_bytes": 1, "max_chunk_chars": 0},
    ],
)
def test_scanner_rejects_non_positive_limits(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        RepositoryScanner(**kwargs)
