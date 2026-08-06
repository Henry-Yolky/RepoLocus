from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from repolocus.analysis import AnalysisFingerprints, stable_fingerprint
from repolocus.config import Settings
from repolocus.core import RepoLocusService
from repolocus.index import RepositoryIndex, StaleScanError
from repolocus.models import Symbol
from repolocus.parsers import ParseResult, ParserRegistry
from repolocus.scanner import RepositoryScanner
from repolocus.security import PrivacyStore


def _service(
    root: Path,
    state: Path,
    scanner: RepositoryScanner | None = None,
) -> RepoLocusService:
    return RepoLocusService(
        Settings(model="local"),
        scanner=scanner,
        privacy=PrivacyStore(state / "privacy.json"),
    )


def test_unchanged_auto_cache_hit_reads_no_content_and_opens_no_update_transaction(
    sample_repo: Path,
    isolated_user_dirs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(sample_repo, isolated_user_dirs)
    first = service.scan(sample_repo)

    def unexpected_update(_index: RepositoryIndex, _scan) -> None:  # type: ignore[no-untyped-def]
        raise AssertionError("an exact auto cache hit must not open the fact update transaction")

    monkeypatch.setattr(RepositoryIndex, "update", unexpected_update)
    second = service.scan(sample_repo, refresh="auto")

    assert second.result.stats.content_reads == 0
    assert second.result.stats.parsed_files == 0
    assert second.update.content_generation == first.update.content_generation
    assert second.update.scan_revision == first.update.scan_revision


def test_auto_cache_hit_reads_metadata_and_files_from_one_sqlite_snapshot(
    tmp_path: Path,
    isolated_user_dirs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "value.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    service = _service(repository, isolated_user_dirs)
    first = service.scan(repository)
    source.write_text("VALUE = 2\n", encoding="utf-8")

    with (
        RepositoryIndex.open(repository) as reader,
        RepositoryIndex.open(repository) as writer,
    ):
        snapshot = reader.snapshot()
        candidate = service.scanner.scan(
            repository,
            cached_files={file.path: file for file in snapshot.files},
            trusted_cache=False,
            base_generation=snapshot.content_generation,
            base_scan_revision=snapshot.scan_revision,
            refresh_mode="auto",
        )
        # Exercise the cache-hit read path with a candidate that matches the
        # competing commit. Without one read transaction, metadata can come
        # from the old snapshot while file rows come from the new snapshot.
        candidate.stats.content_reads = 0
        candidate.stats.parsed_files = 0
        original_get_metadata = reader.get_metadata
        competing_updates = []

        def commit_between_metadata_and_file_reads() -> dict[str, str]:
            metadata = original_get_metadata()
            if not competing_updates:
                competing_updates.append(writer.update(candidate))
            return metadata

        monkeypatch.setattr(reader, "get_metadata", commit_between_metadata_and_file_reads)

        cache_hit = reader.auto_cache_hit(candidate)

    assert cache_hit is None
    assert competing_updates[0].content_generation == first.update.content_generation + 1


def test_auto_cache_hit_validates_scan_root_and_rechecks_repository_identity(
    tmp_path: Path,
    isolated_user_dirs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "value.py").write_text("VALUE = 1\n", encoding="utf-8")
    service = _service(repository, isolated_user_dirs)
    service.scan(repository)

    with RepositoryIndex.open(repository) as index:
        snapshot = index.snapshot()
        candidate = service.scanner.scan(
            repository,
            cached_files={file.path: file for file in snapshot.files},
            trusted_cache=True,
            base_generation=snapshot.content_generation,
            base_scan_revision=snapshot.scan_revision,
            refresh_mode="auto",
        )
        foreign = tmp_path / "foreign"
        foreign.mkdir()
        with pytest.raises(ValueError, match="does not match index root"):
            index.auto_cache_hit(replace(candidate, root=foreign))
        with pytest.raises(StaleScanError, match="identity changed"):
            index.auto_cache_hit(replace(candidate, repository_identity="0" * 64))

        original_get_metadata = index.get_metadata
        detached = tmp_path / "detached-repository"
        replaced = False

        def replace_root_after_metadata_read() -> dict[str, str]:
            nonlocal replaced
            metadata = original_get_metadata()
            if not replaced:
                replaced = True
                repository.rename(detached)
                repository.mkdir()
                (repository / "new.py").write_text("NEW = 1\n", encoding="utf-8")
            return metadata

        monkeypatch.setattr(index, "get_metadata", replace_root_after_metadata_read)

        with pytest.raises(StaleScanError, match="identity changed"):
            index.auto_cache_hit(candidate)


def test_always_reads_every_supported_file_without_invalidating_content(
    sample_repo: Path,
    isolated_user_dirs: Path,
) -> None:
    service = _service(sample_repo, isolated_user_dirs)
    first = service.scan(sample_repo)

    refreshed = service.scan(sample_repo, refresh="always")

    assert refreshed.result.stats.content_reads == refreshed.result.stats.indexed_files
    assert refreshed.result.stats.parsed_files == 0
    assert refreshed.update.content_generation == first.update.content_generation
    assert refreshed.update.scan_revision == first.update.scan_revision + 1


def test_rebuild_reinvokes_parser_even_when_source_hash_is_unchanged(
    tmp_path: Path,
    isolated_user_dirs: Path,
) -> None:
    class CountingParser:
        languages = frozenset({"python"})
        cache_key = "test-rebuild-count:v1"
        priority = 0

        def __init__(self) -> None:
            self.calls = 0

        def parse(
            self,
            path: str,
            text: str,
            language: str,
            *,
            max_chunk_lines: int,
            max_chunk_chars: int,
        ) -> ParseResult:
            del path, text, language, max_chunk_lines, max_chunk_chars
            self.calls += 1
            return ParseResult()

    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "value.py").write_text("VALUE = 1\n", encoding="utf-8")
    parser = CountingParser()
    registry = ParserRegistry()
    registry.register(parser)
    service = _service(
        repository,
        isolated_user_dirs,
        RepositoryScanner(parser_registry=registry),
    )
    first = service.scan(repository)

    rebuilt = service.scan(repository, refresh="rebuild")

    assert parser.calls == 2
    assert rebuilt.result.stats.content_reads == 1
    assert rebuilt.result.stats.parsed_files == 1
    assert rebuilt.update.content_generation == first.update.content_generation
    assert rebuilt.update.scan_revision == first.update.scan_revision + 1


def test_multiple_changed_files_advance_content_generation_once(
    tmp_path: Path,
    isolated_user_dirs: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    first_path = repository / "a.py"
    second_path = repository / "b.py"
    first_path.write_text("A = 1\n", encoding="utf-8")
    second_path.write_text("B = 1\n", encoding="utf-8")
    service = _service(repository, isolated_user_dirs)
    first = service.scan(repository)
    first_path.write_text("A = 2\n", encoding="utf-8")
    second_path.write_text("B = 2\n", encoding="utf-8")

    changed = service.scan(repository)

    assert changed.update.changed == 2
    assert changed.update.content_generation == first.update.content_generation + 1
    assert changed.update.scan_revision == first.update.scan_revision + 1


def test_diagnostic_change_advances_only_scan_revision(
    tmp_path: Path,
    isolated_user_dirs: Path,
) -> None:
    class DiagnosticScanner(RepositoryScanner):
        add_warning = False

        def scan(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            result = super().scan(*args, **kwargs)
            if self.add_warning:
                result.warnings.append("diagnostic changed")
            return result

    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "value.py").write_text("VALUE = 1\n", encoding="utf-8")
    scanner = DiagnosticScanner()
    service = _service(repository, isolated_user_dirs, scanner)
    first = service.scan(repository)
    scanner.add_warning = True

    diagnostic = service.scan(repository)

    assert diagnostic.result.stats.content_reads == 0
    assert diagnostic.update.content_generation == first.update.content_generation
    assert diagnostic.update.scan_revision == first.update.scan_revision + 1


def test_scan_revision_cas_rejects_stale_commit_even_when_content_is_unchanged(
    tmp_path: Path,
    isolated_user_dirs: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "value.py").write_text("VALUE = 1\n", encoding="utf-8")
    scanner = RepositoryScanner()
    service = _service(repository, isolated_user_dirs, scanner)
    service.scan(repository)
    with RepositoryIndex.open(repository) as index:
        snapshot = index.snapshot()
    stale = scanner.scan(
        repository,
        cached_files={file.path: file for file in snapshot.files},
        trusted_cache=False,
        base_generation=snapshot.content_generation,
        base_scan_revision=snapshot.scan_revision,
        refresh_mode="always",
    )
    competing = service.scan(repository, refresh="always")

    with RepositoryIndex.open(repository) as index:
        with pytest.raises(StaleScanError, match="scan revision"):
            index.update(stale)
        current = index.snapshot()
    assert current.scan_revision == competing.update.scan_revision
    assert current.content_generation == competing.update.content_generation


class _EmptyParser:
    priority = 0

    def __init__(self, language: str, cache_key: str, calls: list[str] | None = None) -> None:
        self.languages = frozenset({language})
        self.cache_key = cache_key
        self.calls = calls

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
        if self.calls is not None:
            self.calls.append(path)
        return ParseResult()


def test_parser_manifest_and_fingerprint_ignore_registration_and_dict_order() -> None:
    first = ParserRegistry()
    first.register(_EmptyParser("python", "python-test:v1"))
    first.register(_EmptyParser("go", "go-test:v1"))
    second = ParserRegistry()
    second.register(_EmptyParser("go", "go-test:v1"))
    second.register(_EmptyParser("python", "python-test:v1"))

    assert first.cache_manifest() == second.cache_manifest()
    assert stable_fingerprint("test", {"b": 2, "a": 1}) == stable_fingerprint(
        "test", {"a": 1, "b": 2}
    )


def test_component_fingerprint_validation_fails_closed() -> None:
    with pytest.raises(ValueError, match="component must not be empty"):
        stable_fingerprint("", {})
    with pytest.raises(ValueError, match="SHA-256"):
        AnalysisFingerprints("short", "0" * 64, "0" * 64, "0" * 64)
    with pytest.raises(ValueError, match="SHA-256"):
        AnalysisFingerprints("g" * 64, "0" * 64, "0" * 64, "0" * 64)
    with pytest.raises(ValueError, match="incomplete"):
        AnalysisFingerprints.from_metadata({"scan_fingerprint": "0" * 64})


def test_parser_cache_key_change_reparses_but_preserves_equal_content_facts(
    tmp_path: Path,
    isolated_user_dirs: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "value.py").write_text("VALUE = 1\n", encoding="utf-8")
    first_registry = ParserRegistry()
    first_registry.register(_EmptyParser("python", "python-test:v1"))
    first_service = _service(
        repository,
        isolated_user_dirs,
        RepositoryScanner(parser_registry=first_registry),
    )
    first = first_service.scan(repository)
    calls: list[str] = []
    second_registry = ParserRegistry()
    second_registry.register(_EmptyParser("python", "python-test:v2", calls))
    second_service = _service(
        repository,
        isolated_user_dirs,
        RepositoryScanner(parser_registry=second_registry),
    )

    reparsed = second_service.scan(repository)

    assert calls == ["value.py"]
    assert reparsed.result.stats.content_reads == 1
    assert reparsed.result.stats.parsed_files == 1
    assert reparsed.update.content_generation == first.update.content_generation
    assert reparsed.update.scan_revision == first.update.scan_revision + 1


def test_scanner_freezes_parser_selection_and_cache_identity_at_construction(
    tmp_path: Path,
    isolated_user_dirs: Path,
) -> None:
    class SymbolParser:
        languages = frozenset({"python"})
        priority = 0

        def __init__(self, cache_key: str, symbol: str) -> None:
            self.cache_key = cache_key
            self.symbol = symbol
            self.calls = 0

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
            self.calls += 1
            return ParseResult(symbols=(Symbol(self.symbol, "variable", path, 1, 1),))

    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "value.py").write_text("VALUE = 1\n", encoding="utf-8")
    original = SymbolParser("symbol-parser:v1", "ORIGINAL")
    replacement = SymbolParser("symbol-parser:v2", "REPLACEMENT")
    registry = ParserRegistry()
    registry.register(original)
    scanner = RepositoryScanner(parser_registry=registry)
    frozen_manifest = scanner.parser_registry.cache_manifest()
    registry.register(replacement, replace=True)

    with pytest.raises(RuntimeError, match="frozen parser registry"):
        scanner.parser_registry.register(replacement, replace=True)
    service = _service(repository, isolated_user_dirs, scanner)
    first = service.scan(repository)
    second = service.scan(repository)
    with RepositoryIndex.open(repository) as index:
        symbols = [symbol.name for symbol in index.get_symbols()]

    assert scanner.parser_registry.cache_manifest() == frozen_manifest
    assert original.calls == 1
    assert replacement.calls == 0
    assert symbols == ["ORIGINAL"]
    assert second.update.content_generation == first.update.content_generation

    original.cache_key = "symbol-parser:mutated"
    with pytest.raises(RuntimeError, match="frozen parser changed its cache identity"):
        service.scan(repository)


def test_component_changes_invalidate_only_their_minimal_scope(
    tmp_path: Path,
    isolated_user_dirs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "value.py").write_text("VALUE = 1\n", encoding="utf-8")
    initial_service = _service(repository, isolated_user_dirs)
    initial = initial_service.scan(repository)

    scan_scanner = RepositoryScanner()
    scan_scanner.fingerprints = replace(
        scan_scanner.fingerprints,
        scan=stable_fingerprint("scan-test", {"version": 2}),
    )
    scan_only = _service(repository, isolated_user_dirs, scan_scanner).scan(repository)
    assert scan_only.result.stats.content_reads == 1
    assert scan_only.result.stats.parsed_files == 0
    assert scan_only.update.content_generation == initial.update.content_generation

    term_scanner = RepositoryScanner()
    term_scanner.fingerprints = replace(
        scan_scanner.fingerprints,
        term_index=stable_fingerprint("term-test", {"version": 2}),
    )
    term_only = _service(repository, isolated_user_dirs, term_scanner).scan(repository)
    assert term_only.result.stats.content_reads == 0
    assert term_only.result.stats.parsed_files == 0
    assert term_only.update.content_generation == scan_only.update.content_generation + 1

    retrieval_scanner = RepositoryScanner()
    retrieval_scanner.fingerprints = replace(
        term_scanner.fingerprints,
        retrieval=stable_fingerprint("retrieval-test", {"version": 2}),
    )

    def unexpected_term_rebuild(_index: RepositoryIndex) -> None:
        raise AssertionError("retrieval-only changes must not rebuild term facts")

    monkeypatch.setattr(RepositoryIndex, "_rebuild_chunk_terms", unexpected_term_rebuild)
    retrieval_only = _service(repository, isolated_user_dirs, retrieval_scanner).scan(repository)
    assert retrieval_only.result.stats.content_reads == 0
    assert retrieval_only.result.stats.parsed_files == 0
    assert retrieval_only.update.content_generation == term_only.update.content_generation
