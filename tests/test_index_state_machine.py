from __future__ import annotations

import hashlib
import tempfile
from dataclasses import replace
from pathlib import Path

from hypothesis import HealthCheck, assume, settings
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule
from hypothesis.strategies import integers, sampled_from

from repolocus.analysis import stable_fingerprint
from repolocus.config import Settings
from repolocus.core import RepoLocusService
from repolocus.index import RepositoryIndex, StaleScanError
from repolocus.scanner import RepositoryScanner
from repolocus.security import PrivacyStore


@settings(
    max_examples=20,
    stateful_step_count=15,
    deadline=None,
    suppress_health_check=(HealthCheck.too_slow,),
)
class IndexRevisionStateMachine(RuleBasedStateMachine):
    """Compare randomized filesystem/index transitions with a small reference model."""

    def __init__(self) -> None:
        super().__init__()
        self.temporary = tempfile.TemporaryDirectory(prefix="repolocus-state-machine-")
        base = Path(self.temporary.name)
        self.root = base / "repository"
        self.root.mkdir()
        self.scanner = RepositoryScanner()
        self.service = RepoLocusService(
            Settings(model="local"),
            scanner=self.scanner,
            privacy=PrivacyStore(base / "privacy.json"),
        )
        self.disk: dict[str, tuple[str, bytes]] = {}
        self.committed: dict[str, tuple[str, bytes]] = {}
        self.disk_metadata: dict[str, tuple[int, int, int]] = {}
        self.committed_metadata: dict[str, tuple[int, int, int]] = {}
        self.content_generation = 0
        self.scan_revision = 0
        self.has_scanned = False
        self.fingerprint_revision = 0

    @rule(
        path=sampled_from(("a.py", "b.py", "nested/c.py")),
        value=integers(min_value=0, max_value=1_000_000),
    )
    def add_or_modify_file(self, path: str, value: int) -> None:
        content = f"VALUE_{path.replace('/', '_').replace('.', '_')} = {value}\n"
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        self.disk[path] = (content, target.read_bytes())
        metadata = target.stat()
        self.disk_metadata[path] = (
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    @rule(path=sampled_from(("a.py", "b.py", "nested/c.py")))
    def delete_file(self, path: str) -> None:
        assume(path in self.disk)
        (self.root / path).unlink()
        self.disk.pop(path)
        self.disk_metadata.pop(path)

    @rule(mode=sampled_from(("auto", "always", "rebuild")))
    def refresh(self, mode: str) -> None:
        content_dirty = self.disk != self.committed
        metadata_dirty = self.disk_metadata != self.committed_metadata
        exact_auto_hit = (
            mode == "auto" and self.has_scanned and not content_dirty and not metadata_dirty
        )
        operation = self.service.scan(self.root, refresh=mode)  # type: ignore[arg-type]
        if not exact_auto_hit:
            self.scan_revision += 1
        if content_dirty:
            self.content_generation += 1
        self.committed = dict(self.disk)
        self.committed_metadata = dict(self.disk_metadata)
        self.has_scanned = True
        assert operation.update.content_generation == self.content_generation
        assert operation.update.scan_revision == self.scan_revision

    @precondition(lambda self: self.has_scanned)
    @rule()
    def never_reuses_the_committed_snapshot(self) -> None:
        before = self._snapshot()
        self.service.evidence("VALUE", self.root, refresh="never")
        after = self._snapshot()
        assert after.content_generation == before.content_generation
        assert after.scan_revision == before.scan_revision
        assert {file.path: file.text for file in after.files} == {
            file.path: file.text for file in before.files
        }

    @precondition(
        lambda self: (
            self.has_scanned
            and self.disk == self.committed
            and self.disk_metadata == self.committed_metadata
        )
    )
    @rule()
    def retrieval_fingerprint_change_has_minimal_scope(self) -> None:
        self.fingerprint_revision += 1
        self.scanner.fingerprints = replace(
            self.scanner.fingerprints,
            retrieval=stable_fingerprint(
                "state-machine-retrieval",
                {"revision": self.fingerprint_revision},
            ),
        )
        operation = self.service.scan(self.root)
        self.scan_revision += 1
        assert operation.result.stats.content_reads == 0
        assert operation.result.stats.parsed_files == 0
        assert operation.update.content_generation == self.content_generation
        assert operation.update.scan_revision == self.scan_revision

    @precondition(lambda self: self.has_scanned)
    @rule()
    def stale_scan_commit_is_rejected(self) -> None:
        snapshot = self._snapshot()
        stale = self.scanner.scan(
            self.root,
            cached_files={file.path: file for file in snapshot.files},
            trusted_cache=False,
            base_generation=snapshot.content_generation,
            base_scan_revision=snapshot.scan_revision,
            refresh_mode="always",
        )
        dirty = self.disk != self.committed
        competing = self.service.scan(self.root, refresh="always")
        self.scan_revision += 1
        if dirty:
            self.content_generation += 1
        self.committed = dict(self.disk)
        self.committed_metadata = dict(self.disk_metadata)
        with RepositoryIndex.open(self.root) as index:
            try:
                index.update(stale)
            except StaleScanError:
                pass
            else:  # pragma: no cover - state machine safety assertion
                raise AssertionError("stale scan commit unexpectedly succeeded")
        assert competing.update.content_generation == self.content_generation
        assert competing.update.scan_revision == self.scan_revision

    @invariant()
    def sqlite_matches_the_reference_model(self) -> None:
        snapshot = self._snapshot()
        assert snapshot.content_generation == self.content_generation
        assert snapshot.scan_revision == self.scan_revision
        if not self.has_scanned:
            assert snapshot.files == ()
            return
        indexed = {file.path: file for file in snapshot.files if not file.stale}
        assert set(indexed) == set(self.committed)
        for path, (content, raw) in self.committed.items():
            assert indexed[path].sha256 == hashlib.sha256(raw).hexdigest()
            assert indexed[path].text == content

    def _snapshot(self):  # type: ignore[no-untyped-def]
        with RepositoryIndex.open(self.root) as index:
            return index.snapshot()

    def teardown(self) -> None:
        self.temporary.cleanup()


TestIndexRevisionStateMachine = IndexRevisionStateMachine.TestCase
