"""Pure, generation-aware Repository Architecture Diff."""

from .engine import compare_snapshots, snapshot_from_index, snapshot_from_view
from .formatting import render_diff_markdown
from .models import (
    SNAPSHOT_FORMAT_VERSION,
    EntryPointIdentity,
    FileChange,
    FileDigest,
    FileMove,
    FingerprintCompatibility,
    RepositoryDiff,
    RepositoryFacts,
    RepositorySnapshot,
    ResolvedDependencyIdentity,
    ReviewItem,
    SourceEvidence,
    SymbolIdentity,
    SymbolMove,
)
from .serialization import (
    diff_to_dict,
    dumps_diff,
    dumps_snapshot,
    load_snapshot,
    loads_snapshot,
    save_snapshot,
    snapshot_from_dict,
    snapshot_to_dict,
)

__all__ = [
    "SNAPSHOT_FORMAT_VERSION",
    "EntryPointIdentity",
    "FileChange",
    "FileDigest",
    "FileMove",
    "FingerprintCompatibility",
    "RepositoryDiff",
    "RepositoryFacts",
    "RepositorySnapshot",
    "ResolvedDependencyIdentity",
    "ReviewItem",
    "SourceEvidence",
    "SymbolIdentity",
    "SymbolMove",
    "compare_snapshots",
    "diff_to_dict",
    "dumps_diff",
    "dumps_snapshot",
    "load_snapshot",
    "loads_snapshot",
    "render_diff_markdown",
    "save_snapshot",
    "snapshot_from_dict",
    "snapshot_from_index",
    "snapshot_from_view",
    "snapshot_to_dict",
]
