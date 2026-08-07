"""Stable component identities for incremental repository analysis.

Fingerprints are deliberately derived from small, explicit semantic manifests.
They are cache invalidation identities, not trust claims about parser plugins.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

SCAN_POLICY_VERSION = 6
SOURCE_TEXT_NORMALIZATION_VERSION = 1
SECRET_DETECTOR_VERSION = 4
GENERATED_DETECTOR_VERSION = 3
CHUNKER_VERSION = 4
PARSER_FINALIZER_VERSION = 3
TERM_INDEX_VERSION = 5
RETRIEVAL_VERSION = 4
DEPENDENCY_RESOLVER_VERSION = 1


def stable_fingerprint(component: str, manifest: Any) -> str:
    """Return a domain-separated SHA-256 identity for a JSON-compatible manifest."""

    if not isinstance(component, str) or not component:
        raise ValueError("fingerprint component must not be empty")
    payload = json.dumps(
        {"component": component, "manifest": manifest},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class AnalysisFingerprints:
    """Independent cache identities for each analysis layer."""

    scan: str
    parser: str
    term_index: str
    retrieval: str

    def __post_init__(self) -> None:
        for name in ("scan", "parser", "term_index", "retrieval"):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) != 64:
                raise ValueError(f"{name} fingerprint must be a SHA-256 hex digest")
            try:
                bytes.fromhex(value)
            except ValueError as exc:
                raise ValueError(f"{name} fingerprint must be a SHA-256 hex digest") from exc

    def metadata(self) -> dict[str, str]:
        return {
            "scan_fingerprint": self.scan,
            "parser_fingerprint": self.parser,
            "term_index_fingerprint": self.term_index,
            "retrieval_fingerprint": self.retrieval,
        }

    @classmethod
    def from_metadata(cls, metadata: dict[str, str]) -> AnalysisFingerprints | None:
        values = tuple(
            metadata.get(name, "")
            for name in (
                "scan_fingerprint",
                "parser_fingerprint",
                "term_index_fingerprint",
                "retrieval_fingerprint",
            )
        )
        if not any(values):
            return None
        if not all(values):
            raise ValueError("index component fingerprint metadata is incomplete")
        return cls(*values)


def build_analysis_fingerprints(
    *,
    parser_manifest: object,
    scan_limits: dict[str, int],
    chunk_limits: dict[str, int],
    legacy_cache_key: str = "",
) -> AnalysisFingerprints:
    """Build minimal-scope identities for one scanner/parser configuration."""

    scan = stable_fingerprint(
        "scan",
        {
            "scanner_policy": SCAN_POLICY_VERSION,
            "source_text_normalization": SOURCE_TEXT_NORMALIZATION_VERSION,
            "secret_detector": SECRET_DETECTOR_VERSION,
            "generated_detector": GENERATED_DETECTOR_VERSION,
            "limits": dict(sorted(scan_limits.items())),
            "legacy_cache_key": legacy_cache_key,
        },
    )
    parser = stable_fingerprint(
        "parser",
        {
            "chunker": CHUNKER_VERSION,
            "finalizer": PARSER_FINALIZER_VERSION,
            "source_text_normalization": SOURCE_TEXT_NORMALIZATION_VERSION,
            "limits": dict(sorted(chunk_limits.items())),
            "parsers": parser_manifest,
            "legacy_cache_key": legacy_cache_key,
        },
    )
    term_index = stable_fingerprint("term-index", {"version": TERM_INDEX_VERSION})
    retrieval = stable_fingerprint(
        "retrieval",
        {
            "dependency_resolver": DEPENDENCY_RESOLVER_VERSION,
            "version": RETRIEVAL_VERSION,
        },
    )
    return AnalysisFingerprints(scan, parser, term_index, retrieval)


DEFAULT_ANALYSIS_FINGERPRINTS = build_analysis_fingerprints(
    parser_manifest=(),
    scan_limits={},
    chunk_limits={},
    legacy_cache_key="legacy-unconfigured",
)
