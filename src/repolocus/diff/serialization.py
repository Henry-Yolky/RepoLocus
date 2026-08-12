"""Strict canonical JSON for portable snapshots and diff results."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import stat
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any, NoReturn

from repolocus.analysis import AnalysisFingerprints
from repolocus.security.atomic_write import (
    AtomicWriteError,
    _capture_fallback_descriptor_state,
    _capture_fallback_state,
    _same_fallback_state,
)

from .models import (
    EntryPointIdentity,
    FileChange,
    FileDigest,
    RepositoryDiff,
    RepositoryFacts,
    RepositorySnapshot,
    ResolvedDependencyIdentity,
    ReviewItem,
    SourceEvidence,
    SymbolIdentity,
)

_MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024


def _evidence_to_dict(evidence: SourceEvidence) -> dict[str, object]:
    return {
        "path": evidence.path,
        "start_line": evidence.start_line,
        "end_line": evidence.end_line,
        "generation": evidence.generation,
    }


def _file_to_dict(file: FileDigest) -> dict[str, object]:
    return {
        "path": file.path,
        "sha256": file.sha256,
        "language": file.language,
        "size_bytes": file.size_bytes,
        "line_count": file.line_count,
        "evidence": _evidence_to_dict(file.evidence),
    }


def _symbol_to_dict(symbol: SymbolIdentity) -> dict[str, object]:
    return {
        "name": symbol.name,
        "kind": symbol.kind,
        "signature": symbol.signature,
        "evidence": _evidence_to_dict(symbol.evidence),
    }


def _dependency_to_dict(dependency: ResolvedDependencyIdentity) -> dict[str, object]:
    return {
        "raw_target": dependency.raw_target,
        "target_path": dependency.target_path,
        "target_symbol": dependency.target_symbol,
        "kind": dependency.kind,
        "confidence": dependency.confidence,
        "candidates": list(dependency.candidates),
        "evidence": _evidence_to_dict(dependency.evidence),
    }


def _entry_to_dict(entry: EntryPointIdentity) -> dict[str, object]:
    return {"evidence": _evidence_to_dict(entry.evidence)}


def snapshot_to_dict(snapshot: RepositorySnapshot) -> dict[str, object]:
    """Return the stable JSON-compatible representation of one snapshot."""

    if not isinstance(snapshot, RepositorySnapshot):
        raise TypeError("snapshot must be a RepositorySnapshot")
    fingerprints: dict[str, str] | None = None
    if snapshot.fingerprints is not None:
        fingerprints = {
            "scan": snapshot.fingerprints.scan,
            "parser": snapshot.fingerprints.parser,
            "term_index": snapshot.fingerprints.term_index,
            "retrieval": snapshot.fingerprints.retrieval,
        }
    payload: dict[str, object] = {
        "format_version": snapshot.format_version,
        "schema_version": snapshot.schema_version,
        "repository_identity": snapshot.repository_identity,
        "generation": snapshot.generation,
        "fingerprints": fingerprints,
        "dependency_resolver_fingerprint": snapshot.dependency_resolver_fingerprint,
        "facts": {
            "files": [
                _file_to_dict(file)
                for file in sorted(snapshot.facts.files.values(), key=lambda item: item.path)
            ],
            "symbols": [
                _symbol_to_dict(symbol)
                for symbol in sorted(
                    snapshot.facts.symbols,
                    key=lambda item: item.comparison_key,
                )
            ],
            "dependencies": [
                _dependency_to_dict(dependency)
                for dependency in sorted(
                    snapshot.facts.dependencies,
                    key=lambda item: item.comparison_key,
                )
            ],
            "entry_points": [
                _entry_to_dict(entry)
                for entry in sorted(
                    snapshot.facts.entry_points,
                    key=lambda item: item.comparison_key,
                )
            ],
        },
    }
    payload["snapshot_sha256"] = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return payload


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _expect_object(value: object, keys: set[str], context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be an object")
    actual = set(value)
    if actual != keys:
        missing = ", ".join(sorted(keys - actual))
        unknown = ", ".join(sorted(actual - keys))
        details = []
        if missing:
            details.append(f"missing: {missing}")
        if unknown:
            details.append(f"unknown: {unknown}")
        raise ValueError(f"{context} fields are invalid ({'; '.join(details)})")
    return value


def _expect_list(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{context} must be an array")
    return value


def _expect_string(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{context} must be text")
    return value


def _expect_optional_string(value: object, context: str) -> str | None:
    if value is None:
        return None
    return _expect_string(value, context)


def _expect_integer(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{context} must be an integer")
    return value


def _parse_evidence(value: object, context: str) -> SourceEvidence:
    item = _expect_object(
        value,
        {"path", "start_line", "end_line", "generation"},
        context,
    )
    return SourceEvidence(
        path=_expect_string(item["path"], f"{context}.path"),
        start_line=_expect_integer(item["start_line"], f"{context}.start_line"),
        end_line=_expect_integer(item["end_line"], f"{context}.end_line"),
        generation=_expect_integer(item["generation"], f"{context}.generation"),
    )


def _parse_file(value: object, context: str) -> FileDigest:
    item = _expect_object(
        value,
        {"path", "sha256", "language", "size_bytes", "line_count", "evidence"},
        context,
    )
    return FileDigest(
        path=_expect_string(item["path"], f"{context}.path"),
        sha256=_expect_string(item["sha256"], f"{context}.sha256"),
        language=_expect_string(item["language"], f"{context}.language"),
        size_bytes=_expect_integer(item["size_bytes"], f"{context}.size_bytes"),
        line_count=_expect_integer(item["line_count"], f"{context}.line_count"),
        evidence=_parse_evidence(item["evidence"], f"{context}.evidence"),
    )


def _parse_symbol(value: object, context: str) -> SymbolIdentity:
    item = _expect_object(value, {"name", "kind", "signature", "evidence"}, context)
    return SymbolIdentity(
        name=_expect_string(item["name"], f"{context}.name"),
        kind=_expect_string(item["kind"], f"{context}.kind"),
        signature=_expect_string(item["signature"], f"{context}.signature"),
        evidence=_parse_evidence(item["evidence"], f"{context}.evidence"),
    )


def _parse_dependency(value: object, context: str) -> ResolvedDependencyIdentity:
    item = _expect_object(
        value,
        {
            "raw_target",
            "target_path",
            "target_symbol",
            "kind",
            "confidence",
            "candidates",
            "evidence",
        },
        context,
    )
    candidates = tuple(
        _expect_string(candidate, f"{context}.candidates[{index}]")
        for index, candidate in enumerate(_expect_list(item["candidates"], f"{context}.candidates"))
    )
    confidence = _expect_string(item["confidence"], f"{context}.confidence")
    return ResolvedDependencyIdentity(
        raw_target=_expect_string(item["raw_target"], f"{context}.raw_target"),
        target_path=_expect_optional_string(item["target_path"], f"{context}.target_path"),
        target_symbol=_expect_optional_string(item["target_symbol"], f"{context}.target_symbol"),
        kind=_expect_string(item["kind"], f"{context}.kind"),
        confidence=confidence,  # type: ignore[arg-type]
        candidates=candidates,
        evidence=_parse_evidence(item["evidence"], f"{context}.evidence"),
    )


def _parse_entry(value: object, context: str) -> EntryPointIdentity:
    item = _expect_object(value, {"evidence"}, context)
    return EntryPointIdentity(_parse_evidence(item["evidence"], f"{context}.evidence"))


def _unique_facts(items: list[Any], context: str) -> None:
    if len(items) != len(set(items)):
        raise ValueError(f"{context} contains duplicate facts")


def snapshot_from_dict(value: object) -> RepositorySnapshot:
    """Strictly validate and construct a snapshot from decoded JSON."""

    item = _expect_object(
        value,
        {
            "format_version",
            "schema_version",
            "repository_identity",
            "generation",
            "fingerprints",
            "dependency_resolver_fingerprint",
            "facts",
            "snapshot_sha256",
        },
        "snapshot",
    )
    recorded_digest = _expect_string(item["snapshot_sha256"], "snapshot.snapshot_sha256")
    if len(recorded_digest) != 64 or recorded_digest != recorded_digest.lower():
        raise ValueError("snapshot.snapshot_sha256 must be a lowercase SHA-256 hex digest")
    try:
        bytes.fromhex(recorded_digest)
    except ValueError as exc:
        raise ValueError("snapshot.snapshot_sha256 must be a lowercase SHA-256 hex digest") from exc
    unsigned = {key: field for key, field in item.items() if key != "snapshot_sha256"}
    expected_digest = hashlib.sha256(_canonical_json_bytes(unsigned)).hexdigest()
    if not hmac.compare_digest(recorded_digest, expected_digest):
        raise ValueError("snapshot SHA-256 integrity check failed")
    fingerprints_value = item["fingerprints"]
    fingerprints: AnalysisFingerprints | None
    if fingerprints_value is None:
        fingerprints = None
    else:
        fingerprint_object = _expect_object(
            fingerprints_value,
            {"scan", "parser", "term_index", "retrieval"},
            "snapshot.fingerprints",
        )
        fingerprints = AnalysisFingerprints(
            scan=_expect_string(fingerprint_object["scan"], "snapshot.fingerprints.scan"),
            parser=_expect_string(fingerprint_object["parser"], "snapshot.fingerprints.parser"),
            term_index=_expect_string(
                fingerprint_object["term_index"], "snapshot.fingerprints.term_index"
            ),
            retrieval=_expect_string(
                fingerprint_object["retrieval"], "snapshot.fingerprints.retrieval"
            ),
        )
    facts_value = _expect_object(
        item["facts"],
        {"files", "symbols", "dependencies", "entry_points"},
        "snapshot.facts",
    )
    files = [
        _parse_file(file, f"snapshot.facts.files[{index}]")
        for index, file in enumerate(_expect_list(facts_value["files"], "snapshot.facts.files"))
    ]
    if len(files) != len({file.path for file in files}):
        raise ValueError("snapshot.facts.files contains duplicate paths")
    symbols = [
        _parse_symbol(symbol, f"snapshot.facts.symbols[{index}]")
        for index, symbol in enumerate(
            _expect_list(facts_value["symbols"], "snapshot.facts.symbols")
        )
    ]
    dependencies = [
        _parse_dependency(dependency, f"snapshot.facts.dependencies[{index}]")
        for index, dependency in enumerate(
            _expect_list(facts_value["dependencies"], "snapshot.facts.dependencies")
        )
    ]
    entries = [
        _parse_entry(entry, f"snapshot.facts.entry_points[{index}]")
        for index, entry in enumerate(
            _expect_list(facts_value["entry_points"], "snapshot.facts.entry_points")
        )
    ]
    _unique_facts(symbols, "snapshot.facts.symbols")
    _unique_facts(dependencies, "snapshot.facts.dependencies")
    _unique_facts(entries, "snapshot.facts.entry_points")
    return RepositorySnapshot(
        format_version=_expect_integer(item["format_version"], "snapshot.format_version"),
        schema_version=_expect_integer(item["schema_version"], "snapshot.schema_version"),
        repository_identity=_expect_string(
            item["repository_identity"], "snapshot.repository_identity"
        ),
        generation=_expect_integer(item["generation"], "snapshot.generation"),
        fingerprints=fingerprints,
        dependency_resolver_fingerprint=_expect_optional_string(
            item["dependency_resolver_fingerprint"],
            "snapshot.dependency_resolver_fingerprint",
        ),
        facts=RepositoryFacts(
            files={file.path: file for file in files},
            symbols=frozenset(symbols),
            dependencies=frozenset(dependencies),
            entry_points=frozenset(entries),
        ),
    )


def _reject_constant(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _reject_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON numbers are not allowed")
    return parsed


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def dumps_snapshot(snapshot: RepositorySnapshot) -> str:
    """Return deterministic compact JSON with one trailing newline."""

    return _canonical_json_bytes(snapshot_to_dict(snapshot)).decode("ascii") + "\n"


def loads_snapshot(payload: str | bytes | bytearray) -> RepositorySnapshot:
    """Parse bounded JSON, rejecting duplicates, drift, and non-finite numbers."""

    if not isinstance(payload, (str, bytes, bytearray)):
        raise ValueError("snapshot payload must be text or bytes")
    if len(payload) > _MAX_SNAPSHOT_BYTES:
        raise ValueError("snapshot payload exceeds the 256 MiB limit")
    try:
        decoded = json.loads(
            payload,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
        return snapshot_from_dict(decoded)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as exc:
        raise ValueError("snapshot JSON is invalid") from exc


def load_snapshot(path: Path | str) -> RepositorySnapshot:
    """Load one bounded snapshot file without executing repository code."""

    source = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    descriptor = -1
    try:
        before = _capture_fallback_state(source, directory=False)
        descriptor = os.open(source, flags)
        opened = _capture_fallback_descriptor_state(descriptor)
        opened_metadata = os.fstat(descriptor)
        if not _same_fallback_state(before, opened):
            raise ValueError("snapshot file changed while it was opened")
        if opened_metadata.st_size > _MAX_SNAPSHOT_BYTES:
            raise ValueError("snapshot file exceeds the 256 MiB limit")
        chunks: list[bytes] = []
        remaining = opened_metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError("snapshot file was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("snapshot file grew while reading")
        after_descriptor = _capture_fallback_descriptor_state(descriptor)
        after_path = _capture_fallback_state(source, directory=False)
        if not _same_fallback_state(opened, after_descriptor) or not _same_fallback_state(
            opened, after_path
        ):
            raise ValueError("snapshot file changed while it was read")
        payload = b"".join(chunks)
    except AtomicWriteError as exc:
        raise ValueError("snapshot path must be a non-symlink regular file") from exc
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"snapshot file cannot be read: {source}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return loads_snapshot(payload)


def _safe_snapshot_parent(path: Path) -> Path:
    parent = path.parent.expanduser()
    absolute = Path(os.path.abspath(parent))
    try:
        resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"snapshot parent does not exist: {parent}") from exc
    if os.path.normcase(str(absolute)) != os.path.normcase(str(resolved)):
        raise ValueError("snapshot parent must not traverse symbolic links")
    try:
        metadata = resolved.lstat()
    except OSError as exc:
        raise ValueError(f"snapshot parent cannot be inspected: {resolved}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ValueError("snapshot parent must be a non-symlink directory")
    return resolved


def save_snapshot(
    snapshot: RepositorySnapshot,
    path: Path | str,
    *,
    overwrite: bool = False,
) -> Path:
    """Publish canonical JSON via a same-directory temporary file."""

    if not isinstance(overwrite, bool):
        raise ValueError("overwrite must be true or false")
    requested = Path(path)
    if not requested.name or requested.name in {".", ".."}:
        raise ValueError("snapshot path must name a file")
    parent = _safe_snapshot_parent(requested)
    destination = parent / requested.name
    try:
        existing = destination.lstat()
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise ValueError(f"snapshot destination cannot be inspected: {destination}") from exc
    if existing is not None:
        if stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode):
            raise ValueError("snapshot destination must be a non-symlink regular file")
        if not overwrite:
            raise ValueError(f"snapshot already exists: {destination}")
    payload = dumps_snapshot(snapshot).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            if hasattr(os, "fchmod"):
                os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, destination)
        else:
            try:
                os.link(temporary, destination)
            except FileExistsError as exc:
                raise ValueError(f"snapshot already exists: {destination}") from exc
            temporary.unlink()
        if os.name != "nt":
            directory_descriptor = os.open(
                parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    except BaseException:
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise
    return destination


def _change_to_dict(change: FileChange) -> dict[str, object]:
    return {
        "kind": change.kind,
        "old": _file_to_dict(change.old) if change.old is not None else None,
        "new": _file_to_dict(change.new) if change.new is not None else None,
    }


def _review_to_dict(item: ReviewItem) -> dict[str, object]:
    return {
        "priority": item.priority,
        "area": item.area,
        "path": item.path,
        "reason": item.reason,
        "old": _evidence_to_dict(item.old) if item.old is not None else None,
        "new": _evidence_to_dict(item.new) if item.new is not None else None,
    }


def diff_to_dict(diff: RepositoryDiff) -> dict[str, object]:
    """Return stable JSON data for CLI, Action, and future MCP consumers."""

    if not isinstance(diff, RepositoryDiff):
        raise TypeError("diff must be a RepositoryDiff")
    return {
        "old_generation": diff.old_generation,
        "new_generation": diff.new_generation,
        "compatibility": {
            "schema": diff.compatibility.schema,
            "scan": diff.compatibility.scan,
            "parser": diff.compatibility.parser,
            "term_index": diff.compatibility.term_index,
            "retrieval": diff.compatibility.retrieval,
            "dependency_resolver": diff.compatibility.dependency_resolver,
            "degraded": diff.compatibility.degraded,
            "reasons": list(diff.compatibility.reasons),
        },
        "is_empty": diff.is_empty,
        "added_files": [_file_to_dict(item) for item in diff.added_files],
        "removed_files": [_file_to_dict(item) for item in diff.removed_files],
        "changed_files": [_change_to_dict(item) for item in diff.changed_files],
        "moved_files": [
            {
                "old": _file_to_dict(item.old),
                "new": _file_to_dict(item.new),
                "confidence": item.confidence,
            }
            for item in diff.moved_files
        ],
        "added_symbols": [_symbol_to_dict(item) for item in diff.added_symbols],
        "removed_symbols": [_symbol_to_dict(item) for item in diff.removed_symbols],
        "moved_symbols": [
            {
                "old": _symbol_to_dict(item.old),
                "new": _symbol_to_dict(item.new),
                "confidence": item.confidence,
            }
            for item in diff.moved_symbols
        ],
        "added_entry_points": [_entry_to_dict(item) for item in diff.added_entry_points],
        "removed_entry_points": [_entry_to_dict(item) for item in diff.removed_entry_points],
        "added_dependencies": [_dependency_to_dict(item) for item in diff.added_dependencies],
        "removed_dependencies": [_dependency_to_dict(item) for item in diff.removed_dependencies],
        "configuration_changes": [_change_to_dict(item) for item in diff.configuration_changes],
        "security_boundary_changes": [
            _change_to_dict(item) for item in diff.security_boundary_changes
        ],
        "test_area_changes": [_change_to_dict(item) for item in diff.test_area_changes],
        "review_order": [_review_to_dict(item) for item in diff.review_order],
    }


def dumps_diff(diff: RepositoryDiff) -> str:
    """Return canonical compact JSON for a diff result."""

    return _canonical_json_bytes(diff_to_dict(diff)).decode("ascii") + "\n"
