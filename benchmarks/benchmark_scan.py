#!/usr/bin/env python3
"""Generate a deterministic synthetic repository and time scan phases."""

from __future__ import annotations

import argparse
import json
import os
import platform
import tempfile
import time
import tracemalloc
from pathlib import Path

from repolocus.config import Settings
from repolocus.core import RepoLocusService


def _populate(root: Path, count: int) -> None:
    for number in range(count):
        shard = root / "src" / f"group_{number // 1000:03d}"
        shard.mkdir(parents=True, exist_ok=True)
        (shard / f"module_{number:06d}.py").write_text(
            f"def function_{number:06d}(value: int) -> int:\n"
            f'    """Return a deterministic fixture value for module {number}."""\n'
            f"    return value + {number}\n",
            encoding="utf-8",
        )


def _timed(service: RepoLocusService, repository: Path) -> tuple[float, int, dict[str, object]]:
    tracemalloc.start()
    started = time.perf_counter()
    try:
        operation = service.scan(repository)
        elapsed = time.perf_counter() - started
        _current, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return elapsed, peak_bytes, operation.to_dict()


def _index_bytes(index_path: Path) -> int:
    candidates = (
        index_path,
        Path(str(index_path) + "-wal"),
        Path(str(index_path) + "-shm"),
    )
    return sum(candidate.stat().st_size for candidate in candidates if candidate.is_file())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", type=int, default=1_000)
    parser.add_argument("--keep", action="store_true")
    arguments = parser.parse_args()
    if arguments.files <= 0:
        parser.error("--files must be positive")

    temporary = None
    if arguments.keep:
        repository = Path(tempfile.mkdtemp(prefix="repolocus-benchmark-")) / "repository"
    else:
        temporary = tempfile.TemporaryDirectory(prefix="repolocus-benchmark-")
        repository = Path(temporary.name) / "repository"
    repository.mkdir()
    cache = repository.parent / "cache"
    os.environ["XDG_CACHE_HOME"] = str(cache)
    _populate(repository, arguments.files)
    service = RepoLocusService(Settings(model="local"))
    cold_seconds, cold_peak_bytes, cold = _timed(service, repository)
    warm_seconds, warm_peak_bytes, warm = _timed(service, repository)
    changed_file = repository / "src" / "group_000" / "module_000000.py"
    changed_file.write_text(
        changed_file.read_text(encoding="utf-8") + "\nCHANGED = True\n",
        encoding="utf-8",
    )
    incremental_seconds, incremental_peak_bytes, incremental = _timed(service, repository)
    source_bytes = sum(path.stat().st_size for path in repository.rglob("*") if path.is_file())
    index_path = Path(str(incremental["index_path"]))
    index_bytes = _index_bytes(index_path)
    report = {
        "files": arguments.files,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cold_seconds": round(cold_seconds, 6),
        "cold_peak_python_bytes": cold_peak_bytes,
        "warm_seconds": round(warm_seconds, 6),
        "warm_peak_python_bytes": warm_peak_bytes,
        "single_change_seconds": round(incremental_seconds, 6),
        "single_change_peak_python_bytes": incremental_peak_bytes,
        "source_bytes": source_bytes,
        "index_bytes": index_bytes,
        "index_amplification": round(index_bytes / source_bytes, 6) if source_bytes else 0.0,
        "cold": cold,
        "warm": warm,
        "single_change": incremental,
    }
    if arguments.keep:
        print(
            json.dumps(
                report | {"repository": str(repository), "cache": str(cache)},
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
        assert temporary is not None
        temporary.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
