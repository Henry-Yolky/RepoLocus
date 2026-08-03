#!/usr/bin/env python3
"""Fail CI when dependency metadata needs an explicit license review."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_REVIEW_REQUIRED = re.compile(
    r"(?:\bA?GPL\b|\bLGPL\b|GNU (?:Affero )?General Public License|"
    r"Server Side Public License|UNKNOWN|NOASSERTION)",
    re.IGNORECASE,
)
_REVIEWED_LICENSE_MARKERS = (
    "Apache",
    "BSD",
    "ISC",
    "MIT",
    "MPL",
    "Mozilla Public License",
    "PSF",
    "Python Software Foundation",
)


def main(path: str) -> int:
    report_path = Path(path)
    try:
        entries = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"cannot read license report {report_path}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(entries, list):
        print("license report must contain a JSON list", file=sys.stderr)
        return 2
    flagged: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            flagged.append("malformed report entry")
            continue
        name = str(entry.get("Name", "unknown"))
        version = str(entry.get("Version", "unknown"))
        license_name = str(entry.get("License", "UNKNOWN"))
        if _REVIEW_REQUIRED.search(license_name) or not any(
            marker.casefold() in license_name.casefold() for marker in _REVIEWED_LICENSE_MARKERS
        ):
            flagged.append(f"{name}=={version}: {license_name}")
    if flagged:
        print("dependency licenses requiring explicit review:", file=sys.stderr)
        for item in flagged:
            print(f"- {item}", file=sys.stderr)
        return 1
    print(f"checked {len(entries)} dependency license records")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: check_licenses.py LICENSES.json", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
