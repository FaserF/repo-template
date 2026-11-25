#!/usr/bin/env python3
"""Synchronize GitHub Issue Templates with latest version placeholders & privacy warnings."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path


def get_latest_ha_version() -> str:
    """Fetch latest Home Assistant PyPI version gracefully."""
    try:
        req = urllib.request.Request(
            "https://pypi.org/pypi/homeassistant/json",
            headers={"User-Agent": "FaserF-Fleet"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return str(json.loads(resp.read().decode("utf-8"))["info"]["version"])
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, TimeoutError):
        return "2026.11.3"


def update_template(file_path: Path, integration_version: str, ha_version: str) -> bool:
    """Update version placeholders and remove sensitive input fields in one issue form."""
    if not file_path.is_file():
        return False
    original = file_path.read_text(encoding="utf-8")
    target_ver = f"v{integration_version.lstrip('v')}"
    blocks = re.split(r"(\s*-\s*type:)", original)

    for i in range(2, len(blocks), 2):
        blk = blocks[i]
        m = re.search(r"id:\s*([a-zA-Z0-9_-]+)", blk)
        if not m:
            continue
        fid = m.group(1)
        if fid in ("integration_version", "version"):
            blk = re.sub(
                r'placeholder:\s*(["\']?)(e\.g\.\s*)?[^\n"\']+\1',
                lambda match: (
                    f"placeholder: {match.group(1) or ''}{match.group(2) or ''}{target_ver}{match.group(1) or ''}"
                ),
                blk,
            )
        elif fid == "ha_version":
            blk = re.sub(
                r'placeholder:\s*(["\']?)(e\.g\.\s*)?[^\n"\']+\1',
                lambda match: (
                    f"placeholder: {match.group(1) or ''}{match.group(2) or ''}{ha_version}{match.group(1) or ''}"
                ),
                blk,
            )
        blocks[i] = blk

    updated = "".join(blocks)
    if updated != original:
        file_path.write_text(updated, encoding="utf-8")
        return True
    return False


def main() -> int:
    """Update all YAML issue forms in .github/ISSUE_TEMPLATE."""
    ver = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.environ.get("RELEASE_VERSION", "v1.0.0")
    )
    tdir = Path(".github/ISSUE_TEMPLATE")
    if not tdir.is_dir():
        return 0
    ha_ver = get_latest_ha_version()
    for path in sorted(tdir.iterdir()):
        if path.suffix in (".yml", ".yaml") and update_template(path, ver, ha_ver):
            print(f"Updated issue template: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
