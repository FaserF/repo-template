#!/usr/bin/env python3
"""SemVer & CalVer Version Manager for @FaserF Fleet Repositories.

Supports stable, beta, nightly/dev channels, explicit version overrides,
and updates custom_components/*/manifest.json, config.yaml, pyproject.toml, and package.json.
"""

from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import re
import subprocess
from pathlib import Path

VER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:(b)(\d+)|(-dev|-nightly|a|rc)(\d+))?$")


def find_manifest() -> str | None:
    """Locate integration manifest.json if present."""
    matches = sorted(glob.glob("custom_components/*/manifest.json"))
    return matches[0] if matches else None


def get_current_version(manifest_path: str | None = None) -> str:
    """Resolve highest semantic/CalVer tag or fall back to repository metadata."""
    manifest_path = manifest_path or find_manifest()
    try:
        tags = subprocess.check_output(
            ["git", "tag"], stderr=subprocess.DEVNULL, text=True
        ).splitlines()
        parsed = []
        for raw in tags:
            tag = raw.strip()
            m = VER_RE.match(tag)
            if not m:
                continue
            y, mo, p, bp, bn, dp, dn = m.groups()
            rank = 1 if bp else (0 if dp else 2)
            num = int(bn) if bp else (int(dn) if dp else 0)
            parsed.append((int(y), int(mo), int(p), rank, num, tag.lstrip("v")))
        if parsed:
            return max(parsed)[-1]
    except (subprocess.SubprocessError, OSError):
        pass

    if manifest_path and Path(manifest_path).is_file():
        return str(
            json.loads(Path(manifest_path).read_text(encoding="utf-8")).get(
                "version", "1.0.0"
            )
        )
    if Path("pyproject.toml").is_file():
        m = re.search(
            r'^version\s*=\s*"([^"]+)"',
            Path("pyproject.toml").read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        if m:
            return m.group(1)
    if Path("package.json").is_file():
        pkg = json.loads(Path("package.json").read_text(encoding="utf-8"))
        if pkg.get("version"):
            return str(pkg["version"])
    return "1.0.0"


def write_version(ver: str, manifest_path: str | None = None) -> None:
    """Write updated version string to all supported repository metadata files."""
    clean = ver.lstrip("v")
    for mf in (
        [manifest_path]
        if manifest_path
        else sorted(glob.glob("custom_components/*/manifest.json"))
    ):
        if mf and Path(mf).is_file():
            data = json.loads(Path(mf).read_text(encoding="utf-8"))
            data["version"] = clean
            Path(mf).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    if Path("pyproject.toml").is_file():
        txt = Path("pyproject.toml").read_text(encoding="utf-8")
        new_txt = re.sub(
            r'^version\s*=\s*".*?"',
            f'version = "{clean}"',
            txt,
            count=1,
            flags=re.MULTILINE,
        )
        if new_txt != txt:
            Path("pyproject.toml").write_text(new_txt, encoding="utf-8")

    if Path("package.json").is_file():
        pkg = json.loads(Path("package.json").read_text(encoding="utf-8"))
        if "version" in pkg:
            pkg["version"] = clean
            Path("package.json").write_text(
                json.dumps(pkg, indent=2) + "\n", encoding="utf-8"
            )

    if Path("config.yaml").is_file() and Path("Dockerfile").is_file():
        cfg = Path("config.yaml").read_text(encoding="utf-8")
        new_cfg = re.sub(
            r"^version:\s*.*$", f'version: "{clean}"', cfg, count=1, flags=re.MULTILINE
        )
        if new_cfg != cfg:
            Path("config.yaml").write_text(new_cfg, encoding="utf-8")


def calculate_version(
    channel: str,
    level: str = "patch",
    curr: str | None = None,
    now: datetime.datetime | None = None,
    override: str | None = None,
) -> str:
    """Compute next SemVer/CalVer release version cleanly."""
    if override and override.strip():
        return override.strip().lstrip("vV")

    now = now or datetime.datetime.now(datetime.UTC)
    curr = (curr or get_current_version()).lstrip("vV")
    m = VER_RE.match(curr)
    if not m:
        return (
            "1.0.0"
            if channel == "stable"
            else ("1.0.0b0" if channel == "beta" else "1.0.0-dev0")
        )

    v1, v2, v3 = int(m.group(1)), int(m.group(2)), int(m.group(3))
    stype = "b" if m.group(4) else (m.group(6) if m.group(6) else None)
    snum = int(m.group(5) or m.group(7) or 0)
    is_calver = v1 >= 2020

    if is_calver:
        year, month = now.year, now.month
        new_cycle = (year != v1) or (month != v2)
        p = 0 if new_cycle else v3
        if channel == "stable":
            if stype and not new_cycle:
                return f"{year}.{month}.{p}"
            return f"{year}.{month}.0" if new_cycle else f"{year}.{month}.{p + 1}"
        if channel == "beta":
            if new_cycle:
                return f"{year}.{month}.0b0"
            if stype == "b":
                return f"{year}.{month}.{p}b{snum + 1}"
            if stype:
                return f"{year}.{month}.{p}b0"
            return f"{year}.{month}.{p + 1}b0"
        if new_cycle:
            return f"{year}.{month}.0-dev0"
        return (
            f"{year}.{month}.{p}-dev{snum + 1}"
            if stype == "-dev"
            else f"{year}.{month}.{p + 1}-dev0"
        )

    if channel == "stable":
        if stype and level == "patch":
            return f"{v1}.{v2}.{v3}"
        if level == "major":
            return f"{v1 + 1}.0.0"
        if level == "minor":
            return f"{v1}.{v2 + 1}.0"
        return f"{v1}.{v2}.{v3 + 1}"

    if channel == "beta":
        if stype == "b" and level == "patch":
            return f"{v1}.{v2}.{v3}b{snum + 1}"
        if stype == "-dev" and level == "patch":
            return f"{v1}.{v2}.{v3}b0"
        if level == "major":
            return f"{v1 + 1}.0.0b0"
        if level == "minor":
            return f"{v1}.{v2 + 1}.0b0"
        return f"{v1}.{v2}.{v3 + 1}b0"

    if stype == "-dev" and level == "patch":
        return f"{v1}.{v2}.{v3}-dev{snum + 1}"
    if level == "major":
        return f"{v1 + 1}.0.0-dev0"
    if level == "minor":
        return f"{v1}.{v2 + 1}.0-dev0"
    return f"{v1}.{v2}.{v3 + 1}-dev0"


def main() -> int:
    """CLI entrypoint for release version resolution."""
    parser = argparse.ArgumentParser(description="SemVer/CalVer Version Manager")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("bump", "dry-run"):
        sp = sub.add_parser(name)
        sp.add_argument(
            "--type", choices=["stable", "beta", "dev", "nightly"], required=True
        )
        sp.add_argument("--level", choices=["major", "minor", "patch"], default="patch")
        sp.add_argument("--override", default="")
    args = parser.parse_args()

    new_ver = calculate_version(args.type, args.level, override=args.override)
    if args.command == "bump" and not os.environ.get("DRY_RUN"):
        write_version(new_ver)
    print(new_ver)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
