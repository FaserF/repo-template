#!/usr/bin/env python3
"""Unified Release Metadata, Changelog, and Impact Calculator for @FaserF Fleet."""

from __future__ import annotations

import datetime
import glob
import json
import os
import re
import subprocess
import uuid
from pathlib import Path

from version_manager import calculate_version, get_current_version

TAG_RE = re.compile(
    r"^v?\d+\.\d+\.\d+(?:(?:b|a|rc|-beta|-alpha|-rc|-dev|-nightly)\.?\d*)?$"
)


def run_git(args: list[str]) -> str:
    """Run git command safely and return stripped stdout."""
    res = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    return res.stdout.strip() if res.returncode == 0 else ""


def detect_project_title(repo: str) -> str:
    """Resolve human-friendly project display name."""
    manifests = sorted(glob.glob("custom_components/*/manifest.json"))
    if manifests:
        return str(
            json.loads(Path(manifests[0]).read_text(encoding="utf-8")).get("name")
            or Path(manifests[0]).parent.name
        )
    if Path("pyproject.toml").is_file():
        m = re.search(
            r'^name\s*=\s*"([^"]+)"',
            Path("pyproject.toml").read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        if m:
            return m.group(1)
    return repo.split("/")[-1] if "/" in repo else Path.cwd().name


def is_tag_prerelease(tag: str, channel: str, override_flag: str) -> bool:
    """Determine GitHub prerelease boolean from explicit flag, channel, or tag suffix."""
    if override_flag in ("true", "false"):
        return override_flag == "true"
    if channel in ("beta", "nightly", "dev"):
        return True
    return bool(
        re.search(
            r"(?:\d(?:b|a|rc)\d*$|-(?:beta|alpha|rc|dev|nightly))", tag, re.IGNORECASE
        )
    )


def choose_changelog_base(
    tags: list[str], target_tag: str, channel: str, re_release: bool
) -> tuple[str, str]:
    """Select meaningful previous tag baseline based on release channel."""
    candidates = [t for t in tags if t != target_tag]
    if not candidates:
        return "", "initial release — full history"
    if re_release:
        return candidates[0], f"re-release changes vs `{candidates[0]}`"

    base_m = re.match(r"^v?(\d+\.\d+\.\d+)", target_tag)
    base_ver = base_m.group(1) if base_m else target_tag.lstrip("v")
    stable_tags = [t for t in candidates if re.match(r"^v?\d+\.\d+\.\d+$", t)]

    if channel == "stable":
        return (
            (stable_tags[0], f"since last stable (`{stable_tags[0]}`)")
            if stable_tags
            else ("", "initial stable release")
        )
    if channel == "beta":
        same_betas = [
            t
            for t in candidates
            if re.match(rf"^v?{re.escape(base_ver)}(?:b|-beta)\d+$", t)
        ]
        if same_betas:
            return same_betas[0], f"since previous beta (`{same_betas[0]}`)"
        return (
            (stable_tags[0], f"since `{stable_tags[0]}` (first beta of {base_ver})")
            if stable_tags
            else (candidates[0], f"since `{candidates[0]}`")
        )
    return candidates[0], f"since `{candidates[0]}`"


def build_impact_banner(
    changelog_from: str, channel: str, target_ref: str
) -> tuple[str, int]:
    """Analyze changed file categories & breaking change risk level."""
    diff_range = f"{changelog_from}..{target_ref}" if changelog_from else target_ref
    commits = int(run_git(["rev-list", "--count", diff_range]) or "0")
    changed = [
        f
        for f in run_git(
            ["diff", "--name-only", changelog_from, target_ref]
            if changelog_from
            else ["ls-files"]
        ).splitlines()
        if f.strip()
    ]

    core_cnt = sum(
        1
        for f in changed
        if f.startswith(("custom_components/", "app/", "src/"))
        and "/translations/" not in f
    )
    trans_cnt = sum(
        1 for f in changed if "/translations/" in f or f.endswith("strings.json")
    )
    test_cnt = sum(1 for f in changed if f.startswith("tests/"))
    ci_cnt = sum(1 for f in changed if f.startswith((".github/", "scripts/")))
    docs_cnt = sum(1 for f in changed if f.startswith("docs/") or f.endswith(".md"))

    log_msgs = run_git(["log", "--format=%B", diff_range])
    breaking_cnt = len(
        re.findall(
            r"\bBREAKING CHANGE\b|\bBREAKING:\b|^[a-zA-Z]+!:", log_msgs, re.MULTILINE
        )
    )

    severity, alert_type, preamble = (
        "Low",
        "NOTE",
        "Minor updates and code improvements.",
    )
    if breaking_cnt > 0:
        severity, alert_type = "Critical", "CAUTION"
        preamble = f"Contains **{breaking_cnt} breaking change(s)** — review carefully and back up before updating."
    elif core_cnt > 8:
        severity, alert_type = "High", "WARNING"
        preamble = "Contains substantial core codebase changes — verify backups before updating."
    elif core_cnt > 2 or trans_cnt > 5:
        severity, alert_type = "Medium", "TIP"
        preamble = "Contains feature updates and enhancements."

    if channel != "stable":
        preamble = (
            f"ℹ️ **Pre-release `{channel}` build** intended for testing.  \n{preamble}"
        )

    areas = []
    for icon, label, cnt in (
        ("⚙️", "Core", core_cnt),
        ("🗣️", "Translations", trans_cnt),
        ("🧪", "Tests", test_cnt),
        ("🚀", "CI/CD", ci_cnt),
        ("📖", "Docs", docs_cnt),
    ):
        if cnt:
            pct = round((cnt / max(len(changed), 1)) * 100)
            areas.append(f"{icon} {label} ({cnt} files · {pct}%)")

    banner = f"> [!{alert_type}]\n> **Release Risk: {severity}**  \n> {preamble}  \n> **Affected areas:** {' · '.join(areas) if areas else 'Metadata/maintenance only.'}\n"
    return banner, commits


def main() -> int:
    """Compute target version/tag, changelog body, and emit GITHUB_OUTPUT variables."""
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    explicit_tag = os.environ.get("INPUT_TAG_NAME", "").strip()
    channel = (os.environ.get("CHANNEL") or "stable").strip().lower()
    bump_level = (os.environ.get("BUMP_LEVEL") or "patch").strip().lower()
    version_override = os.environ.get("VERSION_OVERRIDE", "").strip()
    re_release = os.environ.get("RE_RELEASE", "false").lower() == "true"
    custom_msg = os.environ.get("CUSTOM_MESSAGE", "").strip()
    pre_flag = os.environ.get("PRERELEASE_FLAG", "auto").strip().lower()

    if explicit_tag:
        version = explicit_tag.lstrip("vV")
        tag = explicit_tag if explicit_tag.startswith("v") else f"v{explicit_tag}"
    elif re_release:
        version = (
            version_override.lstrip("vV") if version_override else get_current_version()
        )
        tag = f"v{version}"
    else:
        version = calculate_version(channel, bump_level, override=version_override)
        tag = f"v{version}"

    is_pre = is_tag_prerelease(tag, channel, pre_flag)
    all_tags = [
        t.strip()
        for t in run_git(["tag", "-l", "--sort=-v:refname"]).splitlines()
        if TAG_RE.match(t.strip())
    ]
    from_tag, cl_label = choose_changelog_base(all_tags, tag, channel, re_release)
    target_ref = (
        tag
        if (re_release and run_git(["rev-parse", "-q", "--verify", f"refs/tags/{tag}"]))
        else "HEAD"
    )

    cl_script = Path("scripts/generate_changelog.py")
    if not cl_script.is_file():
        cl_script = Path("/tmp/generate_changelog.py")
    cl_args = ["python3", str(cl_script), "--repo", repo]
    if from_tag:
        cl_args.extend(["--from-tag", from_tag])
    changelog_md = (
        subprocess.check_output(cl_args, text=True).strip()
        if cl_script.is_file()
        else "_No changelog available._"
    )

    banner, commit_count = build_impact_banner(from_tag, channel, target_ref)
    title_name = detect_project_title(repo)
    badge = {
        "stable": "![Stable](https://img.shields.io/badge/channel-stable-brightgreen?style=flat-square)",
        "beta": "![Beta](https://img.shields.io/badge/channel-beta-orange?style=flat-square)",
    }.get(
        channel,
        "![Nightly](https://img.shields.io/badge/channel-nightly-blue?style=flat-square)",
    )

    released_at = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M UTC")
    parts = [f"# {title_name} {tag}  {badge}", ""]
    if custom_msg:
        parts.extend([f"> {custom_msg}", ""])
    parts.extend(
        [
            banner,
            changelog_md,
            "",
            "| Detail | Value |",
            "|---|---|",
            f"| **Version** | `{version}` |",
            f"| **Channel** | `{channel}`{' (re-release)' if re_release else ''} |",
            f"| **Released** | `{released_at}` |",
            f"| **Commits** | `{commit_count}` ({cl_label}) |",
        ]
    )
    body = "\n".join(parts) + "\n"
    Path("/tmp/gh_release_body.md").write_text(body, encoding="utf-8")

    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        delim = f"EOF_{uuid.uuid4().hex}"
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(
                f"version={version}\ntag={tag}\nis_prerelease={'true' if is_pre else 'false'}\n"
            )
            fh.write(f"from_tag={from_tag}\nbody<<{delim}\n{body}\n{delim}\n")
    print(
        f"Release resolved: tag={tag}, version={version}, prerelease={is_pre}, re_release={re_release}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
