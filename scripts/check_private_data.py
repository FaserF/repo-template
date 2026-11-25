#!/usr/bin/env python3
"""Reject accidental private IPv4s, real MAC addresses, and tokens from Git diffs."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])")
SECRET_RES = (
    re.compile(r"(?i)\b(?:bearer|token)\s+[a-z0-9._~-]{24,}"),
    re.compile(
        r"\b(?:(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{16,}|(?:sk-proj|sk)-[A-Za-z0-9_-]{16,})"
    ),
    re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}"),
)
SYNTHETIC_MAC_RES = (
    re.compile(r"(?i)^00:00:00:00:00:00$"),
    re.compile(r"(?i)^00:11:22:33:44:[0-9a-f]{2}$"),
    re.compile(r"(?i)^02:00:00:00:00:[0-9a-f]{2}$"),
    re.compile(r"(?i)^11:22:33:44:55:66$"),
    re.compile(r"(?i)^aa:bb:cc:dd:ee:ff$"),
)
PRIVATE_IPV4_NETWORKS = (
    ipaddress.ip_network("10" + ".0.0.0/8"),
    ipaddress.ip_network("172" + ".16.0.0/12"),
    ipaddress.ip_network("192" + ".168.0.0/16"),
)
SAFE_EXAMPLE_IPS = {
    "192.168.1.1",
    "192.168.1.2",
    "192.168.0.1",
    "10.0.0.1",
    "172.16.0.1",
}


@dataclass(frozen=True)
class AddedLine:
    path: str
    line_number: int
    text: str


@dataclass(frozen=True)
class Violation:
    path: str
    line_number: int
    category: str


def _run_git(args: list[str]) -> str:
    return subprocess.check_output(
        ["git", "-c", f"safe.directory={Path.cwd().resolve().as_posix()}", *args],
        text=True,
        encoding="utf-8",
    )


def _added_lines(diff: str) -> list[AddedLine]:
    path = ""
    line_no = 0
    added: list[AddedLine] = []
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
            continue
        if line.startswith("@@"):
            m = re.search(r"\+(\d+)(?:,\d+)?", line)
            line_no = int(m.group(1)) if m else 0
            continue
        if not path or line.startswith("---"):
            continue
        if line.startswith("+"):
            added.append(AddedLine(path, line_no, line[1:]))
            line_no += 1
        elif not line.startswith("-"):
            line_no += 1
    return added


def _load_private_patterns() -> tuple[re.Pattern[str], ...]:
    raw: list[str] = []
    if Path(".private-data-patterns").is_file():
        raw.extend(
            Path(".private-data-patterns").read_text(encoding="utf-8").splitlines()
        )
    raw.extend(os.environ.get("PRIVATE_DATA_PATTERNS", "").splitlines())
    return tuple(
        re.compile(p.strip(), re.IGNORECASE)
        for p in raw
        if p.strip() and not p.strip().startswith("#")
    )


def find_violations(
    lines: Iterable[AddedLine], private_patterns: Iterable[re.Pattern[str]]
) -> list[Violation]:
    """Scan added lines without logging sensitive literal values."""
    violations: set[Violation] = set()
    patterns = tuple(private_patterns)
    for line in lines:
        lower = line.text.lower()
        is_example = any(
            w in lower for w in ("example", "placeholder", "dummy", "mock", "test_")
        )
        for value in IPV4_RE.findall(line.text):
            if value in SAFE_EXAMPLE_IPS or is_example:
                continue
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                continue
            if any(addr in net for net in PRIVATE_IPV4_NETWORKS):
                violations.add(Violation(line.path, line.line_number, "private IPv4"))
        for value in MAC_RE.findall(line.text):
            if not is_example and not any(
                pat.fullmatch(value) for pat in SYNTHETIC_MAC_RES
            ):
                violations.add(Violation(line.path, line.line_number, "MAC address"))
        if any(pat.search(line.text) for pat in SECRET_RES) and not is_example:
            violations.add(
                Violation(line.path, line.line_number, "credential-like value")
            )
        if any(pat.search(line.text) for pat in patterns):
            violations.add(
                Violation(line.path, line.line_number, "installation denylist")
            )
    return sorted(violations, key=lambda v: (v.path, v.line_number, v.category))


def _self_test() -> None:
    lines = [
        AddedLine("a.py", 1, "host = '" + "192." + "168.42.99'"),
        AddedLine("a.py", 2, "mac = '" + "de:ad:be:" + "ef:12:34'"),
        AddedLine("a.py", 3, "tok = '" + "ghp_" + "A" * 24 + "'"),
    ]
    cats = {v.category for v in find_violations(lines, ())}
    if cats != {"private IPv4", "MAC address", "credential-like value"}:
        raise RuntimeError(f"Privacy scanner self-test failed: {cats}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Private Data Diff Guard")
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--staged", action="store_true")
    src.add_argument("--base")
    src.add_argument("--github-event-name")
    parser.add_argument("--github-before", default="")
    parser.add_argument("--default-branch", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
    if args.staged:
        diff = _run_git(["diff", "--cached", "--unified=0", "--no-ext-diff"])
    elif args.base:
        diff = _run_git(["diff", "--unified=0", "--no-ext-diff", args.base])
    elif args.github_event_name:
        if (
            args.github_event_name == "push"
            and args.github_before
            and set(args.github_before) != {"0"}
        ):
            base = args.github_before
        elif args.default_branch:
            remote_ref = f"refs/remotes/origin/{args.default_branch}"
            _run_git(
                [
                    "fetch",
                    "--no-tags",
                    "origin",
                    f"+refs/heads/{args.default_branch}:{remote_ref}",
                ]
            )
            base = _run_git(["merge-base", "HEAD", remote_ref]).strip()
        else:
            return 0
        diff = _run_git(["diff", "--unified=0", "--no-ext-diff", base])
    else:
        return 0

    violations = find_violations(_added_lines(diff), _load_private_patterns())
    for v in violations:
        print(f"{v.path}:{v.line_number}: {v.category}")
    if violations:
        print(f"Private-data check failed with {len(violations)} finding(s).")
        return 1
    print("Private-data check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
