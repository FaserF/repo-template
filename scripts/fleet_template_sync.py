#!/usr/bin/env python3
"""Fleet Template Synchronizer for @FaserF GitHub Repositories.

Standardizes workflows, issue triage, agent guidelines, and community health files
using FaserF/repo-template as the central source of truth.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("fleet_template_sync")

PILOT_REPOS = [
    "FaserF/ShieldDNS",
    "FaserF/hassio-addons",
    "FaserF/ha-openwrt",
    "FaserF/ha-whatsapp",
]

TEMPLATE_REPO = "FaserF/repo-template"
TEMPLATE_VERSION = "v1"
TEMPLATE_LOCAL_DIR = Path(os.environ.get("TEMPLATE_DIR", Path(__file__).resolve().parent.parent if (Path(__file__).resolve().parent.parent / "AGENTS.md").exists() else "c:/Users/fabian/GitHub/repo-template"))

BOT_NAME = "faserf-hermes-agent[bot]"
BOT_EMAIL = "342667397+faserf-hermes-agent[bot]@users.noreply.github.com"
BOT_APP_LINK = "https://github.com/apps/faserf-hermes-agent"


def run_cmd(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    """Run subprocess command and return exit code, stdout, stderr."""
    res = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    return res.returncode, res.stdout.strip(), res.stderr.strip()


def detect_repo_type(repo_name: str, work_dir: Path) -> str:
    """Classify repository type based on name and directory contents."""
    lower_name = repo_name.lower()
    if lower_name == "hassio-addons" or lower_name.endswith("-addons"):
        return "ha-addon"
    if lower_name.startswith("ha-") or (work_dir / "custom_components").is_dir():
        return "ha-integration"
    if (work_dir / "go.mod").is_file():
        return "go"
    if (work_dir / "pyproject.toml").is_file() or (work_dir / "setup.py").is_file():
        return "python"
    return "generic"


def sanitize_no_personal_links(content: str) -> str:
    """Replace personal domain references (fabiseitz.de) with official GitHub App link."""
    # Replace markdown links
    content = re.sub(r"\[([^\]]+)\]\(https?://(?:[a-zA-Z0-9\-_]+\.)?fabiseitz\.de[^\)]*\)", r"[\1](" + BOT_APP_LINK + ")", content)
    # Replace plain URLs
    content = re.sub(r"https?://(?:[a-zA-Z0-9\-_]+\.)?fabiseitz\.de[^\s\)\"\'>]*", BOT_APP_LINK, content)
    return content


def get_caller_workflow_ci(repo_type: str) -> str:
    return f"""name: CI

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

permissions:
  contents: write
  pull-requests: write

jobs:
  ci:
    uses: {TEMPLATE_REPO}/.github/workflows/reusable-ci.yml@{TEMPLATE_VERSION}
    with:
      project_type: "{repo_type}"
    secrets: inherit
"""


def get_caller_workflow_linter() -> str:
    return f"""name: Linter

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

permissions:
  contents: read

jobs:
  lint:
    uses: {TEMPLATE_REPO}/.github/workflows/reusable-linter.yml@{TEMPLATE_VERSION}
"""


def get_caller_workflow_issue_triage() -> str:
    return f"""name: Issue Triage

on:
  issues:
    types: [opened]

permissions:
  contents: read
  issues: write
  pull-requests: write

jobs:
  triage:
    uses: {TEMPLATE_REPO}/.github/workflows/reusable-issue-triage.yml@{TEMPLATE_VERSION}
    with:
      auto_openhands: true
"""


def get_caller_workflow_bot() -> str:
    return f"""name: Hermes Interactive Bot

on:
  issue_comment:
    types: [created, edited]
  pull_request_review_comment:
    types: [created, edited]
  pull_request_review:
    types: [submitted, edited]
  issues:
    types: [edited]
  pull_request:
    types: [edited]

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  bot:
    uses: {TEMPLATE_REPO}/.github/workflows/reusable-hermes-bot.yml@{TEMPLATE_VERSION}
    secrets: inherit
"""


def get_caller_workflow_openhands() -> str:
    return f"""name: OpenHands Issue Resolver

on:
  issues:
    types: [labeled]
  pull_request:
    types: [labeled]

permissions:
  contents: write
  pull-requests: write
  issues: write

jobs:
  resolve:
    if: github.event.label.name == 'openhands:ready'
    uses: {TEMPLATE_REPO}/.github/workflows/reusable-openhands-resolver.yml@{TEMPLATE_VERSION}
    secrets: inherit
"""


def get_caller_workflow_release() -> str:
    return f"""name: Release

on:
  push:
    tags:
      - "v*"

permissions:
  contents: write

jobs:
  release:
    uses: {TEMPLATE_REPO}/.github/workflows/reusable-release.yml@{TEMPLATE_VERSION}
    secrets: inherit
"""


def get_caller_workflow_pr_reviewer() -> str:
    return f"""name: PR Reviewer

on:
  pull_request:
    types: [opened, synchronize, reopened, review_requested]

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  review:
    uses: {TEMPLATE_REPO}/.github/workflows/reusable-pr-reviewer.yml@{TEMPLATE_VERSION}
    secrets: inherit
"""


def get_caller_workflow_security_scanner() -> str:
    return f"""name: Security Scanner

on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:

concurrency:
  group: ${{{{ github.workflow }}}}-${{{{ github.ref }}}}
  cancel-in-progress: true

permissions:
  contents: write
  pull-requests: write
  issues: write

jobs:
  security-scan:
    uses: {TEMPLATE_REPO}/.github/workflows/reusable-security-scanner.yml@{TEMPLATE_VERSION}
    secrets: inherit
"""


def sync_repository(repo_full_name: str, apply: bool = True) -> bool:
    """Clone, harmonize with FaserF/repo-template, and open PR via faserf-hermes-agent[bot]."""
    log.info("Processing repository %s ...", repo_full_name)
    with tempfile.TemporaryDirectory() as tmp_dir:
        clone_path = Path(tmp_dir) / "repo"

        # 1. Clone repository
        code, _, err = run_cmd(["gh", "repo", "clone", repo_full_name, str(clone_path), "--", "--depth=1"])
        if code != 0:
            log.error("Failed to clone %s: %s", repo_full_name, err)
            return False

        # Skip only if already correctly synced at current version without obsolete workflows
        github_dir = clone_path / ".github"
        workflows_dir = github_dir / "workflows"
        ci_yml = workflows_dir / "ci.yml"
        sec_yml = workflows_dir / "security-scanner.yml"
        hermes_yml = github_dir / "hermes-repo.yml"

        has_obsolete = False
        if workflows_dir.exists():
            for obs in [
                "ci-orchestrator.yml", "issue-orchestrator.yml",
                "validate-integration.yaml", "validate-integration.yml",
                "validate.yaml", "validate.yml"
            ]:
                if (workflows_dir / obs).exists():
                    has_obsolete = True
                    break

        already_synced = (
            not has_obsolete
            and hermes_yml.exists()
            and sec_yml.exists()
            and ci_yml.exists()
            and f"{TEMPLATE_REPO}/.github/workflows/reusable-ci.yml@{TEMPLATE_VERSION}" in ci_yml.read_text(encoding="utf-8", errors="ignore")
        )

        if already_synced:
            log.info("Repository %s already has correct template baseline at %s. Skipping.", repo_full_name, TEMPLATE_VERSION)
            return True

        # Determine repo type
        repo_name = repo_full_name.split("/")[-1]
        repo_type = detect_repo_type(repo_name, clone_path)
        log.info("Detected type for %s: %s", repo_name, repo_type)

        # 2. Write .github/hermes-repo.yml
        github_dir = clone_path / ".github"
        workflows_dir = github_dir / "workflows"
        issue_tmpl_dir = github_dir / "ISSUE_TEMPLATE"

        workflows_dir.mkdir(parents=True, exist_ok=True)
        issue_tmpl_dir.mkdir(parents=True, exist_ok=True)

        hermes_cfg = f"""# Hermes Fleet Configuration
type: {repo_type}
profile: full
openhands:
  enabled: true
  auto_triage: true
  interactive_commands: true
code_review:
  enabled: true
releases:
  enabled: true
permissions:
  # admins: (optional — omit to auto-detect from repo owner + collaborator write/admin permissions)
  # admins:
  #   - FaserF
  #   - Eidolf
  allow_collaborators: true
  public_actions:
    - review
    - help
  restricted_actions:
    - resolve
    - autofix
    - pause
"""
        # Only create hermes-repo.yml if it doesn't exist yet (preserve per-repo overrides)
        if not (github_dir / "hermes-repo.yml").exists():
            (github_dir / "hermes-repo.yml").write_text(hermes_cfg, encoding="utf-8")

        # 3. Copy standard files from template (preserving repo customizations)
        if TEMPLATE_LOCAL_DIR.exists():
            for src_rel in [
                "AGENTS.md",
                ".github/FUNDING.yml",
                ".github/renovate.json",
                ".github/ISSUE_TEMPLATE/bug_report.yml",
                ".github/ISSUE_TEMPLATE/feature_request.yml",
                ".github/ISSUE_TEMPLATE/config.yml",
            ]:
                src_path = TEMPLATE_LOCAL_DIR / src_rel
                dst_path = clone_path / src_rel
                if src_path.exists():
                    # Preserve existing custom renovate.json, issue templates, and repository-specific AGENTS.md
                    if dst_path.exists() and src_rel in [
                        "AGENTS.md",
                        ".github/renovate.json",
                        ".github/ISSUE_TEMPLATE/bug_report.yml",
                        ".github/ISSUE_TEMPLATE/feature_request.yml",
                        ".github/ISSUE_TEMPLATE/config.yml"
                    ]:
                        log.info("Preserving existing custom %s in %s", src_rel, repo_full_name)
                        continue

                    dst_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_path, dst_path)

                    # Dynamic project discussions link in config.yml
                    if src_rel == ".github/ISSUE_TEMPLATE/config.yml":
                        cfg_txt = dst_path.read_text(encoding="utf-8")
                        cfg_txt = cfg_txt.replace("FaserF/repo-template/discussions", f"{repo_full_name}/discussions")
                        dst_path.write_text(cfg_txt, encoding="utf-8")

        # 4. Remove obsolete legacy workflows
        for obsolete in [
            "ci-orchestrator.yml",
            "issue-orchestrator.yml",
            "validate-integration.yaml",
            "validate-integration.yml",
            "validate.yaml",
            "validate.yml",
            "ci-pipeline.yml",
            "lint-and-test.yml",
        ]:
            obs_path = workflows_dir / obsolete
            if obs_path.exists():
                log.info("Removing obsolete pre-template workflow %s in %s", obsolete, repo_full_name)
                obs_path.unlink()

        # 5. Generate caller workflows (preserving specialized CI if already present)
        has_custom_ci = False
        if repo_type != "ha-integration":
            for candidate in ["test.yml", "tests.yml", "build.yml", "pipeline.yml"]:
                c_path = workflows_dir / candidate
                if c_path.exists() and TEMPLATE_REPO not in c_path.read_text(encoding="utf-8", errors="ignore"):
                    has_custom_ci = True
                    break

        if not has_custom_ci:
            (workflows_dir / "ci.yml").write_text(get_caller_workflow_ci(repo_type), encoding="utf-8")
        else:
            log.info("Preserving repository's specialized CI pipeline in %s", repo_full_name)

        (workflows_dir / "linter.yml").write_text(get_caller_workflow_linter(), encoding="utf-8")
        (workflows_dir / "issue-triage.yml").write_text(get_caller_workflow_issue_triage(), encoding="utf-8")
        (workflows_dir / "hermes-bot.yml").write_text(get_caller_workflow_bot(), encoding="utf-8")
        (workflows_dir / "openhands-resolver.yml").write_text(get_caller_workflow_openhands(), encoding="utf-8")
        (workflows_dir / "release.yml").write_text(get_caller_workflow_release(), encoding="utf-8")
        (workflows_dir / "pr-reviewer.yml").write_text(get_caller_workflow_pr_reviewer(), encoding="utf-8")
        (workflows_dir / "security-scanner.yml").write_text(get_caller_workflow_security_scanner(), encoding="utf-8")

        # 5. Sanitize any legacy workflows or templates for personal links
        for f in github_dir.rglob("*.y*ml"):
            try:
                txt = f.read_text(encoding="utf-8")
                sanitized = sanitize_no_personal_links(txt)
                if sanitized != txt:
                    f.write_text(sanitized, encoding="utf-8")
            except Exception:
                pass

        # 6. Check Git Diff
        code, status_out, _ = run_cmd(["git", "status", "--porcelain"], cwd=clone_path)
        if not status_out.strip():
            log.info("No changes needed for %s (already aligned).", repo_full_name)
            return True

        if not apply:
            log.info("[DRY-RUN] Changes detected for %s:\n%s", repo_full_name, status_out)
            return True

        # 7. Commit & Create PR
        branch_name = "chore/standardize-hermes-template"
        run_cmd(["git", "checkout", "-b", branch_name], cwd=clone_path)
        run_cmd(["git", "config", "user.name", BOT_NAME], cwd=clone_path)
        run_cmd(["git", "config", "user.email", BOT_EMAIL], cwd=clone_path)
        run_cmd(["git", "add", "."], cwd=clone_path)

        commit_msg = (
            "chore(ci): standardize workflows, issue triage and agent guidelines\n\n"
            "- Connect to reusable workflows in FaserF/repo-template\n"
            "- Add automated two-stage issue triage and OpenHands resolution\n"
            "- Add CodeRabbit-parity interactive commands (@faserf-hermes-agent)\n"
            "- Add fleet AGENTS.md guidelines and sanitized community templates\n"
            "- Standardize commit author and review attribution under faserf-hermes-agent[bot]"
        )
        run_cmd(["git", "commit", "-m", commit_msg], cwd=clone_path)

        # Push branch
        gh_token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if gh_token:
            run_cmd(["git", "remote", "set-url", "origin", f"https://x-access-token:{gh_token}@github.com/{repo_full_name}.git"], cwd=clone_path)
        code, _, push_err = run_cmd(["git", "push", "-u", "origin", branch_name, "--force"], cwd=clone_path)
        if code != 0:
            log.error("Failed to push branch to %s: %s", repo_full_name, push_err)
            return False

        # Open PR
        pr_body = (
            "## 🤖 Fleet Template Standardization\n\n"
            "This pull request standardizes this repository against the central source of truth: [`FaserF/repo-template`](https://github.com/FaserF/repo-template).\n\n"
            "### Changes Included:\n"
            "* **Reusable Workflows:** Thin caller workflows connected to central CI, linter, release, and CodeRabbit-parity bot listeners.\n"
            "* **Issue Auto-Triage & OpenHands:** Pre-filled verification checklist, version detection, and autonomous bugfix solving.\n"
            "* **Agent Guidelines:** Standardized `AGENTS.md` specifying fleet hygiene and bot author constraints.\n"
            "* **Clean Attribution:** Zero personal domain exposures; all bot references link to [faserf-hermes-agent[bot]](https://github.com/apps/faserf-hermes-agent).\n\n"
            "> *Triggered autonomously by Hermes Fleet AI on behalf of @FaserF.*"
        )
        code, pr_out, pr_err = run_cmd([
            "gh", "pr", "create",
            "--repo", repo_full_name,
            "--head", branch_name,
            "--title", "chore(ci): standardize workflows, issue triage and agent guidelines from repo-template",
            "--body", pr_body,
        ], cwd=clone_path)

        if code == 0:
            log.info("Successfully created PR for %s: %s", repo_full_name, pr_out)
            return True
        elif "already exists" in pr_err.lower():
            log.info("PR already exists for %s: %s", repo_full_name, pr_err)
            return True
        else:
            log.warning("PR creation had error on %s: %s", repo_full_name, pr_err)
            return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Fleet Template Synchronizer")
    parser.add_argument("--pilot", action="store_true", help="Run only on the 4 pilot repositories")
    parser.add_argument("--all", action="store_true", help="Run across all non-fork FaserF repositories")
    parser.add_argument("--repos", nargs="+", help="Specific repositories to sync (e.g. FaserF/ShieldDNS)")
    parser.add_argument("--apply", action="store_true", help="Apply changes and open PRs (default is dry-run)")
    args = parser.parse_args()

    targets: list[str] = []
    if args.pilot:
        targets = PILOT_REPOS
    elif args.repos:
        targets = args.repos
    elif args.all:
        code, out, err = run_cmd(["gh", "repo", "list", "FaserF", "--limit", "100", "--json", "nameWithOwner,isFork,isArchived"])
        if code == 0:
            import json
            for r in json.loads(out):
                if not r.get("isFork") and not r.get("isArchived") and r.get("nameWithOwner") != TEMPLATE_REPO:
                    targets.append(r["nameWithOwner"])
        else:
            log.error("Failed to list repos: %s", err)
            sys.exit(1)
    else:
        log.info("No targets specified. Use --pilot, --repos, or --all. (Defaulting to --pilot)")
        targets = PILOT_REPOS

    log.info("Selected %d target repositories for synchronization.", len(targets))
    successes = 0
    for t in targets:
        if sync_repository(t, apply=args.apply):
            successes += 1

    log.info("Completed template sync: %d/%d repositories processed successfully.", successes, len(targets))


if __name__ == "__main__":
    main()
