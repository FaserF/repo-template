"""Regression tests for workflow caller permissions, release zip guard, and triage parsing."""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any

import yaml

from scripts import fleet_template_sync as sync

REPO_ROOT = Path(__file__).resolve().parent.parent
WF_DIR = REPO_ROOT / ".github" / "workflows"

PERM_LEVEL = {"none": 0, "read": 1, "write": 2}


def _perm_rank(val: Any) -> int:
    if isinstance(val, str):
        return PERM_LEVEL.get(val.lower(), 0)
    return 0


def _collect_required_permissions(reusable_path: Path) -> dict[str, int]:
    data = yaml.safe_load(reusable_path.read_text(encoding="utf-8"))
    required: dict[str, int] = {}
    for perms_block in [data.get("permissions", {})] + [
        job.get("permissions", {})
        for job in (data.get("jobs") or {}).values()
        if isinstance(job, dict)
    ]:
        if isinstance(perms_block, dict):
            for scope, level in perms_block.items():
                required[scope] = max(required.get(scope, 0), _perm_rank(level))
    return required


def _caller_permissions(
    caller_data: dict[str, Any], job_data: dict[str, Any]
) -> dict[str, int]:
    granted: dict[str, int] = {}
    for perms_block in (
        caller_data.get("permissions", {}),
        job_data.get("permissions", {}),
    ):
        if isinstance(perms_block, dict):
            for scope, level in perms_block.items():
                granted[scope] = max(granted.get(scope, 0), _perm_rank(level))
    return granted


class WorkflowPermissionsTests(unittest.TestCase):
    """Ensure every caller workflow grants at least the permissions of its reusable target."""

    def test_repo_caller_workflows_cover_reusable_permissions(self) -> None:
        for wf_path in sorted(WF_DIR.glob("*.y*ml")):
            data = yaml.safe_load(wf_path.read_text(encoding="utf-8"))
            for job_name, job_data in (data.get("jobs") or {}).items():
                if not isinstance(job_data, dict):
                    continue
                uses = str(job_data.get("uses", ""))
                m = re.search(r"\.github/workflows/(reusable-[^@\s]+)", uses)
                if not m:
                    continue
                target_path = WF_DIR / m.group(1)
                self.assertTrue(target_path.is_file(), f"Missing target {target_path}")
                required = _collect_required_permissions(target_path)
                granted = _caller_permissions(data, job_data)
                for scope, req_rank in required.items():
                    self.assertGreaterEqual(
                        granted.get(scope, 0),
                        req_rank,
                        f"{wf_path.name} job '{job_name}' missing/under-scoped '{scope}' for {target_path.name}",
                    )

    def test_fleet_sync_generated_callers_cover_reusable_permissions(self) -> None:
        generators = [
            ("ci.yml", sync.get_caller_workflow_ci("ha-integration")),
            ("linter.yml", sync.get_caller_workflow_linter()),
            ("issue-triage.yml", sync.get_caller_workflow_issue_triage()),
            ("hermes-bot.yml", sync.get_caller_workflow_bot()),
            ("openhands-resolver.yml", sync.get_caller_workflow_openhands()),
            ("release.yml", sync.get_caller_workflow_release()),
            ("pr-reviewer.yml", sync.get_caller_workflow_pr_reviewer()),
            ("security-scanner.yml", sync.get_caller_workflow_security_scanner()),
        ]
        for label, content in generators:
            data = yaml.safe_load(content)
            for job_name, job_data in (data.get("jobs") or {}).items():
                uses = str(job_data.get("uses", ""))
                m = re.search(r"\.github/workflows/(reusable-[^@\s]+)", uses)
                self.assertIsNotNone(m, f"Expected reusable workflow ref in {label}")
                target_path = WF_DIR / m.group(1)
                required = _collect_required_permissions(target_path)
                granted = _caller_permissions(data, job_data)
                for scope, req_rank in required.items():
                    self.assertGreaterEqual(
                        granted.get(scope, 0),
                        req_rank,
                        f"fleet_template_sync {label} job '{job_name}' under-scoped '{scope}' for {target_path.name}",
                    )

    def test_reusable_release_verifies_hacs_manifest_version(self) -> None:
        txt = (WF_DIR / "reusable-release.yml").read_text(encoding="utf-8")
        self.assertIn("ref: ${{ inputs.tag_name || '' }}", txt)
        self.assertIn("Manifest version mismatch", txt)

    def test_reusable_triage_version_regex_avoids_words(self) -> None:
        txt = (WF_DIR / "reusable-issue-triage.yml").read_text(encoding="utf-8")
        self.assertNotIn(r"([\w\.\-]+)", txt)
        self.assertIn(r"(v?\d+\.\d+", txt)
        self.assertIn(r"-\s*\[[xX]\]", txt)


if __name__ == "__main__":
    unittest.main()
