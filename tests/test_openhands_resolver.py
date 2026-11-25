"""Unit tests for scripts/openhands_resolver.py."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import openhands_resolver as resolver


class OpenHandsResolverTests(unittest.TestCase):
    """Test safety bounds, secret checks, and OmniRoute agent execution."""

    def test_safe_repo_path_blocks_traversal_and_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            with patch.object(resolver, "REPO_ROOT", root):
                with self.assertRaises(ValueError):
                    resolver.safe_repo_path("../outside.txt")
                with self.assertRaises(ValueError):
                    resolver.safe_repo_path(".env")
                with self.assertRaises(ValueError):
                    resolver.safe_repo_path("creds/server.key")
                allowed = resolver.safe_repo_path("app/main.py")
                self.assertEqual(allowed, (root / "app/main.py").resolve())

    def test_main_requires_omniroute_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "gh_output.txt"
            env_updates = {
                "TARGET_NUMBER": "42",
                "OMNIROUTE_API_KEY": "",
                "OMNIROUTE_BASE_URL": "",
                "GITHUB_OUTPUT": str(out),
            }
            with patch.dict(os.environ, env_updates, clear=False):
                self.assertEqual(resolver.main(), 1)
            self.assertIn("resolver_status=blocked", out.read_text(encoding="utf-8"))

    def test_run_agent_loop_handles_edit_and_finish(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            sample = root / "demo.py"
            sample.write_text("VALUE = 1\n", encoding="utf-8")

            responses = [
                {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "tool_calls": [
                                    {
                                        "id": "tc1",
                                        "type": "function",
                                        "function": {
                                            "name": "edit_file",
                                            "arguments": '{"path": "demo.py", "target": "VALUE = 1", "replacement": "VALUE = 2"}',
                                        },
                                    }
                                ],
                            }
                        }
                    ]
                },
                {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "tool_calls": [
                                    {
                                        "id": "tc2",
                                        "type": "function",
                                        "function": {
                                            "name": "finish",
                                            "arguments": '{"status": "resolved", "summary": "Updated VALUE to 2 and verified."}',
                                        },
                                    }
                                ],
                            }
                        }
                    ]
                },
            ]

            with (
                patch.object(resolver, "REPO_ROOT", root),
                patch.object(resolver, "call_omniroute", side_effect=responses),
            ):
                status, summary = resolver.run_agent_loop(
                    "https://omni.example/v1",
                    "test-key",
                    "auto/coding",
                    "Fix demo",
                    5,
                )

            self.assertEqual(status, "resolved")
            self.assertIn("Updated VALUE to 2", summary)
            self.assertEqual(sample.read_text(encoding="utf-8"), "VALUE = 2\n")


if __name__ == "__main__":
    unittest.main()
