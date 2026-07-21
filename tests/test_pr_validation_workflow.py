"""Policy tests for the repository pull-request validation workflow."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "validate-pr.yml"


class PullRequestValidationWorkflowTests(unittest.TestCase):
    def test_validation_runs_on_hosted_runner_with_read_only_permissions(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("pull_request:", content)
        self.assertNotIn("pull_request_target", content)
        self.assertIn("runs-on: ubuntu-latest", content)
        self.assertNotIn("self-hosted", content)
        self.assertIn("permissions:\n  contents: read", content)
        self.assertNotIn("contents: write", content)

    def test_validation_executes_repository_and_action_contract_checks(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("python3 -m unittest discover", content)
        self.assertIn("python3 -m compileall", content)
        self.assertIn("scripts tests", content)
        self.assertIn("git diff --check", content)
        self.assertIn("continue-on-error: true", content)
        self.assertIn("Upload failed suite diagnostics", content)
        self.assertIn("steps.full-suite.outcome == 'failure'", content)
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            content,
        )
        self.assertIn(
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
            content,
        )
        self.assertIn(
            "rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667",
            content,
        )
        self.assertIn(
            "mikefarah/yq@sha256:76def1f56f456ecc1c3173ea275218ee17139bc2018c5a07887b15afd88ec03e",
            content,
        )


if __name__ == "__main__":
    unittest.main()
