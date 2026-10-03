"""Policy tests for the repository pull-request validation workflow."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "validate-pr.yml"


class PullRequestValidationWorkflowTests(unittest.TestCase):
    def test_pr_validation_uses_hosted_metadata_with_read_only_permissions(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("pull_request:", content)
        self.assertNotIn("pull_request_target", content)
        self.assertIn('runner_json: \'["ubuntu-latest"]\'', content)
        self.assertIn("self_hosted_mode: none", content)
        self.assertNotIn("self-hosted", content)
        self.assertIn("permissions:\n  contents: read", content)
        self.assertIn("pull-requests: read", content)
        self.assertNotIn("contents: write", content)

    def test_pr_never_checks_out_or_executes_candidate_code(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "uses: optimizr-tech/optimizr-actions/.github/workflows/_pr-metadata.yml@v1",
            content,
        )
        for forbidden in (
            "actions/checkout", "steps:", "run:", "docker ",
            "python3 -m unittest", "secrets:", "workflow_dispatch:",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, content)
        for field in ("pr_number", "pr_title", "pr_body", "base_sha", "head_sha"):
            with self.subTest(field=field):
                self.assertIn(f"      {field}:", content)


if __name__ == "__main__":
    unittest.main()
