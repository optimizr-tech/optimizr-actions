"""Policy tests for the repository pull-request validation workflow."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "validate-pr.yml"


class PullRequestValidationWorkflowTests(unittest.TestCase):
    def test_pr_metadata_validation_uses_authorized_self_hosted_runner_with_read_only_permissions(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("pull_request:", content)
        self.assertNotIn("pull_request_target", content)
        self.assertIn(
            'runner_json: \'["self-hosted","Linux","local-docker"]\'', content
        )
        self.assertIn("self_hosted_mode: metadata-pr", content)
        self.assertIn("permissions:\n  contents: read", content)
        self.assertIn("pull-requests: read", content)
        self.assertNotIn("contents: write", content)

    def test_metadata_job_never_checks_out_or_executes_candidate_code(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")
        metadata_job = content.split("  validate:\n", 1)[1].split(
            "  validate-candidate:\n", 1
        )[0]
        self.assertIn(
            "uses: optimizr-tech/optimizr-actions/.github/workflows/_pr-metadata.yml@v1",
            metadata_job,
        )
        for forbidden in (
            "actions/checkout", "steps:", "run:", "docker ",
            "python3 -m unittest", "secrets:", "workflow_dispatch:",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, metadata_job)
        for field in ("pr_number", "pr_title", "pr_body", "base_sha", "head_sha"):
            with self.subTest(field=field):
                self.assertIn(f"      {field}:", metadata_job)

    def test_candidate_code_is_not_run_by_the_pull_request_workflow(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")
        jobs = content.split("jobs:\n", 1)[1]
        job_names = [
            line.strip()[:-1]
            for line in jobs.splitlines()
            if line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":")
        ]
        self.assertEqual(["validate"], job_names)
        self.assertNotIn("validate-candidate:", content)
        self.assertNotIn("runs-on:", content)
        self.assertNotIn("actions/checkout", content)
        self.assertNotIn("python3 -m unittest discover -v", content)
        self.assertNotIn("secrets:", content)

        move_v1 = (ROOT / ".github/workflows/move-v1.yml").read_text(encoding="utf-8")
        scope_job = move_v1.split("  scope:\n", 1)[1].split("  validate:\n", 1)[0]
        validate_job = move_v1.split("  validate:\n", 1)[1].split("  move-v1:\n", 1)[0]
        self.assertIn("|| 'local-docker'", scope_job)
        self.assertIn("python3 -m unittest discover -v", validate_job)
        self.assertIn("needs: [scope, validate]", move_v1)


if __name__ == "__main__":
    unittest.main()
