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

    def test_candidate_contracts_run_on_hosted_runner_without_persisted_credentials(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("validate-candidate:\n", content)
        candidate_job = content.split("  validate-candidate:\n", 1)[1]
        self.assertIn("name: Validate portable action contracts", candidate_job)
        self.assertIn("runs-on: ubuntu-latest", candidate_job)
        self.assertIn("actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", candidate_job)
        self.assertIn("persist-credentials: false", candidate_job)
        self.assertIn("python3 -m unittest discover -v", candidate_job)
        self.assertIn("python3 -m compileall -q scripts tests", candidate_job)
        self.assertIn("git diff --check", candidate_job)
        self.assertIn("rhysd/actionlint@sha256:", candidate_job)
        self.assertIn("mikefarah/yq@sha256:", candidate_job)
        self.assertNotIn("self-hosted", candidate_job)
        self.assertNotIn("secrets:", content)


if __name__ == "__main__":
    unittest.main()
