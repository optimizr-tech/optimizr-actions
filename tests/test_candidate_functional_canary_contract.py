from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "_candidate-functional-canary.yml"


class CandidateFunctionalCanaryContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_canary_is_opt_in_reusable_with_read_only_permissions(self) -> None:
        trigger = self.text.split("permissions:", 1)[0]
        permissions = self.text.split("permissions:", 1)[1].split("jobs:", 1)[0]

        self.assertIn("workflow_call:", trigger)
        self.assertNotIn("pull_request_target:", trigger)
        self.assertNotIn("workflow_dispatch:", trigger)
        self.assertIn("contents: read", permissions)
        self.assertNotIn("contents: write", permissions)
        self.assertNotIn("packages: read", permissions)
        self.assertNotIn("secrets:", self.text)
        self.assertNotIn("secrets: inherit", self.text)

    def test_runner_selection_is_fixed_to_the_isolated_ephemeral_lane(self) -> None:
        inputs = self.text.split("    inputs:", 1)[1].split("    outputs:", 1)[0]

        self.assertNotIn("runner_json:", inputs)
        self.assertIn(
            "runner_json: '[\"self-hosted\",\"Linux\",\"ephemeral\",\"isolated-pr-canary\"]'",
            self.text,
        )
        runner_line = next(line for line in self.text.splitlines() if "runner_json:" in line)
        self.assertNotIn("local-docker", runner_line)
        self.assertNotIn("ubuntu-latest", self.text)
        self.assertIn("InfraOps assigns isolated-pr-canary", self.text)

    def test_candidate_sha_is_taken_from_the_pull_request_head(self) -> None:
        inputs = self.text.split("    inputs:", 1)[1].split("    outputs:", 1)[0]

        self.assertNotIn("candidate_sha:", inputs)
        self.assertIn("candidate_sha: ${{ github.event.pull_request.head.sha }}", self.text)
        self.assertNotIn("inputs.candidate_sha", self.text)
        self.assertIn("github.event_name == 'pull_request'", self.text)
        self.assertIn("github.event.pull_request.head.sha != ''", self.text)

    def test_delegates_to_repository_validation_with_ephemeral_pr_mode(self) -> None:
        self.assertIn("_repository-validation.yml@v1", self.text)
        self.assertIn("allow_ephemeral_pr: true", self.text)
        self.assertIn("require_trusted_ref: false", self.text)
        self.assertIn("script_path: ${{ inputs.script_path }}", self.text)
        repository_validation = (ROOT / ".github" / "workflows" / "_repository-validation.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("persist-credentials: false", repository_validation)
        self.assertIn("ref: ${{ inputs.candidate_sha || github.sha }}", repository_validation)

    def test_contract_documents_opt_in_and_keeps_existing_gates_separate(self) -> None:
        doc = (ROOT / "docs" / "CANDIDATE_FUNCTIONAL_CANARY.md").read_text(encoding="utf-8")
        runner_doc = (ROOT / "docs" / "RUNNER_AND_TRUST_BOUNDARIES.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("metadata-only", doc)
        self.assertIn("post-merge", doc)
        self.assertIn("opt-in", doc)
        self.assertIn("required check", doc)
        self.assertIn("isolated-pr-canary", doc)
        self.assertIn("does not prove host isolation", doc)
        self.assertIn("registration alone does not establish host/daemon isolation", runner_doc)


if __name__ == "__main__":
    unittest.main()
