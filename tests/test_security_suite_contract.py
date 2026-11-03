from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SecuritySuiteContractTests(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / ".github/workflows/_security-suite.yml").read_text(encoding="utf-8")

    def test_profiles_and_child_workflows_are_allowlisted(self):
        for profile in ("python)", "node)", "compose|infra)", "monorepo)"):
            self.assertIn(profile, self.text)
        for workflow in (
            "_static-lint.yml@v1",
            "_security-gate.yml@v1",
            "_dependency-policy.yml@v1",
            "_sast-gate.yml@v1",
            "_supply-chain-evidence.yml@v1",
        ):
            self.assertIn(workflow, self.text)

    def test_permissions_and_inputs_are_restricted(self):
        self.assertIn("permissions:\n  contents: read", self.text)
        self.assertNotIn("secrets: inherit", self.text)
        self.assertNotIn("command:", self.text)
        self.assertNotIn("bash -c", self.text)
        self.assertNotIn("eval ", self.text)
        self.assertIn("fromJSON(inputs.runner_json)", self.text)

    def test_dependency_subdirectory_is_propagated_to_confined_gate(self):
        self.assertIn("dependency_working_directory:", self.text)
        self.assertIn("working_directory: ${{ inputs.dependency_working_directory }}", self.text)
        self.assertIn("_dependency-policy.yml@v1", self.text)

    def test_filesystem_exception_policy_is_propagated_to_security_gate(self):
        self.assertIn("exceptions_file:", self.text)
        self.assertIn("exceptions_file: ${{ inputs.exceptions_file }}", self.text)

    def test_summary_uploads_after_runner_trust_gate_and_avoids_stale_artifacts(self):
        self.assertIn("if: always()", self.text)
        self.assertIn("needs.profile.result == 'success'", self.text)
        self.assertIn(
            "steps.summary.outputs.evidence_path != '' || steps.trust_failure_summary.outputs.evidence_path != ''",
            self.text,
        )
        self.assertIn("artifacts/security-suite/summary.json", self.text)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", self.text)
        self.assertNotIn("github.event.client_payload", self.text)

    def test_profile_trust_failure_keeps_status_artifact_without_caller_checkout(self):
        summary = self.text.split("  summary:\n", 1)[1]
        job_header, steps = summary.split("    steps:\n", 1)
        self.assertIn("    if: always()", job_header)
        self.assertIn(
            "result: ${{ steps.summary.outputs.result || steps.trust_failure_summary.outputs.result }}",
            job_header,
        )
        self.assertIn(
            "evidence_path: ${{ steps.summary.outputs.evidence_path || steps.trust_failure_summary.outputs.evidence_path }}",
            job_header,
        )

        caller_checkout = steps.split("- name: Checkout caller at the exact triggering SHA", 1)[1].split(
            "- name: Checkout reusable evidence helper", 1
        )[0]
        self.assertIn("if: ${{ needs.profile.result == 'success' }}", caller_checkout)

        fallback = steps.split("- name: Write status-only summary when runner trust fails", 1)[1].split(
            "- name: Upload suite summary", 1
        )[0]
        self.assertIn("needs.profile.result != 'success'", fallback)
        self.assertNotIn("actions/checkout@", fallback)
        self.assertIn('"source_checked": False', fallback)
        self.assertIn('"result": "failed"', fallback)
        self.assertIn('\"result\": \"failed\"', fallback)
        self.assertIn('"evidence_path": str(summary_path)', fallback)
        self.assertIn(
            "steps.summary.outputs.evidence_path != '' || steps.trust_failure_summary.outputs.evidence_path != ''",
            steps,
        )


    def test_suite_enforces_runner_trust_before_children(self):
        self.assertIn("self_hosted_mode:", self.text)
        self.assertIn("trusted-pr", self.text)
        self.assertIn(
            'hosted validation must use ["ubuntu-latest"] with mode=none',
            self.text,
        )
        self.assertIn('os.environ["EVENT_NAME"] != "pull_request"', self.text)
        self.assertIn('"ephemeral" not in labels', self.text)
        self.assertIn('os.environ["EVENT_REF"] != "refs/heads/main"', self.text)
        self.assertLess(
            self.text.index("Validate runner trust contract"),
            self.text.index("Resolve allowlisted profile"),
        )

    def test_suite_propagates_runner_mode_to_every_child(self):
        self.assertEqual(
            self.text.count("self_hosted_mode: ${{ inputs.self_hosted_mode }}"),
            5,
        )


if __name__ == "__main__":
    unittest.main()
