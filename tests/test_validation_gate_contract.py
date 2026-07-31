from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ValidationGateContractTests(unittest.TestCase):
    def test_gate_exposes_one_attestation_for_release_and_deploy(self):
        text = (ROOT / ".github/workflows/_validation-gate.yml").read_text()
        self.assertIn("_repository-validation.yml@v1", text)
        self.assertIn("_security-suite.yml@v1", text)
        self.assertIn("validation-attestation", text)
        for output in (
            "result:",
            "validated_sha:",
            "validation_path:",
            "evidence_digest:",
            "actions_workflow_sha:",
        ):
            self.assertIn(output, text)
        self.assertIn("job.workflow_sha", text)
        self.assertNotIn("[skip-tests]", text)
        self.assertNotIn("curl ", text)
        self.assertNotIn("actions/runs", text)

    def test_gate_requires_exact_context_sha_and_complete_children(self):
        text = (ROOT / ".github/workflows/_validation-gate.yml").read_text()
        self.assertIn("candidate SHA must equal github.sha", text)
        self.assertIn("needs.repository-validation.result", text)
        self.assertIn("needs.security-suite.result", text)
        self.assertIn("if: always()", text)

    def test_security_suite_exports_success_result(self):
        text = (ROOT / ".github/workflows/_security-suite.yml").read_text()
        self.assertIn("jobs.summary.outputs.result", text)
        self.assertIn("steps.summary.outputs.result", text)
        self.assertIn('echo "result=passed" >> "$GITHUB_OUTPUT"', text)


if __name__ == "__main__":
    unittest.main()
