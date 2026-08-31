from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ValidationGateContractTests(unittest.TestCase):
    def test_gate_exposes_one_attestation_for_release_and_deploy(self):
        text = (ROOT / ".github/workflows/_validation-gate.yml").read_text()
        self.assertIn("_repository-validation.yml@f042163c0d83712736bbc9cc168c4f9f98c488cf", text)
        self.assertIn("_security-suite.yml@f042163c0d83712736bbc9cc168c4f9f98c488cf", text)
        self.assertIn("validation-attestation@f042163c0d83712736bbc9cc168c4f9f98c488cf", text)
        self.assertNotIn("62ea4fba2da72e502a3141391a5db988f8a98c16", text)
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

    def test_gate_accepts_only_governed_ephemeral_pull_request_runners(self):
        text = (ROOT / ".github/workflows/_validation-gate.yml").read_text()
        self.assertIn("ephemeral-pr", text)
        self.assertIn('"ephemeral" not in labels', text)
        self.assertIn('os.environ["EVENT_NAME"] != "pull_request"', text)
        self.assertIn(
            "allow_ephemeral_pr: ${{ inputs.validation_path == 'ephemeral-pr' }}",
            text,
        )
        self.assertIn(
            "require_trusted_ref: ${{ inputs.validation_path == 'self-hosted' || inputs.validation_path == 'reviewed-emergency' }}",
            text,
        )

    def test_gate_propagates_security_runner_trust_mode(self):
        text = (ROOT / ".github/workflows/_validation-gate.yml").read_text()
        self.assertIn(
            "self_hosted_mode: ${{ inputs.validation_path == 'ephemeral-pr' && 'ephemeral-pr' || ((inputs.validation_path == 'self-hosted' || inputs.validation_path == 'reviewed-emergency') && 'trusted-main' || 'none') }}",
            text,
        )

    def test_gate_propagates_node_toolchain_to_repository_validation(self):
        text = (ROOT / ".github/workflows/_validation-gate.yml").read_text()
        repository_validation = text.split("  repository-validation:", 1)[1].split(
            "  security-suite:", 1
        )[0]
        for input_name in ("node_version", "npm_version", "pnpm_version"):
            self.assertIn(f"{input_name}: ${{{{ inputs.{input_name} }}}}", repository_validation)

    def test_security_suite_exports_success_result(self):
        text = (ROOT / ".github/workflows/_security-suite.yml").read_text()
        self.assertIn("jobs.summary.outputs.result", text)
        self.assertIn("steps.summary.outputs.result", text)
        self.assertIn('echo "result=passed" >> "$GITHUB_OUTPUT"', text)


if __name__ == "__main__":
    unittest.main()
