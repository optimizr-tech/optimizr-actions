import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RepositoryValidationContractTests(unittest.TestCase):
    def test_reusable_workflow_is_call_only_and_read_only(self):
        text = (ROOT / ".github/workflows/_repository-validation.yml").read_text()
        self.assertIn("workflow_call:", text)
        self.assertNotIn("workflow_dispatch:", text)
        self.assertIn("contents: read", text)
        self.assertIn("fromJSON(inputs.runner_json)", text)
        self.assertNotIn("secrets: inherit", text)
        self.assertNotIn("pull_request_target", text)
        self.assertIn("persist-credentials: false", text)

    def test_reusable_never_filters_on_the_caller_event_name(self):
        text = (ROOT / ".github/workflows/_repository-validation.yml").read_text()
        self.assertNotIn("github.event_name == 'workflow_call'", text)
        self.assertNotIn("github.event_name == 'workflow_dispatch'", text)
        self.assertIn("jobs.validation.outputs.validated_sha", text)

    def test_reusable_exposes_commit_bound_outputs(self):
        text = (ROOT / ".github/workflows/_repository-validation.yml").read_text()
        self.assertIn("validated_sha:", text)
        self.assertIn("evidence_path:", text)
        self.assertIn("result:", text)
        self.assertIn("steps.contract.outputs.result", text)
        self.assertIn("inputs.candidate_sha || github.sha", text)

    def test_reusable_exposes_bounded_opt_in_retry_contract(self):
        text = (ROOT / ".github/workflows/_repository-validation.yml").read_text()
        action = (ROOT / ".github/actions/repository-validation/action.yml").read_text()
        for content in (text, action):
            self.assertIn("retry_attempts", content)
            self.assertIn("retry_backoff_seconds", content)
            self.assertIn("failure_kind", content)
            self.assertIn("attempt_count", content)
        self.assertIn("retry_attempts: ${{ inputs.retry_attempts }}", text)
        self.assertIn(
            "retry_backoff_seconds: ${{ inputs.retry_backoff_seconds }}", text
        )
        self.assertIn("--retry-attempts", action)
        self.assertIn("--retry-backoff-seconds", action)
        self.assertIn("retryable_dependency", (ROOT / "docs/REPOSITORY_VALIDATION.md").read_text())

    def test_reusable_verifies_checkout_integrity_before_repository_script(self):
        text = (ROOT / ".github/workflows/_repository-validation.yml").read_text()

        self.assertIn("required_paths_json:", text)
        self.assertIn("checkout-integrity@v1", text)
        self.assertIn("clean: true", text)
        self.assertLess(
            text.index("Verify checkout integrity"),
            text.index("Run repository contract"),
        )

    def test_required_checkout_paths_remain_bounded_for_generic_consumers(self):
        text = (ROOT / "scripts/repository_validation/runner.py").read_text()
        self.assertIn("MAX_REQUIRED_PATHS = 256", text)
        self.assertIn("required_paths must contain at most {MAX_REQUIRED_PATHS} entries", text)

    def test_validation_gate_forwards_retry_outputs_without_changing_default(self):
        text = (ROOT / ".github/workflows/_validation-gate.yml").read_text()
        self.assertIn("retry_attempts:", text)
        self.assertIn("retry_backoff_seconds:", text)
        self.assertIn("default: 1", text)
        self.assertIn("failure_kind:", text)
        self.assertIn("attempt_count:", text)
        self.assertIn("needs.repository-validation.outputs.failure_kind", text)

    def test_repository_validation_can_use_temporary_ghcr_auth_for_trusted_docker_checks(self):
        text = (ROOT / ".github/workflows/_repository-validation.yml").read_text()
        gate = (ROOT / ".github/workflows/_validation-gate.yml").read_text()

        self.assertIn("registry_auth:", text)
        self.assertIn("packages: read", text)
        self.assertIn("REGISTRY_TOKEN: ${{ github.token }}", text)
        self.assertIn("docker login ghcr.io", text)
        self.assertIn("Clean temporary registry authentication", text)
        self.assertIn("registry_auth:", gate)
        self.assertIn("packages: read", gate)
        self.assertIn("registry_auth: ${{ inputs.registry_auth }}", gate)

    def test_validation_gate_forwards_required_checkout_paths(self):
        text = (ROOT / ".github/workflows/_validation-gate.yml").read_text()

        self.assertIn("required_paths_json:", text)
        self.assertIn(
            "required_paths_json: ${{ inputs.required_paths_json }}",
            text,
        )

    def test_reusable_provisions_optional_node_toolchain_before_consumer_script(self):
        text = (ROOT / ".github/workflows/_repository-validation.yml").read_text()

        for input_name in ("node_version:", "npm_version:", "pnpm_version:"):
            self.assertIn(input_name, text)

        setup_node = text.index("actions/setup-node@")
        setup_pnpm = text.index("pnpm/action-setup@")
        run_contract = text.index("- name: Run repository contract")
        self.assertLess(setup_node, run_contract)
        self.assertLess(setup_pnpm, run_contract)
        self.assertIn("npm install --global", text)
        self.assertIn("NODE_VERSION: ${{ inputs.node_version }}", text)
        self.assertIn("NPM_VERSION: ${{ inputs.npm_version }}", text)
        self.assertIn("PNPM_VERSION: ${{ inputs.pnpm_version }}", text)

    def test_ephemeral_override_is_bounded_to_pull_request_runner_labels(self):
        text = (ROOT / ".github/workflows/_repository-validation.yml").read_text()
        self.assertIn("allow_ephemeral_pr:", text)
        self.assertIn("ALLOW_EPHEMERAL_PR", text)
        self.assertIn('"ephemeral" not in labels', text)
        self.assertIn('os.environ["EVENT_NAME"] != "pull_request"', text)
        self.assertIn("ephemeral self-hosted repository validation", text)

    def test_emergency_reusable_owns_environment_protection(self):
        text = (ROOT / ".github/workflows/_repository-validation-emergency.yml").read_text()
        self.assertIn("workflow_call:", text)
        self.assertNotIn("workflow_dispatch:", text)
        self.assertIn("environment: ${{ inputs.environment_name }}", text)
        self.assertIn("billing-emergency validation must use a trusted self-hosted runner", text)
        self.assertIn("require_trusted_ref: true", text)
        self.assertNotIn("secrets: inherit", text)

    def test_emergency_dispatch_is_a_consumer_caller_template(self):
        text = (ROOT / "templates/workflows/repository-validation-emergency.yml").read_text()
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("_repository-validation-emergency.yml@v1", text)
        self.assertIn("environment_name:", text)
        self.assertNotIn("run:", text)

    def test_composite_action_uses_python_argv_runner(self):
        text = (ROOT / ".github/actions/repository-validation/action.yml").read_text()
        self.assertIn("repository_validation/runner.py", text)
        self.assertIn("args_json", text)
        self.assertNotIn("eval ", text)
        self.assertNotIn("bash -c", text)
        self.assertIn('candidate_sha="${HEAD_SHA:-$GITHUB_SHA}"', text)

    def test_trust_step_receives_github_token_without_exposing_it_to_execution_step(self):
        text = (ROOT / ".github/actions/repository-validation/action.yml").read_text()
        trust = text.split("- name: Validate candidate trust boundary", 1)[1].split(
            "- name: Execute repository validation", 1
        )[0]
        execute = text.split("- name: Execute repository validation", 1)[1]

        self.assertIn("VALIDATION_GITHUB_TOKEN: ${{ github.token }}", trust)
        self.assertNotIn("VALIDATION_GITHUB_TOKEN", execute)
        self.assertNotIn("github.token", execute)


if __name__ == "__main__":
    unittest.main()
