from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ValidationRunnerPortabilityTests(unittest.TestCase):
    WORKFLOWS = (
        "_docker-compose-validate.yml",
        "_trivy-scan.yml",
        "_commitlint.yml",
        "_validate-pr.yml",
        "_python-uv-test.yml",
        "_node-project-test.yml",
        "_quality-gate-collect-security.yml",
        "_quality-gate-collect-dup.yml",
        "_quality-gate-baseline.yml",
        "_quality-gate-pr.yml",
        "_security-suite.yml",
        "_static-lint.yml",
        "_security-gate.yml",
        "_dependency-policy.yml",
        "_sast-gate.yml",
        "_supply-chain-evidence.yml",
    )

    def test_reusables_accept_governed_runner_selection(self):
        for name in self.WORKFLOWS:
            text = (ROOT / ".github/workflows" / name).read_text()
            with self.subTest(workflow=name):
                self.assertIn("runner_json:", text)
                self.assertIn("self_hosted_mode:", text)
                self.assertIn("fromJSON(inputs.runner_json)", text)
                self.assertNotIn("runs-on: ubuntu-latest", text)

    def test_reusables_never_infer_billing_policy_from_skip_tests(self):
        for name in self.WORKFLOWS:
            text = (ROOT / ".github/workflows" / name).read_text()
            with self.subTest(workflow=name):
                self.assertNotIn("[skip-tests]", text)
                self.assertNotIn("github.event.head_commit.message", text)

    def test_pr_capable_workflows_require_ephemeral_self_hosted_runners(self):
        for name in (
            "_commitlint.yml",
            "_validate-pr.yml",
            "_node-project-test.yml",
            "_quality-gate-collect-security.yml",
            "_quality-gate-collect-dup.yml",
            "_quality-gate-pr.yml",
            "_security-suite.yml",
            "_static-lint.yml",
            "_security-gate.yml",
            "_dependency-policy.yml",
            "_sast-gate.yml",
            "_supply-chain-evidence.yml",
        ):
            text = (ROOT / ".github/workflows" / name).read_text()
            with self.subTest(workflow=name):
                self.assertIn('"ephemeral" not in labels', text)
                self.assertIn('os.environ["EVENT_NAME"] != "pull_request"', text)

    def test_trusted_pr_mode_is_available_for_authorized_persistent_validation(self):
        for name in (
            "_python-uv-test.yml",
            "_node-project-test.yml",
            "_security-suite.yml",
            "_static-lint.yml",
            "_security-gate.yml",
            "_dependency-policy.yml",
            "_sast-gate.yml",
            "_supply-chain-evidence.yml",
        ):
            text = (ROOT / ".github/workflows" / name).read_text()
            with self.subTest(workflow=name):
                self.assertIn("trusted-pr", text)
                trusted_pr_index = text.index('mode == "trusted-pr"')
                ephemeral_index = text.index('mode == "ephemeral-pr"')
                trusted_pr_block = text[trusted_pr_index:ephemeral_index]
                self.assertIn('os.environ["EVENT_NAME"] != "pull_request"', trusted_pr_block)
                self.assertNotIn('"ephemeral" not in labels', trusted_pr_block)

    def test_explicit_optional_skip_remains_caller_controlled(self):
        for name in (
            "_docker-compose-validate.yml",
            "_trivy-scan.yml",
            "_python-uv-test.yml",
        ):
            text = (ROOT / ".github/workflows" / name).read_text()
            with self.subTest(workflow=name):
                self.assertIn("!inputs.skip", text)

    def test_python_uv_uses_actions_owned_composite(self):
        text = (ROOT / ".github/workflows/_python-uv-test.yml").read_text()
        self.assertNotIn(
            "optimizr-infra-ops/.github/actions/python-uv-test-steps",
            text,
        )
        self.assertEqual(
            text.count(
                "optimizr-tech/optimizr-actions/.github/actions/"
                "python-uv-test-steps@v1"
            ),
            2,
        )

    def test_rabbitmq_service_avoids_deprecated_memory_environment(self):
        text = (ROOT / ".github/workflows/_python-uv-test.yml").read_text()
        self.assertIn("--memory 1g", text)
        self.assertNotIn("RABBITMQ_VM_MEMORY_HIGH_WATERMARK", text)

    def test_serve_integration_services_match_runtime_pins(self):
        text = (ROOT / ".github/workflows/_python-uv-test.yml").read_text()
        for image in (
            "postgres:16.14-alpine@sha256:e013e867e712fec275706a6c51c966f0bb0c93cfa8f51000f85a15f9865a28cb",
            "redis:7.4.9-alpine@sha256:b1addbe72465a718643cff9e60a58e6df1841e29d6d7d60c9a85d8d72f08d1a7",
            "rabbitmq:4.2.9-management-alpine@sha256:a51ed990cb4392ce136380fb01fdb8aab1203565953f5ea9711bf839b1b709db",
        ):
            with self.subTest(image=image):
                self.assertIn(image, text)


if __name__ == "__main__":
    unittest.main()
