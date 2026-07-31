from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ValidationRunnerPortabilityTests(unittest.TestCase):
    WORKFLOWS = (
        "_docker-compose-validate.yml",
        "_trivy-scan.yml",
        "_commitlint.yml",
        "_validate-pr.yml",
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

    def test_pr_metadata_workflows_require_ephemeral_self_hosted_runners(self):
        for name in ("_commitlint.yml", "_validate-pr.yml"):
            text = (ROOT / ".github/workflows" / name).read_text()
            with self.subTest(workflow=name):
                self.assertIn('ALLOW_TRUSTED_MAIN: "false"', text)
                self.assertIn('"ephemeral" not in labels', text)

    def test_explicit_optional_skip_remains_caller_controlled(self):
        for name in ("_docker-compose-validate.yml", "_trivy-scan.yml"):
            text = (ROOT / ".github/workflows" / name).read_text()
            with self.subTest(workflow=name):
                self.assertIn("if: ${{ !inputs.skip }}", text)


if __name__ == "__main__":
    unittest.main()
