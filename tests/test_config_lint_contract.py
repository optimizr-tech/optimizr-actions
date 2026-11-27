from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ConfigLintContractTests(unittest.TestCase):
    def test_reusable_workflow_is_read_only_and_pins_checkout(self):
        workflow = (ROOT / ".github/workflows/_config-lint.yml").read_text()
        self.assertIn("workflow_call:", workflow)
        self.assertIn("contents: read", workflow)
        self.assertRegex(workflow, r"actions/checkout@[0-9a-f]{40}")
        self.assertIn("job.workflow_sha", workflow)
        self.assertIn("scripts/config_lint/runner.py", workflow)
        self.assertNotIn("actions: write", workflow)

    def test_hadolint_image_uses_verified_immutable_digest(self):
        runner = (ROOT / "scripts/config_lint/runner.py").read_text()
        self.assertIn(
            "hadolint/hadolint@sha256:",
            runner,
        )
        self.assertIn(
            "32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d",
            runner,
        )
        self.assertNotIn("hadolint/hadolint:latest", runner)

    def test_contract_documents_policy_failures_and_rollback(self):
        doc = (ROOT / "docs/CONFIG_LINT.md").read_text()
        for expected in (
            "fail_on", "allowed_published_ports", "require_read_only",
            "require_cap_drop", "expires", "GitHub annotations", "contents: read",
            "Rollback", "docker compose config --format",
        ):
            self.assertIn(expected, doc)

    def test_policy_template_has_empty_exception_set_and_default_blocking_levels(self):
        import json

        policy = json.loads((ROOT / "templates/config-lint-policy.json").read_text())
        self.assertEqual(1, policy["version"])
        self.assertEqual(["error", "warning"], policy["fail_on"])
        self.assertEqual([], policy["exceptions"])


if __name__ == "__main__":
    unittest.main()
