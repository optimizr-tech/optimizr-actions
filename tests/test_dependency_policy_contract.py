from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DependencyPolicyContractTests(unittest.TestCase):
    def test_action_scans_vulnerabilities_and_licenses_and_fails_closed(self):
        text = (ROOT / ".github/actions/dependency-policy/action.yml").read_text()
        self.assertIn("--scanners vuln,license", text)
        self.assertIn("--exit-code 0", text)
        self.assertIn("dependency_policy/policy.py", text)
        self.assertIn('bin/uv" lock --check', text)
        self.assertIn('bin/poetry" check --lock', text)
        self.assertIn("validate-requirements", text)
        self.assertIn("validate-db", text)
        self.assertIn("--skip-db-update", text)
        self.assertIn("python3 -m venv", text)
        self.assertNotIn("--user", text)
        self.assertNotIn("continue-on-error", text)
        self.assertIn("realpath -e", text)
        self.assertIn("resolves outside the repository", text)

    def test_workflow_uses_pinned_actions_and_read_only_permissions(self):
        text = (ROOT / ".github/workflows/_dependency-policy.yml").read_text()
        self.assertIn("contents: read", text)
        self.assertIn("fromJSON(inputs.runner_json)", text)
        self.assertRegex(text, r"actions/checkout@[0-9a-f]{40}")
        self.assertRegex(text, r"actions/upload-artifact@[0-9a-f]{40}")


if __name__ == "__main__":
    unittest.main()
