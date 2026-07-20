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

    def test_summary_always_uploads_sanitized_evidence(self):
        self.assertIn("if: always()", self.text)
        self.assertIn("artifacts/security-suite/summary.json", self.text)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", self.text)
        self.assertNotIn("github.event.client_payload", self.text)


if __name__ == "__main__":
    unittest.main()
