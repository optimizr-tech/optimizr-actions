from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StaticSiteContractTests(unittest.TestCase):
    def test_workflow_is_protected_exact_sha_and_pinned(self):
        text = (ROOT / ".github/workflows/_static-site-deploy.yml").read_text()
        self.assertIn("environment: ${{ inputs.environment_name }}", text)
        self.assertIn("ref: ${{ inputs.deployed_sha }}", text)
        self.assertIn('"self-hosted" not in labels', text)
        self.assertIn("contents: read", text)
        self.assertNotIn("secrets: inherit", text)
        self.assertIn("if: always()", text)
        self.assertIn("actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd", text)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", text)

    def test_action_has_manifest_not_command_inputs(self):
        text = (ROOT / ".github/actions/static-site-deploy/action.yml").read_text()
        self.assertIn("manifest_path", text)
        self.assertIn("static_site/runner.py", text)
        self.assertNotIn("command:", text)
        self.assertNotIn("bash -c", text)
        self.assertNotIn("eval ", text)


if __name__ == "__main__":
    unittest.main()
