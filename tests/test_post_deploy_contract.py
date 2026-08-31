from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PostDeployContractTests(unittest.TestCase):
    def test_workflow_is_protected_exact_sha_and_self_hosted(self):
        text = (ROOT / ".github/workflows/_post-deploy-verification.yml").read_text()
        self.assertIn("environment: ${{ inputs.environment_name }}", text)
        self.assertIn("ref: ${{ inputs.deployed_sha }}", text)
        self.assertIn('"self-hosted" not in labels', text)
        self.assertIn("contents: read", text)
        self.assertNotIn("secrets: inherit", text)
        self.assertIn("if: always()", text)
        self.assertIn("_negative-probes.yml@f042163c0d83712736bbc9cc168c4f9f98c488cf", text)
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", text)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", text)

    def test_action_uses_declarative_runner_only(self):
        text = (ROOT / ".github/actions/post-deploy-verification/action.yml").read_text()
        self.assertIn("post_deploy/runner.py", text)
        self.assertNotIn("bash -c", text)
        self.assertNotIn("eval ", text)
        self.assertNotIn("command:", text)


if __name__ == "__main__":
    unittest.main()
