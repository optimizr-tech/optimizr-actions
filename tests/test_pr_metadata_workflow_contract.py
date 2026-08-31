from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/_pr-metadata.yml"
ACTION = ROOT / ".github/actions/pr-metadata-validation/action.yml"
VALIDATOR = ROOT / ".github/actions/pr-metadata-validation/validate.py"


class PRMetadataWorkflowContractTests(unittest.TestCase):
    def test_workflow_is_read_only_and_metadata_only(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("metadata-pr", text)
        self.assertIn("ephemeral-pr", text)
        self.assertIn("contents: read", text)
        self.assertIn("pull-requests: read", text)
        self.assertIn("pr-metadata-validation@f042163c0d83712736bbc9cc168c4f9f98c488cf", text)
        for forbidden in (
            "actions/checkout",
            "actions/setup-node",
            "actions/setup-python",
            "npm ",
            "pip ",
            "docker ",
            "sudo ",
            "secrets:",
        ):
            self.assertNotIn(forbidden, text)

    def test_action_executes_only_trusted_action_path(self):
        text = ACTION.read_text(encoding="utf-8")
        self.assertIn('$GITHUB_ACTION_PATH/validate.py', text)
        self.assertNotIn("github.workspace", text.lower())
        self.assertNotIn("checkout", text.lower())

    def test_validator_uses_api_and_never_executes_candidate_code(self):
        text = VALIDATOR.read_text(encoding="utf-8")
        self.assertIn("/commits?per_page=100", text)
        self.assertIn('"state": "closed"', text)
        self.assertIn('"head": f"{head_owner}:{head_ref}"', text)
        self.assertIn("urllib.parse.urlencode", text)
        self.assertIn("validate_pr_lifecycle", text)
        self.assertIn("urllib.request", text)
        for forbidden in (
            "subprocess",
            "os.system",
            "eval(",
            "exec(",
            "docker",
            "npm",
            "pip",
            'method="DELETE"',
            "method='DELETE'",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
