from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RepositoryValidationContractTests(unittest.TestCase):
    def test_reusable_workflow_has_call_dispatch_protection_and_read_only_permissions(self):
        text = (ROOT / ".github/workflows/_repository-validation.yml").read_text()
        self.assertIn("workflow_call:", text)
        self.assertNotIn("workflow_dispatch:", text)
        self.assertIn("contents: read", text)
        self.assertIn("fromJSON(inputs.runner_json)", text)
        template = (ROOT / "templates/repository-validation-emergency.yml").read_text()
        self.assertIn("workflow_dispatch:", template)
        self.assertIn("environment:", template)
        self.assertIn("needs: approval", template)
        self.assertIn("_repository-validation.yml@v1", template)
        self.assertNotIn("secrets: inherit", text)
        self.assertNotIn("pull_request_target", text)

    def test_composite_action_uses_python_argv_runner(self):
        text = (ROOT / ".github/actions/repository-validation/action.yml").read_text()
        self.assertIn("repository_validation/runner.py", text)
        self.assertIn("args_json", text)
        self.assertNotIn("eval ", text)
        self.assertNotIn("bash -c", text)
        self.assertIn('candidate_sha="${HEAD_SHA:-$GITHUB_SHA}"', text)


if __name__ == "__main__":
    unittest.main()
