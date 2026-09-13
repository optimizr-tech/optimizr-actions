from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class StaticLintContractTests(unittest.TestCase):
    def test_action_pins_archives_and_checksums(self):
        text=(ROOT/".github/actions/static-lint/action.yml").read_text()
        self.assertIn("0.11.0",text); self.assertIn("1.7.12",text); self.assertIn("sha256sum -c",text); self.assertIn("static_lint/runner.py",text); self.assertNotIn("continue-on-error",text)
    def test_workflow_is_portable_and_read_only(self):
        text=(ROOT/".github/workflows/_static-lint.yml").read_text()
        self.assertIn("fromJSON(inputs.runner_json)",text); self.assertIn("contents: read",text); self.assertNotIn("secrets: inherit",text); self.assertIn("if: always()",text)

    def test_workflow_derives_tracked_lint_paths_before_scanning(self):
        text=(ROOT/".github/workflows/_static-lint.yml").read_text()
        self.assertIn("Derive tracked lint paths",text)
        self.assertIn('git", "ls-files", "-z"',text)
        self.assertIn("required_paths_json=",text)
        self.assertIn("required_paths_json: ${{ steps.checkout_paths.outputs.required_paths_json }}",text)
        self.assertLess(text.index("Derive tracked lint paths"),text.index("Verify checkout integrity"))
        self.assertLess(text.index("Verify checkout integrity"),text.index("Run portable static lint"))

if __name__=="__main__": unittest.main()
