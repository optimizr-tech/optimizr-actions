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

if __name__=="__main__": unittest.main()
