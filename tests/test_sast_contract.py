from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SastContractTests(unittest.TestCase):
    def test_action_uses_pinned_semgrep_and_local_rules_only(self):
        text = (ROOT / ".github/actions/sast-gate/action.yml").read_text()
        self.assertIn("semgrep==1.170.0", text)
        self.assertIn("--metrics=off", text)
        self.assertIn("sast_gate/runner.py", text)
        self.assertNotIn("p/", text)
        self.assertNotIn("https://semgrep.dev", text)
        self.assertIn('--repository "$GITHUB_REPOSITORY"', text)
        self.assertIn('--head-sha "$GITHUB_SHA"', text)
        self.assertIn("realpath -e", text)
        self.assertIn("resolves outside the repository", text)

    def test_rule_profiles_exist_and_workflow_is_read_only(self):
        self.assertTrue((ROOT / "rules/sast/python.yml").exists())
        self.assertTrue((ROOT / "rules/sast/typescript.yml").exists())
        text = (ROOT / ".github/workflows/_sast-gate.yml").read_text()
        self.assertIn("contents: read", text)
        self.assertIn("fromJSON(inputs.runner_json)", text)
        self.assertIn("if: always()", text)


if __name__ == "__main__":
    unittest.main()
