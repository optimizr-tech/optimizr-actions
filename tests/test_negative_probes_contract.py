from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NegativeProbeContractTests(unittest.TestCase):
    def test_workflow_uses_protected_environment_and_named_targets(self):
        text = (ROOT / ".github/workflows/_negative-probes.yml").read_text()
        self.assertIn("environment:", text)
        self.assertIn("deployed_sha:", text)
        self.assertIn("ref: ${{ inputs.deployed_sha }}", text)
        for name in ("PROBE_TARGET_1", "PROBE_TARGET_2", "PROBE_TARGET_3"):
            self.assertIn(name, text)
        self.assertNotIn("secrets: inherit", text)
        self.assertIn("if: always()", text)

    def test_action_executes_declarative_runner_not_inline_consumer_shell(self):
        text = (ROOT / ".github/actions/negative-probes/action.yml").read_text()
        self.assertIn("negative_probes/runner.py", text)
        self.assertNotIn("eval ", text)
        self.assertNotIn("bash -c", text)
        self.assertIn("realpath -e", text)
        self.assertIn("resolves outside the repository", text)


if __name__ == "__main__":
    unittest.main()
