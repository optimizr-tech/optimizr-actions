from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class EnvWriterContractTests(unittest.TestCase):
    def test_action_passes_paths_not_secret_values(self):
        text = (ROOT / ".github/actions/write-env-file/action.yml").read_text()
        self.assertIn("schema_path", text)
        self.assertIn("allowed_root", text)
        self.assertIn("evidence_path", text)
        self.assertNotIn("secret_values", text)
        self.assertNotIn("bash -c", text)
        self.assertNotIn("eval ", text)
        self.assertIn("scripts/env_writer/runner.py", text)


if __name__ == "__main__":
    unittest.main()
