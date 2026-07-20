from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BadgeRecoveryContractTests(unittest.TestCase):
    def test_workflow_has_write_only_where_needed_and_serializes_updates(self):
        text = (ROOT / ".github/workflows/_release-badge-recovery.yml").read_text()
        self.assertIn("contents: write", text)
        self.assertIn("cancel-in-progress: false", text)
        self.assertIn("fromJSON(inputs.runner_json)", text)
        self.assertNotIn("secrets: inherit", text)
        self.assertIn("actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd", text)
        self.assertIn("update-release-badge@v1", text)
        self.assertIn("release-badge-resolver@v1", text)
        resolver = (ROOT / ".github/actions/release-badge-resolver/action.yml").read_text()
        self.assertIn("release_badge/resolver.py", resolver)
        self.assertNotIn("git clone", text)


if __name__ == "__main__":
    unittest.main()
