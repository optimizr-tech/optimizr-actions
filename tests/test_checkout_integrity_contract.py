from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github/actions/checkout-integrity/action.yml"


class CheckoutIntegrityContractTests(unittest.TestCase):
    def test_action_verifies_exact_sha_required_paths_and_sanitized_summary(self):
        text = ACTION.read_text(encoding="utf-8")

        for needle in (
            "expected_sha:",
            "required_paths_json:",
            "check-workspace",
            "--expected-sha",
            "--required-paths-json",
            "GITHUB_STEP_SUMMARY",
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)

    def test_action_has_no_unpinned_third_party_dependency_or_secret_inheritance(self):
        text = ACTION.read_text(encoding="utf-8")

        self.assertNotRegex(text, r"uses:\s+[^@\s]+@v\d")
        self.assertNotIn("secrets: inherit", text)


if __name__ == "__main__":
    unittest.main()
