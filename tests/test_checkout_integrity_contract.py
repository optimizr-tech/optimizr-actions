from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github/actions/checkout-integrity/action.yml"
RUNNER = ROOT / "scripts/repository_validation/runner.py"


class CheckoutIntegrityContractTests(unittest.TestCase):
    def test_action_verifies_exact_sha_required_paths_and_sanitized_summary(self):
        text = ACTION.read_text(encoding="utf-8")

        for needle in (
            "expected_sha:",
            "required_paths_json:",
            "repair_missing_paths:",
            "check-workspace",
            "repair-workspace",
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

    def test_action_repairs_only_after_a_bounded_integrity_failure(self):
        text = ACTION.read_text(encoding="utf-8")
        runner_text = RUNNER.read_text(encoding="utf-8")

        self.assertIn("repair_missing_paths", text)
        self.assertIn("check-workspace", text)
        self.assertIn("repair-workspace", text)
        self.assertIn('"sparse-checkout", "disable"', runner_text)
        self.assertIn('"checkout",\n        "--force"', runner_text)
        self.assertIn('case "$REPAIR_MISSING_PATHS" in', text)
        self.assertIn('if [ "$REPAIR_MISSING_PATHS" != "true" ]; then', text)


if __name__ == "__main__":
    unittest.main()
