"""Contract tests for reviewed vulnerability baseline policy."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SecurityBaselinePolicyTests(unittest.TestCase):
    def test_gate_accepts_reviewed_baseline_input(self) -> None:
        action = (ROOT / ".github/actions/security-gate/action.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("  baseline_file:", action)
        self.assertIn("INPUT_BASELINE_FILE:", action)
        self.assertIn("baseline_tool=", action)
        self.assertIn("--scope \"$target\"", action)

    def test_self_hosted_deploy_forwards_baseline_file(self) -> None:
        content = (
            ROOT / ".github/workflows/_vps-self-hosted-deploy.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("security_baseline_file:", content)
        self.assertIn("baseline_file: ${{ inputs.security_baseline_file }}", content)


if __name__ == "__main__":
    unittest.main()
