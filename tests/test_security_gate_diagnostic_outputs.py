"""Contract tests for actionable deploy security diagnostics."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SecurityGateDiagnosticOutputTests(unittest.TestCase):
    def test_retry_action_exposes_finding_counts(self) -> None:
        content = (ROOT / ".github/actions/security-retry-result/action.yml").read_text(
            encoding="utf-8"
        )
        for output in (
            "fixable_vulnerability_count",
            "unfixed_vulnerability_count",
            "misconfiguration_count",
            "secret_count",
        ):
            self.assertIn(f"  {output}:", content)

    def test_self_hosted_deploy_failure_prints_classification_and_counts(self) -> None:
        for workflow in (
            ".github/workflows/_vps-self-hosted-deploy.yml",
            ".github/workflows/_vps-monorepo-deploy.yml",
        ):
            with self.subTest(workflow=workflow):
                content = (ROOT / workflow).read_text(encoding="utf-8")
                self.assertIn("SECURITY_CLASSIFICATION:", content)
                self.assertIn("FIXABLE_COUNT:", content)
                self.assertIn("UNFIXED_COUNT:", content)
                self.assertIn("MISCONFIGURATION_COUNT:", content)
                self.assertIn("SECRET_COUNT:", content)
                self.assertIn("INITIAL_FAILURE_REASON:", content)
                self.assertIn("FINAL_FAILURE_REASON:", content)
                self.assertIn("classification=${SECURITY_CLASSIFICATION}", content)
                self.assertIn("failure_reason=${failure_reason}", content)
                self.assertIn("fixable=${FIXABLE_COUNT}", content)
                self.assertIn("unfixed=${UNFIXED_COUNT}", content)
                self.assertIn("misconfigurations=${MISCONFIGURATION_COUNT}", content)
                self.assertIn("secrets=${SECRET_COUNT}", content)


if __name__ == "__main__":
    unittest.main()
