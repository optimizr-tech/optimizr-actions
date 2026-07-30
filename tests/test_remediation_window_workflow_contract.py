from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RemediationWindowWorkflowContractTests(unittest.TestCase):
    def test_public_workflows_use_trusted_time_and_complete_coverage(self) -> None:
        action = (ROOT / ".github/actions/security-gate/action.yml").read_text()
        hosted = (ROOT / ".github/workflows/_security-gate.yml").read_text()
        self_hosted = (ROOT / ".github/workflows/_vps-self-hosted-deploy.yml").read_text()
        monorepo = (ROOT / ".github/workflows/_vps-monorepo-deploy.yml").read_text()
        manifest = (ROOT / ".github/actions/record-deploy-manifest/action.yml").read_text()
        for content in (action, hosted, self_hosted, monorepo):
            self.assertNotIn("remediation_window_evaluated_at", content)
        self.assertIn('"$remediation_window_tool" collect', action)
        self.assertIn('"$remediation_window_tool" "${remediation_eval_args[@]}"', action)
        self.assertIn("remediation_window_uncovered", action)
        for workflow in (hosted, self_hosted, monorepo):
            self.assertIn("remediation_window_uncovered", workflow)
            self.assertIn("Governed remediation window", workflow)
        self.assertIn("security_remediation_window_state", manifest)
        self.assertIn("--remediation-window-state", manifest)


if __name__ == "__main__":
    unittest.main()
