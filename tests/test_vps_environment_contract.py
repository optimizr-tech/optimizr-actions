from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class VpsEnvironmentContractTests(unittest.TestCase):
    def test_self_hosted_deploy_exposes_and_uses_target_environment(self) -> None:
        text = (ROOT / ".github/workflows/_vps-self-hosted-deploy.yml").read_text()

        self.assertIn("homologation_environment:", text)
        self.assertIn("default: false", text)
        self.assertIn(
            "name: ${{ inputs.homologation_environment && 'homologation' || 'production' }}",
            text,
        )
