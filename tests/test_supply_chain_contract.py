from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SupplyChainContractTests(unittest.TestCase):
    def test_action_generates_two_sbom_formats_and_slsa_provenance(self):
        text = (ROOT / ".github/actions/supply-chain-evidence/action.yml").read_text()
        self.assertIn("--format cyclonedx", text)
        self.assertIn("--format spdx-json", text)
        self.assertIn("supply_chain/evidence.py", text)
        self.assertIn("setup-trivy@81e514348e19b6112ce2a7e3ecbafe19c1e1f567", text)
        self.assertNotIn(":latest", text)
        self.assertIn('image_input=("$scan_identity")', text)
        self.assertIn("resolve-local", text)
        self.assertIn("resolve-kind", text)
        self.assertIn("too many image references", text)
        self.assertIn("bootstrap.json", text)
        self.assertIn("summary.json", text)

    def test_workflow_uploads_evidence_even_on_failure(self):
        text = (ROOT / ".github/workflows/_supply-chain-evidence.yml").read_text()
        self.assertIn("if: always()", text)
        self.assertIn("contents: read", text)
        self.assertIn("fromJSON(inputs.runner_json)", text)
        self.assertRegex(text, r"actions/checkout@[0-9a-f]{40}")
        self.assertRegex(text, r"actions/upload-artifact@[0-9a-f]{40}")


if __name__ == "__main__":
    unittest.main()
