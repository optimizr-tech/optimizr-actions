from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OrgAuditContractTests(unittest.TestCase):
    def test_public_job_is_read_only_hosted_and_uploads_only_public_report(self):
        text = (ROOT / ".github/workflows/org-adoption-audit.yml").read_text()
        self.assertIn("schedule:", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("runs-on: ubuntu-latest", text)
        self.assertIn("permissions:\n  contents: read", text)
        self.assertIn("ORG_AUDIT_REPOSITORIES", text)
        self.assertIn("ORG_AUDIT_TOKEN", text)
        self.assertIn("--public", text)
        self.assertIn("public-report", text)
        self.assertIn("actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd", text)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", text)
        self.assertNotIn("git clone", text)


if __name__ == "__main__":
    unittest.main()
