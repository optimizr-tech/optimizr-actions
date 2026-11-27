from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DastBaselineContractTests(unittest.TestCase):
    def test_reusable_workflow_has_passive_pinned_self_hosted_contract(self):
        text = (ROOT / ".github/workflows/_dast-baseline.yml").read_text()
        self.assertIn("workflow_call:", text)
        self.assertIn("contents: read", text)
        self.assertIn("fromJSON(inputs.runner_json)", text)
        self.assertIn('["self-hosted","Linux"]', text)
        self.assertIn("ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af", text)
        self.assertIn("zap-baseline.py", text)
        self.assertNotIn("zap-full-scan.py", text)
        self.assertNotIn("secrets:", text)
        self.assertIn("OUTOFSCOPE", text)
        self.assertIn("max_duration_minutes", text)
        self.assertIn("default: high", text)

    def test_report_script_only_emits_sanitized_fields_and_enforces_overrides(self):
        text = (ROOT / "scripts/dast_baseline/report.py").read_text()
        self.assertIn('"rule_id": plugin_id', text)
        self.assertIn('"instances": len(alert.get("instances", []))', text)
        self.assertIn('configured == "IGNORE"', text)
        self.assertIn('configured == "FAIL"', text)
        self.assertNotIn('"request":', text)
        self.assertNotIn('"response":', text)
        self.assertIn("THRESHOLDS[threshold]", text)

    def test_documented_weekly_consumer_covers_storefront_and_admin(self):
        text = (ROOT / "docs/DAST_BASELINE.md").read_text()
        self.assertIn("cron:", text)
        self.assertIn("storefront", text)
        self.assertIn("admin", text)
        self.assertIn("rollback", text.lower())


if __name__ == "__main__":
    unittest.main()
