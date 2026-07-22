"""Behavioral tests for effective summaries with signal-only findings."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "security_gate" / "report.py"
spec = importlib.util.spec_from_file_location("security_gate_report", MODULE_PATH)
assert spec and spec.loader
report_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report_module)


class SecurityReportEffectiveSummaryTests(unittest.TestCase):
    def test_enforced_summary_preserves_unfixed_findings_from_complete_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            complete = directory / "image-abcd.json"
            enforced = directory / "image-abcd-enforced.json"
            complete.write_text(
                json.dumps(
                    {
                        "Results": [
                            {
                                "Vulnerabilities": [
                                    {
                                        "VulnerabilityID": "CVE-2026-0001",
                                        "Severity": "HIGH",
                                        "FixedVersion": "1.2.4",
                                    },
                                    {
                                        "VulnerabilityID": "CVE-2026-0002",
                                        "Severity": "HIGH",
                                        "FixedVersion": "",
                                    },
                                ]
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            enforced.write_text(
                json.dumps({"Results": [{"Vulnerabilities": []}]}),
                encoding="utf-8",
            )

            summary = report_module.summarize_trivy_report(enforced)

        self.assertEqual(summary["vulnerabilities"]["fixable"], 0)
        self.assertEqual(summary["vulnerabilities"]["unfixed"], 1)
        self.assertEqual(summary["vulnerabilities"]["total"], 1)


if __name__ == "__main__":
    unittest.main()
