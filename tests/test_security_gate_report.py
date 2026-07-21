"""Behavioral tests for actionable versus signal-only Trivy findings."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.security_gate.report import TrivyReportError, main, summarize_trivy_report


class SecurityGateReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def _report(self, payload: object) -> Path:
        path = self.root / "report.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_classifies_fixed_and_unfixed_without_exposing_details(self) -> None:
        report = self._report(
            {
                "Results": [
                    {
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-0001",
                                "Severity": "CRITICAL",
                                "FixedVersion": "2.0.1",
                                "Title": "sensitive title",
                            },
                            {
                                "VulnerabilityID": "CVE-2026-0002",
                                "Severity": "HIGH",
                                "FixedVersion": "",
                                "Status": "fix_deferred",
                            },
                            {
                                "VulnerabilityID": "CVE-2026-0003",
                                "Severity": "HIGH",
                                "Status": "will_not_fix",
                            },
                        ],
                        "Misconfigurations": [{"ID": "DS001"}],
                        "Secrets": [{"RuleID": "private-key"}],
                    }
                ]
            }
        )

        summary = summarize_trivy_report(report)

        self.assertEqual(3, summary["vulnerabilities"]["total"])
        self.assertEqual(1, summary["vulnerabilities"]["fixable"])
        self.assertEqual(2, summary["vulnerabilities"]["unfixed"])
        self.assertEqual({"CRITICAL": 1, "HIGH": 2}, summary["vulnerabilities"]["by_severity"])
        self.assertEqual(1, summary["misconfigurations"])
        self.assertEqual(1, summary["secrets"])
        self.assertNotIn("CVE-2026", json.dumps(summary))
        self.assertNotIn("sensitive title", json.dumps(summary))

    def test_cli_writes_signal_policy_and_github_summary(self) -> None:
        report = self._report(
            {
                "Results": [
                    {
                        "Vulnerabilities": [
                            {"Severity": "HIGH", "FixedVersion": ""},
                        ]
                    }
                ]
            }
        )
        output = self.root / "summary.json"
        github_summary = self.root / "step-summary.md"

        code = main(
            [
                "--report",
                str(report),
                "--output",
                str(output),
                "--github-summary",
                str(github_summary),
            ]
        )

        self.assertEqual(0, code)
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual("signal-only", payload["policy"]["unfixed_vulnerabilities"])
        markdown = github_summary.read_text(encoding="utf-8")
        self.assertIn("Vulnerabilities without a fix | 1 | Signal only", markdown)

    def test_rejects_malformed_result_shapes(self) -> None:
        report = self._report({"Results": {"unexpected": True}})
        with self.assertRaisesRegex(TrivyReportError, "Results must be an array"):
            summarize_trivy_report(report)


if __name__ == "__main__":
    unittest.main()
