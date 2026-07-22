"""Behavioral tests for reviewed vulnerability baselines."""

from __future__ import annotations

from datetime import date
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "security_gate" / "baseline.py"
spec = importlib.util.spec_from_file_location("security_gate_baseline", MODULE_PATH)
assert spec and spec.loader
baseline_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline_module)


class SecurityBaselineTests(unittest.TestCase):
    def _report(self, directory: Path, vulnerabilities: list[dict[str, str]]) -> Path:
        path = directory / "report.json"
        path.write_text(
            json.dumps(
                {
                    "Results": [
                        {
                            "Target": "debian",
                            "Class": "os-pkgs",
                            "Type": "debian",
                            "Vulnerabilities": vulnerabilities,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return path

    def _baseline(self, directory: Path, findings: list[dict[str, str]], expires: str) -> Path:
        path = directory / "baseline.json"
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "owner": "optimizr-tech/security",
                    "reviewed_at": "2026-07-22",
                    "expires": expires,
                    "statement": "Reviewed upstream runtime baseline",
                    "compensating_control": "Private network and authenticated access",
                    "findings": findings,
                }
            ),
            encoding="utf-8",
        )
        return path

    def _finding(self, vulnerability_id: str, fixed_version: str = "1.2.4") -> dict[str, str]:
        return {
            "VulnerabilityID": vulnerability_id,
            "PkgName": "libexample",
            "InstalledVersion": "1.2.3",
            "FixedVersion": fixed_version,
            "Severity": "HIGH",
        }

    def _baseline_finding(self, vulnerability_id: str, fixed_version: str = "1.2.4") -> dict[str, str]:
        return {
            "target": "debian",
            "id": vulnerability_id,
            "package": "libexample",
            "installed_version": "1.2.3",
            "fixed_version": fixed_version,
        }

    def test_reviewed_finding_is_removed_from_enforcement_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = self._report(directory, [self._finding("CVE-2026-0001")])
            baseline = self._baseline(
                directory,
                [self._baseline_finding("CVE-2026-0001")],
                "2026-08-22",
            )
            output = directory / "enforced.json"
            summary = directory / "baseline-summary.json"
            result = baseline_module.apply_baseline(
                report,
                baseline,
                output,
                summary,
                today=date(2026, 7, 22),
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result["matched"], 1)
        self.assertEqual(result["remaining"], 0)
        self.assertEqual(payload["Results"][0]["Vulnerabilities"], [])

    def test_new_finding_remains_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = self._report(
                directory,
                [self._finding("CVE-2026-0001"), self._finding("CVE-2026-0002")],
            )
            baseline = self._baseline(
                directory,
                [self._baseline_finding("CVE-2026-0001")],
                "2026-08-22",
            )
            output = directory / "enforced.json"
            summary = directory / "baseline-summary.json"
            result = baseline_module.apply_baseline(
                report,
                baseline,
                output,
                summary,
                today=date(2026, 7, 22),
            )
        self.assertEqual(result["matched"], 1)
        self.assertEqual(result["remaining"], 1)

    def test_expired_baseline_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = self._report(directory, [self._finding("CVE-2026-0001")])
            baseline = self._baseline(
                directory,
                [self._baseline_finding("CVE-2026-0001")],
                "2026-07-21",
            )
            with self.assertRaisesRegex(ValueError, "expired"):
                baseline_module.apply_baseline(
                    report,
                    baseline,
                    directory / "enforced.json",
                    directory / "summary.json",
                    today=date(2026, 7, 22),
                )


if __name__ == "__main__":
    unittest.main()
