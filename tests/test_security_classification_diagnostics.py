"""Behavioral tests for explicit security-gate failure classifications."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
AGGREGATE_PATH = ROOT / "scripts" / "security_gate" / "aggregate.py"

spec = importlib.util.spec_from_file_location("security_gate_aggregate", AGGREGATE_PATH)
assert spec and spec.loader
aggregate_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aggregate_module)


class SecurityClassificationDiagnosticsTests(unittest.TestCase):
    def _summary(
        self,
        directory: Path,
        *,
        fixable: int = 0,
        unfixed: int = 0,
        misconfigurations: int = 0,
        secrets: int = 0,
    ) -> Path:
        path = directory / "summary.json"
        path.write_text(
            "{\n"
            '  "schema_version": 1,\n'
            f'  "vulnerabilities": {{"fixable": {fixable}, "unfixed": {unfixed}}},\n'
            f'  "misconfigurations": {misconfigurations},\n'
            f'  "secrets": {secrets}\n'
            "}\n",
            encoding="utf-8",
        )
        return path

    def test_misconfiguration_has_explicit_classification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = self._summary(Path(directory), misconfigurations=1)
            result = aggregate_module.aggregate_summaries([summary])
        self.assertEqual(result["classification"], "misconfiguration_detected")

    def test_secret_has_explicit_classification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = self._summary(Path(directory), secrets=1)
            result = aggregate_module.aggregate_summaries([summary])
        self.assertEqual(result["classification"], "secret_detected")

    def test_scanner_failure_is_not_reported_as_security_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = self._summary(Path(directory))
            result = aggregate_module.aggregate_summaries([summary], gate_error=True)
        self.assertEqual(result["classification"], "scanner_error")

    def test_actionable_vulnerability_remains_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = self._summary(Path(directory), fixable=2)
            result = aggregate_module.aggregate_summaries([summary])
        self.assertEqual(result["classification"], "actionable_vulnerability")


if __name__ == "__main__":
    unittest.main()
