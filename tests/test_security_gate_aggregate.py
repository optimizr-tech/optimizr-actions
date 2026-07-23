from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.security_gate.aggregate import AggregateError, aggregate_summaries, main


class SecurityGateAggregateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def _summary(
        self,
        name: str,
        *,
        fixable: int = 0,
        unfixed: int = 0,
        misconfigurations: int = 0,
        secrets: int = 0,
    ) -> Path:
        path = self.root / name
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "vulnerabilities": {
                        "total": fixable + unfixed,
                        "fixable": fixable,
                        "unfixed": unfixed,
                        "by_severity": {},
                    },
                    "misconfigurations": misconfigurations,
                    "secrets": secrets,
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_aggregates_actionable_counts(self) -> None:
        result = aggregate_summaries(
            [
                self._summary("one.json", fixable=2, unfixed=1),
                self._summary("two.json", unfixed=3),
            ]
        )

        self.assertEqual("actionable_vulnerability", result["classification"])
        self.assertEqual(2, result["fixable_vulnerability_count"])
        self.assertEqual(4, result["unfixed_vulnerability_count"])

    def test_misconfiguration_precedes_actionable_vulnerability(self) -> None:
        result = aggregate_summaries(
            [self._summary("one.json", fixable=1, misconfigurations=1)]
        )
        self.assertEqual("misconfiguration_detected", result["classification"])

    def test_secret_precedes_misconfiguration(self) -> None:
        result = aggregate_summaries(
            [self._summary("one.json", misconfigurations=1, secrets=1)]
        )
        self.assertEqual("secret_detected", result["classification"])

    def test_unfixed_only_is_warning(self) -> None:
        result = aggregate_summaries([self._summary("one.json", unfixed=2)])
        self.assertEqual("unfixed_warning", result["classification"])

    def test_clean_report_is_clean(self) -> None:
        result = aggregate_summaries([self._summary("one.json")])
        self.assertEqual("clean", result["classification"])

    def test_explicit_runtime_error_forces_scanner_error(self) -> None:
        result = aggregate_summaries(
            [self._summary("one.json", fixable=1)], gate_error=True
        )
        self.assertEqual("scanner_error", result["classification"])

    def test_cli_writes_outputs(self) -> None:
        summary = self._summary("one.json", fixable=1, unfixed=2)
        output = self.root / "github-output.txt"

        code = main(
            [
                "--summary",
                str(summary),
                "--github-output",
                str(output),
            ]
        )

        self.assertEqual(0, code)
        values = dict(
            line.split("=", 1)
            for line in output.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual("actionable_vulnerability", values["classification"])
        self.assertEqual("1", values["fixable_vulnerability_count"])
        self.assertEqual("2", values["unfixed_vulnerability_count"])

    def test_rejects_invalid_summary(self) -> None:
        with self.assertRaises(AggregateError):
            aggregate_summaries([])

        path = self.root / "bad.json"
        path.write_text('{"schema_version": 2}', encoding="utf-8")
        with self.assertRaises(AggregateError):
            aggregate_summaries([path])


if __name__ == "__main__":
    unittest.main()
