"""Regression coverage for the pinned actionlint JSON diagnostic contract."""

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from static_lint.runner import (
    effective_actionlint_exit_code,
    filter_actionlint_queue_errors,
)


class ActionlintJsonDiagnosticsTests(unittest.TestCase):
    def diagnostic(self, **changes):
        diagnostic = {
            "message": (
                'unexpected key "queue" for "concurrency" section. '
                'expected one of "cancel-in-progress", "group"'
            ),
            "filepath": ".github/workflows/ci.yml",
            "line": 5,
            "column": 3,
            "kind": "syntax-check",
            "snippet": "  queue: max\n  ^~~~~",
            "end_column": 8,
        }
        diagnostic.update(changes)
        return diagnostic

    def filter(self, *diagnostics, locations=None):
        output = "".join(json.dumps(item) + "\n" for item in diagnostics)
        return filter_actionlint_queue_errors(
            output,
            locations if locations is not None else {".github/workflows/ci.yml": {(5, 3)}},
        )

    def test_accepts_real_actionlint_json_only_at_a_validated_queue_key(self):
        filtered, accepted, parseable = self.filter(self.diagnostic())

        self.assertEqual((filtered, accepted, parseable), ("", 1, True))
        self.assertEqual(effective_actionlint_exit_code(1, filtered, accepted, parseable), 0)

    def test_keeps_unrelated_diagnostics_with_their_original_json(self):
        unrelated = self.diagnostic(message='unexpected key "unknown" for "jobs" section')

        filtered, accepted, parseable = self.filter(self.diagnostic(), unrelated)

        self.assertEqual(filtered, json.dumps(unrelated) + "\n")
        self.assertEqual((accepted, parseable), (1, True))
        self.assertEqual(effective_actionlint_exit_code(1, filtered, accepted, parseable), 1)

    def test_never_accepts_a_different_location_kind_or_message(self):
        changes = (
            {"line": 6},
            {"column": 4},
            {"filepath": ".github/workflows/other.yml"},
            {"kind": "expression"},
            {"message": self.diagnostic()["message"] + ". additional failure"},
            {"message": 'unexpected key "queue" for "concurrency" section'},
        )
        for change in changes:
            with self.subTest(change=change):
                diagnostic = self.diagnostic(**change)
                filtered, accepted, parseable = self.filter(diagnostic)
                self.assertEqual(filtered, json.dumps(diagnostic) + "\n")
                self.assertEqual((accepted, parseable), (0, True))

    def test_normalizes_relative_workflow_paths_without_accepting_other_files(self):
        for filepath in ("./.github/workflows/ci.yml", ".github\\workflows\\ci.yml"):
            with self.subTest(filepath=filepath):
                self.assertEqual(self.filter(self.diagnostic(filepath=filepath)), ("", 1, True))

    def test_invalid_queue_without_validated_locations_remains_blocking(self):
        diagnostic = self.diagnostic()

        filtered, accepted, parseable = self.filter(diagnostic, locations={})

        self.assertEqual(filtered, json.dumps(diagnostic) + "\n")
        self.assertEqual((accepted, parseable), (0, True))
        self.assertEqual(effective_actionlint_exit_code(1, filtered, accepted, parseable), 1)

    def test_unknown_schema_and_non_integer_positions_fail_closed(self):
        lower_case = self.diagnostic()
        upper_case = {key[:1].upper() + key[1:]: value for key, value in lower_case.items()}
        diagnostics = (
            upper_case,
            self.diagnostic(line=True),
            self.diagnostic(column="3"),
            self.diagnostic(filepath=None),
            self.diagnostic(message=None),
            self.diagnostic(kind=None),
        )

        for diagnostic in diagnostics:
            with self.subTest(diagnostic=diagnostic):
                filtered, accepted, parseable = self.filter(diagnostic)
                self.assertEqual(filtered, json.dumps(diagnostic) + "\n")
                self.assertEqual((accepted, parseable), (0, False))
                self.assertEqual(effective_actionlint_exit_code(1, filtered, accepted, parseable), 1)

    def test_fatal_actionlint_exit_cannot_be_downgraded(self):
        filtered, accepted, parseable = self.filter(self.diagnostic())

        self.assertEqual(effective_actionlint_exit_code(2, filtered, accepted, parseable), 2)

    def test_unrelated_json_diagnostic_blocks_even_when_tool_reports_success(self):
        filtered, accepted, parseable = self.filter(self.diagnostic(kind="expression"))

        self.assertEqual(effective_actionlint_exit_code(0, filtered, accepted, parseable), 1)


if __name__ == "__main__":
    unittest.main()
