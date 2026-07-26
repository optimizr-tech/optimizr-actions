from __future__ import annotations

import contextlib
import unittest
import io
from unittest import mock

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "security_retry_result",
    ROOT / ".github" / "actions" / "security-retry-result" / "retry_result.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
evaluate_retry = MODULE.evaluate_retry
IMAGE_A = "sha256:" + "a" * 64
IMAGE_B = "sha256:" + "b" * 64


class SecurityRetryResultTests(unittest.TestCase):
    def test_secret_findings_never_receive_ignore_unfixed_compatibility(self) -> None:
        result = evaluate_retry(
            initial_outcome="failure",
            initial_classification="secret_detected",
            rebuild_outcome="skipped",
            final_outcome="skipped",
            final_classification="",
            retry_enabled=True,
            initial_refs=IMAGE_A,
            remediated_refs="",
            initial_counts=(0, 0, 0, 1),
        )

        self.assertEqual("secret_detected", result["final_result"])
        self.assertFalse(result["passed"])
        self.assertFalse(result["compatibility_allowed"])

    def test_unfixed_only_findings_allow_narrow_ignore_unfixed_compatibility(self) -> None:
        result = evaluate_retry(
            initial_outcome="failure",
            initial_classification="unfixed_warning",
            rebuild_outcome="skipped",
            final_outcome="skipped",
            final_classification="",
            retry_enabled=True,
            initial_refs=IMAGE_A,
            remediated_refs="",
            initial_counts=(0, 3, 0, 0),
        )

        self.assertEqual("unfixed_warning", result["final_result"])
        self.assertFalse(result["passed"])
        self.assertTrue(result["compatibility_allowed"])

    def test_no_change_rebuild_allows_only_the_documented_compatibility_case(self) -> None:
        result = evaluate_retry(
            initial_outcome="failure",
            initial_classification="actionable_vulnerability",
            rebuild_outcome="success",
            final_outcome="failure",
            final_classification="actionable_vulnerability",
            retry_enabled=True,
            initial_refs=IMAGE_A,
            remediated_refs=IMAGE_A,
            initial_counts=(2, 0, 0, 0),
        )

        self.assertEqual("no_change", result["rebuild_result"])
        self.assertFalse(result["passed"])
        self.assertTrue(result["compatibility_allowed"])

    def test_failed_remediation_retry_never_receives_compatibility(self) -> None:
        result = evaluate_retry(
            initial_outcome="failure",
            initial_classification="actionable_vulnerability",
            rebuild_outcome="success",
            final_outcome="failure",
            final_classification="unfixed_warning",
            retry_enabled=True,
            initial_refs=IMAGE_A,
            remediated_refs=IMAGE_B,
            final_counts=(0, 2, 0, 0),
        )

        self.assertEqual("failed", result["rebuild_result"])
        self.assertFalse(result["compatibility_allowed"])

    def test_identical_immutable_ids_are_no_change_and_fail_closed(self) -> None:
        result = evaluate_retry(
            initial_outcome="failure",
            initial_classification="actionable_vulnerability",
            rebuild_outcome="success",
            final_outcome="failure",
            final_classification="actionable_vulnerability",
            retry_enabled=True,
            initial_refs=f"{IMAGE_A}\n{IMAGE_B}",
            remediated_refs=f"{IMAGE_B}\n{IMAGE_A}",
        )

        self.assertEqual("actionable_vulnerability", result["initial_result"])
        self.assertTrue(result["rebuild_attempted"])
        self.assertEqual("no_change", result["rebuild_result"])
        self.assertEqual("actionable_vulnerability", result["final_result"])
        self.assertFalse(result["passed"])

    def test_changed_ids_and_clean_final_scan_pass(self) -> None:
        result = evaluate_retry(
            initial_outcome="failure",
            initial_classification="actionable_vulnerability",
            rebuild_outcome="success",
            final_outcome="success",
            final_classification="clean",
            retry_enabled=True,
            initial_refs=IMAGE_A,
            remediated_refs=IMAGE_B,
        )

        self.assertEqual("passed", result["rebuild_result"])
        self.assertEqual("clean", result["final_result"])
        self.assertTrue(result["passed"])

    def test_changed_ids_with_remaining_findings_are_not_remediation_success(self) -> None:
        result = evaluate_retry(
            initial_outcome="failure",
            initial_classification="actionable_vulnerability",
            rebuild_outcome="success",
            final_outcome="failure",
            final_classification="actionable_vulnerability",
            retry_enabled=True,
            initial_refs=IMAGE_A,
            remediated_refs=IMAGE_B,
        )

        self.assertEqual("failed", result["rebuild_result"])
        self.assertEqual("actionable_vulnerability", result["final_result"])
        self.assertFalse(result["passed"])

    def test_initial_success_accepts_only_passing_classifications(self) -> None:
        for classification in ("clean", "unfixed_warning"):
            with self.subTest(classification=classification):
                result = evaluate_retry(
                    initial_outcome="success",
                    initial_classification=classification,
                    rebuild_outcome="skipped",
                    final_outcome="skipped",
                    final_classification="",
                    retry_enabled=True,
                    initial_refs=IMAGE_A,
                    remediated_refs="",
                )

                self.assertEqual("skipped", result["rebuild_result"])
                self.assertFalse(result["rebuild_attempted"])
                self.assertEqual(classification, result["final_result"])
                self.assertTrue(result["passed"])

    def test_malformed_immutable_ids_fail_closed(self) -> None:
        for initial_refs, remediated_refs in (
            ("sha256:short", IMAGE_B),
            (IMAGE_A, "not-a-digest"),
            ("sha512:" + "a" * 64, IMAGE_B),
            (IMAGE_A, "sha256:" + "g" * 64),
        ):
            with self.subTest(
                initial_refs=initial_refs,
                remediated_refs=remediated_refs,
            ):
                result = evaluate_retry(
                    initial_outcome="failure",
                    initial_classification="actionable_vulnerability",
                    rebuild_outcome="success",
                    final_outcome="success",
                    final_classification="clean",
                    retry_enabled=True,
                    initial_refs=initial_refs,
                    remediated_refs=remediated_refs,
                )

                self.assertEqual("failed", result["rebuild_result"])
                self.assertEqual("scanner_error", result["final_result"])
                self.assertFalse(result["passed"])

    def test_initial_success_requires_a_passing_classification(self) -> None:
        for classification in (
            "",
            "gate_error",
            "scanner_error",
            "misconfiguration_detected",
            "secret_detected",
            "actionable_vulnerability",
        ):
            with self.subTest(classification=classification):
                result = evaluate_retry(
                    initial_outcome="success",
                    initial_classification=classification,
                    rebuild_outcome="skipped",
                    final_outcome="skipped",
                    final_classification="",
                    retry_enabled=True,
                    initial_refs=IMAGE_A,
                    remediated_refs="",
                )

                self.assertEqual("scanner_error", result["final_result"])
                self.assertEqual("skipped", result["rebuild_result"])
                self.assertFalse(result["passed"])

    def test_no_change_preserves_initial_diagnostic_counts(self) -> None:
        result = evaluate_retry(
            initial_outcome="failure",
            initial_classification="actionable_vulnerability",
            rebuild_outcome="success",
            final_outcome="failure",
            final_classification="actionable_vulnerability",
            retry_enabled=True,
            initial_refs=IMAGE_A,
            remediated_refs=IMAGE_A,
            initial_counts=(12, 3, 0, 0),
            final_counts=(8, 2, 0, 0),
        )

        self.assertEqual(12, result["fixable_vulnerability_count"])
        self.assertEqual(3, result["unfixed_vulnerability_count"])

    def test_cli_emits_no_change_evidence_before_failing_closed(self) -> None:
        environment = {
            "INITIAL_OUTCOME": "failure",
            "INITIAL_CLASSIFICATION": "actionable_vulnerability",
            "REBUILD_OUTCOME": "success",
            "FINAL_OUTCOME": "failure",
            "FINAL_CLASSIFICATION": "actionable_vulnerability",
            "RETRY_ENABLED": "true",
            "INITIAL_REFS": IMAGE_A,
            "REMEDIATED_REFS": IMAGE_A,
            "INITIAL_FIXABLE_VULNERABILITY_COUNT": "12",
            "INITIAL_UNFIXED_VULNERABILITY_COUNT": "3",
        }
        output = io.StringIO()

        with mock.patch.dict("os.environ", environment, clear=True), contextlib.redirect_stdout(output):
            exit_code = MODULE.main()

        self.assertEqual(0, exit_code)
        self.assertIn("rebuild_result=no_change", output.getvalue())
        self.assertIn("passed=false", output.getvalue())
        self.assertIn("compatibility_allowed=true", output.getvalue())
        self.assertIn("fixable_vulnerability_count=12", output.getvalue())
        self.assertIn("unfixed_vulnerability_count=3", output.getvalue())


    def test_skipped_initial_scan_fails_closed_with_explicit_outputs(self) -> None:
        result = evaluate_retry(
            initial_outcome="skipped",
            initial_classification="",
            rebuild_outcome="skipped",
            final_outcome="skipped",
            final_classification="",
            retry_enabled=True,
            initial_refs="",
            remediated_refs="",
        )

        self.assertEqual("scanner_error", result["initial_result"])
        self.assertEqual("scanner_error", result["final_result"])
        self.assertEqual("skipped", result["rebuild_result"])
        self.assertFalse(result["passed"])
        self.assertFalse(result["compatibility_allowed"])

    def test_empty_initial_classification_fails_closed(self) -> None:
        result = evaluate_retry(
            initial_outcome="failure",
            initial_classification="",
            rebuild_outcome="skipped",
            final_outcome="skipped",
            final_classification="",
            retry_enabled=True,
            initial_refs=IMAGE_A,
            remediated_refs="",
        )

        self.assertEqual("scanner_error", result["final_result"])
        self.assertFalse(result["passed"])
        self.assertFalse(result["compatibility_allowed"])

    def test_scanner_error_is_explicit_and_fail_closed(self) -> None:
        result = evaluate_retry(
            initial_outcome="failure",
            initial_classification="scanner_error",
            rebuild_outcome="skipped",
            final_outcome="skipped",
            final_classification="",
            retry_enabled=True,
            initial_refs=IMAGE_A,
            remediated_refs="",
        )

        self.assertEqual("scanner_error", result["final_result"])
        self.assertEqual("skipped", result["rebuild_result"])
        self.assertFalse(result["passed"])

    def test_disabled_retry_preserves_actionable_counts_and_references(self) -> None:
        result = evaluate_retry(
            initial_outcome="failure",
            initial_classification="actionable_vulnerability",
            rebuild_outcome="skipped",
            final_outcome="skipped",
            final_classification="",
            retry_enabled=False,
            initial_refs=IMAGE_A,
            remediated_refs="",
            initial_counts=(4, 2, 0, 0),
        )

        self.assertEqual("actionable_vulnerability", result["final_result"])
        self.assertEqual("skipped", result["rebuild_result"])
        self.assertEqual(4, result["fixable_vulnerability_count"])
        self.assertEqual(2, result["unfixed_vulnerability_count"])
        self.assertFalse(result["passed"])

    def test_cli_always_publishes_the_complete_output_contract(self) -> None:
        environment = {
            "INITIAL_OUTCOME": "skipped",
            "INITIAL_CLASSIFICATION": "",
            "REBUILD_OUTCOME": "skipped",
            "FINAL_OUTCOME": "skipped",
            "FINAL_CLASSIFICATION": "",
            "RETRY_ENABLED": "true",
            "INITIAL_REFS": "",
            "REMEDIATED_REFS": "",
        }
        output = io.StringIO()

        with mock.patch.dict("os.environ", environment, clear=True), contextlib.redirect_stdout(output):
            exit_code = MODULE.main()

        published = dict(line.split("=", 1) for line in output.getvalue().splitlines())
        self.assertEqual(0, exit_code)
        self.assertEqual(
            {
                "initial_result",
                "rebuild_attempted",
                "rebuild_result",
                "final_result",
                "passed",
                "compatibility_allowed",
                "fixable_vulnerability_count",
                "unfixed_vulnerability_count",
                "misconfiguration_count",
                "secret_count",
            },
            set(published),
        )
        self.assertEqual("scanner_error", published["final_result"])
        self.assertEqual("false", published["passed"])
        self.assertEqual("false", published["compatibility_allowed"])


if __name__ == "__main__":
    unittest.main()
