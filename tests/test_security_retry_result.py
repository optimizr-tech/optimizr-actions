from __future__ import annotations

import contextlib
import importlib.util
import io
import unittest
from pathlib import Path
from unittest import mock

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


def evaluate(**overrides: object) -> dict[str, object]:
    arguments: dict[str, object] = {
        "initial_outcome": "failure",
        "initial_classification": "actionable_vulnerability",
        "rebuild_outcome": "success",
        "final_outcome": "failure",
        "final_classification": "actionable_vulnerability",
        "retry_enabled": True,
        "initial_refs": IMAGE_A,
        "remediated_refs": IMAGE_A,
        "initial_counts": (1, 0, 0, 0),
        "final_counts": (0, 0, 0, 0),
    }
    arguments.update(overrides)
    return evaluate_retry(**arguments)


class SecurityRetryResultTests(unittest.TestCase):
    def test_only_unfixed_findings_receive_compatibility(self) -> None:
        allowed = evaluate(
            initial_classification="unfixed_warning",
            rebuild_outcome="skipped",
            final_outcome="skipped",
            final_classification="",
            remediated_refs="",
            initial_counts=(0, 3, 0, 0),
        )
        self.assertTrue(allowed["compatibility_allowed"])

        denied_cases = (
            {"initial_counts": (1, 0, 0, 0)},
            {"initial_counts": (1, 3, 0, 0)},
            {
                "initial_classification": "unfixed_warning",
                "rebuild_outcome": "skipped",
                "final_outcome": "skipped",
                "final_classification": "",
                "remediated_refs": "",
                "initial_counts": (0, 0, 0, 0),
            },
            {
                "initial_classification": "unfixed_warning",
                "rebuild_outcome": "skipped",
                "final_outcome": "skipped",
                "final_classification": "",
                "remediated_refs": "",
                "initial_counts": (0, 2, 1, 0),
            },
            {
                "initial_classification": "unfixed_warning",
                "rebuild_outcome": "skipped",
                "final_outcome": "skipped",
                "final_classification": "",
                "remediated_refs": "",
                "initial_counts": (0, 2, 0, 1),
            },
        )
        for case in denied_cases:
            with self.subTest(case=case):
                self.assertFalse(evaluate(**case)["compatibility_allowed"])

    def test_actionable_no_change_is_never_compatible(self) -> None:
        result = evaluate(initial_counts=(12, 3, 0, 0))
        self.assertEqual("no_change", result["rebuild_result"])
        self.assertEqual("actionable_vulnerability", result["final_result"])
        self.assertFalse(result["passed"])
        self.assertFalse(result["compatibility_allowed"])
        self.assertEqual(12, result["fixable_vulnerability_count"])
        self.assertEqual(3, result["unfixed_vulnerability_count"])

    def test_non_vulnerability_failures_never_receive_compatibility(self) -> None:
        cases = (
            ("secret_detected", (0, 0, 0, 1)),
            ("misconfiguration_detected", (0, 0, 1, 0)),
            ("scanner_error", (0, 0, 0, 0)),
            ("", (0, 0, 0, 0)),
        )
        for classification, counts in cases:
            with self.subTest(classification=classification):
                result = evaluate(
                    initial_classification=classification,
                    rebuild_outcome="skipped",
                    final_outcome="skipped",
                    final_classification="",
                    remediated_refs="",
                    initial_counts=counts,
                )
                self.assertFalse(result["passed"])
                self.assertFalse(result["compatibility_allowed"])

    def test_initial_success_accepts_only_clean_or_unfixed(self) -> None:
        for classification, counts in (
            ("clean", (0, 0, 0, 0)),
            ("unfixed_warning", (0, 2, 0, 0)),
        ):
            with self.subTest(classification=classification):
                result = evaluate(
                    initial_outcome="success",
                    initial_classification=classification,
                    rebuild_outcome="skipped",
                    final_outcome="skipped",
                    final_classification="",
                    remediated_refs="",
                    initial_counts=counts,
                )
                self.assertTrue(result["passed"])
                self.assertEqual(classification, result["final_result"])

        rejected = evaluate(
            initial_outcome="success",
            initial_classification="actionable_vulnerability",
            rebuild_outcome="skipped",
            final_outcome="skipped",
            final_classification="",
            remediated_refs="",
        )
        self.assertEqual("scanner_error", rejected["final_result"])
        self.assertFalse(rejected["passed"])

    def test_retry_outcomes_are_fail_closed_until_changed_images_pass(self) -> None:
        failed_rebuild = evaluate(rebuild_outcome="failure", remediated_refs="")
        self.assertEqual("failed", failed_rebuild["rebuild_result"])
        self.assertEqual("scanner_error", failed_rebuild["final_result"])

        disabled = evaluate(retry_enabled=False, rebuild_outcome="skipped", remediated_refs="")
        self.assertEqual("skipped", disabled["rebuild_result"])
        self.assertFalse(disabled["compatibility_allowed"])

        clean = evaluate(
            final_outcome="success",
            final_classification="clean",
            remediated_refs=IMAGE_B,
            final_counts=(0, 0, 0, 0),
        )
        self.assertEqual("passed", clean["rebuild_result"])
        self.assertTrue(clean["passed"])

        unfixed = evaluate(
            final_outcome="success",
            final_classification="unfixed_warning",
            remediated_refs=IMAGE_B,
            final_counts=(0, 2, 0, 0),
        )
        self.assertTrue(unfixed["passed"])

        actionable = evaluate(
            remediated_refs=IMAGE_B,
            final_counts=(1, 0, 0, 0),
        )
        self.assertEqual("failed", actionable["rebuild_result"])
        self.assertFalse(actionable["passed"])
        self.assertFalse(actionable["compatibility_allowed"])

    def test_immutable_image_identity_is_validated(self) -> None:
        reordered = evaluate(
            initial_refs=f"{IMAGE_A}\n{IMAGE_B}",
            remediated_refs=f"{IMAGE_B}\n{IMAGE_A}",
        )
        self.assertEqual("no_change", reordered["rebuild_result"])
        self.assertFalse(reordered["compatibility_allowed"])

        malformed_pairs = (
            ("sha256:short", IMAGE_B),
            (IMAGE_A, "not-a-digest"),
            ("sha512:" + "a" * 64, IMAGE_B),
            (IMAGE_A, "sha256:" + "g" * 64),
        )
        for initial_refs, remediated_refs in malformed_pairs:
            with self.subTest(initial_refs=initial_refs, remediated_refs=remediated_refs):
                result = evaluate(initial_refs=initial_refs, remediated_refs=remediated_refs)
                self.assertEqual("scanner_error", result["final_result"])
                self.assertFalse(result["passed"])

    def test_skipped_scan_publishes_complete_fail_closed_contract(self) -> None:
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
        self.assertEqual("false", published["compatibility_allowed"])

    def test_cli_distinguishes_unfixed_from_actionable_findings(self) -> None:
        cases = (
            (
                {
                    "INITIAL_OUTCOME": "failure",
                    "INITIAL_CLASSIFICATION": "unfixed_warning",
                    "REBUILD_OUTCOME": "skipped",
                    "FINAL_OUTCOME": "skipped",
                    "FINAL_CLASSIFICATION": "",
                    "RETRY_ENABLED": "true",
                    "INITIAL_REFS": IMAGE_A,
                    "REMEDIATED_REFS": "",
                    "INITIAL_UNFIXED_VULNERABILITY_COUNT": "3",
                },
                "true",
            ),
            (
                {
                    "INITIAL_OUTCOME": "failure",
                    "INITIAL_CLASSIFICATION": "actionable_vulnerability",
                    "REBUILD_OUTCOME": "success",
                    "FINAL_OUTCOME": "failure",
                    "FINAL_CLASSIFICATION": "actionable_vulnerability",
                    "RETRY_ENABLED": "true",
                    "INITIAL_REFS": IMAGE_A,
                    "REMEDIATED_REFS": IMAGE_A,
                    "INITIAL_FIXABLE_VULNERABILITY_COUNT": "12",
                },
                "false",
            ),
        )
        for environment, expected in cases:
            with self.subTest(expected=expected):
                output = io.StringIO()
                with mock.patch.dict("os.environ", environment, clear=True), contextlib.redirect_stdout(output):
                    self.assertEqual(0, MODULE.main())
                published = dict(line.split("=", 1) for line in output.getvalue().splitlines())
                self.assertEqual(expected, published["compatibility_allowed"])


if __name__ == "__main__":
    unittest.main()
