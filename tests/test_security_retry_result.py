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


class SecurityRetryResultTests(unittest.TestCase):
    def test_identical_immutable_ids_are_no_change_and_fail_closed(self) -> None:
        result = evaluate_retry(
            initial_outcome="failure",
            initial_classification="actionable_vulnerability",
            rebuild_outcome="success",
            final_outcome="failure",
            final_classification="actionable_vulnerability",
            retry_enabled=True,
            initial_refs="sha256:one\nsha256:two",
            remediated_refs="sha256:two\nsha256:one",
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
            initial_refs="sha256:old",
            remediated_refs="sha256:new",
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
            initial_refs="sha256:old",
            remediated_refs="sha256:new",
        )

        self.assertEqual("failed", result["rebuild_result"])
        self.assertEqual("actionable_vulnerability", result["final_result"])
        self.assertFalse(result["passed"])

    def test_initial_success_skips_the_retry(self) -> None:
        result = evaluate_retry(
            initial_outcome="success",
            initial_classification="clean",
            rebuild_outcome="skipped",
            final_outcome="skipped",
            final_classification="",
            retry_enabled=True,
            initial_refs="sha256:one",
            remediated_refs="",
        )

        self.assertEqual("skipped", result["rebuild_result"])
        self.assertFalse(result["rebuild_attempted"])
        self.assertTrue(result["passed"])

    def test_cli_emits_no_change_evidence_before_failing_closed(self) -> None:
        environment = {
            "INITIAL_OUTCOME": "failure",
            "INITIAL_CLASSIFICATION": "actionable_vulnerability",
            "REBUILD_OUTCOME": "success",
            "FINAL_OUTCOME": "failure",
            "FINAL_CLASSIFICATION": "actionable_vulnerability",
            "RETRY_ENABLED": "true",
            "INITIAL_REFS": "sha256:unchanged",
            "REMEDIATED_REFS": "sha256:unchanged",
        }
        output = io.StringIO()

        with mock.patch.dict("os.environ", environment, clear=True), contextlib.redirect_stdout(output):
            exit_code = MODULE.main()

        self.assertEqual(1, exit_code)
        self.assertIn("rebuild_result=no_change", output.getvalue())
        self.assertIn("passed=false", output.getvalue())


if __name__ == "__main__":
    unittest.main()
