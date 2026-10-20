from __future__ import annotations

import unittest

from scripts.ci.classify_actions_failure import classify_evidence


def evidence(*, conclusion: str, jobs: list[dict], annotations: list[dict]) -> dict:
    return {
        "run": {"id": 123, "conclusion": conclusion},
        "jobs": jobs,
        "annotations": annotations,
    }


class ActionsFailureClassificationTests(unittest.TestCase):
    def test_billing_annotation_is_external_and_not_a_code_failure(self) -> None:
        result = classify_evidence(
            evidence(
                conclusion="failure",
                jobs=[
                    {
                        "id": 456,
                        "runner_id": 0,
                        "runner_name": "",
                        "labels": ["ubuntu-latest"],
                        "steps": [],
                        "conclusion": "failure",
                    }
                ],
                annotations=[
                    {
                        "message": (
                            "The job was not started because recent account payments have failed "
                            "or your spending limit needs to be increased."
                        )
                    }
                ],
            )
        )

        self.assertEqual("hosted_billing_blocked", result["classification"])
        self.assertFalse(result["is_code_failure"])
        self.assertFalse(result["promotion_allowed"])
        self.assertEqual(1, result["evidence"]["prestart_jobs"])
        self.assertIn("billing", result["reason"])

    def test_zero_runner_without_billing_is_runner_unavailable(self) -> None:
        result = classify_evidence(
            evidence(
                conclusion="failure",
                jobs=[
                    {
                        "id": 456,
                        "runner_id": 0,
                        "runner_name": "",
                        "labels": ["self-hosted", "Linux", "serve"],
                        "steps": [],
                        "conclusion": "failure",
                    }
                ],
                annotations=[],
            )
        )

        self.assertEqual("runner_unavailable", result["classification"])
        self.assertFalse(result["is_code_failure"])
        self.assertFalse(result["promotion_allowed"])

    def test_infrastructure_signal_can_never_be_passed(self) -> None:
        result = classify_evidence(
            evidence(
                conclusion="success",
                jobs=[
                    {
                        "id": 456,
                        "runner_id": 321,
                        "runner_name": "runner-1",
                        "labels": ["self-hosted", "Linux", "serve"],
                        "steps": [],
                        "conclusion": "success",
                    }
                ],
                annotations=[],
            )
        )

        self.assertEqual("runner_unavailable", result["classification"])
        self.assertFalse(result["promotion_allowed"])

    def test_started_failed_job_is_a_code_or_gate_failure(self) -> None:
        result = classify_evidence(
            evidence(
                conclusion="failure",
                jobs=[
                    {
                        "id": 456,
                        "runner_id": 987,
                        "runner_name": "serve-1",
                        "labels": ["self-hosted", "Linux", "serve"],
                        "steps": [{"name": "Run tests", "conclusion": "failure"}],
                        "conclusion": "failure",
                    }
                ],
                annotations=[],
            )
        )

        self.assertEqual("code_or_gate_failure", result["classification"])
        self.assertTrue(result["is_code_failure"])
        self.assertFalse(result["promotion_allowed"])
        self.assertEqual(1, result["evidence"]["started_jobs"])

    def test_success_is_reported_as_passed(self) -> None:
        result = classify_evidence(
            evidence(
                conclusion="success",
                jobs=[
                    {
                        "id": 456,
                        "runner_id": 987,
                        "runner_name": "serve-1",
                        "labels": ["self-hosted", "Linux", "serve"],
                        "steps": [{"name": "Run tests", "conclusion": "success"}],
                        "conclusion": "success",
                    }
                ],
                annotations=[],
            )
        )

        self.assertEqual("passed", result["classification"])
        self.assertFalse(result["is_code_failure"])
        self.assertTrue(result["promotion_allowed"])

    def test_missing_job_evidence_is_inconclusive(self) -> None:
        result = classify_evidence(
            {"run": {"id": 123, "conclusion": "failure"}, "jobs": [], "annotations": []}
        )

        self.assertEqual("inconclusive", result["classification"])
        self.assertFalse(result["is_code_failure"])
        self.assertFalse(result["promotion_allowed"])
        self.assertIn("job", result["reason"])

    def test_conflicting_started_job_and_billing_annotation_is_inconclusive(self) -> None:
        result = classify_evidence(
            evidence(
                conclusion="failure",
                jobs=[
                    {
                        "id": 456,
                        "runner_id": 987,
                        "runner_name": "serve-1",
                        "labels": ["self-hosted", "Linux", "serve"],
                        "steps": [{"name": "Run tests", "conclusion": "failure"}],
                        "conclusion": "failure",
                    }
                ],
                annotations=[{"message": "recent account payments have failed"}],
            )
        )

        self.assertEqual("inconclusive", result["classification"])
        self.assertFalse(result["is_code_failure"])
        self.assertFalse(result["promotion_allowed"])

    def test_missing_runner_fields_are_inconclusive_and_block_promotion(self) -> None:
        result = classify_evidence(
            evidence(
                conclusion="success",
                jobs=[
                    {
                        "id": 456,
                        "steps": [{"name": "Run tests", "conclusion": "success"}],
                        "conclusion": "success",
                    }
                ],
                annotations=[],
            )
        )

        self.assertEqual("inconclusive", result["classification"])
        self.assertFalse(result["promotion_allowed"])

    def test_command_exit_code_is_nonzero_for_inconclusive(self) -> None:
        from unittest.mock import patch

        with patch(
            "scripts.ci.classify_actions_failure._load_payload",
            return_value={"run": {"id": 123, "conclusion": "failure"}, "jobs": [], "annotations": []},
        ), patch("builtins.print"):
            from scripts.ci.classify_actions_failure import main

            self.assertNotEqual(0, main([]))

    def test_skipped_job_without_runner_is_inconclusive(self) -> None:
        result = classify_evidence(
            evidence(
                conclusion="failure",
                jobs=[
                    {"id": 1, "runner_id": None, "steps": [], "conclusion": "skipped"},
                    {
                        "id": 2,
                        "runner_id": 987,
                        "steps": [{"name": "Run tests", "conclusion": "failure"}],
                        "conclusion": "failure",
                    },
                ],
                annotations=[],
            )
        )

        self.assertEqual("inconclusive", result["classification"])
        self.assertFalse(result["is_code_failure"])
        self.assertFalse(result["promotion_allowed"])

    def test_in_progress_run_never_allows_promotion(self) -> None:
        result = classify_evidence(
            evidence(
                conclusion=None,
                jobs=[
                    {
                        "id": 456,
                        "runner_id": 987,
                        "steps": [{"name": "Run tests", "conclusion": None}],
                        "conclusion": None,
                        "status": "in_progress",
                    }
                ],
                annotations=[],
            )
        )

        self.assertEqual("inconclusive", result["classification"])
        self.assertFalse(result["promotion_allowed"])

    def test_cli_reads_evidence_file_and_maps_exit_codes(self) -> None:
        import contextlib
        import io
        import json
        import tempfile
        from pathlib import Path

        from scripts.ci.classify_actions_failure import main

        passed = evidence(
            conclusion="success",
            jobs=[
                {
                    "id": 456,
                    "runner_id": 987,
                    "steps": [{"name": "Run tests", "conclusion": "success"}],
                    "conclusion": "success",
                }
            ],
            annotations=[],
        )
        blocked = evidence(
            conclusion="failure",
            jobs=[{"id": 456, "runner_id": 0, "steps": [], "conclusion": "failure"}],
            annotations=[{"message": "Your spending limit needs to be increased"}],
        )
        with tempfile.TemporaryDirectory() as tmp:
            for name, payload, code, expected in (
                ("passed.json", passed, 0, "passed"),
                ("blocked.json", blocked, 1, "hosted_billing_blocked"),
            ):
                path = Path(tmp) / name
                path.write_text(json.dumps(payload), encoding="utf-8")
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(code, main(["--evidence", str(path)]))
                self.assertEqual(expected, json.loads(out.getvalue())["classification"])


if __name__ == "__main__":
    unittest.main()
