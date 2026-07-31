from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validation_attestation/attestation.py"


class ValidationAttestationTests(unittest.TestCase):
    def run_script(self, *, candidate="a" * 40, context_sha="a" * 40, results=None):
        results = results or {
            "repository_validation": "success",
            "security_suite": "success",
        }
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "attestation.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--repository", "optimizr-tech/example",
                    "--candidate-sha", candidate,
                    "--context-sha", context_sha,
                    "--validation-path", "hosted",
                    "--required-checks-json", '["repository_validation","security_suite"]',
                    "--results-json", json.dumps(results),
                    "--workflow-repository", "optimizr-tech/optimizr-actions",
                    "--workflow-ref", "optimizr-tech/optimizr-actions/.github/workflows/_validation-gate.yml@v1",
                    "--workflow-sha", "b" * 40,
                    "--run-id", "123",
                    "--evidence", str(evidence),
                ],
                text=True,
                capture_output=True,
            )
            payload = json.loads(evidence.read_text()) if evidence.exists() else None
            return completed, payload

    def test_passed_checks_create_commit_bound_digest(self):
        completed, payload = self.run_script()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["result"], "passed")
        self.assertEqual(payload["validated_sha"], "a" * 40)
        self.assertEqual(payload["actions_workflow_sha"], "b" * 40)
        self.assertRegex(payload["evidence_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_skipped_required_check_fails_closed(self):
        completed, payload = self.run_script(
            results={
                "repository_validation": "success",
                "security_suite": "skipped",
            }
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(payload["result"], "failed")
        self.assertIn("security_suite", payload["blocking_checks"])

    def test_candidate_must_match_caller_context_sha(self):
        completed, payload = self.run_script(
            candidate="a" * 40,
            context_sha="c" * 40,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIsNone(payload)
        self.assertIn("candidate SHA must equal caller context SHA", completed.stderr)


if __name__ == "__main__":
    unittest.main()
