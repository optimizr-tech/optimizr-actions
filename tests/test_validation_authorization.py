from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validation_authorization/authorize.py"


class ValidationAuthorizationTests(unittest.TestCase):
    def run_script(
        self,
        *,
        gate_job_result="success",
        gate_result="passed",
        validated_sha="a" * 40,
        candidate_sha="a" * 40,
        evidence_digest="sha256:" + "b" * 64,
        actions_workflow_sha="c" * 40,
        validation_path="hosted",
        candidate_ref="refs/heads/main",
        required_ref="refs/heads/main",
        allowed_paths_json='["hosted","self-hosted","reviewed-emergency"]',
    ):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "github-output.txt"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--gate-job-result",
                    gate_job_result,
                    "--gate-result",
                    gate_result,
                    "--validated-sha",
                    validated_sha,
                    "--candidate-sha",
                    candidate_sha,
                    "--evidence-digest",
                    evidence_digest,
                    "--actions-workflow-sha",
                    actions_workflow_sha,
                    "--validation-path",
                    validation_path,
                    "--candidate-ref",
                    candidate_ref,
                    "--required-ref",
                    required_ref,
                    "--allowed-paths-json",
                    allowed_paths_json,
                    "--github-output",
                    str(output),
                ],
                text=True,
                capture_output=True,
            )
            output_text = output.read_text(encoding="utf-8") if output.exists() else ""
            return completed, output_text

    def test_complete_canonical_attestation_is_authorized(self):
        completed, output = self.run_script()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("result=authorized\n", output)
        self.assertIn(f"validated_sha={'a' * 40}\n", output)
        self.assertIn(f"evidence_digest=sha256:{'b' * 64}\n", output)
        self.assertIn(f"actions_workflow_sha={'c' * 40}\n", output)
        self.assertIn("validation_path=hosted\n", output)

    def test_skipped_gate_job_is_not_authorized(self):
        completed, output = self.run_script(gate_job_result="skipped")
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(output, "")
        self.assertIn("gate job must succeed", completed.stderr)

    def test_non_passed_gate_result_is_not_authorized(self):
        completed, output = self.run_script(gate_result="failed")
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(output, "")
        self.assertIn("gate result must be passed", completed.stderr)

    def test_validated_sha_must_equal_candidate(self):
        completed, output = self.run_script(candidate_sha="d" * 40)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(output, "")
        self.assertIn("validated SHA must equal candidate SHA", completed.stderr)

    def test_digest_requires_canonical_sha256_prefix(self):
        completed, output = self.run_script(evidence_digest="b" * 64)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(output, "")
        self.assertIn("sha256:<64 lowercase hex>", completed.stderr)

    def test_unknown_validation_path_is_not_authorized(self):
        completed, output = self.run_script(validation_path="local")
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(output, "")
        self.assertIn("validation path is not allowed", completed.stderr)

    def test_candidate_ref_must_match_protected_ref(self):
        completed, output = self.run_script(candidate_ref="refs/heads/dev")
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(output, "")
        self.assertIn("candidate ref must equal required ref", completed.stderr)

    def test_allowed_paths_must_be_unique_non_empty_string_array(self):
        completed, output = self.run_script(allowed_paths_json='["hosted","hosted"]')
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(output, "")
        self.assertIn("allowed paths must be unique", completed.stderr)


if __name__ == "__main__":
    unittest.main()
