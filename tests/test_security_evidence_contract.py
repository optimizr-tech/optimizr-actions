import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.security_evidence import main

ROOT = Path(__file__).resolve().parents[1]


class SecurityEvidenceWorkflowContractTests(unittest.TestCase):
    def test_trivy_exposes_exact_sha_and_artifact_evidence(self) -> None:
        text = (ROOT / ".github/workflows/_trivy-scan.yml").read_text(encoding="utf-8")
        for output in (
            "result:",
            "conclusion:",
            "repository:",
            "run_id:",
            "run_attempt:",
            "producer_sha:",
            "producer_ref:",
            "source_sha:",
            "evidence_path:",
            "evidence_sha256:",
            "evidence_artifact_id:",
            "evidence_artifact_digest:",
        ):
            self.assertIn(output, text)
        self.assertIn("inputs.skip && 'skipped'", text)
        self.assertIn("ref: ${{ github.sha }}", text)
        self.assertIn("ref: ${{ job.workflow_sha }}", text)
        self.assertIn('git -C .optimizr-actions-source rev-parse HEAD', text)
        self.assertIn('test "$producer_source_sha" = "$PRODUCER_SHA"', text)
        self.assertIn("--expected-source-sha \"$EXPECTED_SOURCE_SHA\"", text)
        self.assertIn("artifacts/trivy-evidence/manifest.json", text)
        self.assertIn("id: upload", text)
        self.assertIn("steps.evidence.outputs.evidence_manifest_path != ''", text)
        self.assertIn("steps.upload.outputs.artifact-digest", text)
        self.assertIn("if-no-files-found: error", text)

    def test_actionlint_exception_is_narrowly_scoped_to_github_job_workflow_identity(self) -> None:
        config = (ROOT / ".github/actionlint.yaml").read_text(encoding="utf-8")
        expected = (
            'property "workflow_(repository|ref|sha|file_path)" '
            "is not defined in object type .+"
        )
        for workflow in ("_trivy-scan.yml", "_security-suite.yml"):
            scoped = config.split(f".github/workflows/{workflow}:", 1)[1].split(
                "  .github/workflows/", 1
            )[0]
            self.assertIn(expected, scoped)

    def test_suite_exposes_aggregate_evidence_without_removing_legacy_outputs(self) -> None:
        text = (ROOT / ".github/workflows/_security-suite.yml").read_text(encoding="utf-8")
        self.assertIn("value: ${{ jobs.summary.outputs.result }}", text)
        self.assertIn("value: ${{ jobs.summary.outputs.evidence_path }}", text)
        self.assertIn("value: ${{ jobs.summary.outputs.evidence_sha256 }}", text)
        self.assertIn("ref: ${{ github.sha }}", text)
        self.assertIn("ref: ${{ job.workflow_sha }}", text)
        self.assertIn('git -C .optimizr-actions-source rev-parse HEAD', text)
        self.assertIn('test "$producer_source_sha" = "$PRODUCER_SHA"', text)
        self.assertIn("scripts/security_evidence.py suite", text)
        self.assertIn("if: always()", text)
        self.assertIn("if: ${{ needs.profile.result == 'success' }}", text)
        self.assertIn("id: trust_failure_summary", text)
        self.assertIn('"source_checked": False', text)
        self.assertIn("artifacts/security-suite/manifest.json", text)
        self.assertIn("steps.trust_failure_summary.outputs.evidence_path != ''", text)
        self.assertIn("--evidence-path summary.json", text)
        self.assertIn("--manifest-artifact-path manifest.json", text)
        self.assertIn("steps.upload.outputs.artifact-digest", text)
        self.assertIn("if: always()", text)

    def test_every_security_suite_child_exposes_and_uploads_its_sha_bound_bundle(self) -> None:
        workflows = (
            "_static-lint.yml",
            "_security-gate.yml",
            "_dependency-policy.yml",
            "_sast-gate.yml",
            "_supply-chain-evidence.yml",
        )
        for workflow in workflows:
            with self.subTest(workflow=workflow):
                text = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
                self.assertIn("workflow_call:", text)
                self.assertIn("result:", text)
                self.assertIn("evidence_record:", text)
                self.assertIn("evidence_sha256:", text)
                self.assertIn("evidence_artifact_name:", text)
                self.assertIn("evidence_artifact_id:", text)
                self.assertIn("evidence_artifact_digest:", text)
                self.assertIn("ref: ${{ github.sha }}", text)
                self.assertIn("ref: ${{ job.workflow_sha }}", text)
                self.assertIn(
                    "uses: ./.optimizr-actions-source/.github/actions/security-evidence-bundle",
                    text,
                )
                self.assertIn("id: upload", text)
                self.assertIn("steps.upload.outputs.artifact-digest", text)

    def test_suite_passes_each_child_receipt_to_the_summary_generator(self) -> None:
        text = (ROOT / ".github/workflows/_security-suite.yml").read_text(encoding="utf-8")
        for child in (
            "STATIC_LINT",
            "FILESYSTEM_SECURITY",
            "DEPENDENCY_POLICY",
            "SAST",
            "SUPPLY_CHAIN",
        ):
            self.assertIn(f"{child}_RECORD_JSON:", text)
            self.assertIn(f"{child}_EVIDENCE_SHA256:", text)
            self.assertIn(f"{child}_ARTIFACT_ID:", text)
            self.assertIn(f"{child}_ARTIFACT_DIGEST:", text)
        self.assertIn("--child-evidence-json \"$child_evidence_json\"", text)

    def test_local_bundle_action_checks_both_checked_out_commits(self) -> None:
        text = (ROOT / ".github/actions/security-evidence-bundle/action.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('git -C "$producer_root" rev-parse HEAD', text)
        self.assertIn('git rev-parse HEAD', text)
        self.assertIn('test "$source_actual_sha" = "$EXPECTED_SOURCE_SHA"', text)
        self.assertIn("--expected-source-sha \"$EXPECTED_SOURCE_SHA\"", text)

    def test_missing_trivy_report_writes_failed_manifest_before_returning_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "artifact/manifest.json"
            output = root / "github-output"
            missing_report = root / "missing-report.txt"
            result = main(
                [
                    "trivy",
                    "--repository", "optimizr-tech/marketing-site",
                    "--run-id", "12345",
                    "--run-attempt", "2",
                    "--producer-repository", "optimizr-tech/optimizr-actions",
                    "--producer-ref", "refs/tags/v1",
                    "--producer-sha", "b" * 40,
                    "--producer-file", ".github/workflows/_trivy-scan.yml",
                    "--source-sha", "a" * 40,
                    "--expected-source-sha", "a" * 40,
                    "--artifact-name", "trivy-security-results",
                    "--evidence-path", "trivy-results.txt",
                    "--manifest-path", str(manifest),
                    "--github-output", str(output),
                    "--report-path", str(missing_report),
                    "--scan-type", "fs",
                    "--scan-outcome", "success",
                ]
            )

            self.assertEqual(result, 1)
            self.assertTrue(manifest.exists())
            self.assertIn('"result": "failed"', manifest.read_text(encoding="utf-8"))
            self.assertIn("result=failed", output.read_text(encoding="utf-8"))
            self.assertIn("report_present=false", output.read_text(encoding="utf-8"))

    def test_empty_trivy_report_is_missing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report = root / "empty-report.txt"
            report.write_bytes(b"")
            manifest = root / "artifact/manifest.json"
            output = root / "github-output"
            result = main(
                [
                    "trivy",
                    "--repository", "optimizr-tech/marketing-site",
                    "--run-id", "12345",
                    "--run-attempt", "2",
                    "--producer-repository", "optimizr-tech/optimizr-actions",
                    "--producer-ref", "refs/tags/v1",
                    "--producer-sha", "b" * 40,
                    "--producer-file", ".github/workflows/_trivy-scan.yml",
                    "--source-sha", "a" * 40,
                    "--expected-source-sha", "a" * 40,
                    "--artifact-name", "trivy-security-results",
                    "--evidence-path", "trivy-results.txt",
                    "--manifest-path", str(manifest),
                    "--github-output", str(output),
                    "--report-path", str(report),
                    "--scan-type", "fs",
                    "--scan-outcome", "success",
                ]
            )

            self.assertEqual(result, 1)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(payload["result"], "failed")
            self.assertFalse(payload["evidence_present"])
            self.assertIn("report_present=false", output.read_text(encoding="utf-8"))

    def test_failed_suite_writes_machine_readable_evidence_before_returning_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            summary = root / "artifacts/security-suite/summary.json"
            manifest = root / "artifacts/security-suite/manifest.json"
            output = root / "github-output"
            jobs_json = (
                '{"profile":"success","static_lint":"success",'
                '"filesystem_security":"success","dependency_policy":"failure",'
                '"sast":"success","supply_chain":"skipped"}'
            )
            result = main(
                [
                    "suite",
                    "--repository", "optimizr-tech/marketing-site",
                    "--run-id", "12345",
                    "--run-attempt", "2",
                    "--producer-repository", "optimizr-tech/optimizr-actions",
                    "--producer-ref", "refs/tags/v1",
                    "--producer-sha", "b" * 40,
                    "--producer-file", ".github/workflows/_security-suite.yml",
                    "--source-sha", "a" * 40,
                    "--expected-source-sha", "a" * 40,
                    "--artifact-name", "security-suite-summary",
                    "--evidence-path", "summary.json",
                    "--manifest-path", str(manifest),
                    "--manifest-artifact-path", "manifest.json",
                    "--github-output", str(output),
                    "--summary-path", str(summary),
                    "--profile", "python",
                    "--jobs-json", jobs_json,
                ]
            )

            self.assertEqual(result, 1)
            self.assertTrue(summary.exists())
            self.assertTrue(manifest.exists())
            self.assertIn('"result": "failed"', summary.read_text(encoding="utf-8"))
            output_text = output.read_text(encoding="utf-8")
            self.assertIn("evidence_path=", output_text)
            self.assertIn("summary.json", output_text)

    def test_bundle_cli_emits_a_compact_sha_bound_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            evidence_root = root / "artifacts/static-lint"
            evidence_root.mkdir(parents=True)
            (evidence_root / "lint.json").write_bytes(b'{"passed":true}\n')
            output = root / "github-output"
            result = main(
                [
                    "bundle",
                    "--repository", "optimizr-tech/marketing-site",
                    "--run-id", "12345",
                    "--run-attempt", "2",
                    "--producer-repository", "optimizr-tech/optimizr-actions",
                    "--producer-ref", "refs/tags/v1",
                    "--producer-sha", "b" * 40,
                    "--producer-file", ".github/workflows/_static-lint.yml",
                    "--source-sha", "a" * 40,
                    "--expected-source-sha", "a" * 40,
                    "--artifact-name", "security-suite-static-lint",
                    "--evidence-path", ".",
                    "--manifest-path", str(evidence_root / "evidence-manifest.json"),
                    "--github-output", str(output),
                    "--evidence-directory", str(evidence_root),
                    "--job-conclusion", "success",
                ]
            )

            self.assertEqual(result, 0)
            output_lines = dict(
                line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines()
            )
            record = json.loads(output_lines["evidence_record"])
            manifest = evidence_root / "evidence-manifest.json"
            self.assertEqual(record["source_sha"], "a" * 40)
            self.assertEqual(record["evidence_sha256"], hashlib.sha256(manifest.read_bytes()).hexdigest())
            self.assertEqual(output_lines["result"], "passed")

    def test_successful_bundle_with_missing_raw_files_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            evidence_root = root / "artifacts/sast-gate"
            output = root / "github-output"
            result = main(
                [
                    "bundle",
                    "--repository", "optimizr-tech/marketing-site",
                    "--run-id", "12345",
                    "--run-attempt", "2",
                    "--producer-repository", "optimizr-tech/optimizr-actions",
                    "--producer-ref", "refs/tags/v1",
                    "--producer-sha", "b" * 40,
                    "--producer-file", ".github/workflows/_sast-gate.yml",
                    "--source-sha", "a" * 40,
                    "--expected-source-sha", "a" * 40,
                    "--artifact-name", "security-suite-sast",
                    "--evidence-path", ".",
                    "--manifest-path", str(evidence_root / "evidence-manifest.json"),
                    "--github-output", str(output),
                    "--evidence-directory", str(evidence_root),
                    "--job-conclusion", "success",
                ]
            )

            self.assertEqual(result, 1)
            manifest = json.loads(
                (evidence_root / "evidence-manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["result"], "failed")
            self.assertFalse(manifest["evidence_present"])


if __name__ == "__main__":
    unittest.main()
