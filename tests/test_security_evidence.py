import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.security_evidence import (
    EvidenceError,
    create_evidence_bundle,
    create_evidence_record,
    main,
    serialize_json,
    summarize_security_suite,
    verify_evidence_bundle,
    verify_evidence_record,
)


def _record(evidence: bytes | None = b"scan output\n", **overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "repository": "optimizr-tech/marketing-site",
        "run_id": "12345",
        "run_attempt": "2",
        "producer_repository": "optimizr-tech/optimizr-actions",
        "producer_ref": "refs/tags/v1",
        "producer_sha": "b" * 40,
        "producer_file": ".github/workflows/_security-suite.yml",
        "source_sha": "a" * 40,
        "conclusion": "success",
        "result": "passed",
        "artifact_name": "security-suite-summary",
        "evidence_path": "artifacts/security-suite/summary.json",
        "evidence_bytes": evidence,
        "details": {"profile": "python", "required_jobs": ["sast"]},
    }
    fields.update(overrides)
    return create_evidence_record(**fields)  # type: ignore[arg-type]


def _child_evidence(name: str, **overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "schema_version": 1,
        "repository": "optimizr-tech/marketing-site",
        "run_id": "12345",
        "run_attempt": "2",
        "producer": {
            "repository": "optimizr-tech/optimizr-actions",
            "ref": "refs/tags/v1",
            "sha": "b" * 40,
            "file": {
                "static_lint": ".github/workflows/_static-lint.yml",
                "filesystem_security": ".github/workflows/_security-gate.yml",
                "dependency_policy": ".github/workflows/_dependency-policy.yml",
                "sast": ".github/workflows/_sast-gate.yml",
                "supply_chain": ".github/workflows/_supply-chain-evidence.yml",
            }[name],
        },
        "source_sha": "a" * 40,
        "conclusion": "success",
        "result": "passed",
        "artifact_name": {
            "static_lint": "security-suite-static-lint",
            "filesystem_security": "security-suite-filesystem",
            "dependency_policy": "security-suite-dependencies",
            "sast": "security-suite-sast",
            "supply_chain": "security-suite-supply-chain",
        }[name],
        "artifact_id": "98765",
        "artifact_digest": "d" * 64,
        "evidence_path": ".",
        "evidence_manifest_path": "evidence-manifest.json",
        "evidence_sha256": "e" * 64,
        "evidence_present": True,
        "evidence_file_count": 1,
        "evidence_total_bytes": 4,
        "evidence_index_sha256": "f" * 64,
    }
    record.update(overrides)
    return record


class SecurityEvidenceTests(unittest.TestCase):
    def test_evidence_record_binds_caller_producer_and_raw_sha256(self) -> None:
        evidence = b"scan output\n"
        record = _record(evidence)

        self.assertEqual(record["repository"], "optimizr-tech/marketing-site")
        self.assertEqual(record["run_id"], "12345")
        self.assertEqual(record["run_attempt"], "2")
        self.assertEqual(record["source_sha"], "a" * 40)
        self.assertEqual(record["conclusion"], "success")
        self.assertEqual(record["artifact_name"], "security-suite-summary")
        self.assertEqual(record["evidence_sha256"], hashlib.sha256(evidence).hexdigest())

    def test_verifier_accepts_exact_content_and_expected_identity(self) -> None:
        evidence = b"scan output\n"
        record = _record(evidence)

        verified = verify_evidence_record(
            serialize_json(record),
            evidence,
            expected={
                "repository": "optimizr-tech/marketing-site",
                "run_id": "12345",
                "run_attempt": "2",
                "source_sha": "a" * 40,
                "artifact_name": "security-suite-summary",
            },
        )

        self.assertEqual(verified, record)

    def test_missing_evidence_is_recorded_as_failed_and_cannot_be_verified(self) -> None:
        record = _record(None, conclusion="failure", result="failed")

        self.assertEqual(record["result"], "failed")
        self.assertIsNone(record["evidence_sha256"])
        with self.assertRaisesRegex(EvidenceError, "missing"):
            verify_evidence_record(serialize_json(record), None)

    def test_empty_evidence_cannot_be_marked_as_passed(self) -> None:
        with self.assertRaisesRegex(EvidenceError, "non-empty"):
            _record(b"")

    def test_malformed_manifest_is_rejected(self) -> None:
        with self.assertRaisesRegex(EvidenceError, "valid JSON"):
            verify_evidence_record(b"{not-json", b"scan output\n")

    def test_output_identity_rejects_control_characters(self) -> None:
        with self.assertRaisesRegex(EvidenceError, "control characters"):
            _record(producer_ref="refs/tags/v1\nresult=passed")

    def test_wrong_source_sha_or_run_identity_is_rejected(self) -> None:
        record = _record()
        encoded = serialize_json(record)

        with self.assertRaisesRegex(EvidenceError, "source_sha"):
            verify_evidence_record(encoded, b"scan output\n", expected={"source_sha": "c" * 40})
        with self.assertRaisesRegex(EvidenceError, "run_id"):
            verify_evidence_record(encoded, b"scan output\n", expected={"run_id": "99999"})
        with self.assertRaisesRegex(EvidenceError, "run_attempt"):
            verify_evidence_record(encoded, b"scan output\n", expected={"run_attempt": "1"})
        with self.assertRaisesRegex(EvidenceError, "producer_sha"):
            verify_evidence_record(encoded, b"scan output\n", expected={"producer_sha": "c" * 40})

    def test_corrupted_evidence_bytes_fail_digest_verification(self) -> None:
        record = _record(b"scan output\n")

        with self.assertRaisesRegex(EvidenceError, "SHA-256"):
            verify_evidence_record(serialize_json(record), b"tampered output\n")

    def test_evidence_bundle_indexes_every_file_and_binds_run_and_producer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence_root = Path(temp_dir) / "artifacts/static-lint"
            evidence_root.mkdir(parents=True)
            (evidence_root / "lint.txt").write_bytes(b"lint passed\n")
            nested = evidence_root / "checks"
            nested.mkdir()
            (nested / "shell.json").write_bytes(b"{}\n")

            record = create_evidence_bundle(
                repository="optimizr-tech/marketing-site",
                run_id="12345",
                run_attempt="2",
                producer_repository="optimizr-tech/optimizr-actions",
                producer_ref="refs/tags/v1",
                producer_sha="b" * 40,
                producer_file=".github/workflows/_static-lint.yml",
                source_sha="a" * 40,
                expected_source_sha="a" * 40,
                conclusion="success",
                artifact_name="suite-static-lint",
                evidence_directory=str(evidence_root),
            )

            manifest_bytes = (evidence_root / "evidence-manifest.json").read_bytes()
            verified = verify_evidence_bundle(
                manifest_bytes,
                evidence_root,
                expected={"repository": "optimizr-tech/marketing-site", "source_sha": "a" * 40},
            )

        self.assertEqual(record["result"], "passed")
        self.assertEqual(record["evidence_sha256"], hashlib.sha256(manifest_bytes).hexdigest())
        self.assertEqual(
            [entry["path"] for entry in verified["evidence_files"]],
            ["checks/shell.json", "lint.txt"],
        )

    def test_evidence_bundle_rejects_corrupted_or_missing_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence_root = Path(temp_dir) / "artifacts/sast-gate"
            evidence_root.mkdir(parents=True)
            evidence_file = evidence_root / "results.json"
            evidence_file.write_bytes(b"{}\n")
            create_evidence_bundle(
                repository="optimizr-tech/marketing-site",
                run_id="12345",
                run_attempt="2",
                producer_repository="optimizr-tech/optimizr-actions",
                producer_ref="refs/tags/v1",
                producer_sha="b" * 40,
                producer_file=".github/workflows/_sast-gate.yml",
                source_sha="a" * 40,
                expected_source_sha="a" * 40,
                conclusion="success",
                artifact_name="suite-sast",
                evidence_directory=str(evidence_root),
            )
            manifest_bytes = (evidence_root / "evidence-manifest.json").read_bytes()
            evidence_file.write_bytes(b"tampered\n")
            with self.assertRaisesRegex(EvidenceError, "size|SHA-256"):
                verify_evidence_bundle(manifest_bytes, evidence_root)

            evidence_file.unlink()
            with self.assertRaisesRegex(EvidenceError, "missing"):
                verify_evidence_bundle(manifest_bytes, evidence_root)

    def test_evidence_bundle_rejects_an_empty_success_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence_root = Path(temp_dir) / "artifacts/sast-gate"
            evidence_root.mkdir(parents=True)
            (evidence_root / "results.json").write_bytes(b"")

            record = create_evidence_bundle(
                repository="optimizr-tech/marketing-site",
                run_id="12345",
                run_attempt="2",
                producer_repository="optimizr-tech/optimizr-actions",
                producer_ref="refs/tags/v1",
                producer_sha="b" * 40,
                producer_file=".github/workflows/_sast-gate.yml",
                source_sha="a" * 40,
                expected_source_sha="a" * 40,
                conclusion="success",
                artifact_name="security-suite-sast",
                evidence_directory=str(evidence_root),
            )

            self.assertEqual(record["result"], "failed")
            self.assertEqual(record["evidence_total_bytes"], 0)

    def test_evidence_bundle_rejects_a_preexisting_reserved_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence_root = Path(temp_dir) / "artifacts/static-lint"
            evidence_root.mkdir(parents=True)
            (evidence_root / "lint.txt").write_bytes(b"lint passed\n")
            reserved_manifest = evidence_root / "evidence-manifest.json"
            reserved_manifest.write_bytes(b"existing evidence\n")

            with self.assertRaisesRegex(EvidenceError, "reserved"):
                create_evidence_bundle(
                    repository="optimizr-tech/marketing-site",
                    run_id="12345",
                    run_attempt="2",
                    producer_repository="optimizr-tech/optimizr-actions",
                    producer_ref="refs/tags/v1",
                    producer_sha="b" * 40,
                    producer_file=".github/workflows/_static-lint.yml",
                    source_sha="a" * 40,
                    expected_source_sha="a" * 40,
                    conclusion="success",
                    artifact_name="suite-static-lint",
                    evidence_directory=str(evidence_root),
                )

    def test_malformed_digest_and_inconsistent_pass_are_rejected(self) -> None:
        record = _record()
        record["evidence_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(EvidenceError, "SHA-256 is malformed"):
            verify_evidence_record(serialize_json(record), b"scan output\n")

        record = _record()
        record["conclusion"] = "failure"
        with self.assertRaisesRegex(EvidenceError, "successful conclusion"):
            verify_evidence_record(serialize_json(record), b"scan output\n")

        record = _record()
        record["conclusion"] = []
        with self.assertRaisesRegex(EvidenceError, "conclusion or result is malformed"):
            verify_evidence_record(serialize_json(record), b"scan output\n")

    def test_suite_required_skips_fail_but_optional_skips_are_recorded(self) -> None:
        required_skip = summarize_security_suite(
            profile="python",
            image_refs="",
            jobs={
                "profile": "success",
                "static_lint": "success",
                "filesystem_security": "success",
                "dependency_policy": "skipped",
                "sast": "success",
                "supply_chain": "skipped",
            },
        )
        optional_skip = summarize_security_suite(
            profile="infra",
            image_refs="",
            jobs={
                "profile": "success",
                "static_lint": "success",
                "filesystem_security": "success",
                "dependency_policy": "skipped",
                "sast": "skipped",
                "supply_chain": "skipped",
            },
        )

        self.assertEqual(required_skip["result"], "failed")
        self.assertEqual(required_skip["unexpectedly_skipped"], ["dependency_policy"])
        self.assertEqual(optional_skip["result"], "passed")
        self.assertEqual(
            optional_skip["expected_skipped"],
            ["dependency_policy", "sast", "supply_chain"],
        )

    def test_suite_summary_is_machine_readable_and_rejects_unknown_job_status(self) -> None:
        jobs = {
            "profile": "success",
            "static_lint": "success",
            "filesystem_security": "success",
            "dependency_policy": "success",
            "sast": "success",
            "supply_chain": "skipped",
        }
        payload = summarize_security_suite(profile="python", image_refs="", jobs=jobs)
        self.assertEqual(json.loads(serialize_json(payload)), payload)

        jobs["sast"] = "unknown"
        with self.assertRaisesRegex(EvidenceError, "job result"):
            summarize_security_suite(profile="python", image_refs="", jobs=jobs)

    def test_suite_aggregates_each_successful_child_identity_and_artifact_digest(self) -> None:
        jobs = {
            "profile": "success",
            "static_lint": "success",
            "filesystem_security": "success",
            "dependency_policy": "success",
            "sast": "success",
            "supply_chain": "skipped",
        }
        children = {
            name: _child_evidence(name)
            for name in ("static_lint", "filesystem_security", "dependency_policy", "sast")
        }
        summary = summarize_security_suite(
            profile="python",
            image_refs="",
            jobs=jobs,
            child_evidence=children,
            expected_identity={
                "repository": "optimizr-tech/marketing-site",
                "run_id": "12345",
                "run_attempt": "2",
                "source_sha": "a" * 40,
            },
        )

        self.assertEqual(summary["result"], "passed")
        self.assertEqual(summary["child_evidence"]["static_lint"]["artifact_id"], "98765")
        self.assertEqual(summary["child_evidence"]["sast"]["artifact_digest"], "d" * 64)
        self.assertIsNone(summary["child_evidence"]["supply_chain"])

    def test_suite_fails_closed_when_child_evidence_is_missing_or_mismatched(self) -> None:
        jobs = {
            "profile": "success",
            "static_lint": "success",
            "filesystem_security": "success",
            "dependency_policy": "success",
            "sast": "success",
            "supply_chain": "skipped",
        }
        children = {
            name: _child_evidence(name)
            for name in ("static_lint", "filesystem_security", "dependency_policy", "sast")
        }
        missing = dict(children)
        missing.pop("sast")
        summary = summarize_security_suite(
            profile="python",
            image_refs="",
            jobs=jobs,
            child_evidence=missing,
            expected_identity={"source_sha": "a" * 40},
        )
        self.assertEqual(summary["result"], "failed")
        self.assertIn("missing_record", summary["child_evidence_errors"]["sast"])

        children["sast"]["source_sha"] = "c" * 40
        summary = summarize_security_suite(
            profile="python",
            image_refs="",
            jobs=jobs,
            child_evidence=children,
            expected_identity={"source_sha": "a" * 40},
        )
        self.assertEqual(summary["result"], "failed")
        self.assertIn("source_sha_mismatch", summary["child_evidence_errors"]["sast"])

    def test_suite_rejects_child_run_and_artifact_digest_mismatches(self) -> None:
        jobs = {
            "profile": "success",
            "static_lint": "success",
            "filesystem_security": "success",
            "dependency_policy": "success",
            "sast": "success",
            "supply_chain": "skipped",
        }
        children = {
            name: _child_evidence(name)
            for name in ("static_lint", "filesystem_security", "dependency_policy", "sast")
        }
        children["dependency_policy"]["run_attempt"] = "1"
        children["sast"]["artifact_digest"] = "malformed"
        children["filesystem_security"]["result"] = []

        summary = summarize_security_suite(
            profile="python",
            image_refs="",
            jobs=jobs,
            child_evidence=children,
            expected_identity={"run_id": "12345", "run_attempt": "2"},
        )

        self.assertEqual(summary["result"], "failed")
        self.assertIn(
            "run_attempt_mismatch", summary["child_evidence_errors"]["dependency_policy"]
        )
        self.assertIn(
            "malformed_artifact_digest", summary["child_evidence_errors"]["sast"]
        )
        self.assertIn(
            "malformed_result", summary["child_evidence_errors"]["filesystem_security"]
        )

    def test_suite_required_skip_cannot_pass_without_a_child_receipt(self) -> None:
        jobs = {
            "profile": "success",
            "static_lint": "success",
            "filesystem_security": "success",
            "dependency_policy": "skipped",
            "sast": "success",
            "supply_chain": "skipped",
        }
        children = {
            name: _child_evidence(name)
            for name in ("static_lint", "filesystem_security", "sast")
        }
        summary = summarize_security_suite(
            profile="python",
            image_refs="",
            jobs=jobs,
            child_evidence=children,
            expected_identity={"source_sha": "a" * 40},
        )

        self.assertEqual(summary["result"], "failed")
        self.assertIn("dependency_policy", summary["unexpectedly_skipped"])
        self.assertIsNone(summary["child_evidence"]["dependency_policy"])
        self.assertIn("missing_record", summary["child_evidence_errors"]["dependency_policy"])
        self.assertIsNone(summary["child_evidence"]["supply_chain"])

    def test_suite_cli_aggregates_child_workflow_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            child_outputs: dict[str, object] = {}
            for name in (
                "static_lint",
                "filesystem_security",
                "dependency_policy",
                "sast",
            ):
                record = _child_evidence(name)
                child_outputs[name] = {
                    "record_json": json.dumps(record, separators=(",", ":")),
                    "evidence_sha256": record["evidence_sha256"],
                    "artifact_id": record["artifact_id"],
                    "artifact_digest": record["artifact_digest"],
                }
            jobs_json = json.dumps(
                {
                    "profile": "success",
                    "static_lint": "success",
                    "filesystem_security": "success",
                    "dependency_policy": "success",
                    "sast": "success",
                    "supply_chain": "skipped",
                }
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
                    "--manifest-path", str(root / "manifest.json"),
                    "--manifest-artifact-path", "manifest.json",
                    "--summary-path", str(root / "summary.json"),
                    "--profile", "python",
                    "--jobs-json", jobs_json,
                    "--child-evidence-json", json.dumps(child_outputs),
                ]
            )

            self.assertEqual(result, 0)
            summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["result"], "passed")
            self.assertEqual(summary["child_evidence"]["dependency_policy"]["run_attempt"], "2")
            self.assertIsNone(summary["child_evidence"]["supply_chain"])


if __name__ == "__main__":
    unittest.main()
