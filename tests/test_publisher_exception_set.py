"""Tests for complete image-set exception validation before publisher promotion."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from scripts.container_release.validate_publisher_exception_set import (
    AggregateExceptionSetError,
    validate_aggregate_exception_set,
)


ROOT = Path(__file__).resolve().parents[1]
TODAY = date(2026, 11, 4)
CANDIDATE_SHA = "a" * 40
DIGEST_API = "sha256:" + "1" * 64
DIGEST_WORKER = "sha256:" + "2" * 64
DIGEST_UNCHANGED = "sha256:" + "3" * 64
REGISTRY = "ghcr.io"
NAMESPACE = "optimizr/apps"


class AggregateExceptionSetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fragments = self.root / "fragments"
        self.fragments.mkdir()
        self.policy_root = self.root / "candidate"
        self.policy_root.mkdir()
        self.services = [
            {"name": "api", "security_exceptions_file": "security/api.json"},
            {"name": "worker", "security_exceptions_file": "security/worker.json"},
        ]
        self.unchanged = [
            {
                "service": "scheduler",
                "image": f"{REGISTRY}/{NAMESPACE}/scheduler@{DIGEST_UNCHANGED}",
                "security_exceptions_file": "security/scheduler.json",
            }
        ]
        self._write_fragment("api", DIGEST_API)
        self._write_fragment("worker", DIGEST_WORKER)
        self._write_policy("security/api.json", "CVE-2026-1001", DIGEST_API)
        self._write_policy("security/worker.json", "CVE-2026-1002", DIGEST_WORKER)
        self._write_policy("security/scheduler.json", "CVE-2026-1003", DIGEST_UNCHANGED)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_fragment(
        self,
        service: str,
        digest: str,
        *,
        candidate_sha: str = CANDIDATE_SHA,
    ) -> None:
        directory = self.fragments / service
        directory.mkdir(parents=True, exist_ok=True)
        payload = {
            "service": service,
            "candidate_sha": candidate_sha,
            "image": f"{REGISTRY}/{NAMESPACE}/{service}@{digest}",
            "digest": digest,
            "attestation_verified": True,
            "security_evidence": {
                "source_sha": candidate_sha,
                "image_digest": digest,
                "security_gate_accepted": True,
                "promotion_authorized": True,
            },
        }
        (directory / "candidate-fragment.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )

    def _write_policy(
        self,
        relative_path: str,
        vulnerability_id: str,
        target: str,
        *,
        expires: str = "2030-01-01",
    ) -> None:
        path = self.policy_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "vulnerabilities": [
                        {
                            "id": vulnerability_id,
                            "owner": "platform-security",
                            "statement": "reviewed exception",
                            "compensating_control": "route is blocked",
                            "expires": expires,
                            "scan_types": ["image"],
                            "targets": [target],
                            "purls": ["pkg:generic/example@1.0"],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    def _validate(self, **updates: object) -> dict[str, object]:
        arguments: dict[str, object] = {
            "services": self.services,
            "candidate_fragments_dir": self.fragments,
            "candidate_sha": CANDIDATE_SHA,
            "registry": REGISTRY,
            "image_namespace": NAMESPACE,
            "unchanged_images": self.unchanged,
            "policy_root": self.policy_root,
            "validate_policies": True,
            "set_complete": True,
            "require_promotion_authorized": True,
            "today": TODAY,
        }
        arguments.update(updates)
        return validate_aggregate_exception_set(**arguments)  # type: ignore[arg-type]

    def test_validates_candidate_and_unchanged_images_as_one_set(self) -> None:
        evidence = self._validate()

        self.assertEqual("validated", evidence["status"])
        self.assertEqual(CANDIDATE_SHA, evidence["candidate_sha"])
        self.assertEqual(3, evidence["active_image_count"])
        self.assertEqual(3, evidence["exception_count"])
        self.assertTrue(evidence["set_complete"])
        self.assertEqual(
            {"api", "worker", "scheduler"},
            {item["service"] for item in evidence["images"]},
        )
        self.assertNotIn("reviewed exception", json.dumps(evidence))

    def test_rejects_a_partial_matrix_before_promotion(self) -> None:
        (self.fragments / "worker" / "candidate-fragment.json").unlink()

        with self.assertRaisesRegex(AggregateExceptionSetError, "exactly the requested candidate services"):
            self._validate()

    def test_rejects_candidate_fragment_bound_to_another_source_sha(self) -> None:
        self._write_fragment("worker", DIGEST_WORKER, candidate_sha="b" * 40)

        with self.assertRaisesRegex(AggregateExceptionSetError, "candidate source commit"):
            self._validate()

    def test_rejects_exception_target_outside_complete_final_set(self) -> None:
        self._write_policy("security/worker.json", "CVE-2026-1002", "sha256:" + "f" * 64)

        with self.assertRaisesRegex(ValueError, "outside the exact active image set"):
            self._validate()

    def test_rejects_expired_policy_entry_in_any_service_policy(self) -> None:
        self._write_policy(
            "security/scheduler.json",
            "CVE-2026-1003",
            DIGEST_UNCHANGED,
            expires="2026-11-03",
        )

        with self.assertRaisesRegex(ValueError, "expired"):
            self._validate()

    def test_requires_explicit_complete_set_declaration_when_opted_in(self) -> None:
        with self.assertRaisesRegex(AggregateExceptionSetError, "declare the final set complete"):
            self._validate(set_complete=False)

    def test_rejects_duplicate_active_digests_across_candidate_and_unchanged_images(self) -> None:
        self.unchanged[0]["image"] = f"{REGISTRY}/{NAMESPACE}/scheduler@{DIGEST_API}"

        with self.assertRaisesRegex(ValueError, "duplicate active image ID"):
            self._validate()

    def test_default_mode_preserves_existing_per_image_policy_behavior(self) -> None:
        fragment_path = self.fragments / "api" / "candidate-fragment.json"
        fragment = json.loads(fragment_path.read_text(encoding="utf-8"))
        fragment["attestation_verified"] = False
        fragment_path.write_text(json.dumps(fragment), encoding="utf-8")
        evidence = self._validate(
            unchanged_images=[],
            validate_policies=False,
            set_complete=False,
            require_promotion_authorized=False,
            require_attestations=False,
        )

        self.assertEqual("not_requested", evidence["status"])
        self.assertFalse(evidence["policy_validation_enabled"])
        self.assertEqual(2, evidence["active_image_count"])
        self.assertTrue(evidence["candidate_matrix_complete"])
        self.assertFalse(evidence["set_complete"])

    def test_rejects_invalid_registry_and_empty_namespace_segments(self) -> None:
        with self.assertRaisesRegex(AggregateExceptionSetError, "registry hostname"):
            self._validate(registry="ghcr.io/")
        with self.assertRaisesRegex(AggregateExceptionSetError, "safe repository namespace"):
            self._validate(image_namespace="optimizr//apps")


class AggregateExceptionPublisherWorkflowTests(unittest.TestCase):
    def test_complete_set_validation_is_a_barrier_before_all_promotion(self) -> None:
        workflow = (ROOT / ".github/workflows/_container-build-publish.yml").read_text(
            encoding="utf-8"
        )
        inputs = workflow.split("    inputs:", 1)[1].split("    secrets:", 1)[0]
        build = workflow.split("  build:", 1)[1].split("  aggregate_policy:", 1)[0]
        aggregate_policy = workflow.split("  aggregate_policy:", 1)[1].split("  promote:", 1)[0]
        promote = workflow.split("  promote:", 1)[1].split("  aggregate:", 1)[0]
        aggregate = workflow.split("  aggregate:", 1)[1]

        self.assertIn("security_aggregate_exception_validation:", inputs)
        self.assertIn("default: false", inputs)
        self.assertIn("security_aggregate_exception_set_complete:", inputs)
        self.assertIn("security_aggregate_unchanged_images_json:", inputs)
        self.assertNotIn("Promote verified image by digest", build)
        self.assertIn("Security gate for exact quarantine digest before promotion", build)
        self.assertIn("needs: [validate, build]", aggregate_policy)
        self.assertIn("scripts.container_release.validate_publisher_exception_set", aggregate_policy)
        self.assertIn("candidate-fragments", aggregate_policy)
        self.assertNotIn("packages: write", aggregate_policy)
        self.assertIn("needs: [validate, build, aggregate_policy]", promote)
        self.assertIn("if: ${{ !cancelled() && inputs.push", promote)
        self.assertIn("needs.aggregate_policy.result == 'success'", promote)
        self.assertIn("steps.verify-aggregate-policy.outcome == 'success'", promote)
        self.assertIn("packages: write", promote)
        self.assertIn("needs: [validate, build, aggregate_policy, promote]", aggregate)
        self.assertIn("if: ${{ !cancelled() && needs.validate.result == 'success'", aggregate)
        self.assertIn("publisher-exception-validation.json", aggregate)
        self.assertIn("jobs.aggregate.outputs.manifest_json", workflow)


if __name__ == "__main__":
    unittest.main()
