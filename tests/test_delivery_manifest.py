import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from scripts.delivery.checkout import CheckoutResult
from scripts.delivery.executor import DeliveryExecutorResult
from scripts.delivery.gate_evidence import GateEvidence, evaluate_gate_evidence
from scripts.delivery.manifest import DeliveryManifestSpec, write_delivery_manifest
from scripts.delivery.request import canonicalize_request, parse_request
from scripts.delivery.snapshot_sync import SyncResult


UTC = dt.timezone.utc


class DeliveryManifestTests(unittest.TestCase):
    candidate_sha = "a" * 40

    def result(self, root: Path, *, failed: bool = False) -> DeliveryExecutorResult:
        request = parse_request(
            {
                "repository": "optimizr-tech/optimizr-serve",
                "service": "optimizr-serve",
                "candidate_sha": self.candidate_sha,
                "trusted_ref": "refs/heads/main",
                "compose_file": "docker-compose.yml",
                "container_name": "optimizr-serve",
                "adapter": "manual",
            }
        )
        preflight = evaluate_gate_evidence(
            [
                GateEvidence("filesystem", "passed", "deploy-path"),
                GateEvidence("compose", "passed", "compose-config"),
                GateEvidence("security", "passed", "images"),
            ],
            required_gates=("filesystem", "compose", "security"),
        )
        postflight = evaluate_gate_evidence(
            [
                GateEvidence("rollout", "passed", "compose-up"),
                GateEvidence(
                    "health",
                    "failed" if failed else "passed",
                    "primary-container",
                    "readiness rejected" if failed else "",
                ),
            ],
            required_gates=("rollout", "health"),
        )
        return DeliveryExecutorResult(
            ready=not failed,
            request=canonicalize_request(request),
            head_sha=self.candidate_sha,
            trusted_ref=request.trusted_ref,
            sync=SyncResult(True, 2, True, "snapshot.tar.gz", True),
            preflight=preflight,
            postflight=postflight,
            evidence=(*preflight.evidence, *postflight.evidence),
            failure_reason=postflight.failure_reason,
        )

    def spec(self, root: Path, *, result: DeliveryExecutorResult) -> DeliveryManifestSpec:
        return DeliveryManifestSpec(
            result=result,
            path=root / "delivery-manifest.json",
            environment="production",
            workflow="Protected delivery",
            run_id="run-123",
            actor="deploy-bot",
            runner_name="serve-runner",
            images=(
                {
                    "image": "ghcr.io/optimizr-tech/serve",
                    "digest": "sha256:" + "b" * 64,
                },
            ),
            rollback_of="previous-manifest.json",
            now=dt.datetime(2026, 9, 10, 12, 0, tzinfo=UTC),
        )

    def test_writes_complete_sanitized_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = write_delivery_manifest(self.spec(root, result=self.result(root)))

            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(path, root / "delivery-manifest.json")
            self.assertEqual(1, payload["schema_version"])
            self.assertEqual("success", payload["status"])
            self.assertEqual(self.candidate_sha, payload["candidate_sha"])
            self.assertEqual("manual", payload["adapter"])
            self.assertEqual("previous-manifest.json", payload["rollback_of"])
            self.assertEqual(5, len(payload["gates"]))
            self.assertEqual("sha256:" + "b" * 64, payload["images"][0]["digest"])
            self.assertNotIn("command", payload)

    def test_failed_manifest_preserves_failure_and_never_claims_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = write_delivery_manifest(
                self.spec(root, result=self.result(root, failed=True))
            )

            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("failure", payload["status"])
            self.assertFalse(payload["ready"])
            self.assertEqual("health: readiness rejected", payload["failure_reason"])

    def test_rejects_secret_like_metadata_and_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self.spec(root, result=self.result(root))
            with self.assertRaisesRegex(ValueError, "secret"):
                write_delivery_manifest(
                    DeliveryManifestSpec(
                        **{**spec.__dict__, "actor": "token=do-not-write"}
                    )
                )

            path = write_delivery_manifest(spec)
            self.assertTrue(path.is_file())
            with self.assertRaisesRegex(ValueError, "already exists"):
                write_delivery_manifest(spec)


if __name__ == "__main__":
    unittest.main()
