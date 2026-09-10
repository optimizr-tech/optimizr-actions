from pathlib import Path
import tempfile
import unittest

from scripts.delivery.checkout import CheckoutResult, CheckoutSpec
from scripts.delivery.executor import (
    DeliveryExecutorError,
    DeliveryExecutorSpec,
    execute_delivery,
)
from scripts.delivery.gate_evidence import GateEvidence
from scripts.delivery.request import DeployRequest, parse_request
from scripts.delivery.snapshot_sync import SyncResult, SyncSpec


class DeliveryExecutorTests(unittest.TestCase):
    candidate_sha = "a" * 40

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.checkout_root = self.root / "checkouts"
        self.deploy_root = self.root / "deployments"
        self.snapshot_root = self.root / "snapshots"
        self.lock_root = self.root / "locks"
        for path in (
            self.checkout_root,
            self.deploy_root,
            self.snapshot_root,
            self.lock_root,
        ):
            path.mkdir()
        self.destination = self.deploy_root / "serve"
        self.destination.mkdir()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def request(self) -> DeployRequest:
        return parse_request(
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

    def spec(self) -> DeliveryExecutorSpec:
        request = self.request()
        checkout_destination = self.checkout_root / "candidate"
        return DeliveryExecutorSpec(
            checkout=CheckoutSpec(
                request=request,
                remote="https://github.com/optimizr-tech/optimizr-serve.git",
                destination=checkout_destination,
                allowed_root=self.checkout_root,
            ),
            sync=SyncSpec(
                source=checkout_destination,
                destination=self.destination,
                snapshot_root=self.snapshot_root,
                source_root=self.checkout_root,
                destination_root=self.deploy_root,
            ),
            lock_root=self.lock_root,
        )

    @staticmethod
    def preflight_gates(*, failed: str | None = None) -> tuple[GateEvidence, ...]:
        return tuple(
            GateEvidence(name, "failed" if name == failed else "passed", name)
            for name in ("filesystem", "compose", "security")
        )

    @staticmethod
    def postflight_gates(*, failed: str | None = None) -> tuple[GateEvidence, ...]:
        return tuple(
            GateEvidence(name, "failed" if name == failed else "passed", name)
            for name in ("rollout", "health")
        )

    def test_runs_preflight_sync_and_postflight_under_one_contract(self) -> None:
        events: list[str] = []

        def checkout(spec: CheckoutSpec) -> CheckoutResult:
            events.append("checkout")
            spec.destination.mkdir()
            return CheckoutResult(
                path=spec.destination,
                head_sha=self.candidate_sha,
                trusted_ref=spec.request.trusted_ref,
            )

        def sync(spec: SyncSpec) -> SyncResult:
            events.append("sync")
            self.assertEqual(self.checkout_root / "candidate", spec.source)
            return SyncResult(True, 1, True, "20260910T120000Z.tar.gz", True)

        def run_gates(context: object, phase: str) -> tuple[GateEvidence, ...]:
            events.append(phase)
            return (
                self.preflight_gates()
                if phase == "preflight"
                else self.postflight_gates()
            )

        result = execute_delivery(
            self.spec(),
            checkout=checkout,
            sync=sync,
            run_gates=run_gates,
        )

        self.assertTrue(result.ready)
        self.assertEqual(
            ["checkout", "preflight", "sync", "postflight"],
            events,
        )
        self.assertEqual(self.candidate_sha, result.head_sha)
        self.assertTrue(result.synced)
        self.assertEqual(
            self.candidate_sha,
            result.request["candidate_sha"],
        )
        self.assertEqual(5, len(result.evidence))

    def test_failed_preflight_never_synchronizes(self) -> None:
        sync_calls: list[SyncSpec] = []

        def checkout(spec: CheckoutSpec) -> CheckoutResult:
            spec.destination.mkdir()
            return CheckoutResult(
                path=spec.destination,
                head_sha=self.candidate_sha,
                trusted_ref=spec.request.trusted_ref,
            )

        def sync(spec: SyncSpec) -> SyncResult:
            sync_calls.append(spec)
            return SyncResult(True, 1, True, "snapshot.tar.gz", True)

        def run_gates(context: object, phase: str) -> tuple[GateEvidence, ...]:
            self.assertEqual("preflight", phase)
            return self.preflight_gates(failed="security")

        result = execute_delivery(
            self.spec(),
            checkout=checkout,
            sync=sync,
            run_gates=run_gates,
        )

        self.assertFalse(result.ready)
        self.assertEqual("security: gate failed", result.failure_reason)
        self.assertEqual([], sync_calls)
        self.assertIsNone(result.sync)
        self.assertIsNone(result.postflight)

    def test_failed_postflight_reports_not_ready_after_sync(self) -> None:
        phases: list[str] = []

        def checkout(spec: CheckoutSpec) -> CheckoutResult:
            spec.destination.mkdir()
            return CheckoutResult(
                path=spec.destination,
                head_sha=self.candidate_sha,
                trusted_ref=spec.request.trusted_ref,
            )

        def sync(spec: SyncSpec) -> SyncResult:
            return SyncResult(True, 1, True, "snapshot.tar.gz", True)

        def run_gates(context: object, phase: str) -> tuple[GateEvidence, ...]:
            phases.append(phase)
            return (
                self.preflight_gates()
                if phase == "preflight"
                else self.postflight_gates(failed="health")
            )

        result = execute_delivery(
            self.spec(),
            checkout=checkout,
            sync=sync,
            run_gates=run_gates,
        )

        self.assertFalse(result.ready)
        self.assertEqual("health: gate failed", result.failure_reason)
        self.assertEqual(["preflight", "postflight"], phases)
        self.assertTrue(result.synced)
        self.assertEqual(5, len(result.evidence))

    def test_invalid_gate_evidence_is_not_exposed(self) -> None:
        def checkout(spec: CheckoutSpec) -> CheckoutResult:
            spec.destination.mkdir()
            return CheckoutResult(
                path=spec.destination,
                head_sha=self.candidate_sha,
                trusted_ref=spec.request.trusted_ref,
            )

        def run_gates(context: object, phase: str) -> tuple[GateEvidence, ...]:
            return self.preflight_gates() + (
                GateEvidence("filesystem", "passed", "token=do-not-expose"),
            )

        with self.assertRaisesRegex(
            DeliveryExecutorError,
            "gate evidence could not be evaluated",
        ) as error:
            execute_delivery(
                self.spec(),
                checkout=checkout,
                sync=lambda spec: SyncResult(False, 0, False, None, False),
                run_gates=run_gates,
            )
        self.assertNotIn("do-not-expose", str(error.exception))


if __name__ == "__main__":
    unittest.main()
