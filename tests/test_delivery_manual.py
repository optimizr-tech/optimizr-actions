import json
from pathlib import Path
import tempfile
import unittest

from scripts.delivery.checkout import CheckoutResult, CheckoutSpec
from scripts.delivery.executor import DeliveryExecutorSpec
from scripts.delivery.gate_evidence import GateEvidence
from scripts.delivery.manual import (
    ManualAdapterError,
    ManualAdapterSpec,
    build_manual_plan,
    confirmation_for,
    execute_manual_delivery,
)
from scripts.delivery.request import parse_request
from scripts.delivery.snapshot_sync import SyncResult, SyncSpec


class ManualDeliveryAdapterTests(unittest.TestCase):
    candidate_sha = "a" * 40

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.request_root = self.root / "requests"
        self.checkout_root = self.root / "checkouts"
        self.deploy_root = self.root / "deployments"
        self.snapshot_root = self.root / "snapshots"
        self.lock_root = self.root / "locks"
        for path in (
            self.request_root,
            self.checkout_root,
            self.deploy_root,
            self.snapshot_root,
            self.lock_root,
        ):
            path.mkdir()
        self.destination = self.deploy_root / "optimizr-serve"
        self.destination.mkdir()
        self.request_path = self.request_root / "delivery.json"
        self.request_path.write_text(
            json.dumps(
                {
                    "repository": "optimizr-tech/optimizr-serve",
                    "service": "optimizr-serve",
                    "candidate_sha": self.candidate_sha,
                    "trusted_ref": "refs/heads/main",
                    "compose_file": "docker-compose.yml",
                    "container_name": "optimizr-serve",
                    "adapter": "manual",
                    "reason": "reviewed manual promotion",
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def config(self, **overrides: object) -> ManualAdapterSpec:
        values: dict[str, object] = {
            "request_path": self.request_path,
            "request_root": self.request_root,
            "confirmation": "DEPLOY optimizr-serve " + self.candidate_sha,
            "remote_allowlist": {
                "optimizr-tech/optimizr-serve": (
                    "https://github.com/optimizr-tech/optimizr-serve.git"
                )
            },
            "checkout_root": self.checkout_root,
            "deploy_root": self.deploy_root,
            "snapshot_root": self.snapshot_root,
            "lock_root": self.lock_root,
        }
        values.update(overrides)
        return ManualAdapterSpec(**values)

    def test_builds_an_executor_spec_only_after_exact_confirmation(self) -> None:
        plan = build_manual_plan(self.config())

        self.assertEqual("manual", plan.request.adapter)
        self.assertEqual(self.candidate_sha, plan.request.candidate_sha)
        self.assertIsInstance(plan.executor, DeliveryExecutorSpec)
        self.assertEqual(
            "https://github.com/optimizr-tech/optimizr-serve.git",
            plan.executor.checkout.remote,
        )
        self.assertEqual(
            self.checkout_root / ("optimizr-serve-" + self.candidate_sha),
            plan.executor.checkout.destination,
        )
        self.assertEqual(self.destination, plan.executor.sync.destination)

    def test_rejects_wrong_confirmation_and_non_allowlisted_repository(self) -> None:
        with self.assertRaisesRegex(ManualAdapterError, "confirmation"):
            build_manual_plan(
                self.config(confirmation="DEPLOY optimizr-serve " + "b" * 40)
            )

        with self.assertRaisesRegex(ManualAdapterError, "allowlist"):
            build_manual_plan(self.config(remote_allowlist={}))

    def test_rejects_a_request_for_another_adapter(self) -> None:
        payload = json.loads(self.request_path.read_text(encoding="utf-8"))
        payload["adapter"] = "github-actions"
        self.request_path.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaisesRegex(ManualAdapterError, "manual"):
            build_manual_plan(self.config())

    def test_delegates_execution_to_the_shared_executor(self) -> None:
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
            return SyncResult(False, 0, False, None, False)

        def run_gates(context: object, phase: str) -> tuple[GateEvidence, ...]:
            events.append(phase)
            if phase == "preflight":
                return tuple(GateEvidence(name, "passed", name) for name in (
                    "filesystem",
                    "compose",
                    "security",
                ))
            return tuple(GateEvidence(name, "passed", name) for name in (
                "rollout",
                "health",
            ))

        result = execute_manual_delivery(
            self.config(),
            run_gates=run_gates,
            checkout=checkout,
            sync=sync,
        )

        self.assertTrue(result.ready)
        self.assertEqual(["checkout", "preflight", "sync", "postflight"], events)

    def test_confirmation_helper_is_derived_from_validated_request(self) -> None:
        request = parse_request(
            json.loads(self.request_path.read_text(encoding="utf-8"))
        )

        self.assertEqual(
            "DEPLOY optimizr-serve " + self.candidate_sha,
            confirmation_for(request),
        )


if __name__ == "__main__":
    unittest.main()
