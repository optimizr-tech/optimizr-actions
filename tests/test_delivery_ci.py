import json
from pathlib import Path
import tempfile
import unittest

from scripts.delivery.checkout import CheckoutResult, CheckoutSpec
from scripts.delivery.ci import (
    CiAdapterError,
    CiAdapterSpec,
    build_ci_plan,
    execute_ci_delivery,
)
from scripts.delivery.gate_evidence import GateEvidence
from scripts.delivery.snapshot_sync import SyncResult, SyncSpec


class ProtectedCiAdapterTests(unittest.TestCase):
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
        (self.deploy_root / "optimizr-serve").mkdir()
        self.request_path = self.request_root / "delivery.json"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _write_request(self, provider: str) -> None:
        self.request_path.write_text(
            json.dumps(
                {
                    "repository": "optimizr-tech/optimizr-serve",
                    "service": "optimizr-serve",
                    "candidate_sha": self.candidate_sha,
                    "trusted_ref": "refs/heads/main",
                    "compose_file": "docker-compose.yml",
                    "container_name": "optimizr-serve",
                    "adapter": provider,
                    "reason": "protected CI promotion",
                }
            ),
            encoding="utf-8",
        )

    def config(self, **overrides: object) -> CiAdapterSpec:
        values: dict[str, object] = {
            "provider": "github-actions",
            "request_path": self.request_path,
            "request_root": self.request_root,
            "remote_allowlist": {
                "optimizr-tech/optimizr-serve": (
                    "https://github.com/optimizr-tech/optimizr-serve.git"
                )
            },
            "checkout_root": self.checkout_root,
            "deploy_root": self.deploy_root,
            "snapshot_root": self.snapshot_root,
            "lock_root": self.lock_root,
            "runner_name": "serve-protected-runner",
            "protected_ref": True,
            "protected_runner": True,
        }
        values.update(overrides)
        return CiAdapterSpec(**values)

    def test_builds_the_same_executor_plan_for_github_and_gitlab(self) -> None:
        for provider in ("github-actions", "gitlab-ci"):
            with self.subTest(provider=provider):
                self._write_request(provider)
                plan = build_ci_plan(self.config(provider=provider))

                self.assertEqual(provider, plan.provider)
                self.assertEqual("serve-protected-runner", plan.runner_name)
                self.assertTrue(plan.protected_ref)
                self.assertTrue(plan.protected_runner)
                self.assertEqual(provider, plan.request.adapter)
                self.assertIsInstance(plan.executor.checkout, CheckoutSpec)
                self.assertIsInstance(plan.executor.sync, SyncSpec)
                self.assertEqual(
                    self.checkout_root / ("optimizr-serve-" + self.candidate_sha),
                    plan.executor.checkout.destination,
                )

    def test_requires_both_protected_ref_and_runner(self) -> None:
        self._write_request("github-actions")
        for field in ("protected_ref", "protected_runner"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(CiAdapterError, "protected"):
                    build_ci_plan(self.config(**{field: False}))

    def test_rejects_provider_mismatch_and_unallowlisted_repository(self) -> None:
        self._write_request("github-actions")
        with self.assertRaisesRegex(CiAdapterError, "adapter"):
            build_ci_plan(self.config(provider="gitlab-ci"))

        with self.assertRaisesRegex(CiAdapterError, "allowlist"):
            build_ci_plan(self.config(remote_allowlist={}))

    def test_rejects_unsafe_runner_metadata(self) -> None:
        self._write_request("github-actions")
        with self.assertRaisesRegex(CiAdapterError, "secret"):
            build_ci_plan(self.config(runner_name="token=must-not-appear"))

        with self.assertRaisesRegex(CiAdapterError, "single-line"):
            build_ci_plan(self.config(runner_name="runner\nname"))

    def test_delegates_execution_to_the_shared_executor(self) -> None:
        self._write_request("github-actions")
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
            names = (
                ("filesystem", "compose", "security")
                if phase == "preflight"
                else ("rollout", "health")
            )
            return tuple(GateEvidence(name, "passed", name) for name in names)

        result = execute_ci_delivery(
            self.config(),
            run_gates=run_gates,
            checkout=checkout,
            sync=sync,
        )

        self.assertTrue(result.ready)
        self.assertEqual(["checkout", "preflight", "sync", "postflight"], events)


if __name__ == "__main__":
    unittest.main()
