import json
from pathlib import Path
import tempfile
import unittest

from scripts.delivery.rollback import (
    RollbackError,
    RollbackSpec,
    build_rollback_plan,
    confirmation_for,
)


class DeliveryRollbackTests(unittest.TestCase):
    candidate_sha = "a" * 40

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.manifest_root = self.root / "manifests"
        self.snapshot_root = self.root / "snapshots"
        self.manifest_root.mkdir()
        self.snapshot_root.mkdir()
        self.manifest_path = self.manifest_root / "delivery.json"
        self.snapshot_name = "snapshot-20260910T120000Z.tar.gz"
        self._write_manifest()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _write_manifest(self, **overrides: object) -> None:
        payload: dict[str, object] = {
            "schema_version": 1,
            "status": "success",
            "ready": True,
            "repository": "optimizr-tech/optimizr-serve",
            "service": "optimizr-serve",
            "candidate_sha": self.candidate_sha,
            "trusted_ref": "refs/heads/main",
            "adapter": "manual",
            "compose_file": "docker-compose.yml",
            "container_name": "optimizr-serve",
            "environment": "production",
            "workflow": "Protected delivery",
            "run_id": "run-123",
            "actor": "deploy-bot",
            "runner_name": "serve-runner",
            "images": [],
            "gates": [],
            "rollback_of": None,
            "failure_reason": None,
            "sync": {
                "changed": True,
                "changed_entries": 2,
                "snapshot_created": True,
                "snapshot_name": self.snapshot_name,
                "synced": True,
            },
        }
        payload.update(overrides)
        self.manifest_path.write_text(json.dumps(payload), encoding="utf-8")
        (self.snapshot_root / self.snapshot_name).write_bytes(b"secret-free snapshot")

    def spec(self, **overrides: object) -> RollbackSpec:
        values: dict[str, object] = {
            "manifest_path": self.manifest_path,
            "manifest_root": self.manifest_root,
            "snapshot_root": self.snapshot_root,
            "service": "optimizr-serve",
            "confirmation": "ROLLBACK optimizr-serve " + self.candidate_sha,
            "operator": "release-manager",
            "reason": "restore last approved deployment",
        }
        values.update(overrides)
        return RollbackSpec(**values)

    def test_builds_a_non_mutating_plan_for_a_successful_manifest(self) -> None:
        plan = build_rollback_plan(self.spec())

        self.assertEqual("optimizr-tech/optimizr-serve", plan.repository)
        self.assertEqual("optimizr-serve", plan.service)
        self.assertEqual(self.candidate_sha, plan.candidate_sha)
        self.assertEqual(self.manifest_path, plan.manifest_path)
        self.assertEqual(
            self.snapshot_root / self.snapshot_name,
            plan.snapshot_path,
        )
        self.assertEqual("release-manager", plan.operator)
        self.assertEqual("restore last approved deployment", plan.reason)
        self.assertTrue(self.manifest_path.is_file())
        self.assertTrue((self.snapshot_root / self.snapshot_name).is_file())

    def test_confirmation_helper_is_exact_and_manifest_derived(self) -> None:
        plan = build_rollback_plan(self.spec())

        self.assertEqual(
            "ROLLBACK optimizr-serve " + self.candidate_sha,
            confirmation_for(plan),
        )

    def test_rejects_failed_or_incomplete_manifest(self) -> None:
        for overrides in (
            {"status": "failure"},
            {"ready": False},
            {
                "sync": {
                    "changed": True,
                    "changed_entries": 2,
                    "snapshot_created": False,
                    "snapshot_name": None,
                    "synced": True,
                }
            },
        ):
            self._write_manifest(**overrides)
            with self.assertRaisesRegex(RollbackError, "approved|snapshot"):
                build_rollback_plan(self.spec())

    def test_rejects_wrong_confirmation_service_and_operator_metadata(self) -> None:
        with self.assertRaisesRegex(RollbackError, "confirmation"):
            build_rollback_plan(self.spec(confirmation="ROLLBACK optimizr-serve " + "b" * 40))

        with self.assertRaisesRegex(RollbackError, "service"):
            build_rollback_plan(self.spec(service="other-service"))

        with self.assertRaisesRegex(RollbackError, "secret"):
            build_rollback_plan(self.spec(operator="token=must-not-appear"))

        with self.assertRaisesRegex(RollbackError, "single-line"):
            build_rollback_plan(self.spec(reason="operator\nreason"))

    def test_rejects_missing_or_unsafe_snapshot(self) -> None:
        (self.snapshot_root / self.snapshot_name).unlink()
        with self.assertRaisesRegex(RollbackError, "snapshot"):
            build_rollback_plan(self.spec())

        self._write_manifest(
            **{
                "sync": {
                    "changed": True,
                    "changed_entries": 2,
                    "snapshot_created": True,
                    "snapshot_name": "../outside.tar.gz",
                    "synced": True,
                }
            }
        )
        with self.assertRaisesRegex(RollbackError, "snapshot"):
            build_rollback_plan(self.spec())

    def test_rejects_manifest_outside_declared_root(self) -> None:
        outside = self.root / "outside.json"
        outside.write_text(self.manifest_path.read_text(encoding="utf-8"), encoding="utf-8")

        with self.assertRaisesRegex(RollbackError, "manifest"):
            build_rollback_plan(self.spec(manifest_path=outside))


if __name__ == "__main__":
    unittest.main()
