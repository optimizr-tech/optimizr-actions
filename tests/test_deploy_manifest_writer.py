"""Executable tests for the sanitized deploy-manifest writer."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import stat
import tempfile
import unittest

from scripts.deploy_manifest.write import ManifestConfig, write_manifest


UTC = dt.timezone.utc


class DeployManifestWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.deploy_path = Path(self.temporary.name) / "optimizr-cdn"
        self.deploy_path.mkdir()

    def config(self, **overrides: object) -> ManifestConfig:
        values: dict[str, object] = {
            "deploy_path": self.deploy_path,
            "status": "success",
            "repository": "optimizr-tech/optimizr-cdn",
            "deployed_sha": "a" * 40,
            "deployed_ref": "refs/heads/main",
            "environment": "production",
            "workflow": "Deploy",
            "run_id": "12345",
            "actor": "deploy-bot",
            "runner_name": "cdn-runner",
            "services": ["api", "minio"],
            "images": [
                {
                    "image": "ghcr.io/optimizr-tech/optimizr-cdn-api",
                    "digest": "sha256:" + "b" * 64,
                }
            ],
            "healthchecks": [
                {"name": "api", "status": "passed", "target": "optimizr-cdn-api"}
            ],
            "migration_result": "skipped",
            "rollback_of": None,
            "retention": 50,
            "now": dt.datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
        }
        values.update(overrides)
        return ManifestConfig(**values)

    def test_success_writes_immutable_manifest_and_success_pointer(self) -> None:
        result = write_manifest(self.config())

        payload = json.loads(result.manifest_path.read_text(encoding="utf-8"))
        pointer = json.loads(result.last_successful_path.read_text(encoding="utf-8"))

        self.assertEqual("1.0", payload["schema_version"])
        self.assertEqual("success", payload["status"])
        self.assertEqual("2026-07-19T12:00:00Z", payload["deployed_at"])
        self.assertEqual("a" * 40, payload["deployed_sha"])
        self.assertEqual(payload, pointer)
        self.assertRegex(
            result.manifest_path.name,
            r"^20260719T120000Z-a{12}-12345\.json$",
        )

    def test_failure_does_not_replace_previous_success_pointer(self) -> None:
        first = write_manifest(self.config())
        original = first.last_successful_path.read_text(encoding="utf-8")

        failure = self.config(
            status="failure",
            healthchecks=[{"name": "api", "status": "failed", "target": "optimizr-cdn-api"}],
            now=dt.datetime(2026, 7, 19, 12, 5, tzinfo=UTC),
        )
        second = write_manifest(failure)

        self.assertEqual(original, second.last_successful_path.read_text(encoding="utf-8"))
        failed_payload = json.loads(second.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual("failure", failed_payload["status"])

    def test_permissions_are_restricted(self) -> None:
        result = write_manifest(self.config())

        directory_mode = stat.S_IMODE(result.manifest_path.parent.stat().st_mode)
        manifest_mode = stat.S_IMODE(result.manifest_path.stat().st_mode)
        pointer_mode = stat.S_IMODE(result.last_successful_path.stat().st_mode)

        self.assertEqual(0o750, directory_mode)
        self.assertEqual(0o600, manifest_mode)
        self.assertEqual(0o600, pointer_mode)

    def test_retention_excludes_last_successful_pointer(self) -> None:
        for minute in range(3):
            write_manifest(
                self.config(
                    status="failure" if minute < 2 else "success",
                    retention=2,
                    run_id=str(100 + minute),
                    now=dt.datetime(2026, 7, 19, 12, minute, tzinfo=UTC),
                )
            )

        manifest_dir = self.deploy_path / ".deploy-manifests"
        immutable = sorted(
            path.name
            for path in manifest_dir.glob("*.json")
            if path.name != "last-successful.json"
        )

        self.assertEqual(2, len(immutable))
        self.assertTrue((manifest_dir / "last-successful.json").is_file())
        self.assertNotIn("20260719T120000Z", " ".join(immutable))

    def test_rejects_unsafe_deploy_paths(self) -> None:
        with self.subTest("relative"):
            with self.assertRaisesRegex(ValueError, "absolute"):
                write_manifest(self.config(deploy_path=Path("relative")))

        with self.subTest("root"):
            with self.assertRaisesRegex(ValueError, "root"):
                write_manifest(self.config(deploy_path=Path("/")))

        with self.subTest("missing"):
            with self.assertRaisesRegex(ValueError, "existing directory"):
                write_manifest(self.config(deploy_path=self.deploy_path / "missing"))

        with self.subTest("symlink"):
            target = Path(self.temporary.name) / "target"
            target.mkdir()
            link = Path(self.temporary.name) / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                write_manifest(self.config(deploy_path=link))

    def test_rejects_secret_like_or_malformed_metadata(self) -> None:
        cases = (
            ("multiline", {"workflow": "Deploy\nTOKEN=value"}),
            ("secret assignment", {"rollback_of": "token=abc123"}),
            ("private key", {"deployed_ref": "-----BEGIN PRIVATE KEY-----"}),
            ("signed url", {"repository": "https://example.test/a?X-Amz-Signature=abc"}),
            ("bad digest", {"images": [{"image": "example/api", "digest": "latest"}]}),
            ("unknown image key", {"images": [{"image": "example/api", "digest": "unknown", "token": "x"}]}),
            ("unknown health key", {"healthchecks": [{"name": "api", "status": "passed", "target": "api", "header": "x"}]}),
            ("bad health status", {"healthchecks": [{"name": "api", "status": "green", "target": "api"}]}),
            ("invalid service", {"services": ["api service"]}),
            ("oversized", {"workflow": "x" * 513}),
        )

        for label, overrides in cases:
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    write_manifest(self.config(**overrides))

    def test_atomic_writes_leave_no_temporary_files(self) -> None:
        result = write_manifest(self.config())

        leftovers = [path.name for path in result.manifest_path.parent.iterdir() if path.name.startswith(".")]
        self.assertEqual([], leftovers)


if __name__ == "__main__":
    unittest.main()
