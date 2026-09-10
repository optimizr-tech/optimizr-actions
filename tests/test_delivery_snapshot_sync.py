from __future__ import annotations

from pathlib import Path
import tarfile
import tempfile
import unittest
from subprocess import CompletedProcess

from scripts.delivery.snapshot_sync import (
    SyncError,
    SyncSpec,
    sync_deployment,
)


class FakeRsync:
    def __init__(self, *responses: CompletedProcess[str]) -> None:
        self.responses = list(responses)
        self.calls: list[list[str]] = []

    def __call__(self, command: list[str]) -> CompletedProcess[str]:
        self.calls.append(command)
        return self.responses.pop(0)


class DeliverySnapshotSyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.source_root = self.root / "checkouts"
        self.deploy_root = self.root / "deployments"
        self.snapshot_root = self.root / "snapshots"
        self.source = self.source_root / "candidate"
        self.destination = self.deploy_root / "serve"
        for path in (self.source, self.destination, self.snapshot_root):
            path.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _spec(self, **overrides: object) -> SyncSpec:
        values: dict[str, object] = {
            "source": self.source,
            "destination": self.destination,
            "snapshot_root": self.snapshot_root,
            "source_root": self.source_root,
            "destination_root": self.deploy_root,
        }
        values.update(overrides)
        return SyncSpec(**values)

    @staticmethod
    def _completed(stdout: str = "", returncode: int = 0) -> CompletedProcess[str]:
        return CompletedProcess(
            args=["rsync"],
            returncode=returncode,
            stdout=stdout,
            stderr="",
        )

    def test_no_changes_does_not_create_snapshot_or_run_sync(self) -> None:
        runner = FakeRsync(self._completed())

        result = sync_deployment(self._spec(), run=runner)

        self.assertFalse(result.changed)
        self.assertFalse(result.snapshot_created)
        self.assertFalse(result.synced)
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(list(self.snapshot_root.iterdir()), [])
        self.assertIn("--dry-run", runner.calls[0])

    def test_changes_create_secret_free_snapshot_before_sync(self) -> None:
        (self.destination / "app.txt").write_text("old", encoding="utf-8")
        (self.destination / ".env").write_text("DATABASE_URL=secret", encoding="utf-8")
        secrets = self.destination / ".secrets"
        secrets.mkdir()
        (secrets / "token").write_text("secret", encoding="utf-8")
        (self.destination / "signing.key").write_text("private", encoding="utf-8")
        runner = FakeRsync(self._completed(" >f+++++++++ app.txt\n"), self._completed())

        result = sync_deployment(
            self._spec(snapshot_name="20260910T120000Z.tar.gz"),
            run=runner,
        )

        self.assertTrue(result.changed)
        self.assertTrue(result.snapshot_created)
        self.assertTrue(result.synced)
        self.assertEqual(result.snapshot_name, "20260910T120000Z.tar.gz")
        self.assertEqual(len(runner.calls), 2)
        self.assertNotIn("--dry-run", runner.calls[1])
        snapshot = self.snapshot_root / result.snapshot_name
        with tarfile.open(snapshot, "r:gz") as archive:
            names = set(archive.getnames())
        self.assertIn("./app.txt", names)
        self.assertNotIn("./.env", names)
        self.assertFalse(any(".secrets" in name for name in names))
        self.assertNotIn("./signing.key", names)

    def test_changed_deployment_can_skip_snapshot(self) -> None:
        runner = FakeRsync(self._completed("changed\n"), self._completed())

        result = sync_deployment(self._spec(snapshot_enabled=False), run=runner)

        self.assertTrue(result.changed)
        self.assertFalse(result.snapshot_created)
        self.assertTrue(result.synced)
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(list(self.snapshot_root.iterdir()), [])

    def test_dry_run_failure_fails_closed(self) -> None:
        runner = FakeRsync(self._completed(returncode=23))

        with self.assertRaises(SyncError):
            sync_deployment(self._spec(), run=runner)

        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(list(self.snapshot_root.iterdir()), [])

    def test_sync_failure_does_not_claim_success(self) -> None:
        runner = FakeRsync(
            self._completed("changed\n"),
            self._completed(returncode=12),
        )

        with self.assertRaises(SyncError):
            sync_deployment(
                self._spec(snapshot_name="20260910T120000Z.tar.gz"),
                run=runner,
            )

        self.assertEqual(len(runner.calls), 2)
        self.assertTrue((self.snapshot_root / "20260910T120000Z.tar.gz").exists())

    def test_deployignore_and_prebuilt_compose_are_passed_as_excludes(self) -> None:
        deployignore = self.source / ".deployignore"
        deployignore.write_text("tmp/\n", encoding="utf-8")
        runner = FakeRsync(self._completed(),)

        sync_deployment(
            self._spec(
                deployignore=deployignore,
                exclude_compose_file="compose.prebuilt.yml",
            ),
            run=runner,
        )

        command = runner.calls[0]
        self.assertIn("--exclude=compose.prebuilt.yml", command)
        self.assertIn(f"--exclude-from={deployignore}", command)

    def test_runtime_state_and_private_key_formats_are_excluded_from_sync(self) -> None:
        runner = FakeRsync(self._completed())

        sync_deployment(self._spec(), run=runner)

        command = runner.calls[0]
        for pattern in (
            "--exclude=.env",
            "--exclude=.env.*",
            "--exclude=.secrets",
            "--exclude=.secrets/",
            "--exclude=*.pem",
            "--exclude=*.key",
            "--exclude=*.p12",
            "--exclude=*.pfx",
        ):
            self.assertIn(pattern, command)

    def test_deployignore_outside_source_is_rejected(self) -> None:
        outside = self.root / ".deployignore"
        outside.write_text("tmp/\n", encoding="utf-8")
        runner = FakeRsync(self._completed())

        with self.assertRaises(SyncError):
            sync_deployment(self._spec(deployignore=outside), run=runner)

        self.assertEqual(runner.calls, [])

    def test_source_and_destination_must_be_below_declared_roots(self) -> None:
        runner = FakeRsync(self._completed())

        with self.assertRaises(SyncError):
            sync_deployment(self._spec(source=self.source_root), run=runner)
        with self.assertRaises(SyncError):
            sync_deployment(
                self._spec(destination=self.root / "outside"),
                run=runner,
            )

        self.assertEqual(runner.calls, [])

    def test_snapshot_name_cannot_escape_snapshot_root(self) -> None:
        runner = FakeRsync(self._completed("changed\n"))

        with self.assertRaises(SyncError):
            sync_deployment(self._spec(snapshot_name="../snapshot.tar.gz"), run=runner)

        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
