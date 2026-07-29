from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.security_gate.image_transport import prepare_image_transport


IMAGE_ID = "sha256:" + "a" * 64


class ImageTransportTests(unittest.TestCase):
    def test_direct_access_scans_the_local_image_without_export(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, IMAGE_ID + "\n", "")

        with tempfile.TemporaryDirectory() as temporary:
            result = prepare_image_transport(
                "service:latest",
                mode="direct",
                archive=Path(temporary) / "image.tar",
                runner=runner,
            )

        self.assertEqual("ready", result.status)
        self.assertEqual("direct", result.transport)
        self.assertEqual(IMAGE_ID, result.identity)
        self.assertEqual((), result.scan_args)
        self.assertEqual(
            [["docker", "image", "inspect", "--format", "{{.Id}}", "service:latest"]],
            calls,
        )

    def test_auto_mode_recovers_with_sudo_archive_and_preserves_identity(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
            calls.append(argv)
            if argv[0] == "docker":
                return subprocess.CompletedProcess(argv, 1, "", "permission denied")
            if "inspect" in argv:
                return subprocess.CompletedProcess(argv, 0, IMAGE_ID + "\n", "")
            if argv[3] == "save":
                Path(argv[-1]).write_bytes(b"docker archive")
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "image.tar"
            result = prepare_image_transport(
                "service:latest",
                mode="auto",
                archive=archive,
                runner=runner,
            )

        self.assertEqual("ready", result.status)
        self.assertEqual("archive", result.transport)
        self.assertEqual(IMAGE_ID, result.identity)
        self.assertEqual(("--input", str(archive)), result.scan_args)
        self.assertEqual(
            [
                ["docker", "image", "inspect", "--format", "{{.Id}}", "service:latest"],
                [
                    "sudo",
                    "-n",
                    "docker",
                    "image",
                    "inspect",
                    "--format",
                    "{{.Id}}",
                    "service:latest",
                ],
                ["sudo", "-n", "docker", "save", "service:latest", "-o", str(archive)],
                ["sudo", "-n", "chown", "0:0", str(archive)],
            ],
            calls,
        )

    def test_sudo_save_failure_is_sanitized_and_fail_closed(self) -> None:
        def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
            if "inspect" in argv:
                return subprocess.CompletedProcess(argv, 0, IMAGE_ID + "\n", "")
                return subprocess.CompletedProcess(argv, 1, "", "/redacted/diagnostic")

        with tempfile.TemporaryDirectory() as temporary:
            result = prepare_image_transport(
                "service:latest",
                mode="sudo",
                archive=Path(temporary) / "image.tar",
                runner=runner,
            )

        self.assertEqual("failed", result.status)
        self.assertEqual("docker_save_failed", result.failure_reason)
        self.assertNotIn("secret", result.failure_reason)

    def test_archive_ownership_failure_removes_the_temporary_archive(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
            calls.append(argv)
            if "inspect" in argv:
                return subprocess.CompletedProcess(argv, 0, IMAGE_ID + "\n", "")
            if "save" in argv:
                Path(argv[-1]).write_bytes(b"docker archive")
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 1, "", "permission denied")

        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "image.tar"
            result = prepare_image_transport(
                "service:latest",
                mode="sudo",
                archive=archive,
                runner=runner,
            )

        self.assertEqual("failed", result.status)
        self.assertEqual("docker_archive_ownership_failed", result.failure_reason)
        self.assertFalse(archive.exists())


if __name__ == "__main__":
    unittest.main()
