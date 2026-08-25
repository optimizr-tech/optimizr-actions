from __future__ import annotations

import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import call, Mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "container_release" / "verify_published_digest.py"
SPEC = importlib.util.spec_from_file_location("verify_published_digest", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


IMAGE_REF = "ghcr.io/optimizr-tech/example/admin:commit-sha"
EXPECTED_DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


def completed(returncode: int, output: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["docker"], returncode=returncode, stdout=output)


class VerifyPublishedDigestTests(unittest.TestCase):
    def test_successful_first_read_does_not_wait_or_retry(self) -> None:
        run_command = Mock(
            return_value=completed(0, f"Name: {IMAGE_REF}\nDigest: {EXPECTED_DIGEST}\n")
        )
        sleep = Mock()

        result = MODULE.verify_published_digest(
            IMAGE_REF,
            EXPECTED_DIGEST,
            run_command=run_command,
            sleep=sleep,
        )

        self.assertEqual(EXPECTED_DIGEST, result)
        run_command.assert_called_once()
        sleep.assert_not_called()

    def test_retries_transient_registry_read_after_write_failure(self) -> None:
        run_command = Mock(
            side_effect=[
                completed(1, "manifest unknown"),
                completed(0, f"Digest: {EXPECTED_DIGEST}\n"),
            ]
        )
        sleep = Mock()
        warnings: list[str] = []

        result = MODULE.verify_published_digest(
            IMAGE_REF,
            EXPECTED_DIGEST,
            attempts=5,
            initial_delay_seconds=2,
            run_command=run_command,
            sleep=sleep,
            emit=warnings.append,
        )

        self.assertEqual(EXPECTED_DIGEST, result)
        self.assertEqual(2, run_command.call_count)
        sleep.assert_called_once_with(2)
        self.assertIn("retrying", warnings[0])

    def test_mismatch_remains_fail_closed_after_bounded_retries(self) -> None:
        run_command = Mock(
            return_value=completed(0, f"Digest: {OTHER_DIGEST}\n")
        )
        sleep = Mock()

        with self.assertRaisesRegex(MODULE.DigestVerificationError, "did not match after 3"):
            MODULE.verify_published_digest(
                IMAGE_REF,
                EXPECTED_DIGEST,
                attempts=3,
                initial_delay_seconds=1,
                run_command=run_command,
                sleep=sleep,
            )

        self.assertEqual(3, run_command.call_count)
        self.assertEqual([call(1), call(2)], sleep.call_args_list)

    def test_invalid_expected_digest_is_rejected_before_registry_access(self) -> None:
        run_command = Mock()

        with self.assertRaisesRegex(MODULE.DigestVerificationError, "valid immutable"):
            MODULE.verify_published_digest(
                IMAGE_REF,
                "sha256:not-a-digest",
                run_command=run_command,
            )

        run_command.assert_not_called()
