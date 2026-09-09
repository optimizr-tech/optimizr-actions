from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.delivery.checkout import CheckoutError, CheckoutSpec, checkout_exact_sha
from scripts.delivery.request import DeployRequest, parse_request


class DeliveryCheckoutTests(unittest.TestCase):
    candidate_sha = "a" * 40

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

    def test_checks_out_only_an_ancestor_of_the_trusted_ref(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "checkout"
            calls: list[list[str]] = []

            def run(command: list[str]) -> subprocess.CompletedProcess[str]:
                calls.append(command)
                stdout = (
                    self.candidate_sha + "\n"
                    if command[-2:] == ["rev-parse", "HEAD"]
                    else ""
                )
                return subprocess.CompletedProcess(command, 0, stdout, "")

            result = checkout_exact_sha(
                CheckoutSpec(
                    request=self.request(),
                    remote="https://github.com/optimizr-tech/optimizr-serve.git",
                    destination=destination,
                    allowed_root=root,
                ),
                run=run,
            )

            self.assertEqual(self.candidate_sha, result.head_sha)
            self.assertTrue(destination.is_dir())
            self.assertIn(
                [
                    "git",
                    "-C",
                    str(destination),
                    "fetch",
                    "--no-tags",
                    "--force",
                    "origin",
                    "refs/heads/main",
                ],
                calls,
            )
            self.assertIn(
                [
                    "git",
                    "-C",
                    str(destination),
                    "merge-base",
                    "--is-ancestor",
                    self.candidate_sha,
                    "FETCH_HEAD",
                ],
                calls,
            )
            self.assertIn(
                [
                    "git",
                    "-C",
                    str(destination),
                    "checkout",
                    "--detach",
                    "--force",
                    self.candidate_sha,
                ],
                calls,
            )

    def test_rejects_existing_destination_and_unsafe_remote(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "checkout"
            destination.mkdir()
            with self.assertRaisesRegex(CheckoutError, "destination"):
                checkout_exact_sha(
                    CheckoutSpec(
                        request=self.request(),
                        remote="https://github.com/example/repo.git",
                        destination=destination,
                        allowed_root=root,
                    )
                )

            with self.assertRaisesRegex(CheckoutError, "remote"):
                checkout_exact_sha(
                    CheckoutSpec(
                        request=self.request(),
                        remote="--upload-pack=evil",
                        destination=root / "another-checkout",
                        allowed_root=root,
                    )
                )

            with self.assertRaisesRegex(CheckoutError, "remote"):
                checkout_exact_sha(
                    CheckoutSpec(
                        request=self.request(),
                        remote="not-a-network-url",
                        destination=root / "third-checkout",
                        allowed_root=root,
                    )
                )

            with self.assertRaisesRegex(CheckoutError, "allowed root"):
                checkout_exact_sha(
                    CheckoutSpec(
                        request=self.request(),
                        remote="https://github.com/example/repo.git",
                        destination=root.parent / "outside-checkout",
                        allowed_root=root,
                    )
                )

    def test_cleans_new_destination_when_git_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "checkout"

            def run(command: list[str]) -> subprocess.CompletedProcess[str]:
                code = 1 if "fetch" in command else 0
                return subprocess.CompletedProcess(command, code, "", "not exposed")

            with self.assertRaisesRegex(CheckoutError, "git command failed"):
                checkout_exact_sha(
                    CheckoutSpec(
                        request=self.request(),
                        remote="https://github.com/example/repo.git",
                        destination=destination,
                        allowed_root=root,
                    ),
                    run=run,
                )
            self.assertFalse(destination.exists())

    def test_fails_closed_when_checked_out_head_differs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "checkout"
            other_sha = "b" * 40

            def run(command: list[str]) -> subprocess.CompletedProcess[str]:
                stdout = (
                    other_sha + "\n"
                    if command[-2:] == ["rev-parse", "HEAD"]
                    else ""
                )
                return subprocess.CompletedProcess(command, 0, stdout, "")

            with self.assertRaisesRegex(CheckoutError, "does not match"):
                checkout_exact_sha(
                    CheckoutSpec(
                        request=self.request(),
                        remote="https://github.com/example/repo.git",
                        destination=destination,
                        allowed_root=root,
                    ),
                    run=run,
                )
            self.assertFalse(destination.exists())

    def test_fails_closed_when_candidate_is_not_reachable_from_trusted_ref(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "checkout"

            def run(command: list[str]) -> subprocess.CompletedProcess[str]:
                code = 1 if "merge-base" in command else 0
                stdout = (
                    self.candidate_sha + "\n"
                    if command[-2:] == ["rev-parse", "HEAD"]
                    else ""
                )
                return subprocess.CompletedProcess(command, code, stdout, "not exposed")

            with self.assertRaisesRegex(CheckoutError, "git command failed"):
                checkout_exact_sha(
                    CheckoutSpec(
                        request=self.request(),
                        remote="https://github.com/example/repo.git",
                        destination=destination,
                        allowed_root=root,
                    ),
                    run=run,
                )
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
