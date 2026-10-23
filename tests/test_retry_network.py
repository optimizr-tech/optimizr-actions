"""Behavioral tests for the bounded registry network retry wrapper."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/container_release/retry_network.py"
SPEC = importlib.util.spec_from_file_location("retry_network", SCRIPT)
assert SPEC and SPEC.loader
retry_network = importlib.util.module_from_spec(SPEC)
sys.modules["retry_network"] = retry_network
SPEC.loader.exec_module(retry_network)


class FakeRunner:
    def __init__(self, results: list[tuple[int, str, str]]) -> None:
        self.results = list(results)
        self.calls: list[dict[str, object]] = []

    def __call__(self, argv, **kwargs):  # noqa: ANN001 - subprocess.run shape
        self.calls.append({"argv": argv, **kwargs})
        code, stdout, stderr = self.results.pop(0)
        return subprocess.CompletedProcess(argv, code, stdout, stderr)


class RetryNetworkTests(unittest.TestCase):
    def run_retry(self, results, **kwargs):
        runner = FakeRunner(results)
        sleeps: list[float] = []
        messages: list[str] = []
        result = retry_network.run_with_retry(
            ["docker", "pull", "ghcr.io/example/app@sha256:" + "a" * 64],
            label="docker pull",
            runner=runner,
            sleep=sleeps.append,
            emit=messages.append,
            **kwargs,
        )
        return result, runner, sleeps, messages

    def test_success_on_first_attempt_runs_once_without_sleep(self) -> None:
        result, runner, sleeps, messages = self.run_retry([(0, "ok\n", "")])
        self.assertEqual((0, 1, "success", "ok\n"), (result.returncode, result.attempts, result.classification, result.stdout))
        self.assertEqual(1, len(runner.calls))
        self.assertEqual([], sleeps)
        self.assertFalse(any("::" in message for message in messages))
        self.assertFalse(runner.calls[0]["check"])
        self.assertNotIn("shell", runner.calls[0])

    def test_transient_failures_retry_with_exponential_backoff_then_recover(self) -> None:
        result, runner, sleeps, messages = self.run_retry(
            [
                (1, "", "dial tcp 140.82.112.33:443: connect: no route to host"),
                (1, "", "Could not resolve host: ghcr.io"),
                (0, "digest\n", ""),
            ]
        )
        self.assertEqual((0, 3, "recovered"), (result.returncode, result.attempts, result.classification))
        self.assertEqual([5, 10], sleeps)
        self.assertEqual(3, len(runner.calls))
        self.assertTrue(any(message.startswith("::notice title=Transient network failure recovered::") for message in messages))

    def test_transient_exhaustion_fails_closed_with_classification(self) -> None:
        result, runner, sleeps, messages = self.run_retry(
            [(1, "", "i/o timeout")] * 3, attempts=3, backoff_seconds=2
        )
        self.assertEqual((1, 3, "transient_exhausted"), (result.returncode, result.attempts, result.classification))
        self.assertEqual([2, 4], sleeps)
        self.assertIn("classification=transient_exhausted, attempts=3/3, exit=1", messages[-1])
        self.assertTrue(messages[-1].startswith("::error title=Registry network operation failed::"))

    def test_permanent_failure_is_never_retried(self) -> None:
        for stderr in (
            "Error response from daemon: unauthorized: authentication required",
            "denied: permission_denied: write_package",
            "manifest unknown",
            "Error: invalid reference format",
            "unexpected status: 403 Forbidden",
        ):
            with self.subTest(stderr=stderr):
                result, runner, sleeps, messages = self.run_retry([(1, "", stderr)])
                self.assertEqual("permanent", result.classification)
                self.assertEqual(1, len(runner.calls))
                self.assertEqual([], sleeps)
                self.assertIn("classification=permanent", messages[-1])

    def test_permanent_signature_wins_over_transient_signature(self) -> None:
        result, runner, _, _ = self.run_retry([(1, "", "connection reset by peer; unauthorized")])
        self.assertEqual("permanent", result.classification)
        self.assertEqual(1, len(runner.calls))

    def test_unclassified_failure_is_not_masked_by_retry(self) -> None:
        result, runner, sleeps, messages = self.run_retry([(17, "", "something unexpected")])
        self.assertEqual((17, "unclassified"), (result.returncode, result.classification))
        self.assertEqual(1, len(runner.calls))
        self.assertEqual([], sleeps)
        self.assertIn("exit=17", messages[-1])

    def test_attempts_one_disables_retry(self) -> None:
        result, runner, sleeps, _ = self.run_retry([(1, "", "no route to host")], attempts=1)
        self.assertEqual("transient_exhausted", result.classification)
        self.assertEqual(1, len(runner.calls))
        self.assertEqual([], sleeps)

    def test_failed_attempt_stdout_is_discarded(self) -> None:
        result, _, _, _ = self.run_retry([(1, "partial", "unexpected EOF"), (0, "complete", "")])
        self.assertEqual("complete", result.stdout)

    def test_prior_failed_attempt_continues_the_budget_after_backoff(self) -> None:
        result, runner, sleeps, _ = self.run_retry(
            [(1, "", "TLS handshake timeout"), (0, "", "")], prior_failed_attempts=1
        )
        self.assertEqual((0, 3), (result.returncode, result.attempts))
        self.assertEqual(2, len(runner.calls))
        self.assertEqual([5, 10], sleeps)

    def test_prior_failed_attempt_without_budget_fails_without_running(self) -> None:
        result, runner, sleeps, messages = self.run_retry([], attempts=1, prior_failed_attempts=1)
        self.assertEqual((1, "retry_disabled"), (result.returncode, result.classification))
        self.assertEqual([], runner.calls)
        self.assertEqual([], sleeps)
        self.assertIn("classification=retry_disabled", messages[-1])

    def test_stdin_secret_is_passed_on_stdin_only(self) -> None:
        _, runner, _, messages = self.run_retry([(0, "", "")], stdin_text="s3cr3t")
        self.assertEqual("s3cr3t", runner.calls[0]["input"])
        self.assertNotIn("s3cr3t", " ".join(runner.calls[0]["argv"]))
        self.assertFalse(any("s3cr3t" in message for message in messages))

    def test_missing_executable_is_reported_and_not_retried(self) -> None:
        def missing(argv, **kwargs):  # noqa: ANN001
            raise FileNotFoundError(2, "No such file or directory", argv[0])

        messages: list[str] = []
        result = retry_network.run_with_retry(
            ["missing-binary"], label="missing", runner=missing, sleep=lambda _: None, emit=messages.append
        )
        self.assertEqual((127, 1, "unclassified"), (result.returncode, result.attempts, result.classification))

    def test_bounds_are_enforced(self) -> None:
        for kwargs in ({"attempts": 0}, {"attempts": 6}, {"backoff_seconds": -1}, {"backoff_seconds": 31}):
            with self.subTest(**kwargs), self.assertRaises(ValueError):
                retry_network.run_with_retry(["true"], label="x", runner=FakeRunner([]), **kwargs)

    def test_backoff_is_capped(self) -> None:
        self.assertEqual(60, retry_network.backoff_delay(30, 5))
        self.assertEqual(0, retry_network.backoff_delay(0, 3))


class RetryNetworkCliTests(unittest.TestCase):
    def cli(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, **(env or {})},
        )

    def test_cli_writes_stdout_file_only_on_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp, "index.json")
            ok = self.cli(
                "--label", "inspect", "--attempts", "2", "--backoff-seconds", "0",
                "--stdout-file", str(target), "--", sys.executable, "-c", "print('{\"ok\": true}')",
            )
            self.assertEqual(0, ok.returncode, ok.stderr)
            self.assertEqual('{"ok": true}\n', target.read_text(encoding="utf-8").replace("\r\n", "\n"))

            missing = Path(tmp, "never.json")
            failed = self.cli(
                "--label", "inspect", "--attempts", "2", "--backoff-seconds", "0",
                "--stdout-file", str(missing), "--", sys.executable, "-c",
                "import sys; print('partial'); sys.stderr.write('unauthorized'); sys.exit(3)",
            )
            self.assertEqual(3, failed.returncode)
            self.assertFalse(missing.exists())
            self.assertIn("classification=permanent", failed.stderr)

    def test_cli_retries_transient_and_reads_stdin_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            counter = Path(tmp, "count")
            program = (
                "import pathlib, sys\n"
                f"p = pathlib.Path({str(counter)!r})\n"
                "n = int(p.read_text()) + 1 if p.exists() else 1\n"
                "p.write_text(str(n))\n"
                "if n < 2:\n"
                "    sys.stderr.write('connect: no route to host'); sys.exit(1)\n"
                "assert sys.stdin.read() == 'token'\n"
            )
            result = self.cli(
                "--label", "docker login ghcr.io", "--attempts", "3", "--backoff-seconds", "0",
                "--stdin-env", "TEST_REGISTRY_PASSWORD", "--", sys.executable, "-c", program,
                env={"TEST_REGISTRY_PASSWORD": "token"},
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("2", counter.read_text())
            self.assertIn("succeeded on attempt 2/3", result.stderr)
            self.assertNotIn("token", result.stderr)

    def test_cli_rejects_invalid_bounds_and_missing_stdin_env(self) -> None:
        self.assertEqual(2, self.cli("--label", "x", "--attempts", "9", "--", "true").returncode)
        env = {key: value for key, value in os.environ.items() if key != "OPTIMIZR_UNSET_SECRET_FOR_TEST"}
        unset = subprocess.run(
            [sys.executable, str(SCRIPT), "--label", "x", "--stdin-env", "OPTIMIZR_UNSET_SECRET_FOR_TEST", "--", "true"],
            capture_output=True, text=True, check=False, env=env,
        )
        self.assertEqual(2, unset.returncode)


if __name__ == "__main__":
    unittest.main()
