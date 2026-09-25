import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from repository_validation.runner import (  # noqa: E402
    RETRYABLE_EXIT_CODE,
    ValidationError,
    parse_args_json,
    resolve_script,
    repair_workspace,
    run_validation,
    verify_workspace,
    verify_trusted_candidate,
)


class RepositoryValidationTests(unittest.TestCase):
    def test_repair_workspace_materializes_missing_paths_and_rechecks_integrity(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"GIT_CONFIG_COUNT": "0"}, clear=False
        ), patch("repository_validation.runner.subprocess.run") as run:
            workspace = Path(tmp)
            calls = []

            def fake_run(argv, **kwargs):
                calls.append(list(argv))
                if argv[1:] == ["checkout", "--force", "a" * 40, "--", "."]:
                    (workspace / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
                if argv[1:3] == ["rev-parse", "HEAD"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="a" * 40 + "\n")
                if argv[1:3] == ["rev-parse", "--show-toplevel"]:
                    return subprocess.CompletedProcess(
                        argv, 0, stdout=str(workspace) + "\n"
                    )
                if argv[1:3] == ["status", "--porcelain"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="")
                return subprocess.CompletedProcess(argv, 0, stdout="")

            run.side_effect = fake_run

            result = repair_workspace(
                workspace=workspace,
                expected_sha="a" * 40,
                required_paths=["pyproject.toml"],
                github_token="private-token-value",
            )

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["repair"], "applied")
        self.assertIn(
            ["git", "sparse-checkout", "disable"],
            calls,
        )
        self.assertIn(
            ["git", "checkout", "--force", "a" * 40, "--", "."],
            calls,
        )
        repair_calls = [
            call for call in run.call_args_list
            if call.args[0][1:] in (
                ["sparse-checkout", "disable"],
                ["checkout", "--force", "a" * 40, "--", "."],
            )
        ]
        self.assertEqual(len(repair_calls), 2)
        for call in repair_calls:
            env = call.kwargs["env"]
            self.assertNotIn("VALIDATION_GITHUB_TOKEN", env)
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertNotIn("private-token-value", str(env))
            self.assertTrue(
                str(env["GIT_CONFIG_VALUE_0"]).startswith("AUTHORIZATION: basic ")
            )

    def test_repair_workspace_requires_a_token_before_fetching_missing_objects(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"GIT_CONFIG_COUNT": "0"}, clear=False
        ), patch("repository_validation.runner.subprocess.run") as run:
            workspace = Path(tmp)
            calls = []

            def fake_run(argv, **kwargs):
                calls.append(list(argv))
                if argv[1:3] == ["rev-parse", "HEAD"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="a" * 40 + "\n")
                if argv[1:3] == ["rev-parse", "--show-toplevel"]:
                    return subprocess.CompletedProcess(
                        argv, 0, stdout=str(workspace) + "\n"
                    )
                if argv[1:3] == ["status", "--porcelain"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="")
                return subprocess.CompletedProcess(argv, 0, stdout="")

            run.side_effect = fake_run

            with self.assertRaisesRegex(ValidationError, "requires a GitHub token"):
                repair_workspace(
                    workspace=workspace,
                    expected_sha="a" * 40,
                    required_paths=["pyproject.toml"],
                )

        self.assertNotIn(["git", "sparse-checkout", "disable"], calls)
        self.assertFalse(any(call[1:2] == ["checkout"] for call in calls))

    def test_repair_workspace_never_overwrites_a_dirty_worktree(self):
        with tempfile.TemporaryDirectory() as tmp, patch(
            "repository_validation.runner.subprocess.run"
        ) as run:
            workspace = Path(tmp)
            calls = []

            def fake_run(argv, **kwargs):
                calls.append(list(argv))
                if argv[1:3] == ["rev-parse", "HEAD"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="a" * 40 + "\n")
                if argv[1:3] == ["rev-parse", "--show-toplevel"]:
                    return subprocess.CompletedProcess(
                        argv, 0, stdout=str(workspace) + "\n"
                    )
                if argv[1:3] == ["status", "--porcelain"]:
                    return subprocess.CompletedProcess(argv, 0, stdout=" M app.py\n")
                return subprocess.CompletedProcess(argv, 0, stdout="")

            run.side_effect = fake_run

            with self.assertRaisesRegex(ValidationError, "checkout is not clean"):
                repair_workspace(
                    workspace=workspace,
                    expected_sha="a" * 40,
                    required_paths=["pyproject.toml"],
                )

        self.assertNotIn(["git", "sparse-checkout", "disable"], calls)
        self.assertFalse(any(call[1:2] == ["checkout"] for call in calls))

    def test_verify_workspace_accepts_exact_clean_checkout_and_required_paths(self):
        with tempfile.TemporaryDirectory() as tmp, patch(
            "repository_validation.runner.subprocess.run"
        ) as run:
            workspace = Path(tmp)
            (workspace / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
            run.side_effect = [
                subprocess.CompletedProcess(
                    ["git", "rev-parse", "HEAD"], 0, stdout="a" * 40 + "\n"
                ),
                subprocess.CompletedProcess(
                    ["git", "rev-parse", "--show-toplevel"],
                    0,
                    stdout=str(workspace) + "\n",
                ),
                subprocess.CompletedProcess(
                    ["git", "status", "--porcelain", "--untracked-files=all"],
                    0,
                    stdout="",
                ),
            ]

            result = verify_workspace(
                workspace=workspace,
                expected_sha="a" * 40,
                required_paths=["pyproject.toml"],
            )

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["actual_sha"], "a" * 40)
        self.assertEqual(result["required_paths"], ["pyproject.toml"])

    def test_verify_workspace_fails_when_checkout_does_not_materialize_required_path(self):
        with tempfile.TemporaryDirectory() as tmp, patch(
            "repository_validation.runner.subprocess.run"
        ) as run:
            workspace = Path(tmp)
            run.side_effect = [
                subprocess.CompletedProcess(
                    ["git", "rev-parse", "HEAD"], 0, stdout="a" * 40 + "\n"
                ),
                subprocess.CompletedProcess(
                    ["git", "rev-parse", "--show-toplevel"],
                    0,
                    stdout=str(workspace) + "\n",
                ),
                subprocess.CompletedProcess(
                    ["git", "status", "--porcelain", "--untracked-files=all"],
                    0,
                    stdout="",
                ),
            ]

            with self.assertRaisesRegex(
                ValidationError, "required checkout path is missing: pyproject.toml"
            ):
                verify_workspace(
                    workspace=workspace,
                    expected_sha="a" * 40,
                    required_paths=["pyproject.toml"],
                )

    def test_verify_workspace_fails_when_persistent_worktree_is_dirty(self):
        with tempfile.TemporaryDirectory() as tmp, patch(
            "repository_validation.runner.subprocess.run"
        ) as run:
            workspace = Path(tmp)
            run.side_effect = [
                subprocess.CompletedProcess(
                    ["git", "rev-parse", "HEAD"], 0, stdout="a" * 40 + "\n"
                ),
                subprocess.CompletedProcess(
                    ["git", "rev-parse", "--show-toplevel"],
                    0,
                    stdout=str(workspace) + "\n",
                ),
                subprocess.CompletedProcess(
                    ["git", "status", "--porcelain", "--untracked-files=all"],
                    0,
                    stdout=" D pyproject.toml\n",
                ),
            ]

            with self.assertRaisesRegex(ValidationError, "checkout is not clean"):
                verify_workspace(
                    workspace=workspace,
                    expected_sha="a" * 40,
                )

    def test_parse_args_accepts_only_bounded_string_array(self):
        self.assertEqual(parse_args_json('["--check", "value"]'), ["--check", "value"])
        for invalid in ('{"x": 1}', '[1]', '["bad\\u0000value"]'):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                parse_args_json(invalid)

    def test_resolve_script_rejects_escape_symlink_and_non_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            script = workspace / "validate.sh"
            script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            with self.assertRaises(ValidationError):
                resolve_script(workspace, "validate.sh")
            script.chmod(0o700)
            self.assertEqual(resolve_script(workspace, "validate.sh"), script.resolve())
            with self.assertRaises(ValidationError):
                resolve_script(workspace, "../outside.sh")
            link = workspace / "linked.sh"
            link.symlink_to(script)
            with self.assertRaises(ValidationError):
                resolve_script(workspace, "linked.sh")

    def test_run_validation_executes_argv_without_shell_and_writes_sanitized_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            output = workspace / "args.json"
            script = workspace / "validate.py"
            script.write_text(
                "#!/usr/bin/env python3\n"
                "import json, pathlib, sys\n"
                "pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]))\n",
                encoding="utf-8",
            )
            script.chmod(0o700)
            evidence = workspace / "evidence.json"
            os.environ["SHOULD_NOT_APPEAR"] = "secret-value"
            status = run_validation(
                workspace=workspace,
                script_path="validate.py",
                args=[str(output), "hello world", "$(touch nope)"],
                evidence_path=evidence,
                repository="optimizr/example",
                head_sha="a" * 40,
                base_sha="b" * 40,
                timeout_seconds=10,
            )
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output.read_text()), ["hello world", "$(touch nope)"])
            payload = json.loads(evidence.read_text())
            self.assertEqual(payload["command"]["executable"], "validate.py")
            self.assertEqual(payload["command"]["argument_count"], 3)
            self.assertNotIn("hello world", evidence.read_text())
            self.assertEqual(payload["result"]["exit_code"], 0)
            self.assertNotIn("environment", payload)
            self.assertNotIn("secret-value", evidence.read_text())

    def test_run_validation_accepts_two_hour_command_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            script = workspace / "validate.sh"
            script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            script.chmod(0o700)

            with patch(
                "repository_validation.runner.subprocess.run",
                return_value=subprocess.CompletedProcess(["validate.sh"], 0),
            ) as run_process, patch(
                "repository_validation.runner.collect_versions", return_value={}
            ):
                status = run_validation(
                    workspace=workspace,
                    script_path="validate.sh",
                    args=[],
                    evidence_path=workspace / "evidence.json",
                    repository="optimizr/example",
                    head_sha="a" * 40,
                    base_sha="",
                    timeout_seconds=7200,
                )

            self.assertEqual(status, 0)
            self.assertEqual(run_process.call_args.kwargs["timeout"], 7200)

    def test_run_validation_rejects_command_budget_above_two_hours(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)

            with self.assertRaisesRegex(ValidationError, "1 and 7200"):
                run_validation(
                    workspace=workspace,
                    script_path="validate.sh",
                    args=[],
                    evidence_path=workspace / "evidence.json",
                    repository="optimizr/example",
                    head_sha="a" * 40,
                    base_sha="",
                    timeout_seconds=7201,
                )

    def test_retry_is_opt_in_and_only_retries_the_reserved_transient_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            script = workspace / "validate.py"
            script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            script.chmod(0o700)
            evidence = workspace / "evidence.json"
            statuses = iter([RETRYABLE_EXIT_CODE, 0])

            def fake_run(argv, **kwargs):
                return subprocess.CompletedProcess(argv, next(statuses))

            with patch(
                "repository_validation.runner.subprocess.run", side_effect=fake_run
            ), patch(
                "repository_validation.runner.collect_versions", return_value={}
            ), patch(
                "repository_validation.runner.collect_image_identities", return_value=[]
            ):
                status = run_validation(
                    workspace=workspace,
                    script_path="validate.py",
                    args=[],
                    evidence_path=evidence,
                    repository="optimizr/example",
                    head_sha="a" * 40,
                    base_sha="",
                    timeout_seconds=10,
                    retry_attempts=2,
                    retry_backoff_seconds=0,
                )

            self.assertEqual(status, 0)
            payload = json.loads(evidence.read_text())
            self.assertEqual(payload["result"]["status"], "passed")
            self.assertEqual(payload["result"]["failure_kind"], "none")
            self.assertEqual(payload["result"]["attempt_count"], 2)
            self.assertEqual(
                [attempt["exit_code"] for attempt in payload["result"]["attempts"]],
                [RETRYABLE_EXIT_CODE, 0],
            )

    def test_non_retryable_failure_is_not_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            script = workspace / "validate.py"
            script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            script.chmod(0o700)
            evidence = workspace / "evidence.json"
            calls = 0

            def fake_run(argv, **kwargs):
                nonlocal calls
                calls += 1
                return subprocess.CompletedProcess(argv, 2)

            with patch(
                "repository_validation.runner.subprocess.run", side_effect=fake_run
            ), patch(
                "repository_validation.runner.collect_versions", return_value={}
            ), patch(
                "repository_validation.runner.collect_image_identities", return_value=[]
            ):
                status = run_validation(
                    workspace=workspace,
                    script_path="validate.py",
                    args=[],
                    evidence_path=evidence,
                    repository="optimizr/example",
                    head_sha="a" * 40,
                    base_sha="",
                    timeout_seconds=10,
                    retry_attempts=3,
                )

            self.assertEqual(status, 2)
            payload = json.loads(evidence.read_text())
            self.assertEqual(calls, 1)
            self.assertEqual(payload["result"]["failure_kind"], "command_failed")
            self.assertEqual(payload["result"]["attempt_count"], 1)

    def test_exhausted_transient_retry_remains_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            script = workspace / "validate.py"
            script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            script.chmod(0o700)
            evidence = workspace / "evidence.json"

            with patch(
                "repository_validation.runner.subprocess.run",
                side_effect=lambda argv, **kwargs: subprocess.CompletedProcess(
                    argv, RETRYABLE_EXIT_CODE
                ),
            ), patch(
                "repository_validation.runner.collect_versions", return_value={}
            ), patch(
                "repository_validation.runner.collect_image_identities", return_value=[]
            ):
                status = run_validation(
                    workspace=workspace,
                    script_path="validate.py",
                    args=[],
                    evidence_path=evidence,
                    repository="optimizr/example",
                    head_sha="a" * 40,
                    base_sha="",
                    timeout_seconds=10,
                    retry_attempts=2,
                    retry_backoff_seconds=0,
                )

            payload = json.loads(evidence.read_text())
            self.assertEqual(status, RETRYABLE_EXIT_CODE)
            self.assertEqual(payload["result"]["status"], "failed")
            self.assertEqual(payload["result"]["failure_kind"], "retryable_dependency")
            self.assertTrue(payload["result"]["retry_exhausted"])
            self.assertEqual(payload["result"]["attempt_count"], 2)

    def test_timeout_is_not_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            script = workspace / "validate.py"
            script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            script.chmod(0o700)
            evidence = workspace / "evidence.json"
            calls = 0

            def fake_run(argv, **kwargs):
                nonlocal calls
                calls += 1
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

            with patch(
                "repository_validation.runner.subprocess.run", side_effect=fake_run
            ), patch(
                "repository_validation.runner.collect_versions", return_value={}
            ), patch(
                "repository_validation.runner.collect_image_identities", return_value=[]
            ):
                status = run_validation(
                    workspace=workspace,
                    script_path="validate.py",
                    args=[],
                    evidence_path=evidence,
                    repository="optimizr/example",
                    head_sha="a" * 40,
                    base_sha="",
                    timeout_seconds=10,
                    retry_attempts=3,
                    retry_backoff_seconds=0,
                )

            payload = json.loads(evidence.read_text())
            self.assertEqual(status, 124)
            self.assertEqual(calls, 1)
            self.assertEqual(payload["result"]["failure_kind"], "timeout")
            self.assertEqual(payload["result"]["attempt_count"], 1)

    def test_retry_attempts_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            script = workspace / "validate.py"
            script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            script.chmod(0o700)
            for retry_attempts in (0, 4):
                with self.subTest(retry_attempts=retry_attempts), self.assertRaises(
                    ValidationError
                ):
                    run_validation(
                        workspace=workspace,
                        script_path="validate.py",
                        args=[],
                        evidence_path=workspace / "evidence.json",
                        repository="optimizr/example",
                        head_sha="a" * 40,
                        base_sha="",
                        timeout_seconds=10,
                        retry_attempts=retry_attempts,
                    )

    def test_trusted_candidate_fetch_uses_ephemeral_token_without_argv_or_persistence(self):
        calls: list[tuple[list[str], dict[str, object]]] = []

        def fake_run(argv, **kwargs):
            calls.append((list(argv), dict(kwargs)))
            return subprocess.CompletedProcess(argv, 0)

        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"VALIDATION_GITHUB_TOKEN": "private-token-value", "GIT_CONFIG_COUNT": "0"},
            clear=False,
        ), patch(
            "repository_validation.runner.subprocess.run", side_effect=fake_run
        ):
            verify_trusted_candidate(
                Path(tmp),
                "a" * 40,
                "refs/heads/main",
                github_token="private-token-value",
            )

        self.assertEqual(len(calls), 2)
        fetch_argv, fetch_kwargs = calls[0]
        self.assertEqual(
            fetch_argv,
            ["git", "fetch", "--no-tags", "origin", "refs/heads/main"],
        )
        self.assertNotIn("private-token-value", " ".join(fetch_argv))
        fetch_env = fetch_kwargs["env"]
        self.assertIsInstance(fetch_env, dict)
        self.assertNotIn("VALIDATION_GITHUB_TOKEN", fetch_env)
        self.assertEqual(fetch_env["GIT_CONFIG_COUNT"], "1")
        self.assertEqual(
            fetch_env["GIT_CONFIG_KEY_0"],
            "http.https://github.com/.extraheader",
        )
        self.assertTrue(
            str(fetch_env["GIT_CONFIG_VALUE_0"]).startswith("AUTHORIZATION: basic ")
        )
        self.assertNotIn("private-token-value", str(fetch_env["GIT_CONFIG_VALUE_0"]))

        merge_argv, merge_kwargs = calls[1]
        self.assertEqual(merge_argv[:3], ["git", "merge-base", "--is-ancestor"])
        self.assertNotIn("env", merge_kwargs)


if __name__ == "__main__":
    unittest.main()
