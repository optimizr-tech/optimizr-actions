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
    ValidationError,
    parse_args_json,
    resolve_script,
    run_validation,
    verify_trusted_candidate,
)


class RepositoryValidationTests(unittest.TestCase):
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

    def test_trusted_candidate_fetch_uses_ephemeral_token_without_argv_or_persistence(self):
        calls: list[tuple[list[str], dict[str, object]]] = []

        def fake_run(argv, **kwargs):
            calls.append((list(argv), dict(kwargs)))
            return subprocess.CompletedProcess(argv, 0)

        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"VALIDATION_GITHUB_TOKEN": "private-token-value"},
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
