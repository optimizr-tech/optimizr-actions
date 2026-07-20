import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from repository_validation.runner import (  # noqa: E402
    ValidationError,
    parse_args_json,
    resolve_evidence_path,
    resolve_script,
    run_validation,
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

    def test_evidence_path_must_remain_inside_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            self.assertEqual(
                resolve_evidence_path(workspace, "artifacts/evidence.json"),
                (workspace / "artifacts/evidence.json").resolve(),
            )
            with self.assertRaises(ValidationError):
                resolve_evidence_path(workspace, "../evidence.json")
            outside = workspace.parent / "outside-evidence.json"
            with self.assertRaises(ValidationError):
                resolve_evidence_path(workspace, str(outside))

    def test_run_validation_executes_argv_without_shell_and_writes_sanitized_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            output = workspace / "args.json"
            subprocess = __import__("subprocess")
            subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=workspace, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=workspace, check=True)
            script = workspace / "validate.py"
            script.write_text(
                "#!/usr/bin/env python3\n"
                "import json, pathlib, sys\n"
                "pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]))\n",
                encoding="utf-8",
            )
            script.chmod(0o700)
            subprocess.run(["git", "add", "validate.py"], cwd=workspace, check=True)
            subprocess.run(["git", "commit", "-qm", "test"], cwd=workspace, check=True)
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
            self.assertTrue(payload["workspace"]["clean_before"])
            self.assertFalse(payload["workspace"]["clean_after"])
            self.assertGreaterEqual(payload["workspace"]["changed_entries_after"], 1)
            self.assertEqual(payload["command"]["executable"], "validate.py")
            self.assertEqual(payload["command"]["argument_count"], 3)
            self.assertNotIn("hello world", evidence.read_text())
            self.assertEqual(payload["result"]["exit_code"], 0)
            self.assertNotIn("environment", payload)
            self.assertNotIn("secret-value", evidence.read_text())


if __name__ == "__main__":
    unittest.main()
