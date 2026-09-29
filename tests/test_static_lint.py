import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
ACTIONLINT_JSONL_FORMAT = "{{range $err := .}}{{json $err}}{{end}}"

from static_lint.runner import (
    LintError,
    discover_files,
    effective_actionlint_exit_code,
    filter_actionlint_queue_errors,
    install_spec,
    validate_concurrency_queue_contract,
    validate_exclusions,
)
import static_lint.runner as static_lint_runner


class StaticLintTests(unittest.TestCase):
    def test_install_specs_are_version_and_checksum_pinned(self):
        x64 = install_spec("x86_64")
        arm = install_spec("aarch64")
        self.assertEqual(x64["shellcheck"]["version"], "0.11.0")
        self.assertEqual(x64["actionlint"]["version"], "1.7.12")
        self.assertRegex(x64["shellcheck"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(arm["actionlint"]["sha256"], r"^[0-9a-f]{64}$")
        with self.assertRaises(LintError): install_spec("mips64")

    def test_exclusions_cannot_escape_repository(self):
        self.assertEqual(validate_exclusions("vendor/**\nfixtures/*.sh"), ["vendor/**", "fixtures/*.sh"])
        with self.assertRaises(LintError): validate_exclusions("../outside/**")

    def test_discovery_is_deterministic_and_applies_narrow_exclusions(self):
        tracked = ["scripts/z.sh", ".github/workflows/check.yml", "scripts/a.bash", ".github/actions/demo/action.yaml", "vendor/skip.sh", "README.md"]
        result = discover_files(tracked, ["vendor/**"])
        self.assertEqual(result["shell"], ["scripts/a.bash", "scripts/z.sh"])
        self.assertEqual(result["actions"], [".github/actions/demo/action.yaml", ".github/workflows/check.yml"])

    def test_concurrency_queue_contract_accepts_workflow_and_job_scopes(self):
        content = """name: CI
on: push
concurrency:
  group: workflow
  queue: max
  cancel-in-progress: false
jobs:
  verify:
    runs-on: ubuntu-latest
    concurrency:
      group: job
      queue: single
      cancel-in-progress: true
    steps: []
"""

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "ci.yml").write_text(content, encoding="utf-8")

            allowed_locations, failures = validate_concurrency_queue_contract(root, ["ci.yml"])

        self.assertEqual(failures, [])
        self.assertEqual(allowed_locations, {"ci.yml": {(5, 3), (12, 7)}})

    def test_concurrency_queue_contract_rejects_invalid_values_conflicts_and_scope(self):
        invalid_workflows = {
            "invalid-enum.yml": "concurrency:\n  group: ci\n  queue: urgent\n",
            "invalid-type.yml": "concurrency:\n  group: ci\n  queue: 42\n",
            "max-with-cancel.yml": (
                "concurrency:\n  group: ci\n  queue: max\n"
                "  cancel-in-progress: true\n"
            ),
            "max-with-expression.yml": (
                'concurrency:\n  group: ci\n  queue: max\n'
                '  cancel-in-progress: "${{ inputs.cancel }}"\n'
            ),
            "duplicate-queue.yml": (
                "concurrency:\n  group: ci\n  queue: single\n  queue: max\n"
            ),
            "duplicate-cancel.yml": (
                "concurrency:\n  group: ci\n  queue: max\n"
                "  cancel-in-progress: false\n  cancel-in-progress: false\n"
            ),
            "merged-cancel.yml": (
                "defaults: &defaults\n  cancel-in-progress: true\n"
                "concurrency:\n  <<: *defaults\n  group: ci\n  queue: max\n"
            ),
            "invalid-yaml.yml": "concurrency:\n  queue: [\n",
            "wrong-scope.yml": (
                "jobs:\n  verify:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - name: Invalid\n        queue: max\n"
            ),
        }

        for relative_path, content in invalid_workflows.items():
            with self.subTest(workflow=relative_path):
                with TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory)
                    (root / relative_path).write_text(content, encoding="utf-8")

                    allowed_locations, failures = validate_concurrency_queue_contract(
                        root,
                        [relative_path],
                    )

                self.assertEqual(allowed_locations, {})
                self.assertTrue(failures)

    def test_actionlint_filter_only_suppresses_validated_queue_error_location(self):
        valid_error = {
            "Message": 'unexpected key "queue" for "concurrency" section',
            "Filepath": "ci.yml",
            "Line": 5,
            "Column": 3,
            "Kind": "syntax-check",
        }
        unrelated_errors = [
            {
                **valid_error,
                "Line": 5,
                "Column": 10,
            },
            {
                **valid_error,
                "Message": 'unexpected key "unknown"',
            },
            {
                **valid_error,
                "Filepath": "other.yml",
            },
        ]
        raw_output = "\n".join(
            json.dumps(error) for error in [valid_error, *unrelated_errors]
        ) + "\n"

        filtered_output, suppressed_count, parseable = filter_actionlint_queue_errors(
            raw_output,
            {"ci.yml": {(5, 3)}},
        )

        self.assertEqual(suppressed_count, 1)
        self.assertTrue(parseable)
        self.assertEqual(
            [json.loads(line) for line in filtered_output.splitlines()],
            unrelated_errors,
        )

    def test_actionlint_effective_status_requires_only_valid_queue_diagnostics(self):
        self.assertEqual(effective_actionlint_exit_code(1, "", 1, True), 0)
        self.assertEqual(effective_actionlint_exit_code(1, "other error\n", 1, True), 1)
        self.assertEqual(effective_actionlint_exit_code(1, "", 1, False), 1)
        self.assertEqual(effective_actionlint_exit_code(2, "", 1, True), 2)

    def test_actionlint_filter_fails_closed_on_non_json_output(self):
        filtered_output, suppressed_count, parseable = filter_actionlint_queue_errors(
            "not-json\n",
            {"ci.yml": {(5, 3)}},
        )

        self.assertEqual(filtered_output, "not-json\n")
        self.assertEqual(suppressed_count, 0)
        self.assertFalse(parseable)
        self.assertEqual(
            effective_actionlint_exit_code(0, filtered_output, suppressed_count, parseable),
            2,
        )

    def test_run_lints_accepts_actionlint_empty_jsonl_output(self):
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workflow = root / ".github/workflows/ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("name: CI\non: push\n", encoding="utf-8")
            evidence_dir = root / "artifacts/static-lint"
            tracked = b".github/workflows/ci.yml\0"

            def fake_run(argv, *, cwd, capture_output, text=False, check=False):
                if argv[:3] == ["git", "ls-files", "-z"]:
                    return subprocess.CompletedProcess(argv, 0, stdout=tracked)
                if argv[0] == "shellcheck":
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout="ShellCheck - version 0.11.0\nlicense info\n",
                        stderr="",
                    )
                if argv[0] == "actionlint" and argv[1] == "-version":
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout="actionlint 1.7.12\n",
                        stderr="",
                    )
                if argv[0] == "actionlint":
                    self.assertEqual(
                        argv[1:3],
                        ["-format", ACTIONLINT_JSONL_FORMAT],
                    )
                    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
                self.fail(f"unexpected subprocess: {argv}")

            with patch("static_lint.runner.subprocess.run", side_effect=fake_run):
                status = static_lint_runner.run_lints(
                    root=root,
                    shellcheck=Path("shellcheck"),
                    actionlint=Path("actionlint"),
                    severity="warning",
                    exclusions=[],
                    evidence_dir=evidence_dir,
                )

            self.assertEqual(status, 0)
            self.assertEqual(
                (evidence_dir / "actionlint.jsonl").read_text(encoding="utf-8"),
                "",
            )
            self.assertEqual(
                (evidence_dir / "actionlint.filtered.jsonl").read_text(encoding="utf-8"),
                "",
            )
            evidence = json.loads((evidence_dir / "evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(
                evidence["commands"]["actionlint"],
                {
                    "exit_code": 0,
                    "effective_exit_code": 0,
                    "suppressed_queue_diagnostics": 0,
                },
            )

    def test_run_lints_preserves_raw_queue_diagnostic_and_uses_filtered_status(self):
        diagnostic = {
            "Message": 'unexpected key "queue" for "concurrency" section',
            "Filepath": ".github/workflows/ci.yml",
            "Line": 5,
            "Column": 3,
            "Kind": "syntax-check",
        }

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workflow = root / ".github/workflows/ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "name: CI\non: push\nconcurrency:\n  group: ci\n  queue: max\n"
                "  cancel-in-progress: false\n",
                encoding="utf-8",
            )
            evidence_dir = root / "artifacts/static-lint"
            tracked = b".github/workflows/ci.yml\0"
            actionlint_output = json.dumps(diagnostic) + "\n"

            def fake_run(argv, *, cwd, capture_output, text=False, check=False):
                if argv[:3] == ["git", "ls-files", "-z"]:
                    return subprocess.CompletedProcess(argv, 0, stdout=tracked)
                if argv[0] == "shellcheck":
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout="ShellCheck - version 0.11.0\nlicense info\n",
                        stderr="",
                    )
                if argv[0] == "actionlint" and argv[1] == "-version":
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout="actionlint 1.7.12\n",
                        stderr="",
                    )
                if argv[0] == "actionlint":
                    self.assertEqual(
                        argv[1:3],
                        ["-format", ACTIONLINT_JSONL_FORMAT],
                    )
                    return subprocess.CompletedProcess(
                        argv,
                        1,
                        stdout=actionlint_output,
                        stderr="",
                    )
                self.fail(f"unexpected subprocess: {argv}")

            with patch("static_lint.runner.subprocess.run", side_effect=fake_run):
                status = static_lint_runner.run_lints(
                    root=root,
                    shellcheck=Path("shellcheck"),
                    actionlint=Path("actionlint"),
                    severity="warning",
                    exclusions=[],
                    evidence_dir=evidence_dir,
                )

            self.assertEqual(status, 0)
            self.assertEqual(
                json.loads((evidence_dir / "actionlint.jsonl").read_text(encoding="utf-8")),
                diagnostic,
            )
            self.assertEqual(
                (evidence_dir / "actionlint.filtered.jsonl").read_text(encoding="utf-8"),
                "",
            )
            evidence = json.loads((evidence_dir / "evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(
                evidence["commands"]["actionlint"],
                {
                    "exit_code": 1,
                    "effective_exit_code": 0,
                    "suppressed_queue_diagnostics": 1,
                },
            )


if __name__ == "__main__": unittest.main()
