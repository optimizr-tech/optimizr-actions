"""Runtime regressions found on the first real self-hosted runs (serve, 2026-11-28).

* config-lint: the hadolint image has no ENTRYPOINT, so passing ``--format``
  right after the image made Docker try to execute ``--format``
  (``exec: "--format": executable file not found in $PATH``).
* DAST: ZAP runs as the unprivileged ``zap`` user and could not read the
  rules/context files written by the runner user into the bind-mounted
  work directory (``PermissionError: '/zap/wrk/rules-1.conf'``).
"""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.config_lint import runner

ROOT = Path(__file__).resolve().parents[1]
DAST = ROOT / ".github/workflows/_dast-baseline.yml"


class HadolintInvocationTests(unittest.TestCase):
    def test_hadolint_binary_is_the_container_command(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout="[]", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dockerfile = root / "Dockerfile"
            dockerfile.write_text("FROM scratch\n", encoding="utf-8")
            with patch.object(runner.subprocess, "run", side_effect=fake_run):
                runner.run_hadolint(root, [dockerfile], {"fail_on": ["error"], "exceptions": []}, [])

        self.assertEqual(len(calls), 1)
        argv = calls[0]
        image_at = argv.index(runner.HADOLINT_IMAGE)
        self.assertEqual(argv[image_at + 1], "hadolint", "command after the image must be the hadolint binary")
        self.assertIn("--format", argv[image_at + 2:])


class DastWorkdirPermissionTests(unittest.TestCase):
    def setUp(self):
        self.workflow = DAST.read_text(encoding="utf-8")

    def test_zap_workdir_and_inputs_are_readable_by_the_container_user(self):
        scan_block = self.workflow[self.workflow.index("docker run --rm --network bridge"):]
        before_run = self.workflow[: self.workflow.index("docker run --rm --network bridge")]
        self.assertRegex(before_run, r"chmod\s+(?:-R\s+)?(?:0?777|a\+rwx)\s+\.dast-baseline/raw")
        self.assertRegex(before_run, r"chmod\s+(?:0?644|a\+r)\s+[^\n]*rules-\$index\.conf")
        self.assertRegex(before_run, r"chmod\s+(?:0?644|a\+r)\s+[^\n]*context-\$index\.context")
        self.assertIn("/zap/wrk/", scan_block)

    def test_missing_scan_output_marks_scanner_failed(self):
        self.assertRegex(self.workflow, re.escape('[[ ! -s ".dast-baseline/raw/raw-$index.json" ]]'))
        self.assertIn('echo "scanner_failed=$failed" >> "$GITHUB_OUTPUT"', self.workflow)


if __name__ == "__main__":
    unittest.main()
