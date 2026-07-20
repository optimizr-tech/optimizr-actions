import json
from pathlib import Path
import os
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from node_project.runner import ProjectError, ProjectSpec, execute_project, validate_relative_path


class NodeProjectRunnerTests(unittest.TestCase):
    def test_rejects_traversal_and_invalid_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ProjectError):
                validate_relative_path(root, "../outside", must_exist=False)
            with self.assertRaises(ProjectError):
                ProjectSpec.from_mapping({
                    "name": "web",
                    "working_directory": ".",
                    "package_manager": "npm",
                    "install": True,
                    "lint_script": "lint && whoami",
                })

    def test_executes_package_scripts_as_argv_and_copies_sanitized_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "app"
            project.mkdir()
            (project / "package-lock.json").write_text("{}")
            (project / "package.json").write_text('{"scripts":{"test":"ignored"}}')
            (project / "coverage").mkdir()
            (project / "coverage" / "summary.json").write_text('{"ok":true}')
            bin_dir = root / "bin"
            bin_dir.mkdir()
            log = root / "argv.jsonl"
            npm = bin_dir / "npm"
            npm.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "with open(os.environ['ARGV_LOG'], 'a', encoding='utf-8') as fh:\n"
                "    fh.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            )
            npm.chmod(npm.stat().st_mode | stat.S_IXUSR)
            spec = ProjectSpec.from_mapping({
                "name": "web",
                "working_directory": "app",
                "package_manager": "npm",
                "install": True,
                "lint_script": "lint",
                "test_script": "test",
                "artifact_paths": ["coverage/summary.json"],
            })
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{bin_dir}{os.pathsep}{old_path}"
            os.environ["ARGV_LOG"] = str(log)
            try:
                evidence = execute_project(spec, workspace=root, evidence_root=root / "artifacts")
            finally:
                os.environ["PATH"] = old_path
                os.environ.pop("ARGV_LOG", None)
            argv = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(argv, [["ci"], ["run", "lint"], ["run", "test"]])
            self.assertEqual(evidence["result"], "passed")
            copied = root / "artifacts" / "web" / "collected" / "coverage" / "summary.json"
            self.assertTrue(copied.is_file())

    def test_rejects_symlink_artifacts(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "app"
            project.mkdir()
            (project / "package.json").write_text('{"scripts":{}}')
            outside = root / "secret.txt"
            outside.write_text("secret")
            (project / "leak").symlink_to(outside)
            spec = ProjectSpec.from_mapping({
                "name": "web",
                "working_directory": "app",
                "package_manager": "npm",
                "install": False,
                "artifact_paths": ["leak"],
            })
            with self.assertRaises(ProjectError):
                execute_project(spec, workspace=root, evidence_root=root / "artifacts")


if __name__ == "__main__":
    unittest.main()
