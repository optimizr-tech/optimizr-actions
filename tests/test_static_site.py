import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from static_site.runner import DeployError, DeploySpec, deploy_static_site


class StaticSiteTests(unittest.TestCase):
    def test_spec_rejects_traversal_and_unsafe_identifiers(self):
        with self.assertRaises(DeployError):
            DeploySpec.from_mapping({
                "version": 1,
                "service_name": "site",
                "source_path": "../outside",
                "deploy_root": "/opt/site",
                "allowed_root": "/opt",
                "compose_file": "docker-compose.yml",
                "builder_service": "builder && id",
                "static_volume": "site_static",
                "output_mount_path": "/output",
                "required_outputs": ["index.html"],
            })

    def _fake_docker(self, root: Path) -> tuple[Path, Path]:
        bin_dir = root / "bin"
        bin_dir.mkdir()
        log = root / "docker.jsonl"
        docker = bin_dir / "docker"
        docker.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "with open(os.environ['DOCKER_LOG'], 'a', encoding='utf-8') as fh: fh.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "args=sys.argv[1:]\n"
            "if args[:2] == ['compose','--project-directory'] and 'images' in args: print('sha256:builder')\n"
            "if os.environ.get('FAIL_BUILDER') == '1' and 'compose' in args and 'run' in args: raise SystemExit(7)\n"
        )
        docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
        return bin_dir, log

    def _spec(self, root: Path) -> DeploySpec:
        return DeploySpec.from_mapping({
            "version": 1,
            "service_name": "marketing-site",
            "source_path": "source",
            "deploy_root": str(root / "deploy" / "marketing-site"),
            "allowed_root": str(root / "deploy"),
            "compose_file": "docker-compose.yml",
            "builder_service": "builder",
            "static_volume": "marketing_static",
            "output_mount_path": "/output",
            "required_outputs": ["index.html", "assets/app.js"],
        })

    def test_success_uses_candidate_backup_and_fixed_argv_then_promotes_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            source = workspace / "source"
            source.mkdir(parents=True)
            (source / "docker-compose.yml").write_text("services: {}")
            (source / "new.txt").write_text("new")
            deploy_root = root / "deploy" / "marketing-site"
            deploy_root.mkdir(parents=True)
            (deploy_root / "old.txt").write_text("old")
            bin_dir, log = self._fake_docker(root)
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{bin_dir}{os.pathsep}{old_path}"
            os.environ["DOCKER_LOG"] = str(log)
            try:
                result = deploy_static_site(
                    spec=self._spec(root),
                    workspace=workspace,
                    deployed_sha="a" * 40,
                    docker_mode="direct",
                    evidence_path=workspace / "artifacts" / "evidence.json",
                )
            finally:
                os.environ["PATH"] = old_path
                os.environ.pop("DOCKER_LOG", None)
            self.assertEqual(result["result"], "passed")
            self.assertTrue((deploy_root / "new.txt").is_file())
            self.assertFalse((deploy_root / "old.txt").exists())
            commands = [json.loads(line) for line in log.read_text().splitlines()]
            flattened = json.dumps(commands)
            self.assertIn("marketing_static-candidate-aaaaaaaaaaaa", flattened)
            self.assertIn("marketing_static-backup-aaaaaaaaaaaa", flattened)
            self.assertNotIn("sh", [part for command in commands for part in command])
            self.assertNotIn("-c", [part for command in commands for part in command])
            evidence = (workspace / "artifacts" / "evidence.json").read_text()
            self.assertNotIn(str(root), evidence)
            self.assertIn("sha256:builder", evidence)

    def test_builder_failure_keeps_old_source_and_writes_failed_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            source = workspace / "source"
            source.mkdir(parents=True)
            (source / "docker-compose.yml").write_text("services: {}")
            deploy_root = root / "deploy" / "marketing-site"
            deploy_root.mkdir(parents=True)
            (deploy_root / "old.txt").write_text("old")
            bin_dir, log = self._fake_docker(root)
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{bin_dir}{os.pathsep}{old_path}"
            os.environ["DOCKER_LOG"] = str(log)
            os.environ["FAIL_BUILDER"] = "1"
            try:
                with self.assertRaises(DeployError):
                    deploy_static_site(
                        spec=self._spec(root),
                        workspace=workspace,
                        deployed_sha="b" * 40,
                        docker_mode="direct",
                        evidence_path=workspace / "artifacts" / "evidence.json",
                    )
            finally:
                os.environ["PATH"] = old_path
                os.environ.pop("DOCKER_LOG", None)
                os.environ.pop("FAIL_BUILDER", None)
            self.assertTrue((deploy_root / "old.txt").is_file())
            payload = json.loads((workspace / "artifacts" / "evidence.json").read_text())
            self.assertEqual(payload["result"], "failed")


if __name__ == "__main__":
    unittest.main()
