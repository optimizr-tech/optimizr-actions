from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import yaml

from scripts.security_gate.rebuild import RebuildError, run_remediation


ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github" / "actions" / "security-rebuild" / "action.yml"


class SecurityRebuildRuntimeTests(unittest.TestCase):
    def test_executes_one_fixed_pull_and_required_rebuild(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            allowed_root = Path(temporary) / "optimizr"
            deploy_path = allowed_root / "service"
            deploy_path.mkdir(parents=True)
            (deploy_path / "docker-compose.yml").write_text(
                "services: {}\n", encoding="utf-8"
            )
            calls: list[tuple[list[str], Path]] = []

            def runner(argv: list[str], cwd: Path) -> int:
                calls.append((list(argv), cwd))
                return 0

            result = run_remediation(
                deploy_path=deploy_path,
                compose_file="docker-compose.yml",
                build_all=False,
                required_services="api worker",
                optional_services="",
                no_cache=True,
                allowed_root=allowed_root,
                runner=runner,
            )

            self.assertEqual("skipped", result)
            self.assertEqual(
                [
                    [
                        "sudo",
                        "docker",
                        "compose",
                        "-f",
                        "docker-compose.yml",
                        "pull",
                        "--ignore-buildable",
                    ],
                    [
                        "sudo",
                        "docker",
                        "compose",
                        "-f",
                        "docker-compose.yml",
                        "build",
                        "--pull",
                        "--no-cache",
                        "api",
                    ],
                    [
                        "sudo",
                        "docker",
                        "compose",
                        "-f",
                        "docker-compose.yml",
                        "build",
                        "--pull",
                        "--no-cache",
                        "worker",
                    ],
                ],
                [argv for argv, _cwd in calls],
            )
            self.assertTrue(all(cwd == deploy_path for _argv, cwd in calls))

    def test_optional_failure_is_non_blocking_and_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            allowed_root = Path(temporary) / "optimizr"
            deploy_path = allowed_root / "service"
            deploy_path.mkdir(parents=True)
            (deploy_path / "compose.yml").write_text(
                "services: {}\n", encoding="utf-8"
            )

            def runner(argv: list[str], _cwd: Path) -> int:
                return 1 if argv[-1] == "optional" else 0

            result = run_remediation(
                deploy_path=deploy_path,
                compose_file="compose.yml",
                build_all=False,
                required_services="api",
                optional_services="optional",
                no_cache=False,
                allowed_root=allowed_root,
                runner=runner,
            )

            self.assertEqual("failed", result)

    def test_rejects_traversal_and_invalid_service_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            allowed_root = Path(temporary) / "optimizr"
            deploy_path = allowed_root / "service"
            deploy_path.mkdir(parents=True)
            outside = Path(temporary) / "outside.yml"
            outside.write_text("services: {}\n", encoding="utf-8")

            with self.assertRaises(RebuildError):
                run_remediation(
                    deploy_path=deploy_path,
                    compose_file="../outside.yml",
                    build_all=False,
                    required_services="api",
                    optional_services="",
                    no_cache=True,
                    allowed_root=allowed_root,
                    runner=lambda _argv, _cwd: 0,
                )

            (deploy_path / "compose.yml").write_text(
                "services: {}\n", encoding="utf-8"
            )
            with self.assertRaises(RebuildError):
                run_remediation(
                    deploy_path=deploy_path,
                    compose_file="compose.yml",
                    build_all=False,
                    required_services="api;rm",
                    optional_services="",
                    no_cache=True,
                    allowed_root=allowed_root,
                    runner=lambda _argv, _cwd: 0,
                )

    def test_action_is_a_thin_adapter_without_shell_injection(self) -> None:
        payload = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
        script = payload["runs"]["steps"][0]["run"]

        self.assertIn("scripts/security_gate/rebuild.py", script)
        self.assertIn('"$INPUT_REQUIRED_SERVICES"', script)
        self.assertNotIn("eval ", script)
        self.assertNotIn("bash -c", script)
        self.assertNotIn("${{ inputs.command", script)


if __name__ == "__main__":
    unittest.main()
