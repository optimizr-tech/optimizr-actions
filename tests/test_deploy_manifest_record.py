"""Tests for coherent deploy-state collection and manifest recording."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from scripts.deploy_manifest.record import CollectionError, collect_state
from scripts.deploy_manifest.write import ManifestConfig, write_manifest


class Result:
    def __init__(self, returncode: int = 0, stdout: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


class DeployManifestRecordTests(unittest.TestCase):
    def test_collects_state_with_fixed_docker_argv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            deploy_path = Path(temporary)
            (deploy_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            calls: list[list[str]] = []

            def runner(argv: list[str], *, cwd: Path) -> Result:
                calls.append(list(argv))
                if argv[-2:] == ["config", "--services"]:
                    return Result(stdout="api\nworker\n")
                if argv[-2:] == ["config", "--images"]:
                    return Result(stdout="example/api:1\n")
                if "image" in argv:
                    return Result(stdout="sha256:" + "a" * 64 + "\n")
                if argv[-1] == "api-container":
                    return Result(stdout="true|healthy\n")
                return Result()

            services, images, healthchecks = collect_state(
                deploy_path=deploy_path,
                compose_file="docker-compose.yml",
                container_name="api-container",
                services="",
                docker_mode="direct",
                runner=runner,
            )

            self.assertEqual(["api", "worker"], services)
            self.assertEqual("sha256:" + "a" * 64, images[0]["digest"])
            self.assertEqual("passed", healthchecks[0]["status"])
            flattened = [argument for call in calls for argument in call]
            self.assertNotIn("sh", flattened)
            self.assertNotIn("-c", flattened)
            self.assertIn("config", flattened)
            self.assertIn("inspect", flattened)

    def test_rejects_compose_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            deploy_path = Path(temporary)
            (deploy_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            with self.assertRaises(CollectionError):
                collect_state(
                    deploy_path=deploy_path,
                    compose_file="../outside.yml",
                    container_name="api",
                    services="",
                    docker_mode="direct",
                    runner=lambda *_args, **_kwargs: Result(),
                )

    def test_optional_build_failure_is_explicit_without_replacing_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            deploy_path = Path(temporary)
            result = write_manifest(
                ManifestConfig(
                    deploy_path=deploy_path,
                    status="success",
                    repository="optimizr-tech/example",
                    deployed_sha="a" * 40,
                    deployed_ref="refs/heads/main",
                    environment="production",
                    workflow="Deploy",
                    run_id="1",
                    actor="bot",
                    runner_name="runner",
                    services=["api"],
                    images=[],
                    healthchecks=[],
                    migration_result="passed",
                    optional_build_result="failed",
                    now=dt.datetime(2026, 7, 20, tzinfo=dt.timezone.utc),
                )
            )
            payload = json.loads(result.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual("success", payload["status"])
            self.assertEqual("failed", payload["optional_build_result"])
            self.assertEqual("1.0", payload["schema_version"])


if __name__ == "__main__":
    unittest.main()
