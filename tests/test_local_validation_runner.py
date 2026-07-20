"""Tests for the repository-owned local validation contract."""

from __future__ import annotations

import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.local_validation.run import (
    ValidationError,
    evaluate_metadata,
    normalize_metadata,
    normalize_preset,
    run_validation,
)


def valid_digest(character: str) -> str:
    return "sha256:" + character * 64


class LocalValidationRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        (self.workspace / "presets").mkdir()
        (self.workspace / "scripts" / "ci").mkdir(parents=True)
        (self.workspace / "uv.lock").write_text("version = 1\n", encoding="utf-8")
        preset = json.loads((ROOT / "presets" / "fiscal.json").read_text(encoding="utf-8"))
        self.preset_path = self.workspace / "presets" / "fiscal.json"
        self.preset_path.write_text(json.dumps(preset), encoding="utf-8")

    def metadata(self) -> dict[str, object]:
        required_checks = [
            "uv-lock",
            "uv-sync",
            "ruff-check",
            "ruff-format",
            "mypy",
            "alembic-upgrade",
            "migration-rls",
            "pytest",
        ]
        conformance = [
            "separate-database-identities",
            "rls-fail-closed",
            "real-service-integration",
            "minio-object-lock",
            "recovery",
            "security",
        ]
        return {
            "schema_version": 1,
            "services": {
                "postgres": {"version": "18.1", "digest": valid_digest("a"), "kind": "real"},
                "rabbitmq": {"version": "4.3.1", "digest": valid_digest("b"), "kind": "real"},
                "minio": {
                    "version": "RELEASE.2026-07-01",
                    "digest": valid_digest("c"),
                    "kind": "real",
                },
                "keycloak": {"version": "26.4.0", "digest": valid_digest("d"), "kind": "real"},
            },
            "checks": {name: "passed" for name in required_checks},
            "conformance": {name: "passed" for name in conformance},
        }

    def write_entrypoint(self, metadata: dict[str, object], *, exit_code: int = 0) -> None:
        script = self.workspace / "scripts" / "ci" / "fiscal-local-validation.py"
        script.write_text(
            "import json, os\n"
            f"metadata = {metadata!r}\n"
            "with open(os.environ['OPTIMIZR_VALIDATION_METADATA_PATH'], 'w', encoding='utf-8') as fh:\n"
            "    json.dump(metadata, fh)\n"
            f"raise SystemExit({exit_code})\n",
            encoding="utf-8",
        )

    @staticmethod
    def git_result(_workspace: Path, *args: str) -> str:
        if args == ("status", "--porcelain"):
            return ""
        return "a" * 40

    @staticmethod
    def tool_version(tool: str) -> str:
        return {
            "python": "3.14.2",
            "git": "git version 2.50",
            "docker": "Docker version 28",
            "docker-compose": "Docker Compose version v2.39.1",
            "uv": "uv 0.8.3",
        }[tool]

    def test_success_runs_repository_entrypoint_and_redacts_argv(self) -> None:
        self.write_entrypoint(self.metadata())
        evidence = self.workspace / "artifacts" / "fiscal.json"
        with patch("scripts.local_validation.run._git", self.git_result), patch(
            "scripts.local_validation.run._tool_version", self.tool_version
        ):
            payload = run_validation(
                workspace=self.workspace,
                preset_path=self.preset_path,
                evidence_path=evidence,
                command_args=[],
                allow_dirty=False,
            )
        stored = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual("passed", payload["result"])
        self.assertEqual(payload, stored)
        self.assertEqual([], payload["unresolved_gaps"])
        self.assertEqual(valid_digest("a"), payload["services"]["postgres"]["digest"])
        self.assertEqual("uv 0.8.3", payload["tools"]["uv"])
        self.assertIn("Docker Compose version", payload["tools"]["docker-compose"])
        self.assertIn("argv_sha256", payload["command"])
        self.assertNotIn("argv", payload["command"])
        self.assertNotIn("environment", payload)
        self.assertEqual(0o600, stat.S_IMODE(evidence.stat().st_mode))

    def test_fails_closed_for_missing_digest_and_required_check(self) -> None:
        metadata = self.metadata()
        metadata["services"]["postgres"]["digest"] = "unknown"
        metadata["checks"]["migration-rls"] = "failed"
        normalized = normalize_metadata(metadata)
        preset = normalize_preset(json.loads(self.preset_path.read_text(encoding="utf-8")))
        unresolved = evaluate_metadata(preset, normalized)
        self.assertIn("postgres digest is not immutable", unresolved)
        self.assertIn("required check not passed: migration-rls", unresolved)

    def test_forbidden_service_is_reported(self) -> None:
        metadata = self.metadata()
        metadata["services"]["redis"] = {
            "version": "8.0",
            "digest": valid_digest("e"),
            "kind": "real",
        }
        preset = normalize_preset(json.loads(self.preset_path.read_text(encoding="utf-8")))
        unresolved = evaluate_metadata(preset, normalize_metadata(metadata))
        self.assertIn("forbidden service present: redis", unresolved)

    def test_rejects_traversal_and_secret_like_arguments(self) -> None:
        preset = json.loads(self.preset_path.read_text(encoding="utf-8"))
        preset["entrypoint"] = "../outside.py"
        with self.assertRaises(ValidationError):
            normalize_preset(preset)
        from scripts.local_validation.run import _parse_args_json

        with self.assertRaises(ValidationError):
            _parse_args_json('["token=abc"]')

    def test_entrypoint_failure_preserves_failure_evidence(self) -> None:
        self.write_entrypoint(self.metadata(), exit_code=7)
        evidence = self.workspace / "artifacts" / "failure.json"
        with patch("scripts.local_validation.run._git", self.git_result), patch(
            "scripts.local_validation.run._tool_version", self.tool_version
        ):
            payload = run_validation(
                workspace=self.workspace,
                preset_path=self.preset_path,
                evidence_path=evidence,
                command_args=[],
                allow_dirty=False,
            )
        self.assertEqual("failed", payload["result"])
        self.assertEqual(7, payload["command"]["exit_code"])
        self.assertIn("repository validation entrypoint failed", payload["unresolved_gaps"])
        self.assertTrue(evidence.is_file())


if __name__ == "__main__":
    unittest.main()
