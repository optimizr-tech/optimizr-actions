"""Tests for the portable local validation contract."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LocalValidationRunnerTests(unittest.TestCase):
    def test_runner_records_a_successful_required_command(self) -> None:
        from scripts.local_validation.run import main

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            code = main(
                [
                    "--preset",
                    str(ROOT / "presets" / "fiscal.json"),
                    "--evidence",
                    str(evidence),
                    "--allow-dirty",
                    "--service", "postgres=18@sha256:postgres",
                    "--service", "rabbitmq=4.3@sha256:rabbitmq",
                    "--service", "minio=RELEASE.2026@sha256:minio",
                    "--service", "keycloak=26@sha256:keycloak",
                    "--",
                    sys.executable,
                    "-c",
                    "pass",
                ]
            )
            payload = json.loads(evidence.read_text(encoding="utf-8"))

        self.assertEqual(0, code)
        self.assertEqual("passed", payload["result"])
        self.assertEqual(0, payload["commands"][0]["exit_code"])
        self.assertIn("head_sha", payload["repository"])
        self.assertEqual("sha256:postgres", payload["services"]["postgres"]["digest"])
        self.assertNotIn("environment", payload)

    def test_runner_fails_closed_when_a_required_service_is_unknown(self) -> None:
        from scripts.local_validation.run import main

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            code = main(
                [
                    "--preset",
                    str(ROOT / "presets" / "fiscal.json"),
                    "--evidence",
                    str(evidence),
                    "--allow-dirty",
                ]
            )
            payload = json.loads(evidence.read_text(encoding="utf-8"))

        self.assertEqual(1, code)
        self.assertEqual("failed", payload["result"])
        self.assertIn("postgres", payload["unresolved_gaps"])


if __name__ == "__main__":
    unittest.main()
