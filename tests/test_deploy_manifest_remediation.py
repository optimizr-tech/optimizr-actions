from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.deploy_manifest.remediation import RemediationError, decorate_manifest


class DeployManifestRemediationTests(unittest.TestCase):
    def test_adds_only_sanitized_remediation_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".deploy-manifests"
            root.mkdir()
            manifest = root / "immutable.json"
            last_successful = root / "last-successful.json"
            payload = {"schema_version": "1.0", "status": "success"}
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            last_successful.write_text(json.dumps(payload), encoding="utf-8")

            decorate_manifest(
                manifest=manifest,
                last_successful=last_successful,
                status="success",
                initial_result="actionable_vulnerability",
                rebuild_attempted=True,
                rebuild_result="passed",
                final_result="clean",
            )

            result = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual("actionable_vulnerability", result["security_initial_result"])
            self.assertTrue(result["security_rebuild_attempted"])
            self.assertEqual("passed", result["security_rebuild_result"])
            self.assertEqual("clean", result["security_final_result"])
            self.assertEqual(result, json.loads(last_successful.read_text(encoding="utf-8")))
            serialized = json.dumps(result).lower()
            self.assertNotIn("cve-", serialized)
            self.assertNotIn("description", serialized)

    def test_failure_does_not_replace_last_successful(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".deploy-manifests"
            root.mkdir()
            manifest = root / "immutable.json"
            last_successful = root / "last-successful.json"
            manifest.write_text('{"schema_version":"1.0","status":"failure"}', encoding="utf-8")
            last_successful.write_text('{"stable":true}', encoding="utf-8")

            decorate_manifest(
                manifest=manifest,
                last_successful=last_successful,
                status="failure",
                initial_result="actionable_vulnerability",
                rebuild_attempted=True,
                rebuild_result="failed",
                final_result="gate_error",
            )

            self.assertEqual({"stable": True}, json.loads(last_successful.read_text(encoding="utf-8")))

    def test_records_no_change_without_calling_it_remediation_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".deploy-manifests"
            root.mkdir()
            manifest = root / "immutable.json"
            last_successful = root / "last-successful.json"
            manifest.write_text('{"schema_version":"1.0","status":"failure"}', encoding="utf-8")
            last_successful.write_text('{"stable":true}', encoding="utf-8")

            decorate_manifest(
                manifest=manifest,
                last_successful=last_successful,
                status="failure",
                initial_result="actionable_vulnerability",
                rebuild_attempted=True,
                rebuild_result="no_change",
                final_result="actionable_vulnerability",
            )

            result = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual("no_change", result["security_rebuild_result"])
            self.assertEqual({"stable": True}, json.loads(last_successful.read_text(encoding="utf-8")))

    def test_rejects_unbounded_or_inconsistent_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".deploy-manifests"
            root.mkdir()
            manifest = root / "immutable.json"
            last_successful = root / "last-successful.json"
            manifest.write_text('{"schema_version":"1.0","status":"failure"}', encoding="utf-8")

            with self.assertRaises(RemediationError):
                decorate_manifest(
                    manifest=manifest,
                    last_successful=last_successful,
                    status="failure",
                    initial_result="clean",
                    rebuild_attempted=False,
                    rebuild_result="passed",
                    final_result="clean",
                )


if __name__ == "__main__":
    unittest.main()
