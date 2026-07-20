"""Behavioral tests for security-gate evidence and exception policy."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

try:
    from scripts.security_gate import evidence
except ImportError:  # RED phase: implementation does not exist yet.
    evidence = None


class SecurityGateEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertIsNotNone(evidence, "scripts.security_gate.evidence must exist")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.now = datetime(2026, 7, 19, 20, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_json(self, name: str, payload: object) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_database_metadata_records_fresh_download(self) -> None:
        metadata = self._write_json(
            "metadata.json",
            {
                "Version": 2,
                "UpdatedAt": (self.now - timedelta(hours=6)).isoformat(),
                "NextUpdate": (self.now + timedelta(hours=18)).isoformat(),
                "DownloadedAt": (self.now - timedelta(hours=1)).isoformat(),
            },
        )

        result = evidence.validate_db_metadata(metadata, max_age_hours=30, now=self.now)

        self.assertEqual(result["version"], 2)
        self.assertEqual(result["age_hours"], 1.0)
        self.assertEqual(result["status"], "fresh")

    def test_database_metadata_rejects_stale_download(self) -> None:
        metadata = self._write_json(
            "metadata.json",
            {
                "Version": 2,
                "UpdatedAt": (self.now - timedelta(hours=48)).isoformat(),
                "NextUpdate": (self.now - timedelta(hours=24)).isoformat(),
                "DownloadedAt": (self.now - timedelta(hours=31)).isoformat(),
            },
        )

        with self.assertRaisesRegex(ValueError, "older than 30 hours"):
            evidence.validate_db_metadata(metadata, max_age_hours=30, now=self.now)

    def test_exception_policy_requires_owner_control_and_expiration(self) -> None:
        source = self._write_json(
            "exceptions.json",
            {
                "version": 1,
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-0001",
                        "owner": "security@example.invalid",
                        "statement": "Not reachable in the deployed configuration",
                        "compensating_control": "Ingress route blocks the vulnerable endpoint",
                        "expires": "2026-08-19",
                        "purls": ["pkg:apk/alpine/example@1.0"],
                        "targets": ["sha256:image-a"],
                    }
                ],
            },
        )
        output = self.root / "generated-ignore.yaml"

        summary = evidence.render_exception_policy(
            source,
            target="sha256:image-a",
            output=output,
            today=date(2026, 7, 19),
        )

        rendered = json.loads(output.read_text(encoding="utf-8"))
        entry = rendered["vulnerabilities"][0]
        self.assertEqual(entry["id"], "CVE-2026-0001")
        self.assertEqual(entry["expired_at"], "2026-08-19")
        self.assertIn("owner=security@example.invalid", entry["statement"])
        self.assertIn("control=Ingress route blocks", entry["statement"])
        self.assertEqual(summary["active_exceptions"], 1)
        self.assertEqual(summary["policy_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())

    def test_exception_policy_rejects_expired_or_incomplete_entries(self) -> None:
        expired = self._write_json(
            "expired.json",
            {
                "version": 1,
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-0002",
                        "owner": "security@example.invalid",
                        "statement": "Temporary acceptance",
                        "compensating_control": "Network isolation",
                        "expires": "2026-07-18",
                    }
                ],
            },
        )
        incomplete = self._write_json(
            "incomplete.json",
            {
                "version": 1,
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-0003",
                        "statement": "Missing accountable metadata",
                        "expires": "2026-08-19",
                    }
                ],
            },
        )

        with self.assertRaisesRegex(ValueError, "expired"):
            evidence.render_exception_policy(
                expired,
                target=".",
                output=self.root / "expired-output.yaml",
                today=date(2026, 7, 19),
            )
        with self.assertRaisesRegex(ValueError, "owner"):
            evidence.render_exception_policy(
                incomplete,
                target=".",
                output=self.root / "incomplete-output.yaml",
                today=date(2026, 7, 19),
            )

    def test_exception_policy_only_renders_matching_targets(self) -> None:
        source = self._write_json(
            "scoped.json",
            {
                "version": 1,
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-1000",
                        "owner": "team-a",
                        "statement": "Scoped exception",
                        "compensating_control": "Runtime policy",
                        "expires": "2026-08-19",
                        "targets": ["sha256:image-a"],
                    },
                    {
                        "id": "CVE-2026-2000",
                        "owner": "team-b",
                        "statement": "Other target",
                        "compensating_control": "Runtime policy",
                        "expires": "2026-08-19",
                        "targets": ["sha256:image-b"],
                    },
                ],
            },
        )
        output = self.root / "scoped-output.yaml"

        evidence.render_exception_policy(
            source,
            target="sha256:image-a",
            output=output,
            today=date(2026, 7, 19),
        )

        rendered = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual([item["id"] for item in rendered["vulnerabilities"]], ["CVE-2026-1000"])

    def test_image_identity_prefers_repo_digest_then_image_id(self) -> None:
        with_digest = self._write_json(
            "image-digest.json",
            {
                "Metadata": {
                    "ImageID": "sha256:local-id",
                    "RepoDigests": ["registry.example/app@sha256:repo-digest"],
                }
            },
        )
        without_digest = self._write_json(
            "image-id.json",
            {"Metadata": {"ImageID": "sha256:local-id", "RepoDigests": []}},
        )

        self.assertEqual(
            evidence.resolve_image_identity(with_digest),
            "registry.example/app@sha256:repo-digest",
        )
        self.assertEqual(evidence.resolve_image_identity(without_digest), "sha256:local-id")

    def test_write_evidence_binds_reports_to_exact_commit(self) -> None:
        table = self.root / "scan.txt"
        report = self.root / "scan.json"
        sarif = self.root / "scan.sarif"
        table.write_text("No vulnerabilities\n", encoding="utf-8")
        report.write_text('{"Results": []}\n', encoding="utf-8")
        sarif.write_text('{"runs": []}\n', encoding="utf-8")
        destination = self.root / "evidence.json"

        payload = evidence.write_evidence(
            destination,
            repository="optimizr-tech/example",
            head_sha="a" * 40,
            scan_type="image",
            target="example:build",
            identity="sha256:local-id",
            severity="HIGH,CRITICAL",
            ignore_unfixed=False,
            trivy_version="Version: 0.70.0",
            database={"status": "fresh", "age_hours": 1.0},
            exception_policy={"active_exceptions": 0, "policy_sha256": "none"},
            reports={"table": table, "json": report, "sarif": sarif},
            result="passed",
            created_at=self.now,
        )

        stored = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(stored["repository"]["head_sha"], "a" * 40)
        self.assertEqual(stored["target"]["identity"], "sha256:local-id")
        self.assertEqual(stored["policy"]["ignore_unfixed"], False)
        self.assertEqual(payload, stored)
        self.assertEqual(
            stored["reports"]["json"]["sha256"],
            hashlib.sha256(report.read_bytes()).hexdigest(),
        )
        self.assertNotIn("environment", stored)


if __name__ == "__main__":
    unittest.main()
