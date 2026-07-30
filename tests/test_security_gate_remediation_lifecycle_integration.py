from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "security_gate" / "remediation_window.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "security_gate_remediation_window_lifecycle", MODULE_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RemediationLifecycleIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = _load_module()
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.digest = "sha256:" + "a" * 64

    def _fingerprint(self) -> dict[str, object]:
        return {
            "service": "monitoring",
            "advisory_id": "CVE-2026-2001",
            "package_purl": "pkg:deb/debian/openssl@1.2.3",
            "installed_version": "1.2.3",
            "fixed_version": "1.2.4",
            "image_lineage_digests": [self.digest],
        }

    def _observation(self) -> dict[str, object]:
        return {
            "service_scope": "monitoring",
            "exposure_criticality": "internal",
            "classification": "actionable_vulnerability",
            "severity": "HIGH",
            "known_exploited": False,
            "fixed_image_verified": False,
            "advisory_id": "CVE-2026-2001",
            "package_purl": "pkg:deb/debian/openssl@1.2.3",
            "installed_version": "1.2.3",
            "fixed_version": "1.2.4",
            "image_lineage_digests": [self.digest],
            "source_sha": "c" * 40,
            "image_identity": "sha256:" + "d" * 64,
        }

    def _policy(self, *, status: str, history: list[dict[str, str]]) -> Path:
        path = self.root / "policy.json"
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "policy_owner": "team-monitoring",
                    "entries": [
                        {
                            "id": "rw-lifecycle",
                            "fingerprint": self._fingerprint(),
                            "reason": "upstream_release_pending",
                            "first_seen_at": "2026-07-30T12:00:00Z",
                            "deadline_at": "2026-08-06T12:00:00Z",
                            "owner": "team-monitoring",
                            "reviewer": "security-owner",
                            "statement": "Reviewed lifecycle test.",
                            "compensating_control": "Restricted ingress.",
                            "reviewed_at": "2026-07-30T15:00:00Z",
                            "reviewed_by": "security-owner",
                            "status": status,
                            "history": history,
                        }
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return path

    def _revision(
        self,
        action: str,
        *,
        previous: str,
        deadline: str,
        reviewed: str,
    ) -> dict[str, str]:
        return {
            "action": action,
            "first_seen_at": "2026-07-30T12:00:00Z",
            "previous_deadline_at": previous,
            "deadline_at": deadline,
            "reviewed_at": reviewed,
            "reviewed_by": "security-owner",
            "reason": f"reviewed_{action}",
        }

    def test_extension_uses_effective_deadline_but_preserves_original(self) -> None:
        policy = self._policy(
            status="active",
            history=[
                self._revision(
                    "extended",
                    previous="2026-08-06T12:00:00Z",
                    deadline="2026-08-20T12:00:00Z",
                    reviewed="2026-07-31T00:00:00Z",
                )
            ],
        )
        loaded = self.module.load_policy(
            policy, reference_time="2026-08-01T00:00:00Z"
        )["entries"][0]
        self.assertEqual("2026-08-06T12:00:00Z", loaded["original_deadline_at"])
        self.assertEqual("2026-08-20T12:00:00Z", loaded["deadline_at"])
        self.assertEqual(1, loaded["revision_count"])

    def test_observed_resolved_or_reintroduced_finding_remains_blocking(self) -> None:
        resolved = self._revision(
            "resolved",
            previous="2026-08-06T12:00:00Z",
            deadline="2026-08-06T12:00:00Z",
            reviewed="2026-07-31T00:00:00Z",
        )
        reintroduced = self._revision(
            "reintroduced",
            previous="2026-08-06T12:00:00Z",
            deadline="2026-08-06T12:00:00Z",
            reviewed="2026-08-01T00:00:00Z",
        )
        for status, history in (
            ("resolved", [resolved]),
            ("reintroduced", [resolved, reintroduced]),
        ):
            with self.subTest(status=status):
                result = self.module.evaluate_remediation_windows(
                    policy_path=self._policy(status=status, history=history),
                    observations=[self._observation()],
                    enabled=True,
                    evaluation_time="2026-08-01T12:00:00Z",
                )
                self.assertFalse(result["remediation_window_allowed"])
                self.assertEqual(1, result["reintroduced_count"])
                self.assertEqual("reintroduced", result["remediation_state"])
                finding = result["findings"][0]
                self.assertEqual("finding_reintroduced", finding["failure_reason"])
                self.assertEqual("2026-07-30T12:00:00Z", finding["first_seen_at"])
                self.assertEqual(
                    "2026-08-06T12:00:00Z",
                    finding["original_deadline_at"],
                )
                self.assertEqual(status, finding["policy_entry_status"])


if __name__ == "__main__":
    unittest.main()
