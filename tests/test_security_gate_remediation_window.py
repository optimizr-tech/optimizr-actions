from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "security_gate" / "remediation_window.py"


def _load_module():
    assert MODULE_PATH.is_file(), "scripts/security_gate/remediation_window.py is missing"
    spec = importlib.util.spec_from_file_location(
        "security_gate_remediation_window",
        MODULE_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class SecurityGateRemediationWindowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = _load_module()
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)

    def _policy(
        self,
        *,
        first_seen_at: str = "2026-07-30T12:00:00Z",
        deadline_at: str = "2026-08-06T12:00:00Z",
        status: str = "active",
        extra: dict[str, object] | None = None,
    ) -> Path:
        payload = {
            "version": 1,
            "policy_owner": "team-monitoring",
            "entries": [
                {
                    "id": "rw-monitoring-cve-2026-0001",
                    "fingerprint": {
                        "service": "monitoring",
                        "advisory_id": "CVE-2026-0001",
                        "package_purl": "pkg:deb/debian/openssl@1.2.3",
                        "installed_version": "1.2.3",
                        "fixed_version": "1.2.4",
                        "image_lineage_digests": [
                            "sha256:" + "a" * 64,
                            "sha256:" + "b" * 64,
                        ],
                    },
                    "reason": "upstream_release_pending",
                    "first_seen_at": first_seen_at,
                    "deadline_at": deadline_at,
                    "owner": "team-monitoring",
                    "reviewer": "security-owner",
                    "statement": "Newest compatible official image remains affected.",
                    "compensating_control": "Reviewed ingress restriction and upgrade tracking.",
                    "reviewed_at": "2026-07-30T15:00:00Z",
                    "reviewed_by": "security-owner",
                    "status": status,
                }
            ],
        }
        if extra:
            payload["entries"][0].update(extra)
        path = self.root / "policy.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def _observation(self, *, classification: str = "actionable_vulnerability") -> dict[str, object]:
        return {
            "service_scope": "monitoring",
            "exposure_criticality": "internal",
            "classification": classification,
            "advisory_id": "CVE-2026-0001",
            "package_purl": "pkg:deb/debian/openssl@1.2.3",
            "installed_version": "1.2.3",
            "fixed_version": "1.2.4",
            "image_lineage_digests": [
                "sha256:" + "a" * 64,
                "sha256:" + "b" * 64,
            ],
            "source_sha": "c" * 40,
            "image_identity": "sha256:" + "d" * 64,
            "fixed_image_verified": False,
        }

    def test_exact_match_allows_window_only_when_enabled(self) -> None:
        result = self.module.evaluate_remediation_window(
            policy_path=self._policy(),
            observation=self._observation(),
            enabled=True,
            evaluation_time="2026-07-31T00:00:00Z",
        )

        self.assertTrue(result["remediation_window_allowed"])
        self.assertEqual("active", result["remediation_state"])
        self.assertEqual("allowed_window", result["decision"])
        self.assertEqual("actionable_vulnerability", result["classification"])
        self.assertEqual("2026-08-06T12:00:00Z", result["nearest_deadline"])
        self.assertEqual(1, result["matching_entry_count"])
        self.assertEqual(64, len(result["policy_digest"]))
        self.assertEqual("1", result["evaluator_version"])
        self.assertEqual("", result["failure_reason"])

    def test_disabled_window_path_defaults_to_not_applicable(self) -> None:
        result = self.module.evaluate_remediation_window(
            policy_path=self._policy(),
            observation=self._observation(),
            enabled=False,
            evaluation_time="2026-07-31T00:00:00Z",
        )

        self.assertFalse(result["remediation_window_allowed"])
        self.assertEqual("not_applicable", result["remediation_state"])
        self.assertEqual("not_applicable", result["decision"])

    def test_blocks_future_first_seen_and_expired_deadlines(self) -> None:
        future = self._policy(first_seen_at="2026-08-30T12:00:00Z")
        with self.assertRaises(ValueError):
            self.module.evaluate_remediation_window(
                policy_path=future,
                observation=self._observation(),
                enabled=True,
                evaluation_time="2026-07-31T00:00:00Z",
            )

        expired = self._policy(deadline_at="2026-07-01T12:00:00Z")
        with self.assertRaises(ValueError):
            self.module.evaluate_remediation_window(
                policy_path=expired,
                observation=self._observation(),
                enabled=True,
                evaluation_time="2026-07-31T00:00:00Z",
            )

    def test_blocks_known_exploitation_and_fixed_image_availability(self) -> None:
        for exposure in ("internet-facing", "privileged-boundary"):
            with self.subTest(exposure=exposure):
                result = self.module.evaluate_remediation_window(
                    policy_path=self._policy(),
                    observation=self._observation(),
                    enabled=True,
                    evaluation_time="2026-07-31T00:00:00Z",
                    exposure_criticality=exposure,
                )
                self.assertFalse(result["remediation_window_allowed"])
                self.assertEqual("blocked", result["remediation_state"])
                self.assertEqual("exposure_block", result["failure_reason"])

        result = self.module.evaluate_remediation_window(
            policy_path=self._policy(),
            observation=self._observation(),
            enabled=True,
            evaluation_time="2026-07-31T00:00:00Z",
            fixed_image_verified=True,
        )
        self.assertFalse(result["remediation_window_allowed"])
        self.assertEqual("fixed_image_available", result["failure_reason"])

    def test_policy_rejects_duplicate_fingerprints_and_history_rewinds(self) -> None:
        policy = self._policy(
            extra={
                "history": [
                    {
                        "first_seen_at": "2026-07-30T12:00:00Z",
                        "deadline_at": "2026-08-05T12:00:00Z",
                        "reason": "initial_review",
                        "reviewed_at": "2026-07-29T15:00:00Z",
                        "reviewed_by": "security-owner",
                    }
                ]
            }
        )
        loaded = self.module.load_policy(policy, reference_time="2026-07-31T00:00:00Z")
        self.assertEqual("team-monitoring", loaded["policy_owner"])

        duplicate = self.root / "duplicate.json"
        payload = json.loads(policy.read_text(encoding="utf-8"))
        payload["entries"].append(payload["entries"][0])
        duplicate.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.module.load_policy(duplicate, reference_time="2026-07-31T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
