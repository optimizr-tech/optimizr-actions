from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "security_gate" / "remediation_window.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("security_gate_remediation_window", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SecurityGateRemediationWindowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = _load_module()
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()

    def _fingerprint(self, *, advisory: str, package: str, installed: str, fixed: str, digest: str) -> dict[str, object]:
        return {
            "service": "monitoring",
            "advisory_id": advisory,
            "package_purl": package,
            "installed_version": installed,
            "fixed_version": fixed,
            "image_lineage_digests": [digest],
        }

    def _entry(
        self,
        *,
        entry_id: str,
        advisory: str,
        package: str,
        installed: str,
        fixed: str,
        digest: str,
        first_seen_at: str = "2026-07-30T12:00:00Z",
        deadline_at: str = "2026-08-06T12:00:00Z",
    ) -> dict[str, object]:
        return {
            "id": entry_id,
            "fingerprint": self._fingerprint(
                advisory=advisory,
                package=package,
                installed=installed,
                fixed=fixed,
                digest=digest,
            ),
            "reason": "upstream_release_pending",
            "first_seen_at": first_seen_at,
            "deadline_at": deadline_at,
            "owner": "team-monitoring",
            "reviewer": "security-owner",
            "statement": "Newest compatible official image remains affected.",
            "compensating_control": "Reviewed ingress restriction and upgrade tracking.",
            "reviewed_at": "2026-07-30T15:00:00Z",
            "reviewed_by": "security-owner",
            "status": "active",
        }

    def _policy(self, entries: list[dict[str, object]]) -> Path:
        path = self.workspace / ".github" / "security" / "remediation-windows.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"version": 1, "policy_owner": "team-monitoring", "entries": entries}, indent=2),
            encoding="utf-8",
        )
        return path

    def _observation(
        self,
        *,
        advisory: str,
        package: str,
        installed: str,
        fixed: str,
        digest: str,
        image_identity: str,
        severity: str = "HIGH",
        exposure: str = "internal",
        known_exploited: bool = False,
        fixed_image_verified: bool = False,
    ) -> dict[str, object]:
        return {
            "service_scope": "monitoring",
            "exposure_criticality": exposure,
            "classification": "actionable_vulnerability",
            "severity": severity,
            "known_exploited": known_exploited,
            "advisory_id": advisory,
            "package_purl": package,
            "installed_version": installed,
            "fixed_version": fixed,
            "image_lineage_digests": [digest],
            "source_sha": "c" * 40,
            "image_identity": image_identity,
            "fixed_image_verified": fixed_image_verified,
        }

    def test_complete_set_requires_every_blocking_finding_to_be_covered(self) -> None:
        digest = "sha256:" + "a" * 64
        policy = self._policy([
            self._entry(
                entry_id="rw-1",
                advisory="CVE-2026-0001",
                package="pkg:deb/debian/openssl@1.2.3",
                installed="1.2.3",
                fixed="1.2.4",
                digest=digest,
            )
        ])
        observations = [
            self._observation(
                advisory="CVE-2026-0001",
                package="pkg:deb/debian/openssl@1.2.3",
                installed="1.2.3",
                fixed="1.2.4",
                digest=digest,
                image_identity="sha256:" + "d" * 64,
            ),
            self._observation(
                advisory="CVE-2026-0002",
                package="pkg:deb/debian/libc6@2.0",
                installed="2.0",
                fixed="2.1",
                digest=digest,
                image_identity="sha256:" + "d" * 64,
            ),
        ]

        result = self.module.evaluate_remediation_windows(
            policy_path=policy,
            observations=observations,
            enabled=True,
            evaluation_time="2026-07-31T00:00:00Z",
        )

        self.assertFalse(result["remediation_window_allowed"])
        self.assertEqual(2, result["blocking_total"])
        self.assertEqual(1, result["window_covered"])
        self.assertEqual(1, result["unmatched_count"])
        self.assertEqual(1, result["uncovered_blocking_findings"])
        self.assertEqual("blocked", result["decision"])

    def test_all_exact_findings_allow_one_aggregate_window_decision(self) -> None:
        digest = "sha256:" + "a" * 64
        entries = [
            self._entry(
                entry_id="rw-1",
                advisory="CVE-2026-0001",
                package="pkg:deb/debian/openssl@1.2.3",
                installed="1.2.3",
                fixed="1.2.4",
                digest=digest,
            ),
            self._entry(
                entry_id="rw-2",
                advisory="CVE-2026-0002",
                package="pkg:deb/debian/libc6@2.0",
                installed="2.0",
                fixed="2.1",
                digest=digest,
            ),
        ]
        policy = self._policy(entries)
        observations = [
            self._observation(
                advisory="CVE-2026-0001",
                package="pkg:deb/debian/openssl@1.2.3",
                installed="1.2.3",
                fixed="1.2.4",
                digest=digest,
                image_identity="sha256:" + "d" * 64,
            ),
            self._observation(
                advisory="CVE-2026-0002",
                package="pkg:deb/debian/libc6@2.0",
                installed="2.0",
                fixed="2.1",
                digest=digest,
                image_identity="sha256:" + "d" * 64,
            ),
        ]

        result = self.module.evaluate_remediation_windows(
            policy_path=policy,
            observations=observations,
            enabled=True,
            evaluation_time="2026-07-31T00:00:00Z",
        )

        self.assertTrue(result["remediation_window_allowed"])
        self.assertEqual(2, result["window_covered"])
        self.assertEqual(0, result["uncovered_blocking_findings"])
        self.assertEqual("allowed_window", result["decision"])
        self.assertEqual("active", result["remediation_state"])

    def test_mixed_images_cannot_be_overwritten_by_last_allowed_target(self) -> None:
        digest_a = "sha256:" + "a" * 64
        digest_b = "sha256:" + "b" * 64
        policy = self._policy([
            self._entry(
                entry_id="rw-allowed-last",
                advisory="CVE-2026-0002",
                package="pkg:apk/alpine/libssl@3.0",
                installed="3.0",
                fixed="3.1",
                digest=digest_b,
            )
        ])
        observations = [
            self._observation(
                advisory="CVE-2026-0001",
                package="pkg:deb/debian/openssl@1.2.3",
                installed="1.2.3",
                fixed="1.2.4",
                digest=digest_a,
                image_identity="sha256:" + "d" * 64,
            ),
            self._observation(
                advisory="CVE-2026-0002",
                package="pkg:apk/alpine/libssl@3.0",
                installed="3.0",
                fixed="3.1",
                digest=digest_b,
                image_identity="sha256:" + "e" * 64,
            ),
        ]

        result = self.module.evaluate_remediation_windows(
            policy_path=policy,
            observations=observations,
            enabled=True,
            evaluation_time="2026-07-31T00:00:00Z",
        )

        self.assertFalse(result["remediation_window_allowed"])
        self.assertEqual(1, result["window_covered"])
        self.assertEqual(1, result["uncovered_blocking_findings"])

    def test_disabled_path_does_not_require_policy_or_observations(self) -> None:
        result = self.module.evaluate_remediation_windows(
            policy_path=None,
            observations=[],
            enabled=False,
            evaluation_time="2026-07-31T00:00:00Z",
        )
        self.assertFalse(result["remediation_window_allowed"])
        self.assertEqual("not_applicable", result["decision"])
        self.assertEqual(0, result["blocking_total"])

    def test_policy_path_is_confined_to_workspace(self) -> None:
        policy = self._policy([
            self._entry(
                entry_id="rw-1",
                advisory="CVE-2026-0001",
                package="pkg:deb/debian/openssl@1.2.3",
                installed="1.2.3",
                fixed="1.2.4",
                digest="sha256:" + "a" * 64,
            )
        ])
        resolved = self.module.resolve_policy_path(
            self.workspace,
            ".github/security/remediation-windows.json",
        )
        self.assertEqual(policy.resolve(), resolved)

        for invalid in ("/tmp/policy.json", "../policy.json", ".github/../../policy.json"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.module.resolve_policy_path(self.workspace, invalid)

        link = self.workspace / ".github" / "security" / "policy-link.json"
        try:
            link.symlink_to(policy)
        except OSError:
            self.skipTest("symlink creation is unavailable")
        with self.assertRaises(ValueError):
            self.module.resolve_policy_path(self.workspace, ".github/security/policy-link.json")

    def test_risk_constraints_block_unsafe_windows(self) -> None:
        digest = "sha256:" + "a" * 64
        policy = self._policy([
            self._entry(
                entry_id="rw-critical-too-long",
                advisory="CVE-2026-0001",
                package="pkg:deb/debian/openssl@1.2.3",
                installed="1.2.3",
                fixed="1.2.4",
                digest=digest,
                deadline_at="2026-08-08T12:00:00Z",
            )
        ])
        critical = self._observation(
            advisory="CVE-2026-0001",
            package="pkg:deb/debian/openssl@1.2.3",
            installed="1.2.3",
            fixed="1.2.4",
            digest=digest,
            image_identity="sha256:" + "d" * 64,
            severity="CRITICAL",
        )
        result = self.module.evaluate_remediation_windows(
            policy_path=policy,
            observations=[critical],
            enabled=True,
            evaluation_time="2026-07-31T00:00:00Z",
        )
        self.assertFalse(result["remediation_window_allowed"])
        self.assertEqual(1, result["rejected_count"])
        self.assertEqual("window_limit_exceeded", result["findings"][0]["failure_reason"])

        for override in (
            {"known_exploited": True},
            {"fixed_image_verified": True},
            {"exposure": "internet-facing"},
            {"exposure": "privileged-boundary"},
        ):
            observation = self._observation(
                advisory="CVE-2026-0001",
                package="pkg:deb/debian/openssl@1.2.3",
                installed="1.2.3",
                fixed="1.2.4",
                digest=digest,
                image_identity="sha256:" + "d" * 64,
                severity="CRITICAL",
                **override,
            )
            result = self.module.evaluate_remediation_windows(
                policy_path=self._policy([
                    self._entry(
                        entry_id="rw-safe-duration",
                        advisory="CVE-2026-0001",
                        package="pkg:deb/debian/openssl@1.2.3",
                        installed="1.2.3",
                        fixed="1.2.4",
                        digest=digest,
                    )
                ]),
                observations=[observation],
                enabled=True,
                evaluation_time="2026-07-31T00:00:00Z",
            )
            self.assertFalse(result["remediation_window_allowed"])
            self.assertEqual(1, result["rejected_count"])

    def test_trivy_conversion_preserves_all_fixable_findings(self) -> None:
        report = self.root / "trivy.json"
        report.write_text(
            json.dumps(
                {
                    "Results": [
                        {
                            "Target": "debian",
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-2026-0001",
                                    "Severity": "HIGH",
                                    "PkgIdentifier": {"PURL": "pkg:deb/debian/openssl@1.2.3"},
                                    "InstalledVersion": "1.2.3",
                                    "FixedVersion": "1.2.4",
                                },
                                {
                                    "VulnerabilityID": "CVE-2026-0002",
                                    "Severity": "CRITICAL",
                                    "PkgIdentifier": {"PURL": "pkg:deb/debian/libc6@2.0"},
                                    "InstalledVersion": "2.0",
                                    "FixedVersion": "2.1",
                                },
                                {
                                    "VulnerabilityID": "CVE-2026-0003",
                                    "Severity": "HIGH",
                                    "PkgIdentifier": {"PURL": "pkg:deb/debian/no-fix@1"},
                                    "InstalledVersion": "1",
                                    "FixedVersion": "",
                                },
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        observations = self.module.observations_from_trivy_report(
            report,
            service_scope="monitoring",
            exposure_criticality="internal",
            source_sha="c" * 40,
            image_identity="sha256:" + "d" * 64,
            image_lineage_digests=["sha256:" + "a" * 64],
        )
        self.assertEqual(2, len(observations))
        self.assertEqual({"CVE-2026-0001", "CVE-2026-0002"}, {o["advisory_id"] for o in observations})


if __name__ == "__main__":
    unittest.main()
