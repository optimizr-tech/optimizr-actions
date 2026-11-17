import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dependency_policy.policy import (
    PolicyError,
    detect_ecosystems,
    evaluate_report,
    load_policy,
    validate_package_lock,
)


class DependencyPolicyTests(unittest.TestCase):
    def test_detect_ecosystems_requires_supported_lockfiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text("[project]\nname='x'\n")
            with self.assertRaises(PolicyError):
                detect_ecosystems(root)
            (root / "uv.lock").write_text("version = 1\n")
            self.assertEqual(detect_ecosystems(root), [{"ecosystem": "python-uv", "lockfile": "uv.lock"}])

    def test_package_lock_root_dependencies_must_match_manifest(self):
        manifest = {"dependencies": {"a": "^1.0.0"}, "devDependencies": {"b": "2.0.0"}}
        lock = {"lockfileVersion": 3, "packages": {"": {"dependencies": {"a": "^1.0.0"}, "devDependencies": {"b": "1.0.0"}}}}
        with self.assertRaises(PolicyError):
            validate_package_lock(manifest, lock)
        lock["packages"][""]["devDependencies"]["b"] = "2.0.0"
        validate_package_lock(manifest, lock)

    def test_policy_rejects_expired_exception_and_blocks_vulnerability_and_license(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({
                "version": 1,
                "block_severities": ["HIGH", "CRITICAL"],
                "denied_licenses": ["AGPL-3.0-only"],
                "exceptions": [],
            }))
            policy = load_policy(path)
            report = {"Results": [{
                "Target": "pnpm-lock.yaml",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "demo", "Severity": "HIGH"}],
                "Licenses": [{"PkgName": "copyleft", "Name": "AGPL-3.0-only"}],
            }]}
            decision = evaluate_report(report, policy, today="2026-07-20")
            self.assertEqual(len(decision["blocking"]), 2)
            expired = json.loads(path.read_text())
            expired["exceptions"] = [{
                "kind": "vulnerability", "id": "CVE-1", "package": "demo",
                "owner": "security", "statement": "temporary", "expires": "2026-01-01"
            }]
            path.write_text(json.dumps(expired))
            with self.assertRaises(PolicyError):
                load_policy(path, today="2026-07-20")

    def _load_single_exception_policy(self, path, exception, today="2026-11-17"):
        path.write_text(json.dumps({"version": 1, "exceptions": [exception]}))
        return load_policy(path, today=today)

    @staticmethod
    def _trivy_report(*findings):
        return {
            "Results": [
                {
                    "Target": target,
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": identifier,
                            "PkgName": package,
                            "Severity": "HIGH",
                        }
                    ],
                }
                for target, identifier, package in findings
            ]
        }

    def test_targeted_exception_suppresses_only_exact_trivy_target(self):
        advisory = "GHSA-fc5q-39xc-vjpf"
        package = "picomatch"
        exception = {
            "kind": "vulnerability",
            "id": advisory,
            "package": package,
            "target": "package-lock.json",
            "owner": "test-owner",
            "statement": "Test fixture for a root development-only dependency.",
            "expires": "2026-12-17",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            policy = self._load_single_exception_policy(path, exception)
            decision = evaluate_report(
                self._trivy_report(
                    ("package-lock.json", advisory, package),
                    ("frontend/apps/admin/pnpm-lock.yaml", advisory, package),
                    ("frontend/apps/storefront/pnpm-lock.yaml", advisory, package),
                    ("scripts/package-lock.json", advisory, package),
                    ("package-lock.json", "GHSA-other", package),
                    ("package-lock.json", advisory, "another-package"),
                ),
                policy,
            )

            self.assertEqual(
                decision["suppressed"],
                [
                    {
                        "kind": "vulnerability",
                        "id": advisory,
                        "package": package,
                        "severity": "HIGH",
                        "target": "package-lock.json",
                    }
                ],
            )
            self.assertEqual(
                [(item["target"], item["id"], item["package"]) for item in decision["blocking"]],
                [
                    ("frontend/apps/admin/pnpm-lock.yaml", advisory, package),
                    ("frontend/apps/storefront/pnpm-lock.yaml", advisory, package),
                    ("scripts/package-lock.json", advisory, package),
                    ("package-lock.json", "GHSA-other", package),
                    ("package-lock.json", advisory, "another-package"),
                ],
            )
            self.assertFalse(decision["passed"])

    def test_legacy_exception_without_target_keeps_v1_cross_target_matching(self):
        exception = {
            "kind": "vulnerability",
            "id": "GHSA-fc5q-39xc-vjpf",
            "package": "picomatch",
            "owner": "test-owner",
            "statement": "Existing v1 exception.",
            "expires": "2026-12-17",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            policy = self._load_single_exception_policy(path, exception)
            decision = evaluate_report(
                self._trivy_report(
                    ("package-lock.json", "GHSA-fc5q-39xc-vjpf", "picomatch"),
                    ("frontend/apps/admin/pnpm-lock.yaml", "GHSA-fc5q-39xc-vjpf", "picomatch"),
                    ("frontend/apps/storefront/pnpm-lock.yaml", "GHSA-fc5q-39xc-vjpf", "picomatch"),
                ),
                policy,
            )

            self.assertEqual(
                [item["target"] for item in decision["suppressed"]],
                [
                    "package-lock.json",
                    "frontend/apps/admin/pnpm-lock.yaml",
                    "frontend/apps/storefront/pnpm-lock.yaml",
                ],
            )
            self.assertEqual(decision["blocking"], [])

    def test_targeted_exception_expiry_is_valid_through_expiry_date(self):
        exception = {
            "kind": "vulnerability",
            "id": "GHSA-fc5q-39xc-vjpf",
            "package": "picomatch",
            "target": "package-lock.json",
            "owner": "test-owner",
            "statement": "Expires at the end of this date.",
            "expires": "2026-12-17",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            self.assertEqual(
                len(self._load_single_exception_policy(path, exception, "2026-12-17")["exceptions"]),
                1,
            )
            with self.assertRaises(PolicyError):
                self._load_single_exception_policy(path, exception, "2026-12-18")

    def test_targeted_exception_requires_a_non_empty_exact_target(self):
        exception = {
            "kind": "vulnerability",
            "id": "GHSA-fc5q-39xc-vjpf",
            "package": "picomatch",
            "owner": "test-owner",
            "statement": "Temporary exact-target exception.",
            "expires": "2026-12-17",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            for target in ("", "   ", " package-lock.json ", None, ["package-lock.json"]):
                with self.subTest(target=target):
                    with self.assertRaises(PolicyError):
                        self._load_single_exception_policy(
                            path, {**exception, "target": target}
                        )


if __name__ == "__main__":
    unittest.main()
