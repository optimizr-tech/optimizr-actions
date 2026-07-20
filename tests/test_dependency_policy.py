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


if __name__ == "__main__":
    unittest.main()
