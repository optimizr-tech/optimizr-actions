import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dependency_policy.policy import (  # noqa: E402
    PolicyError,
    detect_ecosystems,
    evaluate_report,
    load_policy,
    validate_package_lock,
    validate_requirements_file,
    collect_direct_dependencies,
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

    def test_hash_locked_requirements_are_supported_and_unhashed_entries_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            req = root / "requirements.txt"
            req.write_text("demo==1.2.3 --hash=sha256:" + "a" * 64 + "\n")
            validate_requirements_file(req)
            self.assertEqual(
                detect_ecosystems(root),
                [{"ecosystem": "python-requirements", "lockfile": "requirements.txt"}],
            )
            req.write_text("demo>=1.2.3\n")
            with self.assertRaises(PolicyError):
                validate_requirements_file(req)

    def test_direct_dependency_scope_is_classified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(json.dumps({
                "dependencies": {"runtime": "1.0.0"},
                "devDependencies": {"test-only": "1.0.0"}
            }))
            direct = collect_direct_dependencies(root)
            self.assertEqual(direct["runtime"], "direct-production")
            self.assertEqual(direct["test-only"], "direct-development")

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
            report = {
                "Results": [{
                    "Target": "pnpm-lock.yaml",
                    "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "demo", "Severity": "HIGH"}],
                    "Licenses": [{"PkgName": "copyleft", "Name": "AGPL-3.0-only"}],
                }]
            }
            decision = evaluate_report(report, policy, today="2026-07-20", direct_dependencies={"demo": "direct-production"})
            self.assertEqual(len(decision["blocking"]), 2)
            self.assertEqual(decision["blocking"][0]["dependency_scope"], "direct-production")
            self.assertEqual(decision["blocking"][1]["dependency_scope"], "transitive")

            expired = json.loads(path.read_text())
            expired["exceptions"] = [{
                "kind": "vulnerability", "id": "CVE-1", "package": "demo",
                "owner": "security", "statement": "temporary", "expires": "2026-01-01"
            }]
            path.write_text(json.dumps(expired))
            with self.assertRaises(PolicyError):
                load_policy(path, today="2026-07-20")

            malformed = json.loads(path.read_text())
            malformed["exceptions"] = [{
                "kind": "license", "id": "AGPL-3.0-only", "package": "copyleft",
                "owner": "security", "statement": "temporary", "extra": "not-a-replacement"
            }]
            path.write_text(json.dumps(malformed))
            with self.assertRaises(PolicyError):
                load_policy(path, today="2026-07-20")


if __name__ == "__main__":
    unittest.main()
