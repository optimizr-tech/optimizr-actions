"""Static contract checks for sanitized deployment evidence."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github/actions/write-deploy-manifest/action.yml"
DOC = ROOT / "docs/DEPLOY_MANIFEST.md"


class DeployManifestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.action = ACTION.read_text(encoding="utf-8")
        cls.doc = DOC.read_text(encoding="utf-8")

    def test_manifest_write_is_atomic_and_private(self) -> None:
        self.assertIn("tempfile.mkstemp", self.action)
        self.assertIn("os.fsync", self.action)
        self.assertIn("os.replace(temporary_name, manifest_path)", self.action)
        self.assertIn("os.chmod(temporary_name, 0o600)", self.action)
        self.assertIn("manifest_dir.mkdir(mode=0o750", self.action)

    def test_failed_deploy_does_not_replace_last_successful(self) -> None:
        self.assertIn('if status == "success":', self.action)
        self.assertIn('manifest_dir / "last-successful.json"', self.action)
        self.assertIn("os.replace(pointer_tmp, last_successful)", self.action)

    def test_action_rejects_unsafe_path_and_unbounded_retention(self) -> None:
        self.assertIn("deploy_path.is_absolute()", self.action)
        self.assertIn('deploy_path == Path("/")', self.action)
        self.assertIn("deploy_path.is_symlink()", self.action)
        self.assertIn("1 <= int(retention_raw) <= 500", self.action)

    def test_action_has_no_generic_secret_or_environment_map_input(self) -> None:
        input_section = self.action.split("outputs:", 1)[0]
        self.assertNotIn("secrets_json:", input_section)
        self.assertNotIn("environment_json:", input_section)
        self.assertNotIn("headers_json:", input_section)
        self.assertNotIn("metadata_json:", input_section)

    def test_schema_and_failure_semantics_are_documented(self) -> None:
        self.assertIn("Schema version 1.0", self.doc)
        self.assertIn("never replaces the last successful pointer", self.doc)
        self.assertIn("Prohibited data", self.doc)
        self.assertIn("Rollback representation", self.doc)


if __name__ == "__main__":
    unittest.main()
