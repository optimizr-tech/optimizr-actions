import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from supply_chain.evidence import (
    EvidenceError,
    build_provenance,
    resolve_image_identity,
    resolve_local_image_id,
)


class SupplyChainEvidenceTests(unittest.TestCase):
    def test_resolve_image_identity_prefers_repo_digest_and_rejects_mutable_only(self):
        inspect = [{"Id": "sha256:" + "a" * 64, "RepoDigests": ["example/app@sha256:" + "b" * 64]}]
        self.assertEqual(resolve_image_identity(inspect), "sha256:" + "b" * 64)
        self.assertEqual(resolve_image_identity([{"Id": "sha256:" + "a" * 64, "RepoDigests": []}]), "sha256:" + "a" * 64)
        self.assertEqual(resolve_local_image_id(inspect), "sha256:" + "a" * 64)
        with self.assertRaises(EvidenceError):
            resolve_image_identity([{"Id": "example/app:latest", "RepoDigests": []}])

    def test_provenance_binds_sha_digest_and_artifact_hashes_without_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sbom = root / "sbom.json"
            sbom.write_text('{"bomFormat":"CycloneDX"}')
            payload = build_provenance(
                repository="optimizr/example",
                head_sha="a" * 40,
                image_ref="example/app:latest",
                image_identity="sha256:" + "b" * 64,
                workflow_ref="optimizr/example/.github/workflows/deploy.yml@refs/heads/main",
                artifacts={"cyclonedx": sbom},
                tool_version="Version: 0.70.0",
                generated_at="2026-07-20T00:00:00Z",
            )
            self.assertEqual(payload["subject"][0]["digest"]["sha256"], "b" * 64)
            self.assertIn("cyclonedx", payload["predicate"]["materials"])
            self.assertNotIn("environment", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
