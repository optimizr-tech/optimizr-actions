import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from supply_chain.evidence import (  # noqa: E402
    EvidenceError,
    build_provenance,
    resolve_image_descriptor,
    resolve_image_identity,
    resolve_local_image_id,
)


class SupplyChainEvidenceTests(unittest.TestCase):
    def test_resolve_image_descriptor_prefers_repository_digest_and_records_kind(self):
        inspect = [{"Id": "sha256:" + "a" * 64, "RepoDigests": ["example/app@sha256:" + "b" * 64]}]
        descriptor = resolve_image_descriptor(inspect)
        self.assertEqual(descriptor, {"identity": "sha256:" + "b" * 64, "identity_kind": "repository_digest"})
        self.assertEqual(resolve_image_identity(inspect), "sha256:" + "b" * 64)
        self.assertEqual(resolve_local_image_id(inspect), "sha256:" + "a" * 64)

        local_only = resolve_image_descriptor([{"Id": "sha256:" + "a" * 64, "RepoDigests": []}])
        self.assertEqual(local_only["identity_kind"], "local_image_id")
        with self.assertRaises(EvidenceError):
            resolve_image_descriptor([{"Id": "example/app:latest", "RepoDigests": []}])

    def test_provenance_uses_slsa_v1_byproducts_and_binds_source_and_subject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cyclonedx = root / "sbom.cyclonedx.json"
            spdx = root / "sbom.spdx.json"
            cyclonedx.write_text('{"bomFormat":"CycloneDX"}', encoding="utf-8")
            spdx.write_text('{"spdxVersion":"SPDX-2.3"}', encoding="utf-8")
            payload = build_provenance(
                repository="optimizr/example",
                head_sha="a" * 40,
                image_ref="example/app:latest",
                image_identity="sha256:" + "b" * 64,
                identity_kind="repository_digest",
                workflow_ref="optimizr/example/.github/workflows/deploy.yml@refs/heads/main",
                artifacts={"cyclonedx": cyclonedx, "spdx": spdx},
                tool_version="Version: 0.70.0",
                generated_at="2026-07-20T00:00:00Z",
            )
            self.assertEqual(payload["predicateType"], "https://slsa.dev/provenance/v1")
            self.assertEqual(payload["subject"][0]["digest"]["sha256"], "b" * 64)
            predicate = payload["predicate"]
            self.assertNotIn("materials", predicate)
            byproducts = predicate["runDetails"]["byproducts"]
            self.assertEqual({item["name"] for item in byproducts}, {"sbom.cyclonedx.json", "sbom.spdx.json"})
            self.assertTrue(all("digest" in item and "sha256" in item["digest"] for item in byproducts))
            self.assertEqual(predicate["buildDefinition"]["externalParameters"]["identityKind"], "repository_digest")
            self.assertEqual(predicate["runDetails"]["metadata"]["startedOn"], "2026-07-20T00:00:00Z")
            self.assertEqual(predicate["runDetails"]["metadata"]["finishedOn"], "2026-07-20T00:00:00Z")
            self.assertNotIn("environment", json.dumps(payload))
            self.assertNotIn("example/app:latest", json.dumps(payload))

    def test_provenance_rejects_invalid_repository_and_identity_kind(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sbom.json"
            artifact.write_text("{}", encoding="utf-8")
            common = dict(
                head_sha="a" * 40,
                image_ref="example/app:latest",
                image_identity="sha256:" + "b" * 64,
                workflow_ref="optimizr/example/.github/workflows/deploy.yml@refs/heads/main",
                artifacts={"cyclonedx": artifact},
                tool_version="Version: 0.70.0",
            )
            with self.assertRaises(EvidenceError):
                build_provenance(repository="not-a-repository", identity_kind="repository_digest", **common)
            with self.assertRaises(EvidenceError):
                build_provenance(repository="optimizr/example", identity_kind="mutable_tag", **common)


if __name__ == "__main__":
    unittest.main()
