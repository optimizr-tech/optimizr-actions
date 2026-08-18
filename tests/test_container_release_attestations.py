"""Tests for fail-closed OCI attestation verification."""

from __future__ import annotations

import unittest

from scripts.container_release.verify_attestations import (
    AttestationError,
    verify_attestation_index,
)


def _manifest(*, attestation: bool = False) -> dict[str, object]:
    if attestation:
        return {
            "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
            "digest": "sha256:" + "a" * 64,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
        }
    return {
        "digest": "sha256:" + "b" * 64,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "platform": {"architecture": "amd64", "os": "linux"},
    }


class VerifyAttestationsTests(unittest.TestCase):
    def test_accepts_platform_manifest_with_sbom_and_provenance(self) -> None:
        result = verify_attestation_index(
            {"manifests": [_manifest(), _manifest(attestation=True), _manifest(attestation=True)]}
        )

        self.assertEqual({"platform_manifests": 1, "attestation_manifests": 2}, result)

    def test_rejects_missing_attestation(self) -> None:
        with self.assertRaisesRegex(AttestationError, "at least 2"):
            verify_attestation_index({"manifests": [_manifest(), _manifest(attestation=True)]})

    def test_rejects_non_index_metadata(self) -> None:
        with self.assertRaisesRegex(AttestationError, "not an OCI index"):
            verify_attestation_index({"config": {}})


if __name__ == "__main__":
    unittest.main()
