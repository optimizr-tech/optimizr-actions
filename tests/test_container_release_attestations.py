"""Tests for fail-closed OCI attestation verification."""

from __future__ import annotations

import unittest

from scripts.container_release.verify_attestations import (
    AttestationError,
    verify_attestation_index,
    verify_attestation_bundle,
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
    def test_accepts_one_manifest_containing_sbom_and_provenance(self) -> None:
        result = verify_attestation_bundle(
            {"manifests": [_manifest(), _manifest(attestation=True)]},
            {"spdxVersion": "SPDX-2.3", "packages": []},
            {"buildType": "https://mobyproject.org/buildkit@v1"},
        )

        self.assertEqual(
            {
                "platform_manifests": 1,
                "attestation_manifests": 1,
                "sbom": 1,
                "provenance": 1,
            },
            result,
        )

    def test_rejects_missing_attestation(self) -> None:
        with self.assertRaisesRegex(AttestationError, "at least 1"):
            verify_attestation_index({"manifests": [_manifest()]})

    def test_rejects_missing_sbom_evidence(self) -> None:
        with self.assertRaisesRegex(AttestationError, "SBOM"):
            verify_attestation_bundle(
                {"manifests": [_manifest(), _manifest(attestation=True)]},
                {},
                {"buildType": "https://mobyproject.org/buildkit@v1"},
            )

    def test_rejects_missing_provenance_evidence(self) -> None:
        with self.assertRaisesRegex(AttestationError, "provenance"):
            verify_attestation_bundle(
                {"manifests": [_manifest(), _manifest(attestation=True)]},
                {"spdxVersion": "SPDX-2.3", "packages": []},
                {},
            )

    def test_rejects_non_index_metadata(self) -> None:
        with self.assertRaisesRegex(AttestationError, "not an OCI index"):
            verify_attestation_index({"config": {}})


if __name__ == "__main__":
    unittest.main()
