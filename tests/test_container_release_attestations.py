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

    def test_requires_expected_source_repository_and_commit_when_requested(self) -> None:
        source_sha = "a" * 40
        provenance = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "configSource": {
                            "uri": "git+https://github.com/acme/service.git@" + source_sha,
                            "digest": {"gitCommit": source_sha},
                        }
                    }
                }
            },
        }

        result = verify_attestation_bundle(
            {"manifests": [_manifest(), _manifest(attestation=True)]},
            {"spdxVersion": "SPDX-2.3", "packages": []},
            provenance,
            expected_source_repository="https://github.com/acme/service",
            expected_source_sha=source_sha,
        )

        self.assertEqual(1, result["provenance"])

    def test_rejects_provenance_for_a_different_source_commit(self) -> None:
        source_sha = "a" * 40
        provenance = {
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "configSource": {
                            "uri": "https://github.com/acme/service",
                            "digest": {"gitCommit": "b" * 40},
                        }
                    }
                }
            }
        }

        with self.assertRaisesRegex(AttestationError, "source does not match"):
            verify_attestation_bundle(
                {"manifests": [_manifest(), _manifest(attestation=True)]},
                {"spdxVersion": "SPDX-2.3", "packages": []},
                provenance,
                expected_source_repository="https://github.com/acme/service",
                expected_source_sha=source_sha,
            )

    def test_rejects_non_https_source_uri_even_when_commit_matches(self) -> None:
        source_sha = "a" * 40
        provenance = {
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "configSource": {
                            "uri": "http://github.com/acme/service",
                            "digest": {"gitCommit": source_sha},
                        }
                    }
                }
            }
        }

        with self.assertRaisesRegex(AttestationError, "source does not match"):
            verify_attestation_bundle(
                {"manifests": [_manifest(), _manifest(attestation=True)]},
                {"spdxVersion": "SPDX-2.3", "packages": []},
                provenance,
                expected_source_repository="https://github.com/acme/service",
                expected_source_sha=source_sha,
            )

    def test_rejects_provenance_without_a_source_binding(self) -> None:
        with self.assertRaisesRegex(AttestationError, "source does not match"):
            verify_attestation_bundle(
                {"manifests": [_manifest(), _manifest(attestation=True)]},
                {"spdxVersion": "SPDX-2.3", "packages": []},
                {"buildType": "https://mobyproject.org/buildkit@v1"},
                expected_source_repository="https://github.com/acme/service",
                expected_source_sha="a" * 40,
            )

    def test_rejects_matching_material_when_primary_source_commit_differs(self) -> None:
        source_sha = "a" * 40
        provenance = {
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "configSource": {
                            "uri": "https://github.com/acme/service",
                            "digest": {"gitCommit": "b" * 40},
                        }
                    },
                    "resolvedDependencies": [
                        {
                            "uri": "https://github.com/acme/service",
                            "digest": {"gitCommit": source_sha},
                        }
                    ],
                }
            }
        }

        with self.assertRaisesRegex(AttestationError, "source does not match"):
            verify_attestation_bundle(
                {"manifests": [_manifest(), _manifest(attestation=True)]},
                {"spdxVersion": "SPDX-2.3", "packages": []},
                provenance,
                expected_source_repository="https://github.com/acme/service",
                expected_source_sha=source_sha,
            )


if __name__ == "__main__":
    unittest.main()
