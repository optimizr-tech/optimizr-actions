"""Tests for exact-digest exception policies used by candidate promotion."""

from __future__ import annotations

import unittest

from scripts.container_release.validate_candidate_exceptions import (
    CandidateExceptionError,
    validate_policy,
)


IMAGE = "ghcr.io/acme/grafana@sha256:" + "a" * 64


def _entry(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": "CVE-2026-12345",
        "owner": "security-team",
        "statement": "Upstream fix is not yet available",
        "compensating_control": "Restricted network exposure",
        "expires": "2026-12-31",
        "scan_types": ["image"],
        "targets": [IMAGE],
        "purls": ["pkg:golang/example.org/module@v1.2.3"],
    }
    value.update(overrides)
    return value


class CandidateExceptionPolicyTests(unittest.TestCase):
    def test_accepts_explicit_digest_target_and_package_url(self) -> None:
        result = validate_policy(
            {"version": 1, "vulnerabilities": [_entry()]},
            candidate_image=IMAGE,
        )

        self.assertEqual(1, result["exception_count"])

    def test_rejects_wildcard_target(self) -> None:
        with self.assertRaisesRegex(CandidateExceptionError, "exact candidate digest"):
            validate_policy(
                {"version": 1, "vulnerabilities": [_entry(targets=["*"])]},
                candidate_image=IMAGE,
            )

    def test_rejects_mismatched_candidate_digest(self) -> None:
        with self.assertRaisesRegex(CandidateExceptionError, "exact candidate digest"):
            validate_policy(
                {
                    "version": 1,
                    "vulnerabilities": [_entry(targets=[IMAGE.replace("a" * 64, "b" * 64)])],
                },
                candidate_image=IMAGE,
            )

    def test_rejects_unscoped_or_wildcard_package_urls(self) -> None:
        for purls in ([], ["*"]):
            with self.subTest(purls=purls):
                with self.assertRaisesRegex(CandidateExceptionError, "exact PURL"):
                    validate_policy(
                        {"version": 1, "vulnerabilities": [_entry(purls=purls)]},
                        candidate_image=IMAGE,
                    )

    def test_rejects_filesystem_scope_and_duplicate_ids(self) -> None:
        with self.assertRaisesRegex(CandidateExceptionError, "image-only"):
            validate_policy(
                {"version": 1, "vulnerabilities": [_entry(scan_types=["image", "fs"])]},
                candidate_image=IMAGE,
            )
        with self.assertRaisesRegex(CandidateExceptionError, "duplicate"):
            validate_policy(
                {"version": 1, "vulnerabilities": [_entry(), _entry()]},
                candidate_image=IMAGE,
            )
        with self.assertRaisesRegex(CandidateExceptionError, "duplicate"):
            validate_policy(
                {
                    "version": 1,
                    "vulnerabilities": [_entry(id="CVE-2026-12345"), _entry(id="cve-2026-12345")],
                },
                candidate_image=IMAGE,
            )

    def test_rejects_boolean_policy_version(self) -> None:
        with self.assertRaisesRegex(CandidateExceptionError, "version must be 1"):
            validate_policy(
                {"version": True, "vulnerabilities": [_entry()]},
                candidate_image=IMAGE,
            )

    def test_rejects_boolean_policy_version(self) -> None:
        with self.assertRaisesRegex(CandidateExceptionError, "version must be 1"):
            validate_policy(
                {"version": True, "vulnerabilities": [_entry()]},
                candidate_image=IMAGE,
            )


if __name__ == "__main__":
    unittest.main()
