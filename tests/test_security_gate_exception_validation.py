"""Contract tests for full-set Trivy exception policy validation."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from scripts.security_gate import evidence


ROOT = Path(__file__).resolve().parents[1]
IMAGE_A = "sha256:" + "a" * 64
IMAGE_B = "sha256:" + "b" * 64
LINEAGE = "sha256:" + "c" * 64
TODAY = date(2026, 9, 28)


class CompleteExceptionPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _entry(self, **updates: object) -> dict[str, object]:
        entry: dict[str, object] = {
            "id": "CVE-2026-0001",
            "owner": "platform-security",
            "statement": "The reviewed finding is not reachable",
            "compensating_control": "The affected route is blocked",
            "expires": "2030-01-01",
            "targets": [IMAGE_A],
            "paths": ["usr/local/bin/service"],
        }
        entry.update(updates)
        return entry

    def _validate(
        self,
        entries: list[object],
        *,
        active_ids: list[str] | None = None,
        image_refs: list[str] | None = None,
    ) -> int:
        active_ids = [IMAGE_A] if active_ids is None else active_ids
        image_refs = [IMAGE_A] if image_refs is None else image_refs
        policy = self.root / "exceptions.json"
        policy.write_text(
            json.dumps({"version": 1, "vulnerabilities": entries}),
            encoding="utf-8",
        )
        active_file = self.root / "active-image-ids.txt"
        active_file.write_text(
            "".join(f"{image_id}\n" for image_id in active_ids),
            encoding="utf-8",
        )

        validator = getattr(evidence, "validate_complete_exception_policy", None)
        self.assertTrue(
            callable(validator),
            "the full exception policy validator must be implemented",
        )
        return validator(
            policy,
            active_image_ids_file=active_file,
            image_refs=image_refs,
            today=TODAY,
        )

    def test_accepts_single_image_and_scoped_filesystem_exceptions(self) -> None:
        entries = [
            self._entry(),
            self._entry(
                id="CVE-2026-0002",
                scan_types=["fs"],
                targets=[],
                paths=["scripts/healthcheck.py"],
                purls=[],
            ),
        ]

        self.assertEqual(self._validate(entries), 2)

    def test_accepts_all_ids_for_multi_image_and_lineage_exceptions(self) -> None:
        entries = [
            self._entry(),
            self._entry(id="CVE-2026-0002", targets=[IMAGE_B]),
            self._entry(
                id="CVE-2026-0003",
                targets=[],
                lineage_digests=[LINEAGE],
                purls=["pkg:golang/example.org/module@1.2.3"],
            ),
        ]

        self.assertEqual(
            self._validate(
                entries,
                active_ids=[IMAGE_B, IMAGE_A],
                image_refs=[IMAGE_A, IMAGE_B],
            ),
            3,
        )

    def test_rejects_active_id_file_that_does_not_equal_scanned_image_refs(self) -> None:
        with self.assertRaisesRegex(ValueError, "must match the complete image_refs set"):
            self._validate(
                [self._entry()],
                active_ids=[IMAGE_A],
                image_refs=[IMAGE_A, IMAGE_B],
            )

    def test_rejects_mutable_image_refs_in_strict_mode(self) -> None:
        with self.assertRaisesRegex(ValueError, "full immutable sha256 image IDs"):
            self._validate(
                [self._entry()],
                active_ids=[IMAGE_A],
                image_refs=["registry.example/app:latest"],
            )

    def test_rejects_empty_active_image_id_set(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            self._validate([self._entry()], active_ids=[], image_refs=[IMAGE_A])

    def test_rejects_malformed_active_image_id(self) -> None:
        with self.assertRaisesRegex(ValueError, "active image ID set contains invalid values"):
            self._validate(
                [self._entry()],
                active_ids=["sha256:ABC"],
                image_refs=[IMAGE_A],
            )

    def test_rejects_duplicate_active_image_ids(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate active image ID"):
            self._validate(
                [self._entry()],
                active_ids=[IMAGE_A, IMAGE_A],
                image_refs=[IMAGE_A],
            )

    def test_rejects_empty_scanned_image_ref_set(self) -> None:
        with self.assertRaisesRegex(ValueError, "complete active image set"):
            self._validate(
                [self._entry()],
                active_ids=[IMAGE_A],
                image_refs=[],
            )

    def test_rejects_duplicate_scanned_image_refs(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate immutable image ID"):
            self._validate(
                [self._entry()],
                active_ids=[IMAGE_A],
                image_refs=[IMAGE_A, IMAGE_A],
            )

    def test_rejects_exception_target_outside_active_set(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside the exact active image set"):
            self._validate(
                [self._entry(targets=[IMAGE_B])],
                active_ids=[IMAGE_A],
                image_refs=[IMAGE_A],
            )

    def test_rejects_wildcard_or_noncanonical_exception_target(self) -> None:
        with self.assertRaisesRegex(ValueError, "full lowercase sha256 image IDs"):
            self._validate([self._entry(targets=["*"])])

    def test_rejects_duplicate_exception_identity(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate exception"):
            self._validate([self._entry(), self._entry(statement="Different wording")])

    def test_rejects_duplicate_scan_types(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate scan types"):
            self._validate([self._entry(scan_types=["image", "image"])])

    def test_rejects_expired_entry_for_another_image_in_the_complete_set(self) -> None:
        with self.assertRaisesRegex(ValueError, "expired"):
            self._validate(
                [self._entry(targets=[IMAGE_B], expires="2026-09-27")],
                active_ids=[IMAGE_A, IMAGE_B],
                image_refs=[IMAGE_A, IMAGE_B],
            )

    def test_rejects_noncanonical_expiration_date(self) -> None:
        with self.assertRaisesRegex(ValueError, "expires must use YYYY-MM-DD"):
            self._validate([self._entry(expires="20300101")])

    def test_rejects_malformed_entry_for_another_image_in_the_complete_set(self) -> None:
        with self.assertRaisesRegex(ValueError, "owner is required"):
            self._validate(
                [self._entry(targets=[IMAGE_B], owner="  ")],
                active_ids=[IMAGE_A, IMAGE_B],
                image_refs=[IMAGE_A, IMAGE_B],
            )

    def test_rejects_filesystem_only_exception_with_image_targets(self) -> None:
        with self.assertRaisesRegex(
            ValueError, "filesystem-only exceptions must not target image IDs"
        ):
            self._validate(
                [self._entry(scan_types=["fs"], paths=["config/app.yml"])],
            )


class SecurityGateExceptionContractTests(unittest.TestCase):
    def test_complete_validation_is_opt_in_and_runs_before_scanning(self) -> None:
        action = (ROOT / ".github/actions/security-gate/action.yml").read_text(
            encoding="utf-8"
        )
        documentation = (ROOT / "docs/SECURITY_GATE.md").read_text(encoding="utf-8")

        self.assertIn("  active_image_ids_file:", action)
        active_input = action.split("  active_image_ids_file:\n", 1)[1].split(
            "\n  baseline_file:", 1
        )[0]
        self.assertIn("required: false", active_input)
        self.assertIn('default: ""', active_input)
        self.assertIn('INPUT_ACTIVE_IMAGE_IDS_FILE: ${{ inputs.active_image_ids_file }}', action)
        self.assertIn("validate-exceptions", action)
        self.assertIn('--active-image-ids-file "$INPUT_ACTIVE_IMAGE_IDS_FILE"', action)
        self.assertIn('"--image-ref=$image_ref"', action)
        self.assertIn("requires an image scan and exceptions_file", action)
        validate_at = action.index('python3 "$evidence_tool" "${validation_args[@]}"')
        scan_loop_at = action.index('for target in "${targets[@]}"; do')
        scan_at = action.index('trivy --cache-dir "$cache_dir" "$command_name"')
        self.assertLess(validate_at, scan_loop_at)
        self.assertLess(validate_at, scan_at)
        self.assertIn("active_image_ids_file", documentation)
        self.assertIn("must match the complete `image_refs` set", documentation)


if __name__ == "__main__":
    unittest.main()
