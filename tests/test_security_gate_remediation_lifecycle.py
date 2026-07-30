from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import unittest

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "security_gate"
    / "remediation_lifecycle.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("remediation_lifecycle", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RemediationLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = _load_module()
        self.first_seen = datetime(2026, 7, 30, 12, tzinfo=timezone.utc)
        self.original_deadline = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)
        self.reference = datetime(2026, 8, 1, 12, tzinfo=timezone.utc)

    def _revision(
        self,
        action: str,
        *,
        previous: str,
        deadline: str,
        reviewed: str,
    ) -> dict[str, str]:
        return {
            "action": action,
            "first_seen_at": "2026-07-30T12:00:00Z",
            "previous_deadline_at": previous,
            "deadline_at": deadline,
            "reviewed_at": reviewed,
            "reviewed_by": "security-owner",
            "reason": f"reviewed_{action}",
        }

    def test_extension_preserves_original_deadline_and_first_seen(self) -> None:
        result = self.module.normalize_lifecycle(
            {
                "status": "active",
                "history": [
                    self._revision(
                        "extended",
                        previous="2026-08-06T12:00:00Z",
                        deadline="2026-08-20T12:00:00Z",
                        reviewed="2026-07-31T00:00:00Z",
                    )
                ],
            },
            first_seen=self.first_seen,
            original_deadline=self.original_deadline,
            reference=self.reference,
        )
        self.assertEqual(
            "2026-08-06T12:00:00Z", result["original_deadline_at"]
        )
        self.assertEqual(
            "2026-08-20T12:00:00Z", result["effective_deadline_at"]
        )
        self.assertEqual(1, result["revision_count"])

    def test_revision_cannot_reset_clock_or_skip_previous_deadline(self) -> None:
        revision = self._revision(
            "extended",
            previous="2026-08-06T12:00:00Z",
            deadline="2026-08-20T12:00:00Z",
            reviewed="2026-07-31T00:00:00Z",
        )
        revision["first_seen_at"] = "2026-07-31T12:00:00Z"
        with self.assertRaisesRegex(ValueError, "preserve first_seen_at"):
            self.module.normalize_lifecycle(
                {"status": "active", "history": [revision]},
                first_seen=self.first_seen,
                original_deadline=self.original_deadline,
                reference=self.reference,
            )

        revision["first_seen_at"] = "2026-07-30T12:00:00Z"
        revision["previous_deadline_at"] = "2026-08-07T12:00:00Z"
        with self.assertRaisesRegex(ValueError, "previous deadline"):
            self.module.normalize_lifecycle(
                {"status": "active", "history": [revision]},
                first_seen=self.first_seen,
                original_deadline=self.original_deadline,
                reference=self.reference,
            )

    def test_resolved_and_reintroduced_require_ordered_history(self) -> None:
        resolved = self._revision(
            "resolved",
            previous="2026-08-06T12:00:00Z",
            deadline="2026-08-06T12:00:00Z",
            reviewed="2026-07-31T00:00:00Z",
        )
        reintroduced = self._revision(
            "reintroduced",
            previous="2026-08-06T12:00:00Z",
            deadline="2026-08-06T12:00:00Z",
            reviewed="2026-08-01T00:00:00Z",
        )
        result = self.module.normalize_lifecycle(
            {"status": "reintroduced", "history": [resolved, reintroduced]},
            first_seen=self.first_seen,
            original_deadline=self.original_deadline,
            reference=self.reference,
        )
        self.assertEqual("reintroduced", result["status"])
        self.assertEqual(
            "2026-08-06T12:00:00Z", result["effective_deadline_at"]
        )
        self.assertEqual(2, result["revision_count"])

        with self.assertRaisesRegex(ValueError, "follow resolved"):
            self.module.normalize_lifecycle(
                {"status": "reintroduced", "history": [reintroduced]},
                first_seen=self.first_seen,
                original_deadline=self.original_deadline,
                reference=self.reference,
            )


if __name__ == "__main__":
    unittest.main()
