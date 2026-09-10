from __future__ import annotations

import unittest

from scripts.delivery.gate_evidence import (
    DEFAULT_REQUIRED_GATES,
    GateEvidence,
    GateEvidenceError,
    evaluate_gate_evidence,
)


class DeliveryGateEvidenceTests(unittest.TestCase):
    def _complete(self) -> list[GateEvidence]:
        return [
            GateEvidence(name=name, status="passed", target=name)
            for name in DEFAULT_REQUIRED_GATES
        ]

    def test_all_required_gates_pass_and_emit_sanitized_evidence(self) -> None:
        result = evaluate_gate_evidence(self._complete())

        self.assertTrue(result.passed)
        self.assertIsNone(result.failure_reason)
        self.assertEqual(
            tuple(DEFAULT_REQUIRED_GATES),
            tuple(item["name"] for item in result.evidence),
        )
        self.assertEqual(
            {"name", "status", "target"},
            set(result.evidence[0]),
        )

    def test_missing_required_gate_fails_closed(self) -> None:
        gates = [gate for gate in self._complete() if gate.name != "health"]

        result = evaluate_gate_evidence(gates)

        self.assertFalse(result.passed)
        self.assertEqual("missing required gate: health", result.failure_reason)

    def test_skipped_required_gate_fails_closed(self) -> None:
        gates = self._complete()
        gates[-1] = GateEvidence(
            name="health",
            status="skipped",
            target="serve",
            reason="not executed",
        )

        result = evaluate_gate_evidence(gates)

        self.assertFalse(result.passed)
        self.assertEqual("required gate skipped: health", result.failure_reason)

    def test_failed_gate_includes_only_sanitized_reason(self) -> None:
        gates = self._complete()
        gates[2] = GateEvidence(
            name="security",
            status="failed",
            target="image",
            reason="fixable vulnerability found",
        )

        result = evaluate_gate_evidence(gates)

        self.assertFalse(result.passed)
        self.assertEqual("security: fixable vulnerability found", result.failure_reason)
        self.assertEqual(
            {
                "name": "security",
                "status": "failed",
                "target": "image",
                "reason": "fixable vulnerability found",
            },
            result.evidence[2],
        )

    def test_optional_skipped_gate_does_not_fail_required_profile(self) -> None:
        gates = [*self._complete(), GateEvidence("smoke", "skipped", "consumer")]

        result = evaluate_gate_evidence(gates)

        self.assertTrue(result.passed)

    def test_duplicate_and_unknown_required_names_are_rejected(self) -> None:
        with self.assertRaises(GateEvidenceError):
            evaluate_gate_evidence(
                [*self._complete(), GateEvidence("health", "passed", "serve")]
            )
        with self.assertRaises(GateEvidenceError):
            evaluate_gate_evidence(
                self._complete(), required_gates=("filesystem", "unknown")
            )

    def test_secret_like_or_multiline_metadata_is_rejected(self) -> None:
        gates = self._complete()
        gates[0] = GateEvidence(
            name="filesystem",
            status="failed",
            target="/srv",
            reason="token=do-not-record",
        )
        with self.assertRaises(GateEvidenceError):
            evaluate_gate_evidence(gates)

        gates[0] = GateEvidence(
            name="filesystem",
            status="passed",
            target="https://user:password@example.test/health",
        )
        with self.assertRaises(GateEvidenceError):
            evaluate_gate_evidence(gates)

        gates[0] = GateEvidence(
            name="filesystem",
            status="failed",
            target="/srv\nsecret",
        )
        with self.assertRaises(GateEvidenceError):
            evaluate_gate_evidence(gates)


if __name__ == "__main__":
    unittest.main()
