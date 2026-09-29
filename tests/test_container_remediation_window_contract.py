"""Contracts for governed remediation windows in the image publisher."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "scripts/container_release/remediation_window_contract.py"
WORKFLOW_PATH = ROOT / ".github/workflows/_container-build-publish.yml"


def load_contract(test: unittest.TestCase):
    test.assertTrue(
        CONTRACT_PATH.is_file(),
        "the publisher needs a tested remediation-window contract helper",
    )
    spec = importlib.util.spec_from_file_location(
        "container_remediation_window_contract", CONTRACT_PATH
    )
    test.assertIsNotNone(spec)
    test.assertIsNotNone(spec.loader if spec else None)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublisherRemediationWindowContractTests(unittest.TestCase):
    def test_disabled_contract_preserves_legacy_service_definitions(self) -> None:
        contract = load_contract(self)
        result = contract.validate_remediation_window_contract(
            enabled=False,
            push=False,
            policy_file="",
            services=[{"name": "api", "context": "api", "dockerfile": "api/Dockerfile"}],
        )
        self.assertEqual([], result)

    def test_enabled_contract_keeps_distinct_matrix_service_contexts(self) -> None:
        contract = load_contract(self)
        result = contract.validate_remediation_window_contract(
            enabled=True,
            push=True,
            policy_file="policies/remediation-windows.json",
            services=[
                {
                    "name": "api",
                    "remediation_window_service_scope": "monitoring/api",
                    "remediation_window_exposure_criticality": "internet-facing",
                },
                {
                    "name": "worker",
                    "remediation_window_service_scope": "monitoring/worker",
                    "remediation_window_exposure_criticality": "internal",
                },
            ],
        )
        self.assertEqual(
            [
                ("api", "monitoring/api", "internet-facing"),
                ("worker", "monitoring/worker", "internal"),
            ],
            [
                (
                    item["name"],
                    item["service_scope"],
                    item["exposure_criticality"],
                )
                for item in result
            ],
        )

    def test_enabled_contract_rejects_missing_or_unknown_service_context(self) -> None:
        contract = load_contract(self)
        base = {
            "name": "api",
            "remediation_window_service_scope": "monitoring/api",
            "remediation_window_exposure_criticality": "internal",
        }
        for changes in (
            {"remediation_window_service_scope": ""},
            {"remediation_window_exposure_criticality": "internet"},
            {"remediation_window_exposure_criticality": "unknown"},
        ):
            with self.subTest(changes=changes), self.assertRaises(contract.ContractError):
                contract.validate_remediation_window_contract(
                    enabled=True,
                    push=True,
                    policy_file="policies/remediation-windows.json",
                    services=[{**base, **changes}],
                )

    def test_enabled_contract_rejects_unsafe_policy_paths_and_non_publishing_runs(self) -> None:
        contract = load_contract(self)
        service = {
            "name": "api",
            "remediation_window_service_scope": "monitoring/api",
            "remediation_window_exposure_criticality": "internal",
        }
        for policy_file, push in (
            ("../outside.json", True),
            ("/absolute/policy.json", True),
            ("policies/remediation.json", False),
        ):
            with self.subTest(policy_file=policy_file, push=push), self.assertRaises(
                contract.ContractError
            ):
                contract.validate_remediation_window_contract(
                    enabled=True,
                    push=push,
                    policy_file=policy_file,
                    services=[service],
                )

    def test_only_fully_covered_actionable_vulnerabilities_can_authorize_promotion(self) -> None:
        contract = load_contract(self)
        fields = {
            "outcome": "failure",
            "result": "failed",
            "classification": "actionable_vulnerability",
            "push": True,
            "window_enabled": True,
            "window_allowed": "true",
            "window_decision": "allowed_window",
            "window_classification": "actionable_vulnerability",
            "window_count": "2",
            "blocking_total": "2",
            "covered": "2",
            "uncovered": "0",
            "rejected": "0",
            "overdue": "0",
            "unmatched": "0",
            "reintroduced": "0",
            "policy_digest": "a" * 64,
            "evaluator_version": "3",
            "image_digest": "sha256:" + "b" * 64,
            "scanned_image_ref": "ghcr.io/optimizr/api@sha256:" + "b" * 64,
            "source_sha": "c" * 40,
            "failure_reason": "",
            "window_failure_reason": "",
        }
        self.assertTrue(contract.security_gate_acceptable(fields))

    def test_publishing_clean_scan_requires_exact_digest_and_source_binding(self) -> None:
        contract = load_contract(self)
        fields = {
            "outcome": "success",
            "result": "passed",
            "classification": "clean",
            "push": "true",
            "image_digest": "sha256:" + "b" * 64,
            "scanned_image_ref": "ghcr.io/optimizr/api@sha256:" + "b" * 64,
            "source_sha": "c" * 40,
        }
        self.assertTrue(contract.security_gate_acceptable(fields))
        for changes in (
            {"image_digest": ""},
            {"scanned_image_ref": "ghcr.io/optimizr/api:latest"},
            {"source_sha": ""},
        ):
            with self.subTest(changes=changes):
                self.assertFalse(contract.security_gate_acceptable({**fields, **changes}))

    def test_default_and_all_non_vulnerability_or_uncovered_failures_remain_blocked(self) -> None:
        contract = load_contract(self)
        allowed = {
            "outcome": "failure",
            "result": "failed",
            "classification": "actionable_vulnerability",
            "window_enabled": True,
            "window_allowed": "true",
            "window_decision": "allowed_window",
            "window_classification": "actionable_vulnerability",
            "window_count": "1",
            "blocking_total": "1",
            "covered": "1",
            "uncovered": "0",
            "rejected": "0",
            "overdue": "0",
            "unmatched": "0",
            "reintroduced": "0",
            "policy_digest": "a" * 64,
            "evaluator_version": "3",
            "image_digest": "sha256:" + "b" * 64,
            "scanned_image_ref": "ghcr.io/optimizr/api@sha256:" + "b" * 64,
            "source_sha": "c" * 40,
            "failure_reason": "",
            "window_failure_reason": "",
        }
        for changes in (
            {"window_enabled": False},
            {"classification": "scanner_error"},
            {"classification": "secret_detected"},
            {"classification": "misconfiguration_detected"},
            {"uncovered": "1"},
            {"rejected": "1"},
            {"overdue": "1"},
            {"unmatched": "1"},
            {"reintroduced": "1"},
            {"scanned_image_ref": "ghcr.io/optimizr/api:mutable"},
            {"failure_reason": "scanner_initialization_failed"},
            {"window_failure_reason": "window_policy_unavailable"},
        ):
            with self.subTest(changes=changes):
                self.assertFalse(contract.security_gate_acceptable({**allowed, **changes}))

        self.assertTrue(
            contract.security_gate_acceptable(
                {
                    "outcome": "success",
                    "result": "passed",
                    "classification": "clean",
                    "window_enabled": False,
                }
            )
        )

    def test_release_security_evidence_binds_sanitized_window_to_source_and_digest(self) -> None:
        contract = load_contract(self)
        evidence = contract.build_security_evidence(
            {
                "outcome": "failure",
                "result": "failed",
                "classification": "actionable_vulnerability",
                "push": "true",
                "window_enabled": "true",
                "window_allowed": "true",
                "window_decision": "allowed_window",
                "window_classification": "actionable_vulnerability",
                "window_count": "2",
                "blocking_total": "2",
                "covered": "2",
                "uncovered": "0",
                "rejected": "0",
                "overdue": "0",
                "unmatched": "0",
                "reintroduced": "0",
                "policy_digest": "a" * 64,
                "evaluator_version": "3",
            },
            image_digest="sha256:" + "b" * 64,
            scanned_image_ref="ghcr.io/optimizr/api@sha256:" + "b" * 64,
            source_sha="c" * 40,
        )
        self.assertEqual("sha256:" + "b" * 64, evidence["image_digest"])
        self.assertEqual("c" * 40, evidence["source_sha"])
        self.assertTrue(evidence["push"])
        self.assertTrue(evidence["security_gate_accepted"])
        self.assertTrue(evidence["promotion_authorized"])
        self.assertEqual(2, evidence["remediation_window"]["covered"])
        self.assertEqual("a" * 64, evidence["remediation_window"]["policy_digest"])
        self.assertNotIn("findings", evidence["remediation_window"])

    def test_non_publishing_clean_scan_is_accepted_without_promotion_authorization(self) -> None:
        contract = load_contract(self)
        evidence = contract.build_security_evidence(
            {
                "outcome": "success",
                "result": "passed",
                "classification": "clean",
                "push": "false",
            },
            image_digest="sha256:" + "b" * 64,
            scanned_image_ref="ghcr.io/optimizr/api:candidate",
            source_sha="c" * 40,
        )
        self.assertTrue(evidence["security_gate_accepted"])
        self.assertFalse(evidence["promotion_authorized"])


class PublisherRemediationWindowWorkflowTests(unittest.TestCase):
    def test_publisher_validates_and_forwards_each_services_window_contract(self) -> None:
        content = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("security_remediation_window_enabled:", content)
        self.assertIn("security_remediation_window_policy_file:", content)
        self.assertIn("Validate remediation-window contract", content)
        self.assertIn("scripts/container_release/remediation_window_contract.py", content)
        self.assertIn("SECURITY_PUSH: ${{ inputs.push }}", content)
        self.assertEqual(
            2, content.count("remediation_window_service_scope: ${{ matrix.service.remediation_window_service_scope }}")
        )
        self.assertEqual(
            2,
            content.count(
                "remediation_window_exposure_criticality: ${{ matrix.service.remediation_window_exposure_criticality }}"
            ),
        )
        self.assertEqual(
            2,
            content.count(
                "remediation_window_image_digest: ${{ steps.build.outputs.digest }}"
            ),
        )
        self.assertEqual(
            2,
            content.count(
                "remediation_window_source_sha: ${{ inputs.candidate_sha }}"
            ),
        )

    def test_promotion_depends_on_the_governed_decision_and_records_its_evidence(self) -> None:
        content = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("remediation_window_contract.py record", content)
        self.assertIn("security-decision.outputs.allowed == 'true'", content)
        self.assertIn('"security_evidence"', content)
        self.assertIn("publisher-security-decision.json", content)
        self.assertIn('security_evidence.get("source_sha") != os.environ["CANDIDATE_SHA"]', content)
        self.assertIn('security_evidence.get("security_gate_accepted") is not True', content)
        self.assertIn('security_evidence.get("promotion_authorized") is not True', content)
