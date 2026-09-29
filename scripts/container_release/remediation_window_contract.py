"""Validate and record the image publisher remediation-window contract."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.security_gate.remediation_window import (  # noqa: E402
    RemediationWindowError,
    validate_remediation_context,
)


class ContractError(ValueError):
    """Raised when publisher remediation-window inputs are unsafe or incomplete."""


_SERVICE_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}\Z")
_POLICY_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_EVALUATOR_VERSION = re.compile(r"[1-9][0-9]{0,5}\Z")
_CLASSIFICATIONS = {
    "clean",
    "actionable_vulnerability",
    "unfixed_warning",
    "misconfiguration_detected",
    "secret_detected",
    "scanner_error",
}
_OUTCOMES = {"success", "failure", "cancelled", "skipped"}
_DECISIONS = {"not_applicable", "blocked", "allowed_window"}
_PASSING_CLASSIFICATIONS = {"clean", "unfixed_warning"}


def validate_remediation_window_contract(
    *,
    enabled: bool,
    push: bool,
    policy_file: str,
    services: Sequence[Mapping[str, Any]],
) -> list[dict[str, str]]:
    """Validate opt-in settings and retain the distinct context for each service."""
    if not isinstance(enabled, bool) or not isinstance(push, bool):
        raise ContractError("enabled and push must be booleans")
    if not enabled:
        return []
    if not push:
        raise ContractError("remediation windows require immutable GHCR publication")
    if (
        not isinstance(policy_file, str)
        or not policy_file
        or len(policy_file) > 1024
        or not _POLICY_PATH.fullmatch(policy_file)
        or any(part in {".", ".."} for part in policy_file.split("/"))
    ):
        raise ContractError("policy_file must be a safe repository-relative path")
    if not isinstance(services, list) or not services:
        raise ContractError("services must be a non-empty JSON array")

    contexts: list[dict[str, str]] = []
    seen_names: set[str] = set()
    for index, service in enumerate(services):
        if not isinstance(service, Mapping):
            raise ContractError(f"services[{index}] must be an object")
        name = service.get("name")
        if not isinstance(name, str) or not _SERVICE_NAME.fullmatch(name):
            raise ContractError(f"services[{index}].name is invalid")
        if name in seen_names:
            raise ContractError("service names must be unique")
        seen_names.add(name)
        try:
            scope, exposure = validate_remediation_context(
                service.get("remediation_window_service_scope"),
                service.get("remediation_window_exposure_criticality"),
            )
        except RemediationWindowError as exc:
            raise ContractError(f"services[{index}] has invalid remediation context") from exc
        contexts.append(
            {
                "name": name,
                "service_scope": scope,
                "exposure_criticality": exposure,
            }
        )
    return contexts


def _boolean(value: Any) -> bool | None:
    if value is True or value == "true":
        return True
    if value is False or value == "false":
        return False
    return None


def _count(value: Any) -> int | None:
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,9}", value):
        return None
    return int(value)


def security_gate_acceptable(fields: Mapping[str, Any]) -> bool:
    """Return true only for a clean gate or a fully-covered immutable image window."""
    outcome = fields.get("outcome")
    result = fields.get("result")
    classification = fields.get("classification")
    if outcome not in _OUTCOMES or classification not in _CLASSIFICATIONS:
        return False
    if _boolean(fields.get("push")) is True:
        digest = fields.get("image_digest")
        image_ref = fields.get("scanned_image_ref")
        source_sha = fields.get("source_sha")
        if (
            not isinstance(digest, str)
            or not _IMAGE_DIGEST.fullmatch(digest)
            or not isinstance(image_ref, str)
            or "@" not in image_ref
            or image_ref.rsplit("@", 1)[-1] != digest
            or not isinstance(source_sha, str)
            or not _GIT_SHA.fullmatch(source_sha)
        ):
            return False
    if outcome == "success":
        return result == "passed" and classification in _PASSING_CLASSIFICATIONS
    if outcome != "failure" or result != "failed":
        return False
    if _boolean(fields.get("window_enabled")) is not True:
        return False
    if classification != "actionable_vulnerability":
        return False
    if fields.get("window_allowed") != "true":
        return False
    if fields.get("window_decision") != "allowed_window":
        return False
    if fields.get("window_classification") != "actionable_vulnerability":
        return False
    if fields.get("failure_reason", "") or fields.get("window_failure_reason", ""):
        return False

    blocking = _count(fields.get("blocking_total"))
    matching = _count(fields.get("window_count"))
    covered = _count(fields.get("covered"))
    uncovered = _count(fields.get("uncovered"))
    rejected = _count(fields.get("rejected"))
    overdue = _count(fields.get("overdue"))
    unmatched = _count(fields.get("unmatched"))
    reintroduced = _count(fields.get("reintroduced"))
    if (
        blocking is None
        or blocking == 0
        or matching is None
        or matching == 0
        or covered != blocking
        or uncovered != 0
        or rejected != 0
        or overdue != 0
        or unmatched != 0
        or reintroduced != 0
    ):
        return False

    image_digest = fields.get("image_digest")
    image_ref = fields.get("scanned_image_ref")
    source_sha = fields.get("source_sha")
    policy_digest = fields.get("policy_digest")
    evaluator_version = fields.get("evaluator_version")
    if not isinstance(image_digest, str) or not _IMAGE_DIGEST.fullmatch(image_digest):
        return False
    if (
        not isinstance(image_ref, str)
        or "@" not in image_ref
        or image_ref.rsplit("@", 1)[-1] != image_digest
        or any(char.isspace() or ord(char) < 32 for char in image_ref)
    ):
        return False
    if not isinstance(source_sha, str) or not _GIT_SHA.fullmatch(source_sha):
        return False
    if not isinstance(policy_digest, str) or not _HEX_DIGEST.fullmatch(policy_digest):
        return False
    if not isinstance(evaluator_version, str) or not _EVALUATOR_VERSION.fullmatch(evaluator_version):
        return False
    return True


def _safe_value(value: Any, allowed: set[str], fallback: str) -> str:
    return value if isinstance(value, str) and value in allowed else fallback


def _safe_text(value: Any, pattern: re.Pattern[str]) -> str:
    return value if isinstance(value, str) and pattern.fullmatch(value) else ""


def build_security_evidence(
    outputs: Mapping[str, Any],
    *,
    image_digest: str,
    scanned_image_ref: str,
    source_sha: str,
) -> dict[str, Any]:
    """Build an allow-listed, finding-free evidence fragment bound to one image."""
    enabled = _boolean(outputs.get("window_enabled")) is True
    window_allowed = outputs.get("window_allowed") == "true"
    default_decision = "blocked" if enabled else "not_applicable"
    counts = {
        "matching_policy_entries": _count(outputs.get("window_count")),
        "blocking_total": _count(outputs.get("blocking_total")),
        "covered": _count(outputs.get("covered")),
        "uncovered": _count(outputs.get("uncovered")),
        "rejected": _count(outputs.get("rejected")),
        "overdue": _count(outputs.get("overdue")),
        "unmatched": _count(outputs.get("unmatched")),
        "reintroduced": _count(outputs.get("reintroduced")),
    }
    gate_outcome = _safe_value(outputs.get("outcome"), _OUTCOMES, "unknown")
    gate_result = _safe_value(outputs.get("result"), {"passed", "failed"}, "unknown")
    classification = _safe_value(outputs.get("classification"), _CLASSIFICATIONS, "scanner_error")
    policy_digest = _safe_text(outputs.get("policy_digest"), _HEX_DIGEST)
    evaluator_version = _safe_text(outputs.get("evaluator_version"), _EVALUATOR_VERSION)
    valid_digest = _safe_text(image_digest, _IMAGE_DIGEST)
    valid_source_sha = _safe_text(source_sha, _GIT_SHA)
    safe_image_ref = (
        scanned_image_ref
        if isinstance(scanned_image_ref, str)
        and len(scanned_image_ref) <= 2048
        and not any(char.isspace() or ord(char) < 32 for char in scanned_image_ref)
        else ""
    )
    evidence: dict[str, Any] = {
        "image_digest": valid_digest,
        "scanned_image_ref": safe_image_ref,
        "source_sha": valid_source_sha,
        "gate": {
            "outcome": gate_outcome,
            "result": gate_result,
            "classification": classification,
        },
        "push": _boolean(outputs.get("push")) is True,
        "remediation_window": {
            "enabled": enabled,
            "allowed": window_allowed,
            "decision": _safe_value(outputs.get("window_decision"), _DECISIONS, default_decision),
            "classification": _safe_value(
                outputs.get("window_classification"), _CLASSIFICATIONS, ""
            ),
            **counts,
            "policy_digest": policy_digest,
            "evaluator_version": evaluator_version,
        },
    }
    decision_fields = dict(outputs)
    decision_fields.update(
        {
            "window_enabled": enabled,
            "image_digest": valid_digest,
            "scanned_image_ref": safe_image_ref,
            "source_sha": valid_source_sha,
            "policy_digest": policy_digest,
            "evaluator_version": evaluator_version,
        }
    )
    gate_accepted = security_gate_acceptable(decision_fields)
    evidence["security_gate_accepted"] = gate_accepted
    evidence["promotion_authorized"] = (
        _boolean(outputs.get("push")) is True and gate_accepted
    )
    return evidence


def _read_boolean_env(name: str) -> bool:
    value = os.environ.get(name, "")
    if value not in {"true", "false"}:
        raise ContractError(f"{name} must be true or false")
    return value == "true"


def _validate_from_environment() -> None:
    try:
        services = json.loads(os.environ["SERVICES_JSON"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise ContractError("SERVICES_JSON must be a JSON array") from exc
    validate_remediation_window_contract(
        enabled=_read_boolean_env("SECURITY_REMEDIATION_WINDOW_ENABLED"),
        push=_read_boolean_env("PUSH"),
        policy_file=os.environ.get("SECURITY_REMEDIATION_WINDOW_POLICY_FILE", ""),
        services=services,
    )


def _outputs_from_environment() -> dict[str, str]:
    fields = {
        "outcome": "SECURITY_OUTCOME",
        "result": "SECURITY_RESULT",
        "classification": "SECURITY_CLASSIFICATION",
        "window_enabled": "SECURITY_WINDOW_ENABLED",
        "push": "SECURITY_PUSH",
        "window_allowed": "SECURITY_WINDOW_ALLOWED",
        "window_decision": "SECURITY_WINDOW_DECISION",
        "window_classification": "SECURITY_WINDOW_CLASSIFICATION",
        "window_count": "SECURITY_WINDOW_COUNT",
        "blocking_total": "SECURITY_WINDOW_BLOCKING_TOTAL",
        "covered": "SECURITY_WINDOW_COVERED",
        "uncovered": "SECURITY_WINDOW_UNCOVERED",
        "rejected": "SECURITY_WINDOW_REJECTED",
        "overdue": "SECURITY_WINDOW_OVERDUE",
        "unmatched": "SECURITY_WINDOW_UNMATCHED",
        "reintroduced": "SECURITY_WINDOW_REINTRODUCED",
        "policy_digest": "SECURITY_WINDOW_POLICY_DIGEST",
        "evaluator_version": "SECURITY_WINDOW_EVALUATOR_VERSION",
        "failure_reason": "SECURITY_FAILURE_REASON",
        "window_failure_reason": "SECURITY_WINDOW_FAILURE_REASON",
    }
    return {key: os.environ.get(name, "") for key, name in fields.items()}


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    if path.is_symlink():
        raise ContractError("security evidence destination must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    if temporary.is_symlink():
        raise ContractError("security evidence temporary file must not be a symlink")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _record_from_environment() -> None:
    fields = _outputs_from_environment()
    evidence = build_security_evidence(
        fields,
        image_digest=os.environ.get("SECURITY_IMAGE_DIGEST", ""),
        scanned_image_ref=os.environ.get("SECURITY_SCANNED_IMAGE_REF", ""),
        source_sha=os.environ.get("SECURITY_SOURCE_SHA", ""),
    )
    destination = Path(os.environ["SECURITY_EVIDENCE_PATH"])
    output = Path(os.environ["GITHUB_OUTPUT"])
    if output.is_symlink():
        raise ContractError("GitHub output must not be a symlink")
    _write_json(destination, evidence)
    with output.open("a", encoding="utf-8") as stream:
        stream.write(f"allowed={'true' if evidence['security_gate_accepted'] else 'false'}\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "record"))
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            _validate_from_environment()
        else:
            _record_from_environment()
        return 0
    except (ContractError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f"container remediation-window contract failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
