"""Evaluate governed remediation-window policies against sanitized observations."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence


_SHA256_DIGEST = re.compile(r"sha256:[0-9a-fA-F]{64}\Z")
_RFC3339_Z = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_BLOCKED_EXPOSURES = {"internet-facing", "privileged-boundary"}
_ALLOWED_CLASSIFICATIONS = {"actionable_vulnerability", "unfixed_warning"}
_DEFAULT_EVALUATOR_VERSION = "1"


class RemediationWindowError(ValueError):
    """Raised when a remediation-window policy or observation is invalid."""


def _load_json(path: Path, label: str) -> Mapping[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise RemediationWindowError(f"{label} must be a regular non-symlink file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RemediationWindowError(f"{label} must be valid UTF-8 JSON") from exc
    if not isinstance(payload, Mapping):
        raise RemediationWindowError(f"{label} must be a JSON object")
    return payload


def _required_text(payload: Mapping[str, Any], field: str, *, label: str = "policy") -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise RemediationWindowError(f"{label} field {field} is required")
    return value.strip()


def _parse_rfc3339_utc(text: str, *, label: str) -> datetime:
    if not isinstance(text, str) or not _RFC3339_Z.fullmatch(text):
        raise RemediationWindowError(f"{label} must use RFC3339 UTC timestamps")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RemediationWindowError(f"{label} must use RFC3339 UTC timestamps") from exc
    if parsed.tzinfo is None:
        raise RemediationWindowError(f"{label} must use RFC3339 UTC timestamps")
    return parsed.astimezone(timezone.utc)


def _normal_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_digest_list(raw: Any, *, label: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not raw:
        raise RemediationWindowError(f"{label} must be a non-empty array")
    digests: list[str] = []
    for index, item in enumerate(raw):
        digest = _normal_text(item).lower()
        if _SHA256_DIGEST.fullmatch(digest) is None:
            raise RemediationWindowError(f"{label}[{index}] must be an immutable sha256 digest")
        digests.append(digest)
    if len(set(digests)) != len(digests):
        raise RemediationWindowError(f"{label} must not contain duplicate digests")
    return tuple(sorted(digests))


def _canonical_fingerprint(raw: Mapping[str, Any]) -> dict[str, Any]:
    fingerprint = raw.get("fingerprint")
    if not isinstance(fingerprint, Mapping):
        raise RemediationWindowError("policy entry fingerprint must be an object")
    service = _required_text(fingerprint, "service", label="fingerprint")
    advisory_id = _required_text(fingerprint, "advisory_id", label="fingerprint")
    package_purl = _required_text(fingerprint, "package_purl", label="fingerprint")
    installed_version = _required_text(fingerprint, "installed_version", label="fingerprint")
    fixed_version = _required_text(fingerprint, "fixed_version", label="fingerprint")
    image_lineage_digests = _normalize_digest_list(
        fingerprint.get("image_lineage_digests"),
        label="fingerprint.image_lineage_digests",
    )
    return {
        "service": service,
        "advisory_id": advisory_id,
        "package_purl": package_purl,
        "installed_version": installed_version,
        "fixed_version": fixed_version,
        "image_lineage_digests": list(image_lineage_digests),
    }


def _fingerprint_key(fingerprint: Mapping[str, Any]) -> tuple[Any, ...]:
    digests = fingerprint["image_lineage_digests"]
    if not isinstance(digests, list):
        raise RemediationWindowError("fingerprint.image_lineage_digests must be an array")
    return (
        fingerprint["service"],
        fingerprint["advisory_id"],
        fingerprint["package_purl"],
        fingerprint["installed_version"],
        fingerprint["fixed_version"],
        tuple(digests),
    )


def _policy_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_revision(entry: Mapping[str, Any], *, first_seen: datetime) -> None:
    if "history" not in entry:
        return
    history = entry["history"]
    if not isinstance(history, list) or not history:
        raise RemediationWindowError("policy entry history must be a non-empty array")
    for index, revision in enumerate(history):
        if not isinstance(revision, Mapping):
            raise RemediationWindowError(f"policy entry history[{index}] must be an object")
        revision_first_seen = _parse_rfc3339_utc(
            _required_text(revision, "first_seen_at", label="history"),
            label="history.first_seen_at",
        )
        if revision_first_seen != first_seen:
            raise RemediationWindowError("policy entry history must preserve first_seen_at")
        revision_deadline = _parse_rfc3339_utc(
            _required_text(revision, "deadline_at", label="history"),
            label="history.deadline_at",
        )
        if revision_deadline < first_seen:
            raise RemediationWindowError("policy entry history deadline must follow first_seen_at")


def load_policy(path: Path, *, reference_time: str | None = None) -> dict[str, Any]:
    """Validate a reviewed remediation-window policy and return its normalized form."""
    payload = _load_json(path, "policy")
    if payload.get("version") != 1:
        raise RemediationWindowError("policy version must be 1")
    owner = _required_text(payload, "policy_owner", label="policy")
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise RemediationWindowError("policy entries must be a non-empty array")

    reference = (
        _parse_rfc3339_utc(reference_time, label="reference_time")
        if reference_time
        else datetime.now(timezone.utc)
    )

    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_fingerprints: set[tuple[Any, ...]] = set()
    for index, raw_entry in enumerate(raw_entries):
        if not isinstance(raw_entry, Mapping):
            raise RemediationWindowError(f"policy entries[{index}] must be an object")
        entry_id = _required_text(raw_entry, "id", label=f"entries[{index}]")
        if entry_id in seen_ids:
            raise RemediationWindowError(f"duplicate policy entry id {entry_id}")
        fingerprint = _canonical_fingerprint(raw_entry)
        fingerprint_key = _fingerprint_key(fingerprint)
        if fingerprint_key in seen_fingerprints:
            raise RemediationWindowError(f"duplicate policy fingerprint at entries[{index}]")

        reason = _required_text(raw_entry, "reason", label=f"entries[{index}]")
        first_seen_at = _parse_rfc3339_utc(
            _required_text(raw_entry, "first_seen_at", label=f"entries[{index}]"),
            label=f"entries[{index}].first_seen_at",
        )
        deadline_at = _parse_rfc3339_utc(
            _required_text(raw_entry, "deadline_at", label=f"entries[{index}]"),
            label=f"entries[{index}].deadline_at",
        )
        owner_text = _required_text(raw_entry, "owner", label=f"entries[{index}]")
        reviewer = _required_text(raw_entry, "reviewer", label=f"entries[{index}]")
        statement = _required_text(raw_entry, "statement", label=f"entries[{index}]")
        compensating_control = _required_text(
            raw_entry,
            "compensating_control",
            label=f"entries[{index}]",
        )
        reviewed_at = _parse_rfc3339_utc(
            _required_text(raw_entry, "reviewed_at", label=f"entries[{index}]"),
            label=f"entries[{index}].reviewed_at",
        )
        reviewed_by = _required_text(raw_entry, "reviewed_by", label=f"entries[{index}]")
        status = _required_text(raw_entry, "status", label=f"entries[{index}]")
        if status != "active":
            raise RemediationWindowError("policy entries must be active to authorize a window")
        if first_seen_at > reference:
            raise RemediationWindowError("policy first_seen_at must not be in the future")
        if deadline_at <= first_seen_at:
            raise RemediationWindowError("policy deadline_at must be after first_seen_at")
        _load_revision(raw_entry, first_seen=first_seen_at)

        seen_ids.add(entry_id)
        seen_fingerprints.add(fingerprint_key)
        entries.append(
            {
                "id": entry_id,
                "fingerprint": fingerprint,
                "reason": reason,
                "first_seen_at": first_seen_at,
                "deadline_at": deadline_at,
                "owner": owner_text,
                "reviewer": reviewer,
                "statement": statement,
                "compensating_control": compensating_control,
                "reviewed_at": reviewed_at,
                "reviewed_by": reviewed_by,
                "status": status,
            }
        )

    return {
        "version": 1,
        "policy_owner": owner,
        "entries": [
            {
                "id": entry["id"],
                "fingerprint": entry["fingerprint"],
                "reason": entry["reason"],
                "first_seen_at": entry["first_seen_at"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "deadline_at": entry["deadline_at"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "owner": entry["owner"],
                "reviewer": entry["reviewer"],
                "statement": entry["statement"],
                "compensating_control": entry["compensating_control"],
                "reviewed_at": entry["reviewed_at"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "reviewed_by": entry["reviewed_by"],
                "status": entry["status"],
            }
            for entry in entries
        ],
        "policy_digest": _policy_digest(path),
    }


def _canonical_observation(observation: Mapping[str, Any]) -> dict[str, Any]:
    service_scope = _required_text(observation, "service_scope", label="observation")
    advisory_id = _required_text(observation, "advisory_id", label="observation")
    package_purl = _required_text(observation, "package_purl", label="observation")
    installed_version = _required_text(observation, "installed_version", label="observation")
    fixed_version = _required_text(observation, "fixed_version", label="observation")
    image_lineage_digests = _normalize_digest_list(
        observation.get("image_lineage_digests"),
        label="observation.image_lineage_digests",
    )
    classification = _normal_text(observation.get("classification"))
    source_sha = _normal_text(observation.get("source_sha"))
    image_identity = _normal_text(observation.get("image_identity"))
    if len(source_sha) != 40 or any(ch not in "0123456789abcdef" for ch in source_sha.lower()):
        raise RemediationWindowError("observation source_sha must be a 40-character git SHA")
    if _SHA256_DIGEST.fullmatch(image_identity.lower()) is None:
        raise RemediationWindowError("observation image_identity must be an immutable sha256 digest")
    return {
        "service": service_scope,
        "service_scope": service_scope,
        "advisory_id": advisory_id,
        "package_purl": package_purl,
        "installed_version": installed_version,
        "fixed_version": fixed_version,
        "image_lineage_digests": list(image_lineage_digests),
        "classification": classification,
        "source_sha": source_sha.lower(),
        "image_identity": image_identity.lower(),
    }


def _fingerprint_matches(observation: Mapping[str, Any], entry: Mapping[str, Any]) -> bool:
    return _fingerprint_key(observation) == _fingerprint_key(entry["fingerprint"])


def evaluate_remediation_window(
    *,
    policy_path: Path,
    observation: Mapping[str, Any],
    enabled: bool,
    evaluation_time: str | None = None,
    exposure_criticality: str | None = None,
    fixed_image_verified: bool = False,
) -> dict[str, Any]:
    """Evaluate whether a specific exact finding is eligible for a remediation window."""
    normalized_observation = _canonical_observation(observation)
    classification = normalized_observation["classification"] or "gate_error"
    evaluation = (
        _parse_rfc3339_utc(evaluation_time, label="evaluation_time")
        if evaluation_time
        else datetime.now(timezone.utc)
    )

    policy = load_policy(policy_path, reference_time=evaluation.strftime("%Y-%m-%dT%H:%M:%SZ"))
    policy_entries = policy["entries"]

    result = {
        "classification": classification,
        "remediation_window_allowed": False,
        "remediation_state": "not_applicable",
        "decision": "not_applicable",
        "matching_entry_count": 0,
        "nearest_deadline": "",
        "policy_digest": policy["policy_digest"],
        "evaluator_version": _DEFAULT_EVALUATOR_VERSION,
        "failure_reason": "",
        "observation_digest": hashlib.sha256(
            json.dumps(normalized_observation, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }

    if not enabled:
        return result

    if classification not in _ALLOWED_CLASSIFICATIONS:
        result.update({"remediation_state": "blocked", "decision": "blocked", "failure_reason": "classification_block"})
        return result

    exposure = (exposure_criticality or _normal_text(observation.get("exposure_criticality"))).strip().lower()
    if exposure in _BLOCKED_EXPOSURES:
        result.update({"remediation_state": "blocked", "decision": "blocked", "failure_reason": "exposure_block"})
        return result

    if fixed_image_verified:
        result.update(
            {
                "remediation_state": "blocked",
                "decision": "blocked",
                "failure_reason": "fixed_image_available",
            }
        )
        return result

    for entry in policy_entries:
        if not _fingerprint_matches(normalized_observation, entry):
            continue
        result["matching_entry_count"] = 1
        result["nearest_deadline"] = entry["deadline_at"]
        if evaluation < _parse_rfc3339_utc(entry["first_seen_at"], label="policy.first_seen_at"):
            result.update(
                {
                    "remediation_state": "blocked",
                    "decision": "blocked",
                    "failure_reason": "future_first_seen",
                }
            )
            return result
        if evaluation > _parse_rfc3339_utc(entry["deadline_at"], label="policy.deadline_at"):
            result.update(
                {
                    "remediation_state": "blocked",
                    "decision": "blocked",
                    "failure_reason": "window_overdue",
                }
            )
            return result
        result.update(
            {
                "remediation_window_allowed": True,
                "remediation_state": "active",
                "decision": "allowed_window",
            }
        )
        return result

    return result


def _boolean(raw: str) -> bool:
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise argparse.ArgumentTypeError("boolean value must be true or false")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--observation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--enabled", type=_boolean, required=True)
    parser.add_argument("--evaluation-time")
    parser.add_argument("--exposure-criticality")
    parser.add_argument("--fixed-image-verified", type=_boolean, default=False)
    return parser


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    if path.is_symlink():
        raise RemediationWindowError("output must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        observation = _load_json(args.observation, "observation")
        result = evaluate_remediation_window(
            policy_path=args.policy,
            observation=observation,
            enabled=args.enabled,
            evaluation_time=args.evaluation_time,
            exposure_criticality=args.exposure_criticality,
            fixed_image_verified=args.fixed_image_verified,
        )
        _atomic_write(args.output, result)
        return 0
    except (RemediationWindowError, OSError, KeyError) as exc:
        print(f"security remediation-window error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
