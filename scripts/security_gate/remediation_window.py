"""Evaluate governed remediation-window policies against sanitized observations."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Iterable, Mapping, Sequence

_SHA256_DIGEST = re.compile(r"sha256:[0-9a-fA-F]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
_RFC3339_Z = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_ALLOWED_SEVERITIES = {"HIGH", "CRITICAL"}
_ALLOWED_CLASSIFICATION = "actionable_vulnerability"
_BLOCKED_CRITICAL_EXPOSURES = {"internet-facing", "privileged-boundary"}
_MAX_WINDOW_DAYS = {"CRITICAL": 7, "HIGH": 30}
_DUE_SOON = timedelta(hours=72)
_EVALUATOR_VERSION = "2"


class RemediationWindowError(ValueError):
    """Raised when a remediation-window policy or observation is invalid."""


def _normal_text(value: Any) -> str:
    return str(value or "").strip()


def _required_text(payload: Mapping[str, Any], field: str, *, label: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise RemediationWindowError(f"{label} field {field} is required")
    return value.strip()


def _required_bool(payload: Mapping[str, Any], field: str, *, label: str) -> bool:
    value = payload.get(field)
    if not isinstance(value, bool):
        raise RemediationWindowError(f"{label} field {field} must be boolean")
    return value


def _parse_rfc3339_utc(text: str, *, label: str) -> datetime:
    if not isinstance(text, str) or _RFC3339_Z.fullmatch(text) is None:
        raise RemediationWindowError(f"{label} must use RFC3339 UTC timestamps")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RemediationWindowError(f"{label} must use RFC3339 UTC timestamps") from exc
    return parsed.astimezone(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_digest_list(raw: Any, *, label: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not raw:
        raise RemediationWindowError(f"{label} must be a non-empty array")
    values: list[str] = []
    for index, item in enumerate(raw):
        digest = _normal_text(item).lower()
        if _SHA256_DIGEST.fullmatch(digest) is None:
            raise RemediationWindowError(f"{label}[{index}] must be an immutable sha256 digest")
        values.append(digest)
    if len(values) != len(set(values)):
        raise RemediationWindowError(f"{label} must not contain duplicate digests")
    return tuple(sorted(values))


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


def resolve_policy_path(workspace: Path, relative_path: str) -> Path:
    """Resolve a repository-relative policy without allowing traversal or symlinks."""
    if not isinstance(relative_path, str) or not relative_path.strip():
        raise RemediationWindowError("policy path is required")
    raw = relative_path.strip().replace("\\", "/")
    candidate_path = PurePosixPath(raw)
    if candidate_path.is_absolute() or ".." in candidate_path.parts:
        raise RemediationWindowError("policy path must be repository-relative without traversal")

    root = workspace.resolve(strict=True)
    candidate = root.joinpath(*candidate_path.parts)
    current = root
    for part in candidate_path.parts:
        current = current / part
        if current.is_symlink():
            raise RemediationWindowError("policy path must not contain symlinks")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RemediationWindowError("policy path escapes the trusted workspace") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise RemediationWindowError("policy must be a regular non-symlink file")
    return resolved


def _canonical_fingerprint(raw: Mapping[str, Any], *, label: str = "fingerprint") -> dict[str, Any]:
    service = _required_text(raw, "service", label=label)
    advisory_id = _required_text(raw, "advisory_id", label=label)
    package_purl = _required_text(raw, "package_purl", label=label)
    installed_version = _required_text(raw, "installed_version", label=label)
    fixed_version = _required_text(raw, "fixed_version", label=label)
    lineage = _normalize_digest_list(raw.get("image_lineage_digests"), label=f"{label}.image_lineage_digests")
    return {
        "service": service,
        "advisory_id": advisory_id,
        "package_purl": package_purl,
        "installed_version": installed_version,
        "fixed_version": fixed_version,
        "image_lineage_digests": list(lineage),
    }


def _fingerprint_key(value: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        value["service"],
        value["advisory_id"],
        value["package_purl"],
        value["installed_version"],
        value["fixed_version"],
        tuple(value["image_lineage_digests"]),
    )


def _policy_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_history(entry: Mapping[str, Any], *, first_seen: datetime) -> list[dict[str, str]]:
    raw = entry.get("history")
    if raw is None:
        return []
    if not isinstance(raw, list) or not raw:
        raise RemediationWindowError("policy entry history must be a non-empty array")
    history: list[dict[str, str]] = []
    previous_deadline: datetime | None = None
    for index, revision in enumerate(raw):
        if not isinstance(revision, Mapping):
            raise RemediationWindowError(f"policy entry history[{index}] must be an object")
        revision_first = _parse_rfc3339_utc(
            _required_text(revision, "first_seen_at", label=f"history[{index}]"),
            label=f"history[{index}].first_seen_at",
        )
        deadline = _parse_rfc3339_utc(
            _required_text(revision, "deadline_at", label=f"history[{index}]"),
            label=f"history[{index}].deadline_at",
        )
        reviewed_at = _parse_rfc3339_utc(
            _required_text(revision, "reviewed_at", label=f"history[{index}]"),
            label=f"history[{index}].reviewed_at",
        )
        reviewed_by = _required_text(revision, "reviewed_by", label=f"history[{index}]")
        reason = _required_text(revision, "reason", label=f"history[{index}]")
        if revision_first != first_seen:
            raise RemediationWindowError("policy entry history must preserve first_seen_at")
        if deadline <= first_seen:
            raise RemediationWindowError("policy entry history deadline must follow first_seen_at")
        if previous_deadline is not None and deadline < previous_deadline:
            raise RemediationWindowError("policy entry history deadlines must be monotonic")
        previous_deadline = deadline
        history.append(
            {
                "first_seen_at": _format_utc(revision_first),
                "deadline_at": _format_utc(deadline),
                "reviewed_at": _format_utc(reviewed_at),
                "reviewed_by": reviewed_by,
                "reason": reason,
            }
        )
    return history


def load_policy(path: Path, *, reference_time: str | None = None) -> dict[str, Any]:
    payload = _load_json(path, "policy")
    if payload.get("version") != 1:
        raise RemediationWindowError("policy version must be 1")
    owner = _required_text(payload, "policy_owner", label="policy")
    entries_raw = payload.get("entries")
    if not isinstance(entries_raw, list) or not entries_raw:
        raise RemediationWindowError("policy entries must be a non-empty array")
    reference = (
        _parse_rfc3339_utc(reference_time, label="reference_time")
        if reference_time
        else datetime.now(timezone.utc)
    )

    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_fingerprints: set[tuple[Any, ...]] = set()
    for index, raw in enumerate(entries_raw):
        if not isinstance(raw, Mapping):
            raise RemediationWindowError(f"policy entries[{index}] must be an object")
        label = f"entries[{index}]"
        entry_id = _required_text(raw, "id", label=label)
        if entry_id in seen_ids:
            raise RemediationWindowError(f"duplicate policy entry id {entry_id}")
        fingerprint_raw = raw.get("fingerprint")
        if not isinstance(fingerprint_raw, Mapping):
            raise RemediationWindowError(f"{label}.fingerprint must be an object")
        fingerprint = _canonical_fingerprint(fingerprint_raw, label=f"{label}.fingerprint")
        key = _fingerprint_key(fingerprint)
        if key in seen_fingerprints:
            raise RemediationWindowError(f"duplicate policy fingerprint at {label}")

        first_seen = _parse_rfc3339_utc(
            _required_text(raw, "first_seen_at", label=label), label=f"{label}.first_seen_at"
        )
        deadline = _parse_rfc3339_utc(
            _required_text(raw, "deadline_at", label=label), label=f"{label}.deadline_at"
        )
        reviewed_at = _parse_rfc3339_utc(
            _required_text(raw, "reviewed_at", label=label), label=f"{label}.reviewed_at"
        )
        if first_seen > reference:
            raise RemediationWindowError("policy first_seen_at must not be in the future")
        if reviewed_at > reference:
            raise RemediationWindowError("policy reviewed_at must not be in the future")
        if deadline <= first_seen:
            raise RemediationWindowError("policy deadline_at must be after first_seen_at")
        status = _required_text(raw, "status", label=label)
        if status != "active":
            raise RemediationWindowError("policy entries must be active to authorize a window")

        entries.append(
            {
                "id": entry_id,
                "fingerprint": fingerprint,
                "reason": _required_text(raw, "reason", label=label),
                "first_seen_at": _format_utc(first_seen),
                "deadline_at": _format_utc(deadline),
                "owner": _required_text(raw, "owner", label=label),
                "reviewer": _required_text(raw, "reviewer", label=label),
                "statement": _required_text(raw, "statement", label=label),
                "compensating_control": _required_text(raw, "compensating_control", label=label),
                "reviewed_at": _format_utc(reviewed_at),
                "reviewed_by": _required_text(raw, "reviewed_by", label=label),
                "status": status,
                "history": _validate_history(raw, first_seen=first_seen),
            }
        )
        seen_ids.add(entry_id)
        seen_fingerprints.add(key)

    return {
        "version": 1,
        "policy_owner": owner,
        "entries": entries,
        "policy_digest": _policy_digest(path),
    }


def _canonical_observation(raw: Mapping[str, Any], *, index: int) -> dict[str, Any]:
    label = f"observations[{index}]"
    fingerprint = _canonical_fingerprint(
        {
            "service": _required_text(raw, "service_scope", label=label),
            "advisory_id": _required_text(raw, "advisory_id", label=label),
            "package_purl": _required_text(raw, "package_purl", label=label),
            "installed_version": _required_text(raw, "installed_version", label=label),
            "fixed_version": _required_text(raw, "fixed_version", label=label),
            "image_lineage_digests": raw.get("image_lineage_digests"),
        },
        label=label,
    )
    classification = _required_text(raw, "classification", label=label)
    severity = _required_text(raw, "severity", label=label).upper()
    exposure = _required_text(raw, "exposure_criticality", label=label).lower()
    source_sha = _required_text(raw, "source_sha", label=label).lower()
    image_identity = _required_text(raw, "image_identity", label=label).lower()
    if _GIT_SHA.fullmatch(source_sha) is None:
        raise RemediationWindowError(f"{label}.source_sha must be a 40-character git SHA")
    if _SHA256_DIGEST.fullmatch(image_identity) is None:
        raise RemediationWindowError(f"{label}.image_identity must be an immutable sha256 digest")
    if severity not in _ALLOWED_SEVERITIES:
        raise RemediationWindowError(f"{label}.severity must be HIGH or CRITICAL")
    return {
        **fingerprint,
        "service_scope": fingerprint["service"],
        "classification": classification,
        "severity": severity,
        "exposure_criticality": exposure,
        "known_exploited": _required_bool(raw, "known_exploited", label=label),
        "fixed_image_verified": _required_bool(raw, "fixed_image_verified", label=label),
        "source_sha": source_sha,
        "image_identity": image_identity,
    }


def _observation_digest(observation: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(observation, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _finding_result(
    observation: Mapping[str, Any],
    *,
    state: str,
    failure_reason: str,
    entry: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "observation_digest": _observation_digest(observation),
        "advisory_id": observation["advisory_id"],
        "package_purl": observation["package_purl"],
        "image_identity": observation["image_identity"],
        "state": state,
        "failure_reason": failure_reason,
        "policy_entry_id": entry["id"] if entry else "",
        "deadline_at": entry["deadline_at"] if entry else "",
    }


def _evaluate_one(
    observation: Mapping[str, Any],
    *,
    entries_by_fingerprint: Mapping[tuple[Any, ...], Mapping[str, Any]],
    evaluation: datetime,
) -> dict[str, Any]:
    if observation["classification"] != _ALLOWED_CLASSIFICATION:
        return _finding_result(observation, state="rejected", failure_reason="classification_block")
    if observation["known_exploited"]:
        return _finding_result(observation, state="rejected", failure_reason="known_exploited")
    if observation["fixed_image_verified"]:
        return _finding_result(observation, state="rejected", failure_reason="fixed_image_available")
    if (
        observation["severity"] == "CRITICAL"
        and observation["exposure_criticality"] in _BLOCKED_CRITICAL_EXPOSURES
    ):
        return _finding_result(observation, state="rejected", failure_reason="critical_exposure_block")

    entry = entries_by_fingerprint.get(_fingerprint_key(observation))
    if entry is None:
        return _finding_result(observation, state="unmatched", failure_reason="policy_entry_not_found")

    first_seen = _parse_rfc3339_utc(entry["first_seen_at"], label="policy.first_seen_at")
    deadline = _parse_rfc3339_utc(entry["deadline_at"], label="policy.deadline_at")
    max_duration = timedelta(days=_MAX_WINDOW_DAYS[observation["severity"]])
    if deadline - first_seen > max_duration:
        return _finding_result(
            observation,
            state="rejected",
            failure_reason="window_limit_exceeded",
            entry=entry,
        )
    if evaluation > deadline:
        return _finding_result(observation, state="overdue", failure_reason="window_overdue", entry=entry)
    if evaluation < first_seen:
        return _finding_result(observation, state="rejected", failure_reason="future_first_seen", entry=entry)
    if deadline - evaluation <= _DUE_SOON:
        return _finding_result(observation, state="due_soon", failure_reason="", entry=entry)
    return _finding_result(observation, state="active", failure_reason="", entry=entry)


def _empty_result() -> dict[str, Any]:
    return {
        "classification": "",
        "remediation_window_allowed": False,
        "remediation_state": "not_applicable",
        "decision": "not_applicable",
        "blocking_total": 0,
        "window_covered": 0,
        "uncovered_blocking_findings": 0,
        "rejected_count": 0,
        "overdue_count": 0,
        "unmatched_count": 0,
        "due_soon_count": 0,
        "matching_entry_count": 0,
        "nearest_deadline": "",
        "policy_digest": "",
        "evaluator_version": _EVALUATOR_VERSION,
        "failure_reason": "",
        "findings": [],
    }


def evaluate_remediation_windows(
    *,
    policy_path: Path | None,
    observations: Sequence[Mapping[str, Any]],
    enabled: bool,
    evaluation_time: str | None = None,
) -> dict[str, Any]:
    """Evaluate all blocking findings and allow only complete exact coverage."""
    result = _empty_result()
    if not enabled:
        return result
    if policy_path is None:
        raise RemediationWindowError("policy path is required when remediation windows are enabled")

    evaluation = (
        _parse_rfc3339_utc(evaluation_time, label="evaluation_time")
        if evaluation_time
        else datetime.now(timezone.utc)
    )
    policy = load_policy(policy_path, reference_time=_format_utc(evaluation))
    result["policy_digest"] = policy["policy_digest"]

    normalized: list[dict[str, Any]] = []
    rejected_during_normalization: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for index, raw in enumerate(observations):
        try:
            observation = _canonical_observation(raw, index=index)
        except RemediationWindowError as exc:
            digest = hashlib.sha256(
                json.dumps(dict(raw), sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            rejected_during_normalization.append(
                {
                    "observation_digest": digest,
                    "advisory_id": _normal_text(raw.get("advisory_id")),
                    "package_purl": _normal_text(raw.get("package_purl")),
                    "image_identity": _normal_text(raw.get("image_identity")),
                    "state": "rejected",
                    "failure_reason": str(exc),
                    "policy_entry_id": "",
                    "deadline_at": "",
                }
            )
            continue
        dedupe_key = (*_fingerprint_key(observation), observation["image_identity"])
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        normalized.append(observation)

    result["blocking_total"] = len(normalized) + len(rejected_during_normalization)
    if result["blocking_total"] == 0:
        return result

    entries_by_fingerprint = {
        _fingerprint_key(entry["fingerprint"]): entry for entry in policy["entries"]
    }
    findings = [
        _evaluate_one(observation, entries_by_fingerprint=entries_by_fingerprint, evaluation=evaluation)
        for observation in normalized
    ]
    findings.extend(rejected_during_normalization)
    findings.sort(
        key=lambda item: (
            item["image_identity"],
            item["advisory_id"],
            item["package_purl"],
            item["observation_digest"],
        )
    )
    result["findings"] = findings

    covered_states = {"active", "due_soon"}
    result["window_covered"] = sum(item["state"] in covered_states for item in findings)
    result["rejected_count"] = sum(item["state"] == "rejected" for item in findings)
    result["overdue_count"] = sum(item["state"] == "overdue" for item in findings)
    result["unmatched_count"] = sum(item["state"] == "unmatched" for item in findings)
    result["due_soon_count"] = sum(item["state"] == "due_soon" for item in findings)
    result["matching_entry_count"] = sum(bool(item["policy_entry_id"]) for item in findings)
    result["uncovered_blocking_findings"] = result["blocking_total"] - result["window_covered"]

    deadlines = [item["deadline_at"] for item in findings if item["deadline_at"]]
    result["nearest_deadline"] = min(deadlines) if deadlines else ""
    result["classification"] = _ALLOWED_CLASSIFICATION

    if result["uncovered_blocking_findings"] == 0:
        result["remediation_window_allowed"] = True
        result["decision"] = "allowed_window"
        result["remediation_state"] = "due_soon" if result["due_soon_count"] else "active"
        return result

    result["decision"] = "blocked"
    if result["overdue_count"]:
        result["remediation_state"] = "overdue"
        result["failure_reason"] = "window_overdue"
    elif result["rejected_count"]:
        result["remediation_state"] = "blocked"
        result["failure_reason"] = "window_rejected"
    else:
        result["remediation_state"] = "blocked"
        result["failure_reason"] = "uncovered_blocking_findings"
    return result


def evaluate_remediation_window(
    *,
    policy_path: Path,
    observation: Mapping[str, Any],
    enabled: bool,
    evaluation_time: str | None = None,
    exposure_criticality: str | None = None,
    fixed_image_verified: bool = False,
) -> dict[str, Any]:
    """Backward-compatible single-observation wrapper."""
    candidate = dict(observation)
    if exposure_criticality is not None:
        candidate["exposure_criticality"] = exposure_criticality
    candidate.setdefault("severity", "HIGH")
    candidate.setdefault("known_exploited", False)
    candidate["fixed_image_verified"] = fixed_image_verified or bool(
        candidate.get("fixed_image_verified", False)
    )
    aggregate = evaluate_remediation_windows(
        policy_path=policy_path,
        observations=[candidate],
        enabled=enabled,
        evaluation_time=evaluation_time,
    )
    aggregate["observation_digest"] = (
        aggregate["findings"][0]["observation_digest"] if aggregate["findings"] else ""
    )
    return aggregate


def observations_from_trivy_report(
    report_path: Path,
    *,
    service_scope: str,
    exposure_criticality: str,
    source_sha: str,
    image_identity: str,
    image_lineage_digests: Sequence[str],
    fixed_image_verified: bool = False,
    known_exploited_ids: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """Create one sanitized observation per unique fixable Trivy finding."""
    report = _load_json(report_path, "Trivy report")
    results = report.get("Results")
    if not isinstance(results, list):
        raise RemediationWindowError("Trivy report Results must be an array")
    normalized_lineage = list(
        _normalize_digest_list(list(image_lineage_digests), label="image_lineage_digests")
    )
    exploited = {str(item).strip() for item in known_exploited_ids if str(item).strip()}
    observations: dict[tuple[Any, ...], dict[str, Any]] = {}
    for result in results:
        if not isinstance(result, Mapping):
            continue
        vulnerabilities = result.get("Vulnerabilities")
        if not isinstance(vulnerabilities, list):
            continue
        for finding in vulnerabilities:
            if not isinstance(finding, Mapping):
                continue
            fixed_version = _normal_text(finding.get("FixedVersion"))
            if not fixed_version:
                continue
            identifier = finding.get("PkgIdentifier")
            purl = ""
            if isinstance(identifier, Mapping):
                purl = _normal_text(identifier.get("PURL"))
            if not purl:
                purl = _normal_text(finding.get("PURL"))
            observation = {
                "service_scope": service_scope,
                "exposure_criticality": exposure_criticality,
                "classification": _ALLOWED_CLASSIFICATION,
                "severity": _normal_text(finding.get("Severity")).upper(),
                "known_exploited": _normal_text(finding.get("VulnerabilityID")) in exploited,
                "advisory_id": _normal_text(finding.get("VulnerabilityID")),
                "package_purl": purl,
                "installed_version": _normal_text(finding.get("InstalledVersion")),
                "fixed_version": fixed_version,
                "image_lineage_digests": normalized_lineage,
                "source_sha": source_sha,
                "image_identity": image_identity,
                "fixed_image_verified": fixed_image_verified,
            }
            key = (
                observation["advisory_id"],
                observation["package_purl"],
                observation["installed_version"],
                observation["fixed_version"],
                tuple(normalized_lineage),
            )
            observations[key] = observation
    return [observations[key] for key in sorted(observations)]


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    if path.is_symlink():
        raise RemediationWindowError("output must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    if temporary.exists() and temporary.is_symlink():
        raise RemediationWindowError("temporary output must not be a symlink")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _boolean(raw: str) -> bool:
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise argparse.ArgumentTypeError("boolean value must be true or false")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--policy", required=True, help="Repository-relative policy path")
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--enabled", type=_boolean, required=True)
    parser.add_argument("--evaluation-time")
    parser.add_argument("--test-mode", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.evaluation_time and not args.test_mode:
            raise RemediationWindowError("evaluation-time override is allowed only in test mode")
        if not args.enabled:
            result = evaluate_remediation_windows(
                policy_path=None,
                observations=[],
                enabled=False,
                evaluation_time=args.evaluation_time,
            )
        else:
            policy = resolve_policy_path(args.workspace, args.policy)
            payload = _load_json(args.observations, "observations")
            raw_observations = payload.get("observations")
            if not isinstance(raw_observations, list):
                raise RemediationWindowError("observations field must be an array")
            result = evaluate_remediation_windows(
                policy_path=policy,
                observations=raw_observations,
                enabled=True,
                evaluation_time=args.evaluation_time,
            )
        _atomic_write(args.output, result)
        return 0
    except (RemediationWindowError, OSError, KeyError) as exc:
        print(f"security remediation-window error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
