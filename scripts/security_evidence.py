#!/usr/bin/env python3
"""Create and verify SHA-bound evidence records for reusable security scans."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = 1
SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ARTIFACT_SHA256 = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
CONCLUSIONS = {"success", "failure", "cancelled", "skipped"}
RESULTS = {"passed", "failed"}
JOB_RESULTS = {"success", "failure", "cancelled", "skipped"}
JOB_NAMES = {
    "profile",
    "static_lint",
    "filesystem_security",
    "dependency_policy",
    "sast",
    "supply_chain",
}
CHILD_EVIDENCE_NAMES = {
    "static_lint",
    "filesystem_security",
    "dependency_policy",
    "sast",
    "supply_chain",
}
CHILD_WORKFLOW_FILES = {
    "static_lint": ".github/workflows/_static-lint.yml",
    "filesystem_security": ".github/workflows/_security-gate.yml",
    "dependency_policy": ".github/workflows/_dependency-policy.yml",
    "sast": ".github/workflows/_sast-gate.yml",
    "supply_chain": ".github/workflows/_supply-chain-evidence.yml",
}
CHILD_ARTIFACT_NAMES = {
    "static_lint": "security-suite-static-lint",
    "filesystem_security": "security-suite-filesystem",
    "dependency_policy": "security-suite-dependencies",
    "sast": "security-suite-sast",
    "supply_chain": "security-suite-supply-chain",
}
CHILD_RECORD_FIELDS = (
    "schema_version",
    "repository",
    "run_id",
    "run_attempt",
    "producer",
    "source_sha",
    "conclusion",
    "result",
    "artifact_name",
    "evidence_path",
    "evidence_manifest_path",
    "evidence_present",
    "evidence_file_count",
    "evidence_total_bytes",
    "evidence_index_sha256",
    "evidence_sha256",
    "artifact_id",
    "artifact_digest",
)


class EvidenceError(ValueError):
    """An evidence record is missing, malformed, or mismatched."""


def serialize_json(payload: Mapping[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _required_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise EvidenceError(f"{label} must be a non-empty trimmed string")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise EvidenceError(f"{label} must not contain control characters")
    return value


def _validate_repository(value: Any, label: str) -> str:
    value = _required_text(value, label)
    if REPOSITORY.fullmatch(value) is None:
        raise EvidenceError(f"{label} must use owner/repository form")
    return value


def _validate_sha(value: Any, label: str) -> str:
    value = _required_text(value, label)
    if SHA.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be a full lowercase Git SHA")
    return value


def _validate_relative_path(value: Any, label: str) -> str:
    value = _required_text(value, label)
    path = PurePosixPath(value)
    if path.is_absolute() or "\\" in value or ".." in path.parts or value.startswith("~"):
        raise EvidenceError(f"{label} must be a safe relative path")
    return path.as_posix()


def _validate_run_number(value: Any, label: str) -> str:
    value = _required_text(str(value) if isinstance(value, int) else value, label)
    if not value.isdecimal() or int(value) < 1:
        raise EvidenceError(f"{label} must be a positive decimal number")
    return value


def create_evidence_record(
    *,
    repository: str,
    run_id: str,
    run_attempt: str,
    producer_repository: str,
    producer_ref: str,
    producer_sha: str,
    producer_file: str,
    source_sha: str,
    conclusion: str,
    result: str,
    artifact_name: str,
    evidence_path: str,
    evidence_bytes: bytes | None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Bind one raw evidence file to caller, run, producer, source and artifact."""
    repository = _validate_repository(repository, "repository")
    run_id = _validate_run_number(run_id, "run_id")
    run_attempt = _validate_run_number(run_attempt, "run_attempt")
    producer_repository = _validate_repository(producer_repository, "producer_repository")
    producer_ref = _required_text(producer_ref, "producer_ref")
    producer_sha = _validate_sha(producer_sha, "producer_sha")
    producer_file = _validate_relative_path(producer_file, "producer_file")
    source_sha = _validate_sha(source_sha, "source_sha")
    if not isinstance(conclusion, str) or conclusion not in CONCLUSIONS:
        raise EvidenceError("conclusion must be success, failure, cancelled, or skipped")
    if not isinstance(result, str) or result not in RESULTS:
        raise EvidenceError("result must be passed or failed")
    artifact_name = _required_text(artifact_name, "artifact_name")
    evidence_path = _validate_relative_path(evidence_path, "evidence_path")
    if evidence_bytes is not None and not isinstance(evidence_bytes, bytes):
        raise EvidenceError("evidence contents must be bytes or missing")
    if result == "passed" and (
        conclusion != "success" or evidence_bytes is None or not evidence_bytes
    ):
        raise EvidenceError(
            "passed evidence requires a successful conclusion and non-empty evidence contents"
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "repository": repository,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "producer": {
            "repository": producer_repository,
            "ref": producer_ref,
            "sha": producer_sha,
            "file": producer_file,
        },
        "source_sha": source_sha,
        "conclusion": conclusion,
        "result": result,
        "artifact_name": artifact_name,
        "evidence_path": evidence_path,
        "evidence_present": evidence_bytes is not None,
        "evidence_sha256": (
            hashlib.sha256(evidence_bytes).hexdigest() if evidence_bytes is not None else None
        ),
        "details": dict(details or {}),
    }


def create_evidence_bundle(
    *,
    repository: str,
    run_id: str,
    run_attempt: str,
    producer_repository: str,
    producer_ref: str,
    producer_sha: str,
    producer_file: str,
    source_sha: str,
    expected_source_sha: str,
    conclusion: str,
    artifact_name: str,
    evidence_directory: str,
) -> dict[str, Any]:
    """Write a sidecar indexing each raw file in a reusable gate artifact."""
    source_sha = _validate_sha(source_sha, "source_sha")
    expected_source_sha = _validate_sha(expected_source_sha, "expected_source_sha")
    if source_sha != expected_source_sha:
        raise EvidenceError("checked-out source SHA does not match caller github.sha")
    if not isinstance(conclusion, str) or conclusion not in CONCLUSIONS - {"skipped"}:
        raise EvidenceError("bundle conclusion must be success, failure, or cancelled")

    root = Path(evidence_directory)
    if root.exists() and root.is_symlink():
        raise EvidenceError("evidence directory must not be a symlink")
    root.mkdir(parents=True, exist_ok=True)
    manifest_path = root / "evidence-manifest.json"
    if manifest_path.exists() or manifest_path.is_symlink():
        raise EvidenceError("evidence-manifest.json path is reserved for the generated index")
    entries: list[dict[str, Any]] = []
    for candidate in sorted(root.rglob("*")):
        if candidate == manifest_path:
            continue
        if candidate.is_symlink():
            raise EvidenceError("evidence bundle must not contain symlinks")
        if not candidate.is_file():
            continue
        relative_path = candidate.relative_to(root).as_posix()
        _validate_relative_path(relative_path, "evidence file path")
        raw_bytes = candidate.read_bytes()
        entries.append(
            {
                "path": relative_path,
                "sha256": hashlib.sha256(raw_bytes).hexdigest(),
                "size_bytes": len(raw_bytes),
            }
        )

    total_bytes = sum(entry["size_bytes"] for entry in entries)
    result = "passed" if conclusion == "success" and total_bytes > 0 else "failed"
    identity = {
        "schema_version": SCHEMA_VERSION,
        "repository": _validate_repository(repository, "repository"),
        "run_id": _validate_run_number(run_id, "run_id"),
        "run_attempt": _validate_run_number(run_attempt, "run_attempt"),
        "producer": {
            "repository": _validate_repository(producer_repository, "producer_repository"),
            "ref": _required_text(producer_ref, "producer_ref"),
            "sha": _validate_sha(producer_sha, "producer_sha"),
            "file": _validate_relative_path(producer_file, "producer_file"),
        },
        "source_sha": source_sha,
        "conclusion": conclusion,
        "result": result,
        "artifact_name": _required_text(artifact_name, "artifact_name"),
        "evidence_path": ".",
    }
    manifest = dict(identity)
    manifest.update(
        {
            "evidence_present": bool(entries),
            "evidence_file_count": len(entries),
            "evidence_total_bytes": total_bytes,
            "evidence_manifest_path": manifest_path.name,
            "evidence_files": entries,
            "evidence_index_sha256": hashlib.sha256(serialize_json(entries)).hexdigest(),
            "details": {"evidence_file_count": len(entries)},
        }
    )
    manifest_bytes = serialize_json(manifest)
    manifest_path.write_bytes(manifest_bytes)
    return {
        **manifest,
        "evidence_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }


def verify_evidence_bundle(
    manifest_bytes: bytes,
    evidence_directory: Path,
    *,
    expected: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Verify the sidecar, every indexed file, and caller-selected identities."""
    try:
        payload = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("evidence bundle manifest must be valid JSON") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceError("evidence bundle manifest has an unsupported schema")

    required = (
        "repository",
        "run_id",
        "run_attempt",
        "producer",
        "source_sha",
        "conclusion",
        "result",
        "artifact_name",
        "evidence_path",
        "evidence_present",
        "evidence_manifest_path",
        "evidence_file_count",
        "evidence_total_bytes",
        "evidence_files",
        "evidence_index_sha256",
    )
    if any(key not in payload for key in required):
        raise EvidenceError("evidence bundle manifest is missing required fields")
    _validate_repository(payload["repository"], "repository")
    _validate_run_number(payload["run_id"], "run_id")
    _validate_run_number(payload["run_attempt"], "run_attempt")
    producer = payload["producer"]
    if not isinstance(producer, dict):
        raise EvidenceError("producer must be an object")
    _validate_repository(producer.get("repository"), "producer.repository")
    _required_text(producer.get("ref"), "producer.ref")
    _validate_sha(producer.get("sha"), "producer.sha")
    _validate_relative_path(producer.get("file"), "producer.file")
    _validate_sha(payload["source_sha"], "source_sha")
    if (
        not isinstance(payload["conclusion"], str)
        or payload["conclusion"] not in CONCLUSIONS - {"skipped"}
    ):
        raise EvidenceError("evidence bundle conclusion is malformed")
    if not isinstance(payload["result"], str) or payload["result"] not in RESULTS:
        raise EvidenceError("evidence bundle result is malformed")
    _required_text(payload["artifact_name"], "artifact_name")
    _validate_relative_path(payload["evidence_path"], "evidence_path")
    _validate_relative_path(payload["evidence_manifest_path"], "evidence_manifest_path")
    if not isinstance(payload["evidence_present"], bool):
        raise EvidenceError("evidence_present must be boolean")
    if not isinstance(payload["evidence_files"], list):
        raise EvidenceError("evidence_files must be an array")
    if (
        not isinstance(payload["evidence_file_count"], int)
        or isinstance(payload["evidence_file_count"], bool)
        or payload["evidence_file_count"] != len(payload["evidence_files"])
    ):
        raise EvidenceError("evidence_file_count does not match indexed files")
    if (
        not isinstance(payload["evidence_total_bytes"], int)
        or isinstance(payload["evidence_total_bytes"], bool)
        or payload["evidence_total_bytes"] < 0
    ):
        raise EvidenceError("evidence_total_bytes is malformed")

    indexed: dict[str, tuple[str, int]] = {}
    for item in payload["evidence_files"]:
        if not isinstance(item, dict):
            raise EvidenceError("evidence file entry must be an object")
        path = _validate_relative_path(item.get("path"), "evidence file path")
        digest = item.get("sha256")
        size = item.get("size_bytes")
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise EvidenceError("evidence file SHA-256 is malformed")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise EvidenceError("evidence file size is malformed")
        if path in indexed:
            raise EvidenceError("evidence file path is duplicated")
        indexed[path] = (digest, size)
    if bool(indexed) != payload["evidence_present"]:
        raise EvidenceError("evidence_present does not match indexed files")
    if payload["evidence_total_bytes"] != sum(size for _, size in indexed.values()):
        raise EvidenceError("evidence_total_bytes does not match indexed files")
    if payload["result"] == "passed" and (
        payload["conclusion"] != "success" or not indexed or payload["evidence_total_bytes"] == 0
    ):
        raise EvidenceError("passed evidence requires successful indexed files")
    if hashlib.sha256(serialize_json(payload["evidence_files"])).hexdigest() != payload[
        "evidence_index_sha256"
    ]:
        raise EvidenceError("evidence index SHA-256 does not match the manifest")

    root = Path(evidence_directory)
    if root.is_symlink():
        raise EvidenceError("evidence directory must not be a symlink")
    actual_paths: set[str] = set()
    manifest_path = _validate_relative_path(payload["evidence_manifest_path"], "evidence_manifest_path")
    for candidate in root.rglob("*"):
        if candidate.is_symlink():
            raise EvidenceError("evidence bundle must not contain symlinks")
        if candidate.is_file():
            path = candidate.relative_to(root).as_posix()
            if path != manifest_path:
                actual_paths.add(path)
    if set(indexed) != actual_paths:
        raise EvidenceError("evidence bundle has missing or unindexed files")
    for relative_path, (expected_digest, expected_size) in indexed.items():
        try:
            raw_bytes = (root / relative_path).read_bytes()
        except FileNotFoundError as exc:
            raise EvidenceError(f"missing evidence file: {relative_path}") from exc
        if len(raw_bytes) != expected_size:
            raise EvidenceError(f"evidence file size does not match: {relative_path}")
        if hashlib.sha256(raw_bytes).hexdigest() != expected_digest:
            raise EvidenceError(f"evidence file SHA-256 does not match: {relative_path}")

    locations = {
        "repository": payload["repository"],
        "run_id": payload["run_id"],
        "run_attempt": payload["run_attempt"],
        "source_sha": payload["source_sha"],
        "producer_repository": producer["repository"],
        "producer_ref": producer["ref"],
        "producer_sha": producer["sha"],
        "producer_file": producer["file"],
        "artifact_name": payload["artifact_name"],
    }
    for key, value in (expected or {}).items():
        if key not in locations:
            raise EvidenceError(f"unsupported expected identity field: {key}")
        if value != locations[key]:
            raise EvidenceError(f"evidence {key} does not match expected identity")
    return payload


def verify_evidence_record(
    manifest_bytes: bytes,
    evidence_bytes: bytes | None,
    *,
    expected: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Verify a downloaded sidecar and the exact raw evidence bytes independently."""
    try:
        payload = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("evidence manifest must be valid JSON") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceError("evidence manifest has an unsupported schema")

    required = (
        "repository",
        "run_id",
        "run_attempt",
        "producer",
        "source_sha",
        "conclusion",
        "result",
        "artifact_name",
        "evidence_path",
        "evidence_present",
        "evidence_sha256",
    )
    if any(key not in payload for key in required):
        raise EvidenceError("evidence manifest is missing required fields")
    _validate_repository(payload["repository"], "repository")
    _validate_run_number(payload["run_id"], "run_id")
    _validate_run_number(payload["run_attempt"], "run_attempt")
    producer = payload["producer"]
    if not isinstance(producer, dict):
        raise EvidenceError("producer must be an object")
    _validate_repository(producer.get("repository"), "producer.repository")
    _required_text(producer.get("ref"), "producer.ref")
    _validate_sha(producer.get("sha"), "producer.sha")
    _validate_relative_path(producer.get("file"), "producer.file")
    _validate_sha(payload["source_sha"], "source_sha")
    if (
        not isinstance(payload["conclusion"], str)
        or payload["conclusion"] not in CONCLUSIONS
        or not isinstance(payload["result"], str)
        or payload["result"] not in RESULTS
    ):
        raise EvidenceError("evidence conclusion or result is malformed")
    _required_text(payload["artifact_name"], "artifact_name")
    _validate_relative_path(payload["evidence_path"], "evidence_path")
    if not isinstance(payload["evidence_present"], bool):
        raise EvidenceError("evidence_present must be boolean")
    if payload["result"] == "passed" and (
        payload["conclusion"] != "success" or evidence_bytes == b""
    ):
        raise EvidenceError(
            "passed evidence requires a successful conclusion and non-empty contents"
        )

    if evidence_bytes is None or not payload["evidence_present"]:
        if payload["evidence_sha256"] is not None:
            raise EvidenceError("missing evidence must not declare a SHA-256")
        raise EvidenceError("evidence contents are missing")
    digest = payload["evidence_sha256"]
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        raise EvidenceError("evidence SHA-256 is malformed")
    if hashlib.sha256(evidence_bytes).hexdigest() != digest:
        raise EvidenceError("evidence SHA-256 does not match downloaded contents")

    locations = {
        "repository": payload["repository"],
        "run_id": payload["run_id"],
        "run_attempt": payload["run_attempt"],
        "source_sha": payload["source_sha"],
        "producer_repository": producer["repository"],
        "producer_ref": producer["ref"],
        "producer_sha": producer["sha"],
        "producer_file": producer["file"],
        "artifact_name": payload["artifact_name"],
        "evidence_path": payload["evidence_path"],
        "conclusion": payload["conclusion"],
        "result": payload["result"],
    }
    for key, value in (expected or {}).items():
        if key not in locations:
            raise EvidenceError(f"unsupported expected identity field: {key}")
        if value != locations[key]:
            raise EvidenceError(f"evidence {key} does not match expected identity")
    return payload


def _child_evidence_issues(
    name: str,
    record: Any,
    *,
    job_result: str,
    expected_identity: Mapping[str, str],
) -> list[str]:
    if record is None:
        return ["missing_record"]
    if not isinstance(record, Mapping):
        return ["malformed_record"]

    issues: list[str] = []
    if record.get("schema_version") != SCHEMA_VERSION:
        issues.append("schema_version_mismatch")
    for key in ("repository", "run_id", "run_attempt", "source_sha"):
        value = record.get(key)
        try:
            if key == "repository":
                _validate_repository(value, key)
            elif key in {"run_id", "run_attempt"}:
                _validate_run_number(value, key)
            else:
                _validate_sha(value, key)
        except EvidenceError:
            issues.append(f"malformed_{key}")
            continue
        if key in expected_identity and value != expected_identity[key]:
            issues.append(f"{key}_mismatch")

    producer = record.get("producer")
    if not isinstance(producer, Mapping):
        issues.append("malformed_producer")
    else:
        try:
            _validate_repository(producer.get("repository"), "producer.repository")
            _required_text(producer.get("ref"), "producer.ref")
            _validate_sha(producer.get("sha"), "producer.sha")
            producer_file = _validate_relative_path(producer.get("file"), "producer.file")
        except EvidenceError:
            issues.append("malformed_producer")
        else:
            if producer_file != CHILD_WORKFLOW_FILES[name]:
                issues.append("producer_file_mismatch")

    conclusion = record.get("conclusion")
    result = record.get("result")
    if not isinstance(conclusion, str) or conclusion not in CONCLUSIONS - {"skipped"}:
        issues.append("malformed_conclusion")
    if not isinstance(result, str) or result not in RESULTS:
        issues.append("malformed_result")
    if result == "passed" and conclusion != "success":
        issues.append("result_conclusion_mismatch")
    if job_result == "success" and result != "passed":
        issues.append("successful_job_without_passing_evidence")
    if job_result in {"failure", "cancelled"} and conclusion != job_result:
        issues.append("job_conclusion_mismatch")

    if record.get("artifact_name") != CHILD_ARTIFACT_NAMES[name]:
        issues.append("artifact_name_mismatch")
    try:
        _validate_relative_path(record.get("evidence_path"), "evidence_path")
        _validate_relative_path(record.get("evidence_manifest_path"), "evidence_manifest_path")
    except EvidenceError:
        issues.append("malformed_evidence_path")

    evidence_sha256 = record.get("evidence_sha256")
    if not isinstance(evidence_sha256, str) or SHA256.fullmatch(evidence_sha256) is None:
        issues.append("malformed_evidence_sha256")
    artifact_id = record.get("artifact_id")
    try:
        _validate_run_number(artifact_id, "artifact_id")
    except EvidenceError:
        issues.append("malformed_artifact_id")
    artifact_digest = record.get("artifact_digest")
    if not isinstance(artifact_digest, str) or ARTIFACT_SHA256.fullmatch(artifact_digest) is None:
        issues.append("malformed_artifact_digest")

    evidence_present = record.get("evidence_present")
    file_count = record.get("evidence_file_count")
    index_sha256 = record.get("evidence_index_sha256")
    if not isinstance(evidence_present, bool):
        issues.append("malformed_evidence_present")
    if not isinstance(file_count, int) or isinstance(file_count, bool) or file_count < 0:
        issues.append("malformed_evidence_file_count")
    elif isinstance(evidence_present, bool) and evidence_present != (file_count > 0):
        issues.append("evidence_file_count_mismatch")
    total_bytes = record.get("evidence_total_bytes")
    if not isinstance(total_bytes, int) or isinstance(total_bytes, bool) or total_bytes < 0:
        issues.append("malformed_evidence_total_bytes")
    if not isinstance(index_sha256, str) or SHA256.fullmatch(index_sha256) is None:
        issues.append("malformed_evidence_index_sha256")
    if result == "passed" and (file_count == 0 or total_bytes == 0):
        issues.append("passing_evidence_has_no_content")
    return issues


def summarize_security_suite(
    *,
    profile: str,
    image_refs: str,
    jobs: Mapping[str, str],
    child_evidence: Mapping[str, Any] | None = None,
    expected_identity: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Create the stable Security Suite summary; required skips remain blocking."""
    if not isinstance(profile, str) or profile not in {
        "python", "node", "compose", "infra", "monorepo"
    }:
        raise EvidenceError("profile is not allowed")
    if not isinstance(jobs, Mapping):
        raise EvidenceError("suite job results must be an object")
    if set(jobs) != JOB_NAMES:
        raise EvidenceError("suite job results must contain exactly the known jobs")
    if any(not isinstance(value, str) or value not in JOB_RESULTS for value in jobs.values()):
        raise EvidenceError("suite job result is not allowed")

    required = {"profile", "static_lint", "filesystem_security"}
    if profile in {"python", "node", "monorepo"}:
        required.update({"dependency_policy", "sast"})
    if profile in {"compose", "infra", "monorepo"} and image_refs.strip():
        required.add("supply_chain")

    failed = sorted(
        name for name, result in jobs.items() if result in {"failure", "cancelled"}
    )
    unexpectedly_skipped = sorted(name for name in required if jobs[name] == "skipped")
    required_not_success = sorted(name for name in required if jobs[name] != "success")
    blocking = sorted(set(failed + required_not_success))
    expected_skipped = sorted(
        name for name, result in jobs.items() if result == "skipped" and name not in required
    )
    summary = {
        "schema_version": 2,
        "profile": profile,
        "jobs": dict(jobs),
        "required_jobs": sorted(required),
        "expected_skipped": expected_skipped,
        "unexpectedly_skipped": unexpectedly_skipped,
        "result": "failed" if blocking else "passed",
    }
    if child_evidence is not None:
        if not isinstance(child_evidence, Mapping):
            raise EvidenceError("child evidence results must be an object")
        child_records: dict[str, Any] = {}
        child_errors: dict[str, list[str]] = {}
        expected = dict(expected_identity or {})
        for name in sorted(CHILD_EVIDENCE_NAMES):
            child_record = child_evidence.get(name)
            if jobs[name] == "skipped" and name not in required:
                if child_record is not None:
                    child_errors[name] = ["skipped_job_has_evidence"]
                child_records[name] = None
                continue
            issues = _child_evidence_issues(
                name,
                child_record,
                job_result=jobs[name],
                expected_identity=expected,
            )
            if child_record is not None and isinstance(child_record, Mapping):
                child_records[name] = {
                    key: child_record.get(key) for key in CHILD_RECORD_FIELDS
                }
                child_records[name]["job_result"] = jobs[name]
            else:
                child_records[name] = None
            if issues:
                child_errors[name] = issues

        summary["child_evidence"] = child_records
        if child_errors:
            summary["child_evidence_errors"] = child_errors
            summary["result"] = "failed"
    return summary


def _read_optional_file(path: str) -> bytes | None:
    candidate = Path(path)
    try:
        return candidate.read_bytes()
    except FileNotFoundError:
        return None


def _write_json(path: str, payload: Mapping[str, Any]) -> bytes:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = serialize_json(payload)
    destination.write_bytes(encoded)
    return encoded


def _write_outputs(path: str, outputs: Mapping[str, Any]) -> None:
    if not path:
        return
    with Path(path).open("a", encoding="utf-8") as output:
        for name, value in outputs.items():
            output.write(f"{name}={'' if value is None else value}\n")


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--producer-repository", required=True)
    parser.add_argument("--producer-ref", required=True)
    parser.add_argument("--producer-sha", required=True)
    parser.add_argument("--producer-file", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--evidence-path", required=True)
    parser.add_argument("--manifest-path", required=True)
    parser.add_argument("--manifest-artifact-path", default="")
    parser.add_argument("--github-output", default="")


def _identity(args: argparse.Namespace) -> dict[str, str]:
    source_sha = _validate_sha(args.source_sha, "source_sha")
    expected_sha = _validate_sha(args.expected_source_sha, "expected_source_sha")
    if source_sha != expected_sha:
        raise EvidenceError("checked-out source SHA does not match caller github.sha")
    return {
        "repository": args.repository,
        "run_id": args.run_id,
        "run_attempt": args.run_attempt,
        "producer_repository": args.producer_repository,
        "producer_ref": args.producer_ref,
        "producer_sha": args.producer_sha,
        "producer_file": args.producer_file,
        "source_sha": source_sha,
        "artifact_name": args.artifact_name,
        "evidence_path": args.evidence_path,
    }


def _base_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    trivy = subparsers.add_parser("trivy")
    _common_arguments(trivy)
    trivy.add_argument("--report-path", required=True)
    trivy.add_argument("--scan-type", choices=("fs", "image"), required=True)
    trivy.add_argument("--scan-outcome", choices=("success", "failure", "cancelled"), required=True)

    bundle = subparsers.add_parser("bundle")
    _common_arguments(bundle)
    bundle.add_argument("--evidence-directory", required=True)
    bundle.add_argument(
        "--job-conclusion", choices=("success", "failure", "cancelled"), required=True
    )

    suite = subparsers.add_parser("suite")
    _common_arguments(suite)
    suite.add_argument("--summary-path", required=True)
    suite.add_argument("--profile", required=True)
    suite.add_argument("--image-refs", default="")
    suite.add_argument("--jobs-json", required=True)
    suite.add_argument("--child-evidence-json", default="{}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _base_parser().parse_args(argv)
    try:
        identity = _identity(args)
        if args.command == "trivy":
            evidence_bytes = _read_optional_file(args.report_path)
            if not evidence_bytes:
                evidence_bytes = None
            conclusion = args.scan_outcome
            result = (
                "passed"
                if conclusion == "success" and evidence_bytes
                else "failed"
            )
            details = {"scan_type": args.scan_type, "report_present": bool(evidence_bytes)}
            record = create_evidence_record(
                **identity,
                conclusion=conclusion,
                result=result,
                evidence_bytes=evidence_bytes,
                details=details,
            )
            _write_json(args.manifest_path, record)
            _write_outputs(
                args.github_output,
                {
                    "result": result,
                    "conclusion": conclusion,
                    "repository": record["repository"],
                    "run_id": record["run_id"],
                    "run_attempt": record["run_attempt"],
                    "producer": (
                        f"{record['producer']['repository']}/"
                        f"{record['producer']['file']}@{record['producer']['sha']}"
                    ),
                    "producer_ref": record["producer"]["ref"],
                    "producer_sha": record["producer"]["sha"],
                    "source_sha": record["source_sha"],
                    "evidence_path": record["evidence_path"] if evidence_bytes else "",
                    "evidence_sha256": record["evidence_sha256"],
                    "evidence_manifest_path": args.manifest_artifact_path or args.manifest_path,
                    "evidence_artifact_name": record["artifact_name"],
                    "report_present": str(bool(evidence_bytes)).lower(),
                },
            )
            return 0 if result == "passed" else 1

        if args.command == "bundle":
            record = create_evidence_bundle(
                repository=identity["repository"],
                run_id=identity["run_id"],
                run_attempt=identity["run_attempt"],
                producer_repository=identity["producer_repository"],
                producer_ref=identity["producer_ref"],
                producer_sha=identity["producer_sha"],
                producer_file=identity["producer_file"],
                source_sha=identity["source_sha"],
                expected_source_sha=args.expected_source_sha,
                conclusion=args.job_conclusion,
                artifact_name=identity["artifact_name"],
                evidence_directory=args.evidence_directory,
            )
            compact_fields = (
                "schema_version",
                "repository",
                "run_id",
                "run_attempt",
                "producer",
                "source_sha",
                "conclusion",
                "result",
                "artifact_name",
                "evidence_path",
                "evidence_manifest_path",
                "evidence_present",
                "evidence_file_count",
                "evidence_total_bytes",
                "evidence_index_sha256",
                "evidence_sha256",
            )
            compact_record = {key: record[key] for key in compact_fields}
            _write_outputs(
                args.github_output,
                {
                    "result": record["result"],
                    "conclusion": record["conclusion"],
                    "repository": record["repository"],
                    "run_id": record["run_id"],
                    "run_attempt": record["run_attempt"],
                    "producer": (
                        f"{record['producer']['repository']}/"
                        f"{record['producer']['file']}@{record['producer']['sha']}"
                    ),
                    "producer_ref": record["producer"]["ref"],
                    "producer_sha": record["producer"]["sha"],
                    "source_sha": record["source_sha"],
                    "evidence_path": record["evidence_path"],
                    "evidence_sha256": record["evidence_sha256"],
                    "evidence_manifest_path": record["evidence_manifest_path"],
                    "evidence_artifact_name": record["artifact_name"],
                    "evidence_present": str(record["evidence_present"]).lower(),
                    "evidence_record": json.dumps(
                        compact_record, separators=(",", ":"), sort_keys=True
                    ),
                },
            )
            return 0 if record["result"] == "passed" or args.job_conclusion != "success" else 1

        try:
            jobs = json.loads(args.jobs_json)
        except json.JSONDecodeError as exc:
            raise EvidenceError("suite jobs must be valid JSON") from exc
        if not isinstance(jobs, dict) or any(
            not isinstance(name, str) or not isinstance(value, str)
            for name, value in jobs.items()
        ):
            raise EvidenceError("suite jobs must be a JSON object of string results")
        try:
            child_outputs = json.loads(args.child_evidence_json)
        except json.JSONDecodeError:
            child_outputs = {}
        if not isinstance(child_outputs, dict):
            child_outputs = {}
        child_evidence: dict[str, Any] = {}
        for name in CHILD_EVIDENCE_NAMES:
            child_output = child_outputs.get(name)
            if child_output is None:
                child_evidence[name] = None
                continue
            if not isinstance(child_output, dict):
                child_evidence[name] = child_output
                continue
            record_json = child_output.get("record_json")
            try:
                child_record = json.loads(record_json) if isinstance(record_json, str) else {}
            except json.JSONDecodeError:
                child_record = {}
            if not isinstance(child_record, dict):
                child_record = {}
            child_record.update(
                {
                    "evidence_sha256": child_output.get("evidence_sha256"),
                    "artifact_id": child_output.get("artifact_id"),
                    "artifact_digest": child_output.get("artifact_digest"),
                }
            )
            child_evidence[name] = child_record
        summary = summarize_security_suite(
            profile=args.profile,
            image_refs=args.image_refs,
            jobs=jobs,
            child_evidence=child_evidence,
            expected_identity={
                "repository": identity["repository"],
                "run_id": identity["run_id"],
                "run_attempt": identity["run_attempt"],
                "source_sha": identity["source_sha"],
            },
        )
        summary_bytes = _write_json(args.summary_path, summary)
        conclusion = "success" if summary["result"] == "passed" else "failure"
        record = create_evidence_record(
            **identity,
            conclusion=conclusion,
            result=summary["result"],
            evidence_bytes=summary_bytes,
            details={key: value for key, value in summary.items() if key != "schema_version"},
        )
        _write_json(args.manifest_path, record)
        _write_outputs(
            args.github_output,
            {
                "result": summary["result"],
                "conclusion": conclusion,
                "repository": record["repository"],
                "run_id": record["run_id"],
                "run_attempt": record["run_attempt"],
                "producer": (
                    f"{record['producer']['repository']}/"
                    f"{record['producer']['file']}@{record['producer']['sha']}"
                ),
                "producer_ref": record["producer"]["ref"],
                "producer_sha": record["producer"]["sha"],
                "source_sha": record["source_sha"],
                "evidence_path": args.summary_path,
                "evidence_sha256": record["evidence_sha256"],
                "evidence_manifest_path": args.manifest_artifact_path or args.manifest_path,
                "evidence_artifact_name": record["artifact_name"],
            },
        )
        return 0 if summary["result"] == "passed" else 1
    except (EvidenceError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
