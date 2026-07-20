"""Validate security policy and write secret-free Trivy evidence."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _parse_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"database metadata field {field} must be a timestamp")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"database metadata field {field} is not ISO-8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_db_metadata(
    metadata_path: Path,
    *,
    max_age_hours: float,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return normalized database metadata or fail when it is unusable/stale."""
    if max_age_hours <= 0:
        raise ValueError("max_age_hours must be greater than zero")
    if not metadata_path.is_file():
        raise ValueError(f"Trivy database metadata is missing: {metadata_path}")
    try:
        raw = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Trivy database metadata is invalid: {metadata_path}") from exc
    if not isinstance(raw, dict):
        raise ValueError("Trivy database metadata must be an object")

    reference = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    updated_at = _parse_datetime(raw.get("UpdatedAt"), "UpdatedAt")
    next_update = _parse_datetime(raw.get("NextUpdate"), "NextUpdate")
    downloaded_at = _parse_datetime(raw.get("DownloadedAt"), "DownloadedAt")
    if downloaded_at > reference:
        raise ValueError("Trivy database DownloadedAt is in the future")
    age_hours = (reference - downloaded_at).total_seconds() / 3600
    if age_hours > max_age_hours:
        raise ValueError(
            f"Trivy database is older than {max_age_hours:g} hours "
            f"({age_hours:.3f} hours)"
        )

    version = raw.get("Version")
    if not isinstance(version, int) or version < 1:
        raise ValueError("Trivy database Version must be a positive integer")
    return {
        "version": version,
        "updated_at": updated_at.isoformat(),
        "next_update": next_update.isoformat(),
        "downloaded_at": downloaded_at.isoformat(),
        "age_hours": round(age_hours, 3),
        "max_age_hours": max_age_hours,
        "status": "fresh",
    }


def _require_text(entry: Mapping[str, Any], field: str, index: int) -> str:
    value = entry.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"vulnerabilities[{index}].{field} is required")
    return value.strip()


def _string_list(entry: Mapping[str, Any], field: str, index: int) -> list[str]:
    value = entry.get(field, [])
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ValueError(f"vulnerabilities[{index}].{field} must be a string array")
    return [item.strip() for item in value]


def render_exception_policy(
    source: Path,
    *,
    target: str,
    output: Path,
    today: date | None = None,
) -> dict[str, Any]:
    """Validate Optimizr exception metadata and render Trivy YAML as JSON."""
    if not source.is_file():
        raise ValueError(f"exception policy is missing: {source}")
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"exception policy is not valid JSON: {source}") from exc
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise ValueError("exception policy version must be 1")
    entries = raw.get("vulnerabilities")
    if not isinstance(entries, list):
        raise ValueError("exception policy vulnerabilities must be an array")

    reference_date = today or datetime.now(timezone.utc).date()
    rendered: list[dict[str, Any]] = []
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            raise ValueError(f"vulnerabilities[{index}] must be an object")
        vulnerability_id = _require_text(item, "id", index)
        owner = _require_text(item, "owner", index)
        statement = _require_text(item, "statement", index)
        control = _require_text(item, "compensating_control", index)
        expires_text = _require_text(item, "expires", index)
        try:
            expires = date.fromisoformat(expires_text)
        except ValueError as exc:
            raise ValueError(
                f"vulnerabilities[{index}].expires must use YYYY-MM-DD"
            ) from exc
        if expires < reference_date:
            raise ValueError(
                f"vulnerabilities[{index}] {vulnerability_id} expired on {expires_text}"
            )

        targets = _string_list(item, "targets", index)
        if not targets:
            raise ValueError(
                f"vulnerabilities[{index}].targets must scope the exception"
            )
        paths = _string_list(item, "paths", index)
        purls = _string_list(item, "purls", index)
        if target not in targets and "*" not in targets:
            continue

        rendered_entry: dict[str, Any] = {
            "id": vulnerability_id,
            "expired_at": expires_text,
            "statement": (
                f"{statement}; owner={owner}; control={control}"
            ),
        }
        if paths:
            rendered_entry["paths"] = paths
        if purls:
            rendered_entry["purls"] = purls
        rendered.append(rendered_entry)

    rendered_policy: dict[str, Any] = {"vulnerabilities": rendered}
    _atomic_write_json(output, rendered_policy)
    return {
        "source": str(source),
        "policy_sha256": _sha256(source),
        "active_exceptions": len(rendered),
        "target": target,
        "status": "validated",
    }


def resolve_image_identity(report_path: Path) -> str:
    """Resolve an immutable image identity from a Trivy JSON report."""
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Trivy JSON report is invalid: {report_path}") from exc
    metadata = report.get("Metadata", {}) if isinstance(report, dict) else {}
    if not isinstance(metadata, dict):
        return ""
    repo_digests = metadata.get("RepoDigests", [])
    if isinstance(repo_digests, list):
        for digest in repo_digests:
            if isinstance(digest, str) and "@sha256:" in digest:
                return digest
    image_id = metadata.get("ImageID")
    if isinstance(image_id, str) and image_id.startswith("sha256:"):
        return image_id
    return ""


def write_evidence(
    destination: Path,
    *,
    repository: str,
    head_sha: str,
    scan_type: str,
    target: str,
    identity: str,
    severity: str,
    ignore_unfixed: bool,
    trivy_version: str,
    database: Mapping[str, Any],
    exception_policy: Mapping[str, Any],
    reports: Mapping[str, Path],
    result: str,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Write one atomic, sanitized evidence record."""
    if not repository.strip():
        raise ValueError("repository is required")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", head_sha):
        raise ValueError("head_sha must be a 40-character commit SHA")
    if scan_type not in {"fs", "image"}:
        raise ValueError("scan_type must be fs or image")
    if scan_type == "image" and not identity:
        raise ValueError("image scans require an immutable image identity")
    if result not in {"passed", "failed"}:
        raise ValueError("result must be passed or failed")

    report_evidence: dict[str, Any] = {}
    for name, path in reports.items():
        if not path.is_file():
            raise ValueError(f"required report is missing: {path}")
        digest = _sha256(path)
        if not _SHA256_PATTERN.fullmatch(digest):
            raise ValueError(f"invalid report digest for {path}")
        report_evidence[name] = {
            "path": str(path),
            "sha256": digest,
            "size_bytes": path.stat().st_size,
        }

    timestamp = (created_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "created_at": timestamp.isoformat(),
        "repository": {"name": repository, "head_sha": head_sha.lower()},
        "target": {"scan_type": scan_type, "value": target, "identity": identity},
        "tool": {"name": "trivy", "version": trivy_version.strip()},
        "database": dict(database),
        "exceptions": dict(exception_policy),
        "policy": {
            "severity": severity,
            "ignore_unfixed": ignore_unfixed,
            "blocking": True,
        },
        "reports": report_evidence,
        "result": result,
    }
    _atomic_write_json(destination, payload)
    return payload


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON object expected: {path}")
    return payload


def _command_validate_db(args: argparse.Namespace) -> int:
    result = validate_db_metadata(
        args.metadata,
        max_age_hours=args.max_age_hours,
    )
    _atomic_write_json(args.output, result)
    return 0


def _command_render_exceptions(args: argparse.Namespace) -> int:
    if args.source:
        result = render_exception_policy(
            args.source,
            target=args.target,
            output=args.output,
        )
    else:
        _atomic_write_json(args.output, {"vulnerabilities": []})
        result = {
            "source": "none",
            "policy_sha256": "none",
            "active_exceptions": 0,
            "target": args.target,
            "status": "not-configured",
        }
    _atomic_write_json(args.summary_output, result)
    return 0


def _command_resolve_image(args: argparse.Namespace) -> int:
    identity = resolve_image_identity(args.report)
    if not identity:
        raise ValueError("Trivy report does not contain an immutable image identity")
    print(identity)
    return 0


def _command_write_evidence(args: argparse.Namespace) -> int:
    reports: dict[str, Path] = {}
    for value in args.report:
        name, separator, path = value.partition("=")
        if not separator or not name or not path:
            raise ValueError("--report must use name=path")
        reports[name] = Path(path)
    write_evidence(
        args.output,
        repository=args.repository,
        head_sha=args.head_sha,
        scan_type=args.scan_type,
        target=args.target,
        identity=args.identity,
        severity=args.severity,
        ignore_unfixed=args.ignore_unfixed,
        trivy_version=args.trivy_version,
        database=_read_json(args.database),
        exception_policy=_read_json(args.exception_summary),
        reports=reports,
        result=args.result,
    )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate-db")
    validate.add_argument("--metadata", type=Path, required=True)
    validate.add_argument("--max-age-hours", type=float, required=True)
    validate.add_argument("--output", type=Path, required=True)
    validate.set_defaults(handler=_command_validate_db)

    render = subparsers.add_parser("render-exceptions")
    render.add_argument("--source", type=Path)
    render.add_argument("--target", required=True)
    render.add_argument("--output", type=Path, required=True)
    render.add_argument("--summary-output", type=Path, required=True)
    render.set_defaults(handler=_command_render_exceptions)

    resolve = subparsers.add_parser("resolve-image")
    resolve.add_argument("--report", type=Path, required=True)
    resolve.set_defaults(handler=_command_resolve_image)

    write = subparsers.add_parser("write-evidence")
    write.add_argument("--output", type=Path, required=True)
    write.add_argument("--repository", required=True)
    write.add_argument("--head-sha", required=True)
    write.add_argument("--scan-type", choices=("fs", "image"), required=True)
    write.add_argument("--target", required=True)
    write.add_argument("--identity", default="")
    write.add_argument("--severity", required=True)
    write.add_argument("--ignore-unfixed", action="store_true")
    write.add_argument("--trivy-version", required=True)
    write.add_argument("--database", type=Path, required=True)
    write.add_argument("--exception-summary", type=Path, required=True)
    write.add_argument("--report", action="append", default=[], required=True)
    write.add_argument("--result", choices=("passed", "failed"), required=True)
    write.set_defaults(handler=_command_write_evidence)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
