"""Validate the complete immutable image set and its exceptions before promotion."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import date
from pathlib import Path
from typing import Any

from scripts.security_gate import evidence as security_evidence


_CANDIDATE_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SERVICE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_POLICY_PATH = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
_REGISTRY = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::[0-9]{1,5})?$"
)
_IMAGE_PATH_SEGMENT = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_MAX_JSON_BYTES = 1024 * 1024


class AggregateExceptionSetError(ValueError):
    """Raised when the publisher's declared final image set is incomplete or unsafe."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _service_name(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SERVICE.fullmatch(value):
        raise AggregateExceptionSetError(f"{field} must be a bounded lowercase service name")
    return value


def _policy_relative_path(value: object, field: str) -> str:
    if value in (None, ""):
        return ""
    if (
        not isinstance(value, str)
        or len(value) > 1024
        or not _POLICY_PATH.fullmatch(value)
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise AggregateExceptionSetError(f"{field} is not a safe repository-relative policy path")
    return value


def _full_image_ref(
    value: object,
    *,
    registry: str,
    image_namespace: str,
    service: str,
    field: str,
) -> tuple[str, str]:
    if not isinstance(value, str) or "@" not in value:
        raise AggregateExceptionSetError(f"{field} must be a full immutable image reference")
    image_name, digest = value.rsplit("@", 1)
    expected_name = f"{registry}/{image_namespace}/{service}"
    if image_name != expected_name or not _DIGEST.fullmatch(digest):
        raise AggregateExceptionSetError(
            f"{field} must match the configured registry, namespace, service, and sha256 digest"
        )
    return value, digest


def _read_json_file(path: Path, *, label: str) -> Any:
    if path.is_symlink() or not path.is_file():
        raise AggregateExceptionSetError(f"{label} must be a regular non-symlink file")
    if path.stat().st_size > _MAX_JSON_BYTES:
        raise AggregateExceptionSetError(f"{label} exceeds the 1 MiB contract limit")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AggregateExceptionSetError(f"{label} must be valid UTF-8 JSON") from exc


def _candidate_fragment_files(root: Path) -> list[Path]:
    if root.is_symlink() or not root.is_dir():
        raise AggregateExceptionSetError("candidate fragments directory is missing or unsafe")
    resolved_root = root.resolve(strict=True)
    paths = sorted(root.rglob("candidate-fragment.json"))
    for parent in {path.parent for path in paths}:
        cursor = root
        for part in parent.relative_to(root).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise AggregateExceptionSetError("candidate fragment directories must not traverse symlinks")
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise AggregateExceptionSetError("candidate fragment must be a regular non-symlink file")
        if not path.resolve(strict=True).is_relative_to(resolved_root):
            raise AggregateExceptionSetError("candidate fragment escapes its artifact directory")
    return paths


def _policy_file(root: Path, relative_path: str) -> tuple[Path, Any, str]:
    resolved_root = root.resolve(strict=True)
    path = root.joinpath(*relative_path.split("/"))
    cursor = root
    for part in relative_path.split("/"):
        cursor = cursor / part
        if cursor.is_symlink():
            raise AggregateExceptionSetError("exception policy paths must not traverse symlinks")
    if not path.is_file() or not path.resolve(strict=True).is_relative_to(resolved_root):
        raise AggregateExceptionSetError("configured exception policy is missing or outside the candidate source")
    raw_bytes = path.read_bytes()
    if len(raw_bytes) > _MAX_JSON_BYTES:
        raise AggregateExceptionSetError("exception policy exceeds the 1 MiB contract limit")
    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AggregateExceptionSetError("exception policy must be valid UTF-8 JSON") from exc
    if (
        not isinstance(payload, Mapping)
        or isinstance(payload.get("version"), bool)
        or payload.get("version") != 1
        or set(payload) != {"version", "vulnerabilities"}
        or not isinstance(payload.get("vulnerabilities"), list)
    ):
        raise AggregateExceptionSetError("exception policy must use the supported version 1 schema")
    return path, payload, _sha256(raw_bytes)


def _validate_policy_files(
    policies: Sequence[tuple[str, Path, Mapping[str, Any], str]],
    *,
    active_image_ids: Sequence[str],
    today: date | None,
) -> int:
    entries: list[Any] = []
    for _service, path, payload, _digest in policies:
        vulnerabilities = payload["vulnerabilities"]
        if not isinstance(vulnerabilities, list):
            raise AggregateExceptionSetError("exception policy vulnerabilities must be an array")
        entries.extend(vulnerabilities)

    with tempfile.TemporaryDirectory(prefix="publisher-exception-validation-") as temporary:
        temp_root = Path(temporary)
        combined_policy = temp_root / "combined-policy.json"
        active_ids_file = temp_root / "active-image-ids.txt"
        combined_policy.write_text(
            json.dumps({"version": 1, "vulnerabilities": entries}), encoding="utf-8"
        )
        active_ids_file.write_text("".join(f"{value}\n" for value in active_image_ids), encoding="utf-8")
        exception_count = security_evidence.validate_complete_exception_policy(
            combined_policy,
            active_image_ids_file=active_ids_file,
            image_refs=active_image_ids,
            today=today,
        )
        for index, (_service, path, _payload, _digest) in enumerate(policies):
            security_evidence.render_exception_policy(
                path,
                target=active_image_ids[0],
                scan_type="image",
                output=temp_root / f"rendered-{index}.json",
                today=today,
            )
    return exception_count


def validate_aggregate_exception_set(
    services: Sequence[Mapping[str, Any]],
    candidate_fragments_dir: Path,
    *,
    candidate_sha: str,
    registry: str,
    image_namespace: str,
    unchanged_images: Sequence[Mapping[str, Any]] = (),
    policy_root: Path,
    validate_policies: bool,
    set_complete: bool,
    require_promotion_authorized: bool,
    require_attestations: bool = True,
    today: date | None = None,
) -> dict[str, Any]:
    """Verify every matrix digest and optionally validate the final-set exception policy.

    The caller's set is the exact candidate matrix plus ``unchanged_images``.
    Setting ``validate_policies`` is an explicit caller assertion that this list is
    the complete final image set for the release.
    """
    if not isinstance(candidate_sha, str) or not _CANDIDATE_SHA.fullmatch(candidate_sha):
        raise AggregateExceptionSetError("candidate_sha must be a full lowercase commit SHA")
    if not isinstance(registry, str) or not _REGISTRY.fullmatch(registry):
        raise AggregateExceptionSetError("registry must be a safe lowercase registry hostname")
    if (
        not isinstance(image_namespace, str)
        or not image_namespace
        or image_namespace.startswith("/")
        or image_namespace.endswith("/")
        or any(not _IMAGE_PATH_SEGMENT.fullmatch(part) for part in image_namespace.split("/"))
    ):
        raise AggregateExceptionSetError("image_namespace must be a safe repository namespace")
    if not isinstance(services, Sequence) or isinstance(services, (str, bytes)) or not services:
        raise AggregateExceptionSetError("services must declare the complete non-empty candidate matrix")
    if not isinstance(unchanged_images, Sequence) or isinstance(unchanged_images, (str, bytes)):
        raise AggregateExceptionSetError("unchanged_images must be a JSON array")
    if validate_policies and not set_complete:
        raise AggregateExceptionSetError("strict exception validation requires the caller to declare the final set complete")
    if not validate_policies and (set_complete or unchanged_images):
        raise AggregateExceptionSetError("final-set declarations require strict exception validation to be enabled")

    expected_services: dict[str, Mapping[str, Any]] = {}
    for index, service in enumerate(services):
        if not isinstance(service, Mapping):
            raise AggregateExceptionSetError(f"services[{index}] must be an object")
        name = _service_name(service.get("name"), f"services[{index}].name")
        if name in expected_services:
            raise AggregateExceptionSetError(f"duplicate candidate service: {name}")
        expected_services[name] = service

    unchanged_by_name: dict[str, Mapping[str, Any]] = {}
    for index, image in enumerate(unchanged_images):
        if not isinstance(image, Mapping):
            raise AggregateExceptionSetError(f"unchanged_images[{index}] must be an object")
        service_name = _service_name(image.get("service"), f"unchanged_images[{index}].service")
        if service_name in expected_services or service_name in unchanged_by_name:
            raise AggregateExceptionSetError(f"duplicate final image service: {service_name}")
        unchanged_by_name[service_name] = image

    fragments_by_service: dict[str, Mapping[str, Any]] = {}
    for path in _candidate_fragment_files(candidate_fragments_dir):
        payload = _read_json_file(path, label="candidate fragment")
        if not isinstance(payload, Mapping):
            raise AggregateExceptionSetError("candidate fragment must be a JSON object")
        service_name = _service_name(payload.get("service"), "candidate fragment service")
        if service_name not in expected_services or service_name in fragments_by_service:
            raise AggregateExceptionSetError("candidate fragments must contain exactly the requested candidate services")
        if payload.get("candidate_sha") != candidate_sha:
            raise AggregateExceptionSetError("candidate fragment does not match the requested candidate source commit")
        image_ref, digest = _full_image_ref(
            payload.get("image"),
            registry=registry,
            image_namespace=image_namespace,
            service=service_name,
            field="candidate fragment image",
        )
        if payload.get("digest") != digest:
            raise AggregateExceptionSetError("candidate fragment image reference does not match its digest")
        if require_attestations and payload.get("attestation_verified") is not True:
            raise AggregateExceptionSetError("candidate fragment is missing verified quarantine attestations")
        gate_evidence = payload.get("security_evidence")
        if not isinstance(gate_evidence, Mapping):
            raise AggregateExceptionSetError("candidate fragment is missing per-image security evidence")
        if gate_evidence.get("source_sha") != candidate_sha:
            raise AggregateExceptionSetError("per-image security evidence does not match the candidate source commit")
        if gate_evidence.get("image_digest") != digest:
            raise AggregateExceptionSetError("per-image security evidence does not match the immutable image digest")
        if gate_evidence.get("security_gate_accepted") is not True:
            raise AggregateExceptionSetError("candidate fragment contains an image rejected by the security gate")
        if require_promotion_authorized and gate_evidence.get("promotion_authorized") is not True:
            raise AggregateExceptionSetError("candidate fragment lacks per-image promotion authorization")
        fragments_by_service[service_name] = {
            "service": service_name,
            "image": image_ref,
            "digest": digest,
            "security_evidence": gate_evidence,
        }

    if set(fragments_by_service) != set(expected_services):
        raise AggregateExceptionSetError("candidate fragments must contain exactly the requested candidate services")

    image_set: list[dict[str, str]] = [
        {"service": service_name, "image": fragment["image"]}
        for service_name, fragment in fragments_by_service.items()
    ]
    for service_name, image in unchanged_by_name.items():
        image_ref, _digest = _full_image_ref(
            image.get("image"),
            registry=registry,
            image_namespace=image_namespace,
            service=service_name,
            field=f"unchanged_images.{service_name}.image",
        )
        image_set.append({"service": service_name, "image": image_ref})
    image_set.sort(key=lambda item: item["service"])

    active_image_ids = [item["image"].rsplit("@", 1)[1] for item in image_set]
    if len(set(active_image_ids)) != len(active_image_ids):
        raise AggregateExceptionSetError("final image set contains a duplicate active image ID")

    policy_records: list[tuple[str, Path, Mapping[str, Any], str]] = []
    policy_hash_records: list[dict[str, str]] = []
    exception_count: int | None = None
    if validate_policies:
        if policy_root.is_symlink() or not policy_root.is_dir():
            raise AggregateExceptionSetError("candidate policy root is missing or unsafe")
        unique_paths: dict[str, tuple[Path, Mapping[str, Any], str]] = {}
        final_services = {
            **{name: service for name, service in expected_services.items()},
            **{name: image for name, image in unchanged_by_name.items()},
        }
        for service_name, definition in final_services.items():
            relative_path = _policy_relative_path(
                definition.get("security_exceptions_file", ""),
                f"{service_name}.security_exceptions_file",
            )
            if not relative_path:
                policy_hash_records.append({"service": service_name, "policy_sha256": "none"})
                continue
            if relative_path not in unique_paths:
                path, payload, digest = _policy_file(policy_root, relative_path)
                unique_paths[relative_path] = (path, payload, digest)
            path, payload, digest = unique_paths[relative_path]
            policy_records.append((service_name, path, payload, digest))
            policy_hash_records.append({"service": service_name, "policy_sha256": digest})

        # Validate every distinct source once; shared policy paths must not
        # duplicate entries merely because several services reference the file.
        distinct_policy_records: list[tuple[str, Path, Mapping[str, Any], str]] = []
        seen_policy_paths: set[Path] = set()
        for record in policy_records:
            if record[1] not in seen_policy_paths:
                distinct_policy_records.append(record)
                seen_policy_paths.add(record[1])
        exception_count = _validate_policy_files(
            distinct_policy_records,
            active_image_ids=active_image_ids,
            today=today,
        )

    image_set_sha256 = _sha256(
        _canonical_json({"candidate_sha": candidate_sha, "images": image_set})
    )
    policy_set_sha256 = _sha256(
        _canonical_json(sorted(policy_hash_records, key=lambda item: item["service"]))
    )
    active_ids_sha256 = _sha256(_canonical_json(sorted(active_image_ids)))
    return {
        "schema_version": 1,
        "status": "validated" if validate_policies else "not_requested",
        "policy_validation_enabled": validate_policies,
        "candidate_matrix_complete": True,
        "set_complete": set_complete,
        "candidate_sha": candidate_sha,
        "images": image_set,
        "active_image_count": len(image_set),
        "active_image_ids_sha256": active_ids_sha256,
        "image_set_sha256": image_set_sha256,
        "policy_set_sha256": policy_set_sha256,
        "exception_count": exception_count,
    }


def _parse_json_argument(value: str, label: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise AggregateExceptionSetError(f"{label} must be valid JSON") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--services-json", required=True)
    parser.add_argument("--candidate-fragments-dir", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--image-namespace", required=True)
    parser.add_argument("--unchanged-images-json", default="[]")
    parser.add_argument("--policy-root", type=Path, required=True)
    parser.add_argument("--validate-policies", action="store_true")
    parser.add_argument("--set-complete", action="store_true")
    parser.add_argument("--require-promotion-authorized", action="store_true")
    parser.add_argument("--require-attestations", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = validate_aggregate_exception_set(
            _parse_json_argument(args.services_json, "services_json"),
            args.candidate_fragments_dir,
            candidate_sha=args.candidate_sha,
            registry=args.registry,
            image_namespace=args.image_namespace,
            unchanged_images=_parse_json_argument(
                args.unchanged_images_json, "unchanged_images_json"
            ),
            policy_root=args.policy_root,
            validate_policies=args.validate_policies,
            set_complete=args.set_complete,
            require_promotion_authorized=args.require_promotion_authorized,
            require_attestations=args.require_attestations,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.output.is_symlink():
            raise AggregateExceptionSetError("validation evidence path must not be a symlink")
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (AggregateExceptionSetError, OSError, ValueError) as exc:
        parser.error(str(exc))
    print(
        "Publisher image-set validation passed: "
        f"images={result['active_image_count']} status={result['status']} "
        f"exceptions={result['exception_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
