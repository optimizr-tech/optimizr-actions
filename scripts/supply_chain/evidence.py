#!/usr/bin/env python3
"""Generate sanitized image SBOM provenance bound to immutable identities."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
IDENTITY_KINDS = frozenset({"repository_digest", "local_image_id"})
MEDIA_TYPES = {
    "cyclonedx": "application/vnd.cyclonedx+json",
    "spdx": "application/spdx+json",
}
BUILD_TYPE = "https://github.com/optimizr-tech/optimizr-actions/blob/v1/docs/SUPPLY_CHAIN_EVIDENCE.md"


class EvidenceError(ValueError):
    """Raised when image or provenance evidence is incomplete."""


def _objects(inspect: Any) -> list[dict[str, Any]]:
    if isinstance(inspect, dict):
        return [inspect]
    if isinstance(inspect, list) and inspect and all(isinstance(item, dict) for item in inspect):
        return inspect
    raise EvidenceError("Docker inspect evidence must be a non-empty object or object array")


def resolve_image_descriptor(inspect: Any) -> dict[str, str]:
    objects = _objects(inspect)
    for item in objects:
        repo_digests = item.get("RepoDigests", []) or []
        if not isinstance(repo_digests, list):
            raise EvidenceError("Docker RepoDigests must be an array")
        for repo_digest in repo_digests:
            if isinstance(repo_digest, str) and "@" in repo_digest:
                digest = repo_digest.rsplit("@", 1)[1]
                if DIGEST_RE.fullmatch(digest):
                    return {"identity": digest, "identity_kind": "repository_digest"}
    for item in objects:
        image_id = item.get("Id")
        if isinstance(image_id, str) and DIGEST_RE.fullmatch(image_id):
            return {"identity": image_id, "identity_kind": "local_image_id"}
    raise EvidenceError("image inspection did not provide an immutable sha256 identity")


def resolve_image_identity(inspect: Any) -> str:
    return resolve_image_descriptor(inspect)["identity"]


def resolve_image_kind(inspect: Any) -> str:
    return resolve_image_descriptor(inspect)["identity_kind"]


def resolve_local_image_id(inspect: Any) -> str:
    for item in _objects(inspect):
        image_id = item.get("Id")
        if isinstance(image_id, str) and DIGEST_RE.fullmatch(image_id):
            return image_id
    raise EvidenceError("image inspection did not provide an immutable local image ID")


def _hash_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise EvidenceError(f"artifact must be a regular non-symlink file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_text(name: str, value: str, *, maximum: int) -> None:
    if not value or len(value) > maximum or any(ord(char) < 32 for char in value):
        raise EvidenceError(f"{name} is empty, too long, or contains control characters")


def _validate_common(repository: str, head_sha: str) -> None:
    if not REPOSITORY_RE.fullmatch(repository):
        raise EvidenceError("repository must use the bounded owner/name form")
    if not SHA_RE.fullmatch(head_sha):
        raise EvidenceError("head_sha must be a lowercase 40-character commit SHA")


def _byproducts(artifacts: Mapping[str, Path]) -> list[dict[str, Any]]:
    if not artifacts:
        raise EvidenceError("at least one SBOM artifact is required")
    descriptors: list[dict[str, Any]] = []
    names: set[str] = set()
    for kind, path in sorted(artifacts.items()):
        if kind not in MEDIA_TYPES:
            raise EvidenceError(f"unsupported SBOM artifact kind: {kind}")
        name = path.name
        if name in names:
            raise EvidenceError(f"duplicate SBOM artifact name: {name}")
        names.add(name)
        descriptors.append(
            {
                "name": name,
                "digest": {"sha256": _hash_file(path)},
                "mediaType": MEDIA_TYPES[kind],
                "annotations": {"bytes": path.stat().st_size, "sbomFormat": kind},
            }
        )
    return descriptors


def build_provenance(
    *,
    repository: str,
    head_sha: str,
    image_ref: str,
    image_identity: str,
    identity_kind: str,
    workflow_ref: str,
    artifacts: Mapping[str, Path],
    tool_version: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    _validate_common(repository, head_sha)
    match = DIGEST_RE.fullmatch(image_identity)
    if not match:
        raise EvidenceError("image_identity must be an immutable sha256 digest")
    if identity_kind not in IDENTITY_KINDS:
        raise EvidenceError("identity_kind must be repository_digest or local_image_id")
    _validate_text("image_ref", image_ref, maximum=512)
    _validate_text("workflow_ref", workflow_ref, maximum=1024)
    _validate_text("tool_version", tool_version, maximum=256)
    timestamp = generated_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    image_alias = hashlib.sha256(image_ref.encode("utf-8")).hexdigest()[:16]
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "container-image", "digest": {"sha256": match.group(1)}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "repository": repository,
                    "headSha": head_sha,
                    "imageAlias": image_alias,
                    "identityKind": identity_kind,
                },
                "internalParameters": {"workflowRef": workflow_ref},
                "resolvedDependencies": [
                    {
                        "uri": f"git+https://github.com/{repository}@{head_sha}",
                        "digest": {"gitCommit": head_sha},
                    }
                ],
            },
            "runDetails": {
                "builder": {
                    "id": workflow_ref,
                    "version": {"trivy": tool_version},
                },
                "metadata": {
                    "invocationId": f"{repository}:{head_sha}:{image_alias}",
                    "startedOn": timestamp,
                    "finishedOn": timestamp,
                },
                "byproducts": _byproducts(artifacts),
            },
        },
    }


def build_summary(
    *,
    repository: str,
    head_sha: str,
    root: Path,
    result: str,
    exit_code: int,
) -> dict[str, Any]:
    _validate_common(repository, head_sha)
    if result not in {"started", "passed", "failed"}:
        raise EvidenceError("result must be started, passed, or failed")
    if exit_code < 0 or exit_code > 255:
        raise EvidenceError("exit_code must be between 0 and 255")
    attestations: list[dict[str, Any]] = []
    if root.exists():
        for path in sorted(root.glob("*/provenance.intoto.json")):
            payload = _read_json(path)
            try:
                digest = payload["subject"][0]["digest"]["sha256"]
            except (KeyError, IndexError, TypeError) as exc:
                raise EvidenceError(f"invalid provenance subject in {path}") from exc
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise EvidenceError(f"invalid provenance digest in {path}")
            attestations.append(
                {
                    "alias": path.parent.name,
                    "subject": {"sha256": digest},
                    "provenance": {"sha256": _hash_file(path), "bytes": path.stat().st_size},
                }
            )
    return {
        "schema_version": 1,
        "repository": repository,
        "head_sha": head_sha,
        "result": result,
        "exit_code": exit_code,
        "attestation_count": len(attestations),
        "attestations": attestations,
    }


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid JSON evidence {path}: {exc}") from exc


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    resolve = sub.add_parser("resolve")
    resolve.add_argument("--inspect", required=True)
    resolve_kind = sub.add_parser("resolve-kind")
    resolve_kind.add_argument("--inspect", required=True)
    resolve_local = sub.add_parser("resolve-local")
    resolve_local.add_argument("--inspect", required=True)
    write = sub.add_parser("write")
    write.add_argument("--repository", required=True)
    write.add_argument("--head-sha", required=True)
    write.add_argument("--image-ref", required=True)
    write.add_argument("--image-identity", required=True)
    write.add_argument("--identity-kind", required=True)
    write.add_argument("--workflow-ref", required=True)
    write.add_argument("--cyclonedx", required=True)
    write.add_argument("--spdx", required=True)
    write.add_argument("--tool-version", required=True)
    write.add_argument("--output", required=True)
    summary = sub.add_parser("summary")
    summary.add_argument("--repository", required=True)
    summary.add_argument("--head-sha", required=True)
    summary.add_argument("--root", required=True)
    summary.add_argument("--result", choices=("started", "passed", "failed"), required=True)
    summary.add_argument("--exit-code", type=int, required=True)
    summary.add_argument("--output", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "resolve":
            print(resolve_image_identity(_read_json(Path(args.inspect))))
            return 0
        if args.command == "resolve-kind":
            print(resolve_image_kind(_read_json(Path(args.inspect))))
            return 0
        if args.command == "resolve-local":
            print(resolve_local_image_id(_read_json(Path(args.inspect))))
            return 0
        if args.command == "summary":
            payload = build_summary(
                repository=args.repository,
                head_sha=args.head_sha,
                root=Path(args.root),
                result=args.result,
                exit_code=args.exit_code,
            )
            _write_json(Path(args.output), payload)
            return 0
        payload = build_provenance(
            repository=args.repository,
            head_sha=args.head_sha,
            image_ref=args.image_ref,
            image_identity=args.image_identity,
            identity_kind=args.identity_kind,
            workflow_ref=args.workflow_ref,
            artifacts={"cyclonedx": Path(args.cyclonedx), "spdx": Path(args.spdx)},
            tool_version=args.tool_version,
        )
        _write_json(Path(args.output), payload)
        return 0
    except (EvidenceError, OSError) as exc:
        print(f"supply-chain evidence error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
