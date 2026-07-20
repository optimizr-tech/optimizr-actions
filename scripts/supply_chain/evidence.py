#!/usr/bin/env python3
"""Generate sanitized image SBOM provenance bound to an immutable identity."""

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


class EvidenceError(ValueError):
    """Raised when image or provenance evidence is incomplete."""


def _objects(inspect: Any) -> list[dict[str, Any]]:
    if isinstance(inspect, dict):
        return [inspect]
    if isinstance(inspect, list) and all(isinstance(item, dict) for item in inspect):
        return inspect
    raise EvidenceError("Docker inspect evidence must be an object or object array")


def resolve_image_identity(inspect: Any) -> str:
    objects = _objects(inspect)
    for item in objects:
        for repo_digest in item.get("RepoDigests", []) or []:
            if isinstance(repo_digest, str) and "@" in repo_digest:
                digest = repo_digest.rsplit("@", 1)[1]
                if DIGEST_RE.fullmatch(digest):
                    return digest
    for item in objects:
        image_id = item.get("Id")
        if isinstance(image_id, str) and DIGEST_RE.fullmatch(image_id):
            return image_id
    raise EvidenceError("image inspection did not provide an immutable sha256 identity")


def resolve_local_image_id(inspect: Any) -> str:
    """Return the immutable local Docker image ID used as the scan target."""
    for item in _objects(inspect):
        image_id = item.get("Id")
        if isinstance(image_id, str) and DIGEST_RE.fullmatch(image_id):
            return image_id
    raise EvidenceError("image inspection did not provide an immutable local image ID")


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_provenance(
    *,
    repository: str,
    head_sha: str,
    image_ref: str,
    image_identity: str,
    workflow_ref: str,
    artifacts: Mapping[str, Path],
    tool_version: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    match = DIGEST_RE.fullmatch(image_identity)
    if not match:
        raise EvidenceError("image_identity must be an immutable sha256 digest")
    if not SHA_RE.fullmatch(head_sha):
        raise EvidenceError("head_sha must be a lowercase 40-character commit SHA")
    materials = {
        name: {"sha256": _hash_file(path), "bytes": path.stat().st_size}
        for name, path in sorted(artifacts.items())
    }
    image_alias = hashlib.sha256(image_ref.encode("utf-8")).hexdigest()[:16]
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "container-image", "digest": {"sha256": match.group(1)}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://optimizr.tech/actions/container-sbom/v1",
                "externalParameters": {
                    "repository": repository,
                    "head_sha": head_sha,
                    "image_alias": image_alias,
                },
                "internalParameters": {"workflow_ref": workflow_ref},
                "resolvedDependencies": [
                    {"uri": f"git+https://github.com/{repository}@{head_sha}", "digest": {"gitCommit": head_sha}}
                ],
            },
            "runDetails": {
                "builder": {"id": workflow_ref},
                "metadata": {
                    "invocationId": f"{repository}:{head_sha}:{image_alias}",
                    "startedOn": generated_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                },
            },
            "materials": materials,
            "tool": {"trivy": tool_version},
        },
    }


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid JSON evidence {path}: {exc}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    resolve = sub.add_parser("resolve")
    resolve.add_argument("--inspect", required=True)
    resolve_local = sub.add_parser("resolve-local")
    resolve_local.add_argument("--inspect", required=True)
    write = sub.add_parser("write")
    write.add_argument("--repository", required=True)
    write.add_argument("--head-sha", required=True)
    write.add_argument("--image-ref", required=True)
    write.add_argument("--image-identity", required=True)
    write.add_argument("--workflow-ref", required=True)
    write.add_argument("--cyclonedx", required=True)
    write.add_argument("--spdx", required=True)
    write.add_argument("--tool-version", required=True)
    write.add_argument("--output", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "resolve":
            print(resolve_image_identity(_read_json(Path(args.inspect))))
            return 0
        if args.command == "resolve-local":
            print(resolve_local_image_id(_read_json(Path(args.inspect))))
            return 0
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        payload = build_provenance(
            repository=args.repository,
            head_sha=args.head_sha,
            image_ref=args.image_ref,
            image_identity=args.image_identity,
            workflow_ref=args.workflow_ref,
            artifacts={"cyclonedx": Path(args.cyclonedx), "spdx": Path(args.spdx)},
            tool_version=args.tool_version,
        )
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except (EvidenceError, OSError) as exc:
        print(f"supply-chain evidence error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
