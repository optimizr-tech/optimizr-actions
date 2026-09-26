"""Validate the attestation manifests retained beside an OCI image index."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class AttestationError(ValueError):
    """Raised when an image index does not retain required attestations."""


def verify_attestation_index(payload: Any, *, required_count: int = 1) -> dict[str, int]:
    """Return sanitized counts for a BuildKit image index.

    BuildKit stores one or more attestation manifests beside the runnable
    platform manifest. A single attestation manifest can contain multiple
    attestation blobs, so the presence of two descriptors is not required.
    """
    if not isinstance(payload, dict):
        raise AttestationError("image metadata is not a JSON object")
    manifests = payload.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        raise AttestationError("image metadata is not an OCI index")

    platform_count = 0
    attestation_count = 0
    for manifest in manifests:
        if not isinstance(manifest, dict):
            raise AttestationError("image index contains an invalid manifest")
        annotations = manifest.get("annotations")
        annotations = annotations if isinstance(annotations, dict) else {}
        if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
            attestation_count += 1
            continue
        platform = manifest.get("platform")
        if isinstance(platform, dict) and platform.get("os") and platform.get("architecture"):
            platform_count += 1

    if platform_count == 0:
        raise AttestationError("image index has no runnable platform manifest")
    if attestation_count < required_count:
        raise AttestationError(
            f"image index retains {attestation_count} attestation manifest(s); "
            f"at least {required_count} required for SBOM and provenance"
        )
    return {
        "platform_manifests": platform_count,
        "attestation_manifests": attestation_count,
    }


def verify_attestation_bundle(
    index_payload: Any,
    sbom_payload: Any,
    provenance_payload: Any,
    *,
    required_count: int = 1,
    expected_source_repository: str = "",
    expected_source_sha: str = "",
) -> dict[str, int]:
    """Verify the index and the two required predicates for one exact digest."""
    counts = verify_attestation_index(index_payload, required_count=required_count)

    if not isinstance(sbom_payload, dict) or not sbom_payload:
        raise AttestationError("SBOM evidence is missing or invalid")
    if not isinstance(sbom_payload.get("spdxVersion"), str):
        raise AttestationError("SBOM evidence is missing SPDX metadata")

    if not isinstance(provenance_payload, dict) or not provenance_payload:
        raise AttestationError("provenance evidence is missing or invalid")
    predicate = provenance_payload.get("predicate")
    predicate = predicate if isinstance(predicate, dict) else provenance_payload
    if not (
        isinstance(predicate.get("buildType"), str)
        or isinstance(predicate.get("buildDefinition"), dict)
    ):
        raise AttestationError("provenance evidence is missing SLSA metadata")

    if bool(expected_source_repository) != bool(expected_source_sha):
        raise AttestationError("expected source repository and SHA must be provided together")
    if expected_source_repository:
        verify_provenance_source(
            provenance_payload,
            expected_repository=expected_source_repository,
            expected_sha=expected_source_sha,
        )

    return {**counts, "sbom": 1, "provenance": 1}


def _normalized_repository_uri(value: Any) -> tuple[str, str]:
    if not isinstance(value, str) or not value.strip():
        return "", ""
    uri = value.strip()
    if uri.startswith("git+"):
        uri = uri[4:]
    if "://" not in uri:
        return "", ""
    parsed = urlsplit(uri)
    if parsed.scheme.lower() != "https":
        return "", ""
    path = parsed.path.rstrip("/")
    revision = ""
    match = re.search(r"(?:@|#)([0-9a-fA-F]{40,64})$", path)
    if match:
        revision = match.group(1).lower()
        path = path[: match.start()]
    if not revision and parsed.fragment:
        match = re.fullmatch(r"([0-9a-fA-F]{40,64})", parsed.fragment)
        if match:
            revision = match.group(1).lower()
    if path.lower().endswith(".git"):
        path = path[:-4]
    repository = f"https://{parsed.netloc.lower()}{path.lower()}".rstrip("/")
    return repository, revision


def _source_digest_values(value: Any) -> set[str]:
    if not isinstance(value, dict):
        return set()
    return {
        item.lower()
        for item in value.values()
        if isinstance(item, str) and re.fullmatch(r"[0-9a-fA-F]{40,64}", item)
    }


def verify_provenance_source(
    provenance: dict[str, Any], *, expected_repository: str, expected_sha: str
) -> None:
    """Require an embedded BuildKit/SLSA source binding for one repo commit."""
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", expected_sha):
        raise AttestationError("expected source SHA must be a full hexadecimal commit")
    expected_repo, _ = _normalized_repository_uri(expected_repository)
    if not expected_repo:
        raise AttestationError("expected source repository is invalid")
    statement = provenance.get("predicate")
    statement = statement if isinstance(statement, dict) else provenance
    config_sources: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    definition = statement.get("buildDefinition")
    if isinstance(definition, dict):
        external = definition.get("externalParameters")
        if isinstance(external, dict) and isinstance(external.get("configSource"), dict):
            config_sources.append(external["configSource"])
        dependencies = definition.get("resolvedDependencies")
        if isinstance(dependencies, list):
            candidates.extend(item for item in dependencies if isinstance(item, dict))
    materials = statement.get("materials")
    if isinstance(materials, list):
        candidates.extend(item for item in materials if isinstance(item, dict))

    expected_sha = expected_sha.lower()

    def matches(candidate: dict[str, Any]) -> bool:
        repository, uri_revision = _normalized_repository_uri(candidate.get("uri"))
        if repository != expected_repo:
            return False
        digests = _source_digest_values(candidate.get("digest"))
        if uri_revision and uri_revision != expected_sha:
            return False
        return expected_sha in digests or uri_revision == expected_sha

    matching_config_sources = [
        source
        for source in config_sources
        if _normalized_repository_uri(source.get("uri"))[0] == expected_repo
    ]
    if matching_config_sources:
        if any(matches(source) for source in matching_config_sources):
            return
        raise AttestationError("provenance source does not match the expected repository and commit")
    for candidate in candidates:
        if matches(candidate):
            return
    raise AttestationError("provenance source does not match the expected repository and commit")


def _read_json(path: Path, *, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AttestationError(f"{label} evidence is not valid JSON") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--sbom-input", type=Path, required=True)
    parser.add_argument("--provenance-input", type=Path, required=True)
    parser.add_argument("--required-count", type=int, default=1)
    parser.add_argument("--expected-source-repository", default="")
    parser.add_argument("--expected-source-sha", default="")
    return parser


def main() -> int:
    args = _parser().parse_args()
    counts = verify_attestation_bundle(
        _read_json(args.input, label="image index"),
        _read_json(args.sbom_input, label="SBOM"),
        _read_json(args.provenance_input, label="provenance"),
        required_count=args.required_count,
        expected_source_repository=args.expected_source_repository,
        expected_source_sha=args.expected_source_sha,
    )
    print(json.dumps(counts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
