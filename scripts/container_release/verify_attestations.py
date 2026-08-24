"""Validate the attestation manifests retained beside an OCI image index."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


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
) -> dict[str, int]:
    """Verify the index and the two required predicates for one exact digest."""
    counts = verify_attestation_index(index_payload, required_count=required_count)

    if not isinstance(sbom_payload, dict) or not sbom_payload:
        raise AttestationError("SBOM evidence is missing or invalid")
    if not isinstance(sbom_payload.get("spdxVersion"), str):
        raise AttestationError("SBOM evidence is missing SPDX metadata")

    if not isinstance(provenance_payload, dict) or not provenance_payload:
        raise AttestationError("provenance evidence is missing or invalid")
    if not (
        isinstance(provenance_payload.get("buildType"), str)
        or isinstance(provenance_payload.get("buildDefinition"), dict)
    ):
        raise AttestationError("provenance evidence is missing SLSA metadata")

    return {**counts, "sbom": 1, "provenance": 1}


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
    return parser


def main() -> int:
    args = _parser().parse_args()
    counts = verify_attestation_bundle(
        _read_json(args.input, label="image index"),
        _read_json(args.sbom_input, label="SBOM"),
        _read_json(args.provenance_input, label="provenance"),
        required_count=args.required_count,
    )
    print(json.dumps(counts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
