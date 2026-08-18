"""Validate the attestation manifests retained beside an OCI image index."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class AttestationError(ValueError):
    """Raised when an image index does not retain required attestations."""


def verify_attestation_index(payload: Any, *, required_count: int = 2) -> dict[str, int]:
    """Return sanitized counts for a BuildKit image index.

    BuildKit stores SBOM and provenance as attestation manifests beside the
    runnable platform manifest. The exact predicate contents are registry
    implementation details; requiring both manifests prevents a caller from
    silently publishing an image whose evidence was dropped during transport.
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--required-count", type=int, default=2)
    return parser


def main() -> int:
    args = _parser().parse_args()
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    counts = verify_attestation_index(payload, required_count=args.required_count)
    print(json.dumps(counts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
