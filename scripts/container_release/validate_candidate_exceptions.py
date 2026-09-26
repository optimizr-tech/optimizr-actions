"""Validate narrow exception scopes before promoting one quarantined image."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


_IMAGE_REF = re.compile(r"^ghcr\.io(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}$")
_REQUIRED_FIELDS = {"id", "owner", "statement", "compensating_control", "expires"}
_ALLOWED_FIELDS = _REQUIRED_FIELDS | {
    "scan_types",
    "targets",
    "purls",
    "paths",
    "lineage_digests",
}


class CandidateExceptionError(ValueError):
    """Raised when a candidate exception is broader than its immutable target."""


def validate_policy(payload: Any, *, candidate_image: str) -> dict[str, int]:
    """Require every exception to match one image digest and explicit package URLs."""
    if not _IMAGE_REF.fullmatch(candidate_image):
        raise CandidateExceptionError("candidate image must be a full GHCR digest reference")
    if (
        not isinstance(payload, dict)
        or isinstance(payload.get("version"), bool)
        or payload.get("version") != 1
    ):
        raise CandidateExceptionError("exception policy version must be 1")
    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list) or not entries or len(entries) > 25:
        raise CandidateExceptionError("candidate policy must contain between 1 and 25 exceptions")

    seen_ids: set[str] = set()
    for index, entry in enumerate(entries):
        label = f"vulnerabilities[{index}]"
        if not isinstance(entry, dict):
            raise CandidateExceptionError(f"{label} must be an object")
        unknown = set(entry) - _ALLOWED_FIELDS
        if unknown:
            raise CandidateExceptionError(f"{label} contains unsupported fields")
        missing = _REQUIRED_FIELDS - set(entry)
        if missing:
            raise CandidateExceptionError(f"{label} is missing required exception metadata")
        identifier = entry["id"]
        if (
            not isinstance(identifier, str)
            or not identifier.strip()
            or identifier != identifier.strip()
            or "*" in identifier
        ):
            raise CandidateExceptionError(f"{label}.id must be an exact advisory identifier")
        identifier_key = identifier.upper()
        if identifier_key in seen_ids:
            raise CandidateExceptionError(f"duplicate exception identifier: {identifier}")
        seen_ids.add(identifier_key)

        scan_types = entry.get("scan_types", ["image"])
        if scan_types != ["image"]:
            raise CandidateExceptionError(f"{label} must be image-only")
        targets = entry.get("targets")
        if targets != [candidate_image]:
            raise CandidateExceptionError(f"{label} must target the exact candidate digest")
        if entry.get("lineage_digests"):
            raise CandidateExceptionError(f"{label} must target the exact candidate digest directly")
        purls = entry.get("purls")
        if (
            not isinstance(purls, list)
            or not purls
            or any(not isinstance(purl, str) or not purl.strip() or "*" in purl for purl in purls)
        ):
            raise CandidateExceptionError(f"{label} must contain at least one exact PURL")
        if len(set(purls)) != len(purls):
            raise CandidateExceptionError(f"{label} contains duplicate PURLs")

    return {"exception_count": len(entries)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--candidate-image", required=True)
    args = parser.parse_args(argv)
    try:
        payload = json.loads(args.policy.read_text(encoding="utf-8"))
        result = validate_policy(payload, candidate_image=args.candidate_image)
    except (OSError, json.JSONDecodeError, CandidateExceptionError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
