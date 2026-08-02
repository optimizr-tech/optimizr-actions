"""Authorize release/deploy from one canonical exact-SHA validation attestation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
GATE_JOB_RESULTS = {"success", "failure", "cancelled", "skipped"}
GATE_RESULTS = {"passed", "failed"}


class AuthorizationError(Exception):
    """A well-formed validation result is not eligible for delivery."""


def parse_allowed_paths(text: str) -> list[str]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("allowed paths must be valid JSON") from exc
    if not isinstance(value, list) or not value:
        raise ValueError("allowed paths must be a non-empty string array")
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError("allowed paths must be a non-empty string array")
    if len(set(value)) != len(value):
        raise ValueError("allowed paths must be unique")
    return value


def require_sha(value: str, label: str) -> None:
    if SHA.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase 40-character Git SHA")


def authorize(args: argparse.Namespace) -> dict[str, str]:
    if args.gate_job_result not in GATE_JOB_RESULTS:
        raise ValueError("gate job result is not allowed")
    if args.gate_result not in GATE_RESULTS:
        raise ValueError("gate result is not allowed")

    require_sha(args.validated_sha, "validated SHA")
    require_sha(args.candidate_sha, "candidate SHA")
    require_sha(args.actions_workflow_sha, "Actions workflow SHA")

    if DIGEST.fullmatch(args.evidence_digest) is None:
        raise ValueError(
            "evidence digest must use sha256:<64 lowercase hex>"
        )
    if not args.candidate_ref or not args.required_ref:
        raise ValueError("candidate ref and required ref must be non-empty")

    allowed_paths = parse_allowed_paths(args.allowed_paths_json)

    if args.gate_job_result != "success":
        raise AuthorizationError("gate job must succeed")
    if args.gate_result != "passed":
        raise AuthorizationError("gate result must be passed")
    if args.validated_sha != args.candidate_sha:
        raise AuthorizationError("validated SHA must equal candidate SHA")
    if args.validation_path not in allowed_paths:
        raise AuthorizationError("validation path is not allowed")
    if args.candidate_ref != args.required_ref:
        raise AuthorizationError("candidate ref must equal required ref")

    return {
        "result": "authorized",
        "validated_sha": args.validated_sha,
        "evidence_digest": args.evidence_digest,
        "actions_workflow_sha": args.actions_workflow_sha,
        "validation_path": args.validation_path,
    }


def write_outputs(path: str, outputs: dict[str, str]) -> None:
    if not path:
        return
    output_path = Path(path)
    with output_path.open("a", encoding="utf-8") as stream:
        for name in (
            "result",
            "validated_sha",
            "evidence_digest",
            "actions_workflow_sha",
            "validation_path",
        ):
            stream.write(f"{name}={outputs[name]}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gate-job-result", required=True)
    parser.add_argument("--gate-result", required=True)
    parser.add_argument("--validated-sha", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--evidence-digest", required=True)
    parser.add_argument("--actions-workflow-sha", required=True)
    parser.add_argument("--validation-path", required=True)
    parser.add_argument("--candidate-ref", required=True)
    parser.add_argument("--required-ref", required=True)
    parser.add_argument("--allowed-paths-json", required=True)
    parser.add_argument("--github-output", default="")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    outputs = authorize(args)
    write_outputs(args.github_output, outputs)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AuthorizationError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
