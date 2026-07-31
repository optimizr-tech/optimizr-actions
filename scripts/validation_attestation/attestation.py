"""Create a sanitized exact-SHA validation attestation."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SHA = re.compile(r"[0-9a-f]{40}\Z")
PATHS = {"hosted", "self-hosted", "reviewed-emergency"}
RESULTS = {"success", "failure", "cancelled", "skipped"}


def parse_json(text: str, expected: type, label: str):
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} must be valid JSON") from exc
    if not isinstance(value, expected):
        raise ValueError(f"{label} has an invalid type")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--context-sha", required=True)
    parser.add_argument("--validation-path", required=True)
    parser.add_argument("--required-checks-json", required=True)
    parser.add_argument("--results-json", required=True)
    parser.add_argument("--workflow-repository", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--github-output", default="")
    args = parser.parse_args()

    for value, label in (
        (args.candidate_sha, "candidate SHA"),
        (args.context_sha, "caller context SHA"),
        (args.workflow_sha, "workflow SHA"),
    ):
        if SHA.fullmatch(value) is None:
            raise ValueError(f"{label} must be a lowercase 40-character Git SHA")
    if args.candidate_sha != args.context_sha:
        raise ValueError("candidate SHA must equal caller context SHA")
    if args.validation_path not in PATHS:
        raise ValueError("validation path is not allowed")

    required = parse_json(args.required_checks_json, list, "required checks")
    results = parse_json(args.results_json, dict, "results")
    if not required or any(not isinstance(item, str) or not item for item in required):
        raise ValueError("required checks must be a non-empty string array")
    if len(set(required)) != len(required):
        raise ValueError("required checks must be unique")
    if set(results) != set(required):
        raise ValueError("results must contain exactly the required checks")
    if any(value not in RESULTS for value in results.values()):
        raise ValueError("result value is not allowed")

    blocking = sorted(name for name in required if results[name] != "success")
    payload = {
        "schema_version": 1,
        "repository": args.repository,
        "validated_sha": args.candidate_sha,
        "validation_path": args.validation_path,
        "required_checks": sorted(required),
        "check_results": {name: results[name] for name in sorted(results)},
        "blocking_checks": blocking,
        "result": "failed" if blocking else "passed",
        "actions_workflow_repository": args.workflow_repository,
        "actions_workflow_ref": args.workflow_ref,
        "actions_workflow_sha": args.workflow_sha,
        "run_id": args.run_id,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    payload["evidence_digest"] = digest
    evidence = Path(args.evidence)
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if args.github_output:
        with Path(args.github_output).open("a", encoding="utf-8") as output:
            output.write(f"result={payload['result']}\n")
            output.write(f"validated_sha={args.candidate_sha}\n")
            output.write(f"validation_path={args.validation_path}\n")
            output.write(f"evidence_digest={digest}\n")
            output.write(f"actions_workflow_sha={args.workflow_sha}\n")
            output.write(f"evidence_path={evidence.as_posix()}\n")
    if blocking:
        print(
            "required validation checks did not succeed: " + ", ".join(blocking),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
