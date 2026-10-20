"""Classify GitHub Actions failures without treating infrastructure as code evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


_BILLING_MARKERS = (
    "recent account payments have failed",
    "spending limit needs to be increased",
    "billing & plans",
)


def _inconclusive(reason: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "classification": "inconclusive",
        "is_code_failure": False,
        "promotion_allowed": False,
        "reason": reason,
        "evidence": evidence or {},
    }


def _collection(value: Any, key: str) -> list[Any] | None:
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and isinstance(value.get(key), list):
        return value[key]
    return None


def _messages(annotations: list[Any]) -> list[str]:
    messages: list[str] = []
    for annotation in annotations:
        if not isinstance(annotation, dict):
            continue
        for key in ("message", "title", "raw_details"):
            value = annotation.get(key)
            if isinstance(value, str):
                messages.append(value.casefold())
    return messages


def _is_billing_message(message: str) -> bool:
    return any(marker in message for marker in _BILLING_MARKERS)


def _summary(run: dict[str, Any], jobs: list[Any], annotations: list[Any]) -> dict[str, Any]:
    return {
        "run_id": run.get("id"),
        "run_conclusion": run.get("conclusion"),
        "job_count": len(jobs),
        "prestart_jobs": 0,
        "started_jobs": 0,
        "unknown_jobs": 0,
        "billing_annotations": sum(
            _is_billing_message(message) for message in _messages(annotations)
        ),
    }


def _job_lifecycle(job: Any) -> str:
    if not isinstance(job, dict):
        return "unknown"
    runner_id = job.get("runner_id")
    steps = job.get("steps")
    if isinstance(runner_id, bool) or not isinstance(runner_id, int):
        return "unknown"
    if not isinstance(steps, list):
        return "unknown"
    if runner_id == 0 or not steps:
        return "prestart"
    if runner_id < 0:
        return "unknown"
    return "started"


def _job_failed(job: dict[str, Any]) -> bool:
    if str(job.get("conclusion") or "").casefold() in {
        "failure",
        "cancelled",
        "timed_out",
        "action_required",
    }:
        return True
    steps = job.get("steps")
    return isinstance(steps, list) and any(
        isinstance(step, dict)
        and str(step.get("conclusion") or "").casefold()
        in {"failure", "cancelled", "timed_out", "action_required"}
        for step in steps
    )


def classify_evidence(payload: Any) -> dict[str, Any]:
    """Return a conservative, secret-free classification for saved API evidence.

    A job is considered pre-start only when GitHub reports both ``runner_id=0``
    and an empty steps array. Billing is classified as external only when every
    observed job is pre-start and an official annotation contains a known
    billing message. Missing or conflicting fields remain inconclusive.
    """

    if not isinstance(payload, dict):
        return _inconclusive("evidence root must be a JSON object")

    run = payload.get("run")
    jobs = _collection(payload.get("jobs"), "jobs")
    annotations = _collection(payload.get("annotations", []), "annotations")
    if not isinstance(run, dict):
        return _inconclusive("run evidence is missing")
    if jobs is None or not jobs:
        return _inconclusive("job evidence is missing")
    if annotations is None:
        return _inconclusive("annotation evidence is not a list")

    summary = _summary(run, jobs, annotations)
    for job in jobs:
        lifecycle = _job_lifecycle(job)
        if lifecycle == "unknown":
            summary["unknown_jobs"] += 1
        elif lifecycle == "prestart":
            summary["prestart_jobs"] += 1
        else:
            summary["started_jobs"] += 1

    if summary["unknown_jobs"]:
        return _inconclusive("job evidence is incomplete", summary)

    billing = summary["billing_annotations"] > 0
    all_prestart = summary["prestart_jobs"] == summary["job_count"]
    any_started = summary["started_jobs"] > 0
    if billing and all_prestart:
        return {
            "classification": "hosted_billing_blocked",
            "is_code_failure": False,
            "promotion_allowed": False,
            "reason": "official billing annotation with no runner-started job steps",
            "evidence": summary,
        }
    if billing and any_started:
        return _inconclusive("billing annotation conflicts with a started job", summary)

    conclusion = str(run.get("conclusion") or "").casefold()
    if all_prestart:
        return {
            "classification": "runner_unavailable",
            "is_code_failure": False,
            "promotion_allowed": False,
            "reason": "jobs ended before runner acquisition and no billing marker was present",
            "evidence": summary,
        }
    if summary["prestart_jobs"] and any_started:
        return _inconclusive("job evidence mixes started and pre-start jobs", summary)
    if any_started and any(_job_failed(job) for job in jobs if isinstance(job, dict)):
        return {
            "classification": "code_or_gate_failure",
            "is_code_failure": True,
            "promotion_allowed": False,
            "reason": "at least one started job or step failed after runner acquisition",
            "evidence": summary,
        }
    if any_started and conclusion == "success":
        if all(
            isinstance(job, dict)
            and str(job.get("conclusion") or "").casefold() == "success"
            and str(job.get("status") or "completed").casefold() == "completed"
            for job in jobs
        ):
            return {
                "classification": "passed",
                "is_code_failure": False,
                "promotion_allowed": True,
                "reason": "all observed jobs started and completed successfully",
                "evidence": summary,
            }
    return _inconclusive("run conclusion and job lifecycle do not establish a cause", summary)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_payload(args: argparse.Namespace) -> Any:
    if args.evidence:
        return _read_json(args.evidence)
    if not all((args.run, args.jobs, args.annotations)):
        raise ValueError("provide --evidence or all of --run, --jobs and --annotations")
    return {
        "run": _read_json(args.run),
        "jobs": _read_json(args.jobs),
        "annotations": _read_json(args.annotations),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, help="combined run/jobs/annotations JSON")
    parser.add_argument("--run", type=Path, help="saved Actions run JSON")
    parser.add_argument("--jobs", type=Path, help="saved Actions jobs JSON")
    parser.add_argument("--annotations", type=Path, help="saved check annotations JSON")
    args = parser.parse_args(argv)
    try:
        result = classify_evidence(_load_payload(args))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["promotion_allowed"] else 1


if __name__ == "__main__":
    sys.exit(main())
