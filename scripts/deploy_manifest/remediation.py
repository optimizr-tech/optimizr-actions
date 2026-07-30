"""Add bounded security-remediation state to an existing deploy manifest."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.security_gate.classifications import (  # noqa: E402
    SECURITY_CLASSIFICATION_INPUTS,
    normalize_security_classification,
)

_REBUILD_RESULTS = {"passed", "failed", "skipped", "no_change"}
_STATUSES = {"success", "failure"}
_REMEDIATION_WINDOW_STATES = {
    "not_applicable",
    "blocked",
    "pending_review",
    "active",
    "due_soon",
    "overdue",
    "resolved",
    "reintroduced",
}


class RemediationError(ValueError):
    """Raised when remediation evidence violates the bounded manifest contract."""


def _load_manifest(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise RemediationError("manifest must be a regular non-symlink file")
    if path.parent.name != ".deploy-manifests":
        raise RemediationError("manifest must remain in .deploy-manifests")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RemediationError("manifest must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
        raise RemediationError("manifest schema_version must be 1.0")
    return payload


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def decorate_manifest(
    *,
    manifest: Path,
    last_successful: Path,
    status: str,
    initial_result: str,
    rebuild_attempted: bool,
    rebuild_result: str,
    final_result: str,
    remediation_window_state: str = "not_applicable",
) -> None:
    """Persist only enum/boolean remediation state in deploy evidence."""
    if status not in _STATUSES:
        raise RemediationError("status must be success or failure")
    try:
        initial_result = normalize_security_classification(initial_result)
        final_result = normalize_security_classification(final_result)
    except ValueError as exc:
        raise RemediationError(str(exc)) from exc
    if rebuild_result not in _REBUILD_RESULTS:
        raise RemediationError("security rebuild result is not allowed")
    if not isinstance(rebuild_attempted, bool):
        raise RemediationError("security rebuild attempted must be boolean")
    if not rebuild_attempted and rebuild_result != "skipped":
        raise RemediationError("an unattempted rebuild must be skipped")
    if rebuild_attempted and rebuild_result == "skipped":
        raise RemediationError("an attempted rebuild cannot be skipped")
    if remediation_window_state not in _REMEDIATION_WINDOW_STATES:
        raise RemediationError("remediation window state is not allowed")

    payload = _load_manifest(manifest)
    payload.update(
        {
            "security_initial_result": initial_result,
            "security_rebuild_attempted": rebuild_attempted,
            "security_rebuild_result": rebuild_result,
            "security_final_result": final_result,
            "security_remediation_window_state": remediation_window_state,
        }
    )
    _atomic_write(manifest, payload)

    if status == "success":
        if last_successful.parent != manifest.parent or last_successful.name != "last-successful.json":
            raise RemediationError("last-successful path is inconsistent")
        if last_successful.is_symlink():
            raise RemediationError("last-successful must not be a symlink")
        _atomic_write(last_successful, payload)


def _boolean(raw: str) -> bool:
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise argparse.ArgumentTypeError("boolean value must be true or false")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--last-successful", type=Path, required=True)
    parser.add_argument("--status", choices=sorted(_STATUSES), required=True)
    parser.add_argument(
        "--initial-result", choices=sorted(SECURITY_CLASSIFICATION_INPUTS), required=True
    )
    parser.add_argument("--rebuild-attempted", type=_boolean, required=True)
    parser.add_argument("--rebuild-result", choices=sorted(_REBUILD_RESULTS), required=True)
    parser.add_argument(
        "--final-result", choices=sorted(SECURITY_CLASSIFICATION_INPUTS), required=True
    )
    parser.add_argument(
        "--remediation-window-state",
        choices=sorted(_REMEDIATION_WINDOW_STATES),
        default="not_applicable",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    decorate_manifest(
        manifest=args.manifest,
        last_successful=args.last_successful,
        status=args.status,
        initial_result=args.initial_result,
        rebuild_attempted=args.rebuild_attempted,
        rebuild_result=args.rebuild_result,
        final_result=args.final_result,
        remediation_window_state=args.remediation_window_state,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
