from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    (ROOT / path).write_text(content, encoding="utf-8")


def replace_once(content: str, old: str, new: str, label: str) -> str:
    count = content.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    return content.replace(old, new, 1)


def patch_evaluator() -> None:
    path = "scripts/security_gate/remediation_window.py"
    content = read(path)
    content = replace_once(
        content,
        'from typing import Any, Iterable, Mapping, Sequence\n',
        'from typing import Any, Iterable, Mapping, Sequence\n\n'
        'import importlib.util\n\n'
        '_LIFECYCLE_PATH = Path(__file__).with_name("remediation_lifecycle.py")\n'
        '_LIFECYCLE_SPEC = importlib.util.spec_from_file_location(\n'
        '    "security_gate_remediation_lifecycle", _LIFECYCLE_PATH\n'
        ')\n'
        'if _LIFECYCLE_SPEC is None or _LIFECYCLE_SPEC.loader is None:\n'
        '    raise RuntimeError("cannot load remediation lifecycle module")\n'
        '_LIFECYCLE_MODULE = importlib.util.module_from_spec(_LIFECYCLE_SPEC)\n'
        '_LIFECYCLE_SPEC.loader.exec_module(_LIFECYCLE_MODULE)\n'
        'RemediationLifecycleError = _LIFECYCLE_MODULE.RemediationLifecycleError\n'
        'normalize_lifecycle = _LIFECYCLE_MODULE.normalize_lifecycle\n',
        "import lifecycle helper",
    )
    content = replace_once(
        content,
        '_EVALUATOR_VERSION = "2"',
        '_EVALUATOR_VERSION = "3"',
        "bump evaluator version",
    )

    start = content.index("def _validate_history(")
    end = content.index("\n\ndef load_policy", start)
    content = content[:start] + content[end + 2 :]

    content = replace_once(
        content,
        '''        status = _required_text(raw, "status", label=label)\n        if status != "active":\n            raise RemediationWindowError("policy entries must be active to authorize a window")\n\n        entries.append(\n''',
        '''        try:\n            lifecycle = normalize_lifecycle(\n                raw,\n                first_seen=first_seen,\n                original_deadline=deadline,\n                reference=reference,\n            )\n        except RemediationLifecycleError as exc:\n            raise RemediationWindowError(str(exc)) from exc\n        status = lifecycle["status"]\n\n        entries.append(\n''',
        "normalize policy lifecycle",
    )
    content = replace_once(
        content,
        '''                "first_seen_at": _format_utc(first_seen),\n                "deadline_at": _format_utc(deadline),\n''',
        '''                "first_seen_at": _format_utc(first_seen),\n                "original_deadline_at": lifecycle["original_deadline_at"],\n                "deadline_at": lifecycle["effective_deadline_at"],\n''',
        "persist original and effective deadlines",
    )
    content = replace_once(
        content,
        '''                "status": status,\n                "history": _validate_history(raw, first_seen=first_seen),\n''',
        '''                "status": status,\n                "history": lifecycle["history"],\n                "revision_count": lifecycle["revision_count"],\n''',
        "persist normalized lifecycle",
    )
    content = replace_once(
        content,
        '''        "policy_entry_id": entry["id"] if entry else "",\n        "deadline_at": entry["deadline_at"] if entry else "",\n''',
        '''        "policy_entry_id": entry["id"] if entry else "",\n        "policy_entry_status": entry["status"] if entry else "",\n        "first_seen_at": entry["first_seen_at"] if entry else "",\n        "original_deadline_at": entry["original_deadline_at"] if entry else "",\n        "deadline_at": entry["deadline_at"] if entry else "",\n        "revision_count": entry["revision_count"] if entry else 0,\n''',
        "extend finding evidence",
    )
    content = replace_once(
        content,
        '''    entry = entries_by_fingerprint.get(_fingerprint_key(observation))\n    if entry is None:\n        return _finding_result(observation, state="unmatched", failure_reason="policy_entry_not_found")\n\n    first_seen =''',
        '''    entry = entries_by_fingerprint.get(_fingerprint_key(observation))\n    if entry is None:\n        return _finding_result(observation, state="unmatched", failure_reason="policy_entry_not_found")\n    if entry["status"] != "active":\n        return _finding_result(\n            observation,\n            state="reintroduced",\n            failure_reason="finding_reintroduced",\n            entry=entry,\n        )\n\n    first_seen =''',
        "block observed non-active lifecycle",
    )
    content = replace_once(
        content,
        '''        "unmatched_count": 0,\n        "due_soon_count": 0,\n''',
        '''        "unmatched_count": 0,\n        "reintroduced_count": 0,\n        "due_soon_count": 0,\n''',
        "initialize reintroduced count",
    )
    content = replace_once(
        content,
        '''                    "policy_entry_id": "",\n                    "deadline_at": "",\n''',
        '''                    "policy_entry_id": "",\n                    "policy_entry_status": "",\n                    "first_seen_at": "",\n                    "original_deadline_at": "",\n                    "deadline_at": "",\n                    "revision_count": 0,\n''',
        "normalize rejected evidence",
    )
    content = replace_once(
        content,
        '''    result["unmatched_count"] = sum(item["state"] == "unmatched" for item in findings)\n    result["due_soon_count"] =''',
        '''    result["unmatched_count"] = sum(item["state"] == "unmatched" for item in findings)\n    result["reintroduced_count"] = sum(\n        item["state"] == "reintroduced" for item in findings\n    )\n    result["due_soon_count"] =''',
        "aggregate reintroduced count",
    )
    content = replace_once(
        content,
        '''    result["decision"] = "blocked"\n    if result["overdue_count"]:\n''',
        '''    result["decision"] = "blocked"\n    if result["reintroduced_count"]:\n        result["remediation_state"] = "reintroduced"\n        result["failure_reason"] = "finding_reintroduced"\n    elif result["overdue_count"]:\n''',
        "prioritize reintroduced failure",
    )
    content = replace_once(
        content,
        '''        "remediation_window_unmatched_count": str(result.get("unmatched_count", 0)),\n        "remediation_window_due_soon_count":''',
        '''        "remediation_window_unmatched_count": str(result.get("unmatched_count", 0)),\n        "remediation_window_reintroduced_count": str(\n            result.get("reintroduced_count", 0)\n        ),\n        "remediation_window_due_soon_count":''',
        "publish reintroduced output",
    )
    write(path, content)


def patch_action() -> None:
    path = ".github/actions/security-gate/action.yml"
    content = read(path)
    content = replace_once(
        content,
        '''  remediation_window_unmatched_count:\n    description: "Findings without exact policy entries"\n    value: ${{ steps.scan.outputs.remediation_window_unmatched_count }}\n  remediation_window_due_soon_count:\n''',
        '''  remediation_window_unmatched_count:\n    description: "Findings without exact policy entries"\n    value: ${{ steps.scan.outputs.remediation_window_unmatched_count }}\n  remediation_window_reintroduced_count:\n    description: "Observed findings whose reviewed lifecycle is resolved or reintroduced"\n    value: ${{ steps.scan.outputs.remediation_window_reintroduced_count }}\n  remediation_window_due_soon_count:\n''',
        "add action reintroduced output",
    )
    content = replace_once(
        content,
        '''          echo "remediation_window_unmatched_count=0"\n          echo "remediation_window_due_soon_count=0"\n''',
        '''          echo "remediation_window_unmatched_count=0"\n          echo "remediation_window_reintroduced_count=0"\n          echo "remediation_window_due_soon_count=0"\n''',
        "initialize action reintroduced output",
    )
    write(path, content)


def patch_contract() -> None:
    path = "tests/test_security_gate_contract.py"
    content = read(path)
    content = replace_once(
        content,
        '''        self.assertIn("remediation_state:", content)\n        self.assertIn("nearest_deadline:", content)\n''',
        '''        self.assertIn("remediation_state:", content)\n        self.assertIn("remediation_window_reintroduced_count:", content)\n        self.assertIn("nearest_deadline:", content)\n''',
        "extend public output contract",
    )
    write(path, content)


def main() -> None:
    patch_evaluator()
    patch_action()
    patch_contract()


if __name__ == "__main__":
    main()
