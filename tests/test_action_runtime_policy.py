"""Node runtime policy for pinned third-party actions.

GitHub removes the Node 20 action runtime from hosted runners on
2026-09-23. Every pinned third-party action in this repository must run on
Node 24, and the Node 20 pins audited on 2026-09-18 must never return.

The guard is offline: it cannot query upstream ``action.yml`` files, so it
keeps an explicit denylist of known Node 20 pins plus the approved Node 24
pins for the runtime-sensitive actions. A new or bumped pin must be verified
against upstream and recorded here before the suite goes green.
"""

from __future__ import annotations

import re
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]

SCAN_ROOTS = (".github", "templates", "presets", "catalog", "scripts")
SCAN_SUFFIXES = {".yml", ".yaml", ".json", ".py", ".sh"}
SKIP_PARTS = {".git", ".worktrees", "__pycache__", "node_modules", ".venv"}

PIN_PATTERN = re.compile(r"^[0-9a-f]{40}$")

NODE20_DEPRECATED_PINS = {
    "dependabot/fetch-metadata": "d7267f607e9d3fb96fc2fbe83e0af444713e90b7",
    "docker/setup-buildx-action": "8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
    "docker/login-action": "c94ce9fb468520275223c153574b00df6fe4bcc9",
    "docker/build-push-action": "10e90e3645eae34f1e60eeb005ba3a3d33f178e8",
}

NODE24_APPROVED_PINS = {
    "dependabot/fetch-metadata": "25dd0e34f4fe68f24cc83900b1fe3fe149efef98",
    "docker/setup-buildx-action": "f87e5991a6d7451dcb8d9637bfbc97413f497069",
    "docker/login-action": "dbcb813823bdd20940b903addbd779551569679f",
    "docker/build-push-action": "c3c9e263c25d99ce0380d002d59b67737d91b0dc",
}

LOCAL_ACTION_RUNTIMES = {"composite", "node24", "docker"}
USES_PATTERN = re.compile(r"^\s*-?\s*uses:\s*(?P<action>[^\s@#]+)@(?P<ref>[^\s#]+)")
USING_PATTERN = re.compile(r"^\s*using:\s*(?P<runtime>[A-Za-z0-9_-]+)")


def scanned_files() -> list[Path]:
    files: list[Path] = []
    for root_name in SCAN_ROOTS:
        root = ROOT / root_name
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in SCAN_SUFFIXES:
                continue
            if SKIP_PARTS & set(path.relative_to(ROOT).parts):
                continue
            files.append(path)
    return files


class ActionRuntimePolicyTests(unittest.TestCase):
    def test_deprecated_node20_pins_are_never_referenced(self) -> None:
        offenders: list[str] = []
        for path in scanned_files():
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                for action, sha in NODE20_DEPRECATED_PINS.items():
                    if sha in line:
                        offenders.append(
                            f"{path.relative_to(ROOT).as_posix()}:{number} "
                            f"references deprecated Node 20 pin {action}@{sha}"
                        )
        self.assertEqual([], offenders)

    def test_runtime_sensitive_actions_use_approved_node24_pins(self) -> None:
        pins: dict[str, list[tuple[str, str]]] = {
            action: [] for action in NODE24_APPROVED_PINS
        }
        for path in scanned_files():
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                match = USES_PATTERN.match(line)
                if not match:
                    continue
                action = match.group("action")
                if action in pins:
                    pins[action].append(
                        (f"{path.relative_to(ROOT).as_posix()}:{number}", match.group("ref"))
                    )

        for action, approved in NODE24_APPROVED_PINS.items():
            with self.subTest(action=action):
                self.assertTrue(pins[action], f"{action} is no longer pinned anywhere")
                for location, ref in pins[action]:
                    self.assertRegex(
                        ref,
                        PIN_PATTERN,
                        f"{location}: {action} must stay pinned to an immutable commit SHA",
                    )
                    self.assertEqual(
                        approved,
                        ref,
                        f"{location}: {action} must use the verified Node 24 release "
                        f"{approved}; verify the runtime upstream before updating this "
                        f"contract",
                    )

    def test_local_composite_actions_do_not_declare_node20(self) -> None:
        actions_dir = ROOT / ".github" / "actions"
        offenders: list[str] = []
        checked = 0
        for metadata in sorted(actions_dir.glob("*/action.y*ml")):
            checked += 1
            for number, line in enumerate(
                metadata.read_text(encoding="utf-8").splitlines(), start=1
            ):
                match = USING_PATTERN.match(line)
                if not match:
                    continue
                runtime = match.group("runtime")
                if runtime not in LOCAL_ACTION_RUNTIMES:
                    offenders.append(
                        f"{metadata.relative_to(ROOT).as_posix()}:{number} "
                        f"declares unsupported runtime {runtime}"
                    )
        self.assertGreater(checked, 0, "no local composite actions discovered")
        self.assertEqual([], offenders)

    def test_unsecure_node_opt_out_is_not_committed(self) -> None:
        offenders: list[str] = []
        for path in scanned_files():
            text = path.read_text(encoding="utf-8")
            if "ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION" in text:
                offenders.append(path.relative_to(ROOT).as_posix())
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
