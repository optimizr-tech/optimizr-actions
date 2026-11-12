"""setup-uv must receive an exact uv version unless the consumer declares one.

Without ``version``, setup-uv resolves "latest" by downloading a manifest on
every job; a network timeout there failed optimizr-payment's dependency policy
on 2026-11-11. An exact version hits the self-hosted runner tool cache.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    ".github/actions/dependency-policy/action.yml",
    ".github/actions/python-uv-test-steps/action.yml",
    ".github/actions/sast-gate/action.yml",
    ".github/actions/static-lint/action.yml",
    ".github/workflows/_python-uv-test.yml",
    ".github/workflows/_quality-gate-collect-security.yml",
]
DEFAULT_UV_VERSION = "0.13.7"


def _steps(path: Path) -> list[list[dict]]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        return []
    if "runs" in doc:
        return [doc["runs"]["steps"]]
    return [job.get("steps", []) for job in (doc.get("jobs") or {}).values()]


def _resolver_script() -> str:
    for steps in _steps(ROOT / FILES[0]):
        for step in steps:
            if step.get("id") == "uv-version":
                return step["run"]
    raise AssertionError("resolver step missing")


class SecurityCollectorNoCacheContract(unittest.TestCase):
    def test_security_collector_does_not_enable_uv_or_pnpm_cache(self) -> None:
        path = ROOT / ".github/workflows/_quality-gate-collect-security.yml"
        for steps in _steps(path):
            for step in steps:
                uses = str(step.get("uses", ""))
                with_ = step.get("with") or {}
                if uses.startswith("astral-sh/setup-uv@"):
                    self.assertEqual(str(with_.get("enable-cache")).lower(), "false")
                if uses.startswith(("actions/setup-node@", "actions/cache@")):
                    self.assertNotIn("cache", with_)
                self.assertNotEqual(step.get("name"), "Initialize pnpm cache")


class UvVersionPinContract(unittest.TestCase):
    def test_every_setup_uv_receives_resolved_version(self) -> None:
        seen = 0
        for rel in FILES:
            for steps in _steps(ROOT / rel):
                ids = [s.get("id") for s in steps]
                for index, step in enumerate(steps):
                    if not str(step.get("uses", "")).startswith("astral-sh/setup-uv@"):
                        continue
                    seen += 1
                    with self.subTest(file=rel):
                        self.assertEqual(
                            step["with"]["version"], "${{ steps.uv-version.outputs.version }}"
                        )
                        self.assertIn("uv-version", ids[:index])
                        resolver = steps[ids.index("uv-version")]
                        self.assertEqual(resolver["env"]["DEFAULT_UV_VERSION"], DEFAULT_UV_VERSION)
                        self.assertEqual(resolver.get("if"), step.get("if"))
        self.assertEqual(seen, len(FILES))

    def test_no_setup_uv_left_without_version_in_repository(self) -> None:
        for path in sorted((ROOT / ".github").rglob("*.yml")):
            rel = path.relative_to(ROOT).as_posix()
            if rel in FILES:
                continue
            for steps in _steps(path):
                for step in steps:
                    if str(step.get("uses", "")).startswith("astral-sh/setup-uv@"):
                        with self.subTest(path=rel):
                            self.assertEqual(step["with"]["version"], DEFAULT_UV_VERSION)

    def _resolve(self, files: dict[str, str]) -> str:
        script = _resolver_script()
        with tempfile.TemporaryDirectory() as tmp:
            for name, body in files.items():
                Path(tmp, name).write_text(body, encoding="utf-8")
            out = Path(tmp, "out")
            env = {**os.environ, "GITHUB_WORKSPACE": tmp, "GITHUB_OUTPUT": str(out),
                   "DEFAULT_UV_VERSION": DEFAULT_UV_VERSION}
            subprocess.run(["bash", "-c", script], check=True, env=env)
            match = re.search(r"^version=(.*)$", out.read_text(encoding="utf-8"), re.M)
            assert match
            return match.group(1)

    def test_default_when_consumer_declares_nothing(self) -> None:
        self.assertEqual(self._resolve({"pyproject.toml": "[project]\nname='x'\n"}), DEFAULT_UV_VERSION)
        self.assertEqual(self._resolve({}), DEFAULT_UV_VERSION)

    def test_consumer_pyproject_required_version_wins(self) -> None:
        body = "[project]\nname='x'\n\n[tool.uv]\nrequired-version = '==0.12.0'\n"
        self.assertEqual(self._resolve({"pyproject.toml": body}), "")

    def test_required_version_outside_tool_uv_is_ignored(self) -> None:
        body = "[tool.other]\nrequired-version = '1'\n"
        self.assertEqual(self._resolve({"pyproject.toml": body}), DEFAULT_UV_VERSION)

    def test_consumer_uv_toml_required_version_wins(self) -> None:
        self.assertEqual(self._resolve({"uv.toml": "required-version = '>=0.13'\n"}), "")


if __name__ == "__main__":
    unittest.main()
