"""Actions cache must not duplicate persistent self-hosted tool caches.

On 2026-11-12 setup-uv spent 12.5 min compressing the persistent
UV_CACHE_DIR before upload, and setup-node restored a 346 MB npm cache into
the persistent ~/.npm. See docs/SELF_HOSTED_RESOURCE_POLICY.md.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
HOSTED_ONLY = "${{ runner.environment == 'github-hosted' }}"
HOSTED_NPM = "${{ runner.environment == 'github-hosted' && 'npm' || '' }}"


def _steps(path: Path):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if "runs" in data:
        yield from data["runs"].get("steps") or []
    for job in (data.get("jobs") or {}).values():
        yield from job.get("steps") or []


def _files():
    for pattern in (".github/workflows/*.yml", ".github/actions/*/action.yml"):
        yield from sorted(ROOT.glob(pattern))


class SelfHostedCacheContractTests(unittest.TestCase):
    def test_setup_uv_never_forces_cache(self) -> None:
        seen = 0
        for path in _files():
            for step in _steps(path):
                if not str(step.get("uses", "")).startswith("astral-sh/setup-uv@"):
                    continue
                seen += 1
                value = str((step.get("with") or {}).get("enable-cache", "auto")).lower()
                with self.subTest(file=path.name, step=step.get("name")):
                    self.assertIn(value, {"auto", "false"})
        self.assertGreater(seen, 0)

    def test_setup_node_npm_cache_is_github_hosted_only(self) -> None:
        seen = 0
        for path in _files():
            for step in _steps(path):
                if not str(step.get("uses", "")).startswith("actions/setup-node@"):
                    continue
                with_ = step.get("with") or {}
                if with_.get("cache") == "pnpm":
                    continue  # job-local pnpm store; cache still saves downloads
                seen += 1
                with self.subTest(file=path.name, step=step.get("name")):
                    self.assertEqual(with_.get("package-manager-cache"), HOSTED_ONLY)
                    if "cache" in with_:
                        self.assertEqual(with_["cache"], HOSTED_NPM)
        self.assertGreater(seen, 0)


if __name__ == "__main__":
    unittest.main()
