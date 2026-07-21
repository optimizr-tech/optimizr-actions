"""Guard the portable-actions repository boundary during migration."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
LEGACY_INFRA_OPS_REFERENCES = Counter(
    {
        (
            ".github/workflows/_python-uv-test.yml",
            "optimizr-tech/optimizr-infra-ops/.github/actions/python-uv-test-steps@v1",
        ): 2,
        (
            ".github/workflows/_quality-gate-baseline.yml",
            "optimizr-tech/optimizr-infra-ops/.github/actions/quality-gate-scripts@v1",
        ): 1,
        (
            ".github/workflows/_quality-gate-pr.yml",
            "optimizr-tech/optimizr-infra-ops/.github/actions/quality-gate-scripts@v1",
        ): 1,
        (
            ".github/workflows/_quality-gate.yml",
            "optimizr-tech/optimizr-infra-ops/.github/actions/quality-gate-scripts@v1",
        ): 1,
    }
)
NEEDLE = "uses: optimizr-tech/optimizr-infra-ops/"


class RepositoryBoundaryTests(unittest.TestCase):
    def test_no_new_portable_dependency_on_infra_ops_is_added(self) -> None:
        actual: Counter[tuple[str, str]] = Counter()
        roots = (ROOT / ".github" / "workflows", ROOT / ".github" / "actions")

        for search_root in roots:
            if not search_root.exists():
                continue
            for path in sorted(search_root.rglob("*.yml")):
                relative = path.relative_to(ROOT).as_posix()
                for line in path.read_text(encoding="utf-8").splitlines():
                    stripped = line.strip()
                    if stripped.startswith(NEEDLE):
                        actual[(relative, stripped.removeprefix("uses: "))] += 1

        self.assertEqual(
            LEGACY_INFRA_OPS_REFERENCES,
            actual,
            "Portable automation must not add new optimizr-infra-ops dependencies; "
            "migrate an allowlisted reference instead.",
        )


if __name__ == "__main__":
    unittest.main()
