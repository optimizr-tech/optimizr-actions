"""Guard the portable-actions repository boundary during migration."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
LEGACY_INFRA_OPS_REFERENCES = {
    (".github/workflows/_python-uv-test.yml", 127),
    (".github/workflows/_python-uv-test.yml", 194),
    (".github/workflows/_quality-gate-baseline.yml", 42),
    (".github/workflows/_quality-gate-pr.yml", 54),
    (".github/workflows/_quality-gate.yml", 43),
    (".github/workflows/_vps-monorepo-deploy.yml", 200),
}
NEEDLE = "uses: optimizr-tech/optimizr-infra-ops/"


class RepositoryBoundaryTests(unittest.TestCase):
    def test_no_new_portable_dependency_on_infra_ops_is_added(self) -> None:
        actual: set[tuple[str, int]] = set()
        roots = (ROOT / ".github" / "workflows", ROOT / ".github" / "actions")

        for search_root in roots:
            if not search_root.exists():
                continue
            for path in sorted(search_root.rglob("*.yml")):
                relative = path.relative_to(ROOT).as_posix()
                for line_number, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), start=1
                ):
                    if line.strip().startswith(NEEDLE):
                        actual.add((relative, line_number))

        self.assertEqual(
            LEGACY_INFRA_OPS_REFERENCES,
            actual,
            "Portable automation must not add new optimizr-infra-ops dependencies; "
            "migrate an allowlisted reference instead.",
        )


if __name__ == "__main__":
    unittest.main()
