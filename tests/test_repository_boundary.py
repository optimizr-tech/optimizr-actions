"""Guard the portable-actions repository boundary."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
LEGACY_INFRA_OPS_REFERENCES = Counter()
NEEDLE = "uses: optimizr-tech/optimizr-infra-ops/"
INTERNAL_REF_RE = re.compile(
    r"^\s*(?:-\s*)?uses:\s*optimizr-tech/optimizr-actions/[^@\s]+@([^\s#]+)",
    re.MULTILINE,
)


class RepositoryBoundaryTests(unittest.TestCase):
    def test_no_portable_dependency_on_infra_ops_is_executable(self) -> None:
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
            "Portable automation must not execute optimizr-infra-ops code.",
        )

    def test_first_party_executable_refs_use_the_floating_v1_tag(self) -> None:
        roots = (
            ROOT / ".github" / "workflows",
            ROOT / ".github" / "actions",
            ROOT / "templates" / "workflows",
        )
        for search_root in roots:
            if not search_root.exists():
                continue
            for path in sorted(search_root.rglob("*.yml")):
                relative = path.relative_to(ROOT).as_posix()
                content = path.read_text(encoding="utf-8")
                refs = INTERNAL_REF_RE.findall(content)
                for ref in refs:
                    with self.subTest(path=relative, ref=ref):
                        self.assertEqual(
                            "v1",
                            ref,
                            "First-party executable refs must use the governed @v1 tag; SHA pins belong only to evidence and third-party actions.",
                        )


if __name__ == "__main__":
    unittest.main()
