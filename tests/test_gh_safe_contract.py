"""Contract tests for the Windows-safe GitHub metadata wrapper."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "win" / "gh-safe.ps1"


class GhSafeContractTests(unittest.TestCase):
    def test_wrapper_rejects_literal_powerShell_newline_escapes(self) -> None:
        content = WRAPPER.read_text(encoding="utf-8")

        self.assertIn("Assert-NoLiteralShellEscape", content)
        self.assertIn(r"'\\[nrt]'", content)
        self.assertIn("Read-Utf8File $bodyPath", content)
        self.assertIn("Read-Utf8File $BodyFile", content)
        self.assertIn("[string[]]$ValidatorArgs", content)
        self.assertIn("@ValidatorArgs", content)


if __name__ == "__main__":
    unittest.main()
