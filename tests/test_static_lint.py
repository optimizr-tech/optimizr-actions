from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from static_lint.runner import (  # noqa: E402
    LintError,
    discover_files,
    install_spec,
    validate_exclusions,
    safe_actionlint_argv,
)


class StaticLintTests(unittest.TestCase):
    def test_install_specs_are_version_and_checksum_pinned(self):
        x64 = install_spec("x86_64")
        arm = install_spec("aarch64")
        self.assertEqual(x64["shellcheck"]["version"], "0.11.0")
        self.assertEqual(x64["actionlint"]["version"], "1.7.12")
        self.assertRegex(x64["shellcheck"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(arm["actionlint"]["sha256"], r"^[0-9a-f]{64}$")
        with self.assertRaises(LintError):
            install_spec("mips64")

    def test_exclusions_cannot_escape_repository(self):
        self.assertEqual(validate_exclusions("vendor/**\nfixtures/*.sh"), ["vendor/**", "fixtures/*.sh"])
        with self.assertRaises(LintError):
            validate_exclusions("../outside/**")

    def test_actionlint_output_format_excludes_source_snippets(self):
        argv = safe_actionlint_argv(Path("/tmp/actionlint"), [".github/workflows/check.yml"])
        rendered = " ".join(str(item) for item in argv)
        self.assertIn("{{.Message}}", rendered)
        self.assertNotIn("{{json .}}", rendered)
        self.assertNotIn("Snippet", rendered)

    def test_discovery_is_deterministic_and_applies_narrow_exclusions(self):
        tracked = [
            "scripts/z.sh",
            ".github/workflows/check.yml",
            "scripts/a.bash",
            ".github/actions/demo/action.yaml",
            "vendor/skip.sh",
            "README.md",
        ]
        result = discover_files(tracked, ["vendor/**"])
        self.assertEqual(result["shell"], ["scripts/a.bash", "scripts/z.sh"])
        self.assertEqual(
            result["actions"],
            [".github/actions/demo/action.yaml", ".github/workflows/check.yml"],
        )


if __name__ == "__main__":
    unittest.main()
