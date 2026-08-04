from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / ".github/actions/pr-metadata-validation/validate.py"
spec = importlib.util.spec_from_file_location("pr_metadata_validation", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class PRMetadataValidationTests(unittest.TestCase):
    def test_valid_org_subject_passes(self):
        self.assertEqual([], module.validate_subject(":shield: security(ci): isolate metadata", "title"))

    def test_portuguese_or_trailing_period_fails(self):
        failures = module.validate_subject(":bug: fix(ci): corrigir validacao.", "title")
        messages = " ".join(item.message for item in failures)
        self.assertIn("trailing period", messages)
        self.assertIn("English", messages)

    def test_invalid_gitmoji_fails(self):
        failures = module.validate_subject(":unknown: fix(ci): repair metadata", "title")
        self.assertTrue(any("not allowed" in item.message for item in failures))

    def test_body_rejects_empty_controls_and_mojibake(self):
        self.assertTrue(module.validate_body("   "))
        self.assertTrue(module.validate_body("hello\x07world"))
        self.assertTrue(module.validate_body("ðŸ broken"))
        self.assertEqual([], module.validate_body("## Summary\nMetadata only."))

    def test_fetch_is_bounded_and_paginates(self):
        calls = []
        original = module._request_json
        try:
            def fake(url, token):
                calls.append(url)
                if url.endswith("/pulls/7"):
                    return {"base": {"sha": "a" * 40}, "head": {"sha": "b" * 40}}
                if url.endswith("page=1"):
                    return [{"commit": {"message": ":bug: fix(ci): repair metadata"}}] * 100
                return [{"commit": {"message": ":memo: docs(ci): explain metadata"}}]
            module._request_json = fake
            pr, commits = module.fetch_pr_metadata("https://api.github.test", "owner/repo", 7, "token")
        finally:
            module._request_json = original
        self.assertEqual("a" * 40, pr["base"]["sha"])
        self.assertEqual(101, len(commits))
        self.assertEqual(3, len(calls))


if __name__ == "__main__":
    unittest.main()
