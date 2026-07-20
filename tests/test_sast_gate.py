import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from sast_gate.runner import (
    SastError,
    filter_findings,
    load_baseline,
    profile_configs,
    sanitize_semgrep_json,
    sanitize_sarif,
)


class SastGateTests(unittest.TestCase):
    def test_profiles_are_allowlisted_local_files(self):
        self.assertEqual(profile_configs("python"), ["python.yml"])
        self.assertEqual(profile_configs("all"), ["python.yml", "typescript.yml"])
        with self.assertRaises(SastError):
            profile_configs("https://example.com/rules.yml")

    def test_expired_baseline_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(json.dumps({"version": 1, "findings": [{
                "rule_id": "rule", "path": "app.py", "fingerprint": "abc",
                "owner": "team", "statement": "legacy", "expires": "2026-01-01"
            }]}))
            with self.assertRaises(SastError):
                load_baseline(path, today="2026-07-20")

    def test_exact_unexpired_baseline_suppresses_only_matching_finding(self):
        baseline = {("rule", "app.py", "abc")}
        findings = [
            {"check_id": "rule", "path": "app.py", "extra": {"fingerprint": "abc", "severity": "ERROR"}},
            {"check_id": "rule", "path": "other.py", "extra": {"fingerprint": "abc", "severity": "ERROR"}},
        ]
        result = filter_findings(findings, baseline, blocking_severities={"ERROR"})
        self.assertEqual(len(result["suppressed"]), 1)
        self.assertEqual(len(result["blocking"]), 1)

    def test_raw_reports_remove_source_snippets_and_metavariable_content(self):
        semgrep = {"results": [{"check_id": "rule", "path": "app.py", "extra": {"lines": "password=secret", "metavars": {"$X": {"abstract_content": "secret"}}, "severity": "ERROR"}}]}
        cleaned = sanitize_semgrep_json(semgrep)
        text = json.dumps(cleaned)
        self.assertNotIn("password=secret", text)
        self.assertNotIn("abstract_content", text)
        sarif = {"runs": [{"results": [{"locations": [{"physicalLocation": {"region": {"snippet": {"text": "secret"}}}}], "fixes": [{"artifactChanges": []}]}]}]}
        cleaned_sarif = sanitize_sarif(sarif)
        sarif_text = json.dumps(cleaned_sarif)
        self.assertNotIn("snippet", sarif_text)
        self.assertNotIn("fixes", sarif_text)


if __name__ == "__main__":
    unittest.main()
