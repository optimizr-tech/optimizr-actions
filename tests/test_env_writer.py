import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from env_writer.runner import EnvFileError, load_schema, render_env, write_env_file


class EnvWriterTests(unittest.TestCase):
    def test_schema_rejects_duplicate_keys_secret_literals_and_invalid_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schema.json"
            path.write_text(json.dumps({
                "version": 1,
                "entries": [
                    {"key": "GOOD", "env": "SOURCE", "required": True, "secret": True},
                    {"key": "GOOD", "literal": "bad", "secret": False},
                ],
            }))
            with self.assertRaises(EnvFileError):
                load_schema(path)
            path.write_text(json.dumps({
                "version": 1,
                "entries": [{"key": "BAD-NAME", "literal": "x", "secret": False}],
            }))
            with self.assertRaises(EnvFileError):
                load_schema(path)
            path.write_text(json.dumps({
                "version": 1,
                "entries": [{"key": "SECRET", "literal": "x", "secret": True}],
            }))
            with self.assertRaises(EnvFileError):
                load_schema(path)

    def test_render_escapes_compose_values_and_never_uses_shell_syntax(self):
        schema = {
            "version": 1,
            "entries": [
                {"key": "PASSWORD", "env": "PASSWORD_SOURCE", "required": True, "secret": True},
                {"key": "MULTILINE", "env": "MULTILINE_SOURCE", "required": True, "secret": True},
                {"key": "PUBLIC_MODE", "literal": "production", "secret": False},
            ],
        }
        rendered, metadata = render_env(
            schema,
            {
                "PASSWORD_SOURCE": 'pa$$word"\\tail',
                "MULTILINE_SOURCE": "line1\nline2\tend",
            },
        )
        self.assertEqual(
            rendered,
            'PASSWORD="pa$$$$word\\"\\\\tail"\n'
            'MULTILINE="line1\\nline2\\tend"\n'
            'PUBLIC_MODE="production"\n',
        )
        self.assertEqual([item["key"] for item in metadata], ["PASSWORD", "MULTILINE", "PUBLIC_MODE"])
        self.assertNotIn("pa$$word", json.dumps(metadata))
        self.assertNotIn("line1", json.dumps(metadata))

    def test_missing_required_value_fails_without_writing_destination(self):
        schema = {
            "version": 1,
            "entries": [{"key": "REQUIRED", "env": "MISSING", "required": True, "secret": True}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination = root / ".env"
            with self.assertRaises(EnvFileError):
                write_env_file(
                    schema=schema,
                    environment={},
                    destination=destination,
                    allowed_root=root,
                    mode=0o600,
                    evidence_path=root / "evidence.json",
                )
            self.assertFalse(destination.exists())

    def test_atomic_write_sets_mode_and_redacts_evidence(self):
        schema = {
            "version": 1,
            "entries": [
                {"key": "SECRET", "env": "SECRET_SOURCE", "required": True, "secret": True},
                {"key": "OPTIONAL", "env": "OPTIONAL_SOURCE", "required": False, "default": "fallback", "secret": False},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination = root / "service" / ".env"
            destination.parent.mkdir()
            evidence = root / "artifacts" / "evidence.json"
            result = write_env_file(
                schema=schema,
                environment={"SECRET_SOURCE": "top-secret"},
                destination=destination,
                allowed_root=root / "service",
                mode=0o600,
                evidence_path=evidence,
            )
            self.assertEqual(destination.read_text(), 'SECRET="top-secret"\nOPTIONAL="fallback"\n')
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            payload = json.loads(evidence.read_text())
            self.assertEqual(payload["result"], "passed")
            self.assertEqual(payload["destination_name"], ".env")
            serialized = json.dumps(payload)
            self.assertNotIn("top-secret", serialized)
            self.assertNotIn("fallback", serialized)
            self.assertEqual(result["entry_count"], 2)

    def test_rejects_destination_outside_root_and_symlink_target(self):
        schema = {"version": 1, "entries": [{"key": "VALUE", "literal": "ok", "secret": False}]}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            allowed = root / "allowed"
            allowed.mkdir()
            with self.assertRaises(EnvFileError):
                write_env_file(
                    schema=schema,
                    environment={},
                    destination=root / "outside.env",
                    allowed_root=allowed,
                    mode=0o600,
                    evidence_path=root / "evidence.json",
                )
            if hasattr(os, "symlink"):
                real = allowed / "real.env"
                real.write_text("old")
                link = allowed / ".env"
                link.symlink_to(real)
                with self.assertRaises(EnvFileError):
                    write_env_file(
                        schema=schema,
                        environment={},
                        destination=link,
                        allowed_root=allowed,
                        mode=0o600,
                        evidence_path=root / "evidence.json",
                    )


if __name__ == "__main__":
    unittest.main()
