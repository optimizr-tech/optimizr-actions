import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from post_deploy.runner import VerificationError, load_manifest, normalize_manifest, run_verification


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok","private":"value"}')
    def log_message(self, *_args):
        return


class PostDeployTests(unittest.TestCase):
    def test_manifest_rejects_destructive_methods_urls_and_excessive_checks(self):
        with self.assertRaises(VerificationError):
            normalize_manifest({"version": 1, "http": [{"name": "bad", "target": "target1", "path": "https://example.test/", "method": "POST", "expected_status": [200]}]})
        with self.assertRaises(VerificationError):
            normalize_manifest({"version": 1, "containers": [{"name": f"c{i}", "container": "x"} for i in range(21)]})

    def test_real_http_and_fake_docker_emit_sanitized_evidence(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                bin_dir = root / "bin"
                bin_dir.mkdir()
                log = root / "docker-argv.jsonl"
                docker = bin_dir / "docker"
                docker.write_text(
                    "#!/usr/bin/env python3\n"
                    "import json, os, sys\n"
                    "with open(os.environ['DOCKER_ARGV_LOG'], 'a', encoding='utf-8') as fh: fh.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                    "print('true|healthy|running|sha256:abc123')\n"
                )
                docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
                old_path = os.environ.get("PATH", "")
                os.environ["PATH"] = f"{bin_dir}{os.pathsep}{old_path}"
                os.environ["DOCKER_ARGV_LOG"] = str(log)
                try:
                    manifest = {
                        "version": 1,
                        "containers": [{"name": "api", "container": "private-container", "health": "healthy"}],
                        "http": [{"name": "api-health", "target": "target1", "path": "/health", "method": "GET", "expected_status": [200], "timeout_seconds": 3}],
                    }
                    evidence = root / "evidence.json"
                    result = run_verification(
                        manifest=manifest,
                        targets={"target1": f"http://127.0.0.1:{server.server_port}"},
                        repository="optimizr/example",
                        deployed_sha="a" * 40,
                        evidence_path=evidence,
                    )
                finally:
                    os.environ["PATH"] = old_path
                    os.environ.pop("DOCKER_ARGV_LOG", None)
                self.assertTrue(result["passed"])
                argv = [json.loads(line) for line in log.read_text().splitlines()]
                self.assertEqual(argv[0][0:3], ["inspect", "--format", "{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.Status}}|{{.Image}}"])
                serialized = evidence.read_text()
                self.assertNotIn("private-container", serialized)
                self.assertNotIn("127.0.0.1", serialized)
                self.assertNotIn("private", serialized)
                self.assertIn("sha256:abc123", serialized)
        finally:
            server.shutdown()
            server.server_close()

    def test_missing_target_is_unavailable_and_writes_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {"version": 1, "http": [{"name": "health", "target": "target1", "path": "/health", "expected_status": [200]}]}
            evidence = root / "evidence.json"
            result = run_verification(manifest=manifest, targets={}, repository="optimizr/example", deployed_sha="b" * 40, evidence_path=evidence)
            self.assertFalse(result["passed"])
            self.assertEqual(result["checks"][0]["outcome"], "unavailable")
            self.assertTrue(evidence.exists())

    def test_load_manifest_rejects_symlink(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlink unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real.json"
            real.write_text('{"version":1,"http":[{"name":"x","target":"target1","path":"/","expected_status":[200]}]}')
            link = root / "manifest.json"
            link.symlink_to(real)
            with self.assertRaises(VerificationError):
                load_manifest(link)


if __name__ == "__main__":
    unittest.main()
