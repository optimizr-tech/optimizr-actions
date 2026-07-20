import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from negative_probes.runner import ProbeError, load_manifest, run_probes


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(403)
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(b"forbidden")

    def log_message(self, *_args):
        return


class NegativeProbeTests(unittest.TestCase):
    def test_manifest_rejects_destructive_methods_and_unbounded_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "probes.json"
            path.write_text(json.dumps({"version": 1, "probes": [{
                "name": "bad", "target": "target1", "path": "/admin",
                "method": "POST", "expected_status": [403], "timeout_seconds": 3
            }]}))
            with self.assertRaises(ProbeError):
                load_manifest(path)

    def test_probe_evidence_uses_alias_not_private_url(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                manifest = root / "probes.json"
                manifest.write_text(json.dumps({"version": 1, "probes": [{
                    "name": "admin-denied", "target": "target1", "path": "/admin",
                    "method": "GET", "expected_status": [401, 403],
                    "required_headers": {"X-Frame-Options": "DENY"},
                    "body_must_not_contain": ["password"], "timeout_seconds": 3
                }]}))
                evidence = root / "evidence.json"
                private_url = f"http://127.0.0.1:{server.server_port}"
                result = run_probes(
                    manifest=load_manifest(manifest),
                    targets={"target1": private_url},
                    evidence_path=evidence,
                    repository="optimizr/example",
                    head_sha="a" * 40,
                )
                self.assertTrue(result["passed"])
                text = evidence.read_text()
                self.assertIn("target1", text)
                self.assertNotIn(private_url, text)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
