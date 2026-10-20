"""Behavior tests for the auth-refreshing OCI layout publisher.

The tests run a small in-process OCI distribution registry so the publisher is
exercised over real HTTP without Docker, network access, or credentials.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import threading
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "container_release" / "push_oci_layout.py"
SPEC = importlib.util.spec_from_file_location("push_oci_layout", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

USERNAME = "registry-user"
PASSWORD = "registry-secret-value"
REPOSITORY = "optimizr-tech/example/alloy"
TAG = "candidate-" + "a" * 40 + "-1-1"

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FakeRegistry:
    """Minimal token-authenticated OCI distribution registry."""

    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, tuple[str, bytes]] = {}
        self.tags: dict[str, str] = {}
        self.valid_tokens: set[str] = set()
        self.token_requests = 0
        self.requests: list[tuple[str, str]] = []
        self.revoke_tokens_on: set[tuple[str, str]] = set()
        self.always_unauthorized = False
        self.forbidden = False
        self.wrong_manifest_digest = False
        self.redirect_blob_head = False
        self.upload_sessions: set[str] = set()
        self.lock = threading.Lock()
        registry = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                return

            def _send(self, status: int, headers: dict[str, str] | None = None, body: bytes = b"") -> None:
                self.send_response(status)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD" and body:
                    self.wfile.write(body)

            def _body(self) -> bytes:
                length = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(length) if length else b""

            def _challenge(self) -> None:
                realm = f"http://{self.headers['Host']}/token"
                self._send(
                    401,
                    {
                        "WWW-Authenticate": (
                            f'Bearer realm="{realm}",service="fake-registry",'
                            f'scope="repository:{REPOSITORY}:pull,push"'
                        )
                    },
                )

            def _authorized(self) -> bool:
                header = self.headers.get("Authorization", "")
                if not header.startswith("Bearer "):
                    return False
                token = header.removeprefix("Bearer ")
                with registry.lock:
                    path = urlsplit(self.path).path
                    for method, revoked in list(registry.revoke_tokens_on):
                        if method == self.command and (
                            path == revoked or (revoked.endswith("/") and path.startswith(revoked))
                        ):
                            registry.revoke_tokens_on.discard((method, revoked))
                            registry.valid_tokens.clear()
                            if revoked.endswith("/uploads/"):
                                registry.upload_sessions.discard(path)
                            return False
                    return token in registry.valid_tokens and not registry.always_unauthorized

            def _handle(self) -> None:
                parts = urlsplit(self.path)
                registry.requests.append((self.command, parts.path))
                if parts.path == "/token":
                    expected = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
                    if self.headers.get("Authorization") != expected:
                        self._send(401)
                        return
                    with registry.lock:
                        registry.token_requests += 1
                        token = f"token-{registry.token_requests}"
                        registry.valid_tokens.add(token)
                    self._send(200, {"Content-Type": "application/json"}, json.dumps({"token": token}).encode())
                    return
                if not self._authorized():
                    self._body()
                    self._challenge()
                    return
                if registry.forbidden:
                    self._send(403)
                    return
                prefix = f"/v2/{REPOSITORY}/"
                if not parts.path.startswith(prefix):
                    self._send(404)
                    return
                rest = parts.path[len(prefix):]
                if rest.startswith("blobs/uploads/") and self.command == "POST":
                    self._body()
                    location = f"/v2/{REPOSITORY}/blobs/uploads/{uuid.uuid4().hex}"
                    registry.upload_sessions.add(location)
                    self._send(202, {"Location": location})
                    return
                if rest.startswith("blobs/uploads/") and self.command == "PUT":
                    data = self._body()
                    if parts.path not in registry.upload_sessions:
                        self._send(404)
                        return
                    registry.upload_sessions.discard(parts.path)
                    digest = parse_qs(parts.query).get("digest", [""])[0]
                    if _digest(data) != digest:
                        self._send(400)
                        return
                    registry.blobs[digest] = data
                    self._send(201, {"Docker-Content-Digest": digest})
                    return
                if rest.startswith("blobs/") and self.command == "HEAD":
                    digest = rest.split("/", 1)[1]
                    if digest in registry.blobs and registry.redirect_blob_head:
                        self._send(307, {"Location": "https://storage.invalid/blob"})
                        return
                    self._send(200 if digest in registry.blobs else 404)
                    return
                if rest.startswith("manifests/") and self.command == "PUT":
                    reference = rest.split("/", 1)[1]
                    data = self._body()
                    digest = _digest(data)
                    registry.manifests[digest] = (self.headers.get("Content-Type", ""), data)
                    if not reference.startswith("sha256:"):
                        registry.tags[reference] = digest
                    reported = "sha256:" + "f" * 64 if registry.wrong_manifest_digest else digest
                    self._send(201, {"Docker-Content-Digest": reported})
                    return
                if rest.startswith("manifests/") and self.command in {"HEAD", "GET"}:
                    reference = rest.split("/", 1)[1]
                    digest = registry.tags.get(reference, reference)
                    if digest not in registry.manifests:
                        self._send(404)
                        return
                    media_type, data = registry.manifests[digest]
                    self._send(200, {"Docker-Content-Digest": digest, "Content-Type": media_type}, data)
                    return
                self._send(405)

            do_GET = do_HEAD = do_POST = do_PUT = _handle  # noqa: N815

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self) -> "FakeRegistry":
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


def write_layout(root: Path) -> dict[str, str]:
    """Write a BuildKit-shaped OCI layout: index -> image + attestation manifests."""
    blobs = root / "blobs" / "sha256"
    blobs.mkdir(parents=True)

    def put(data: bytes) -> str:
        digest = _digest(data)
        (blobs / digest.split(":", 1)[1]).write_bytes(data)
        return digest

    def descriptor(media_type: str, data: bytes, **extra: object) -> dict[str, object]:
        return {"mediaType": media_type, "digest": put(data), "size": len(data), **extra}

    config = json.dumps({"architecture": "amd64", "os": "linux"}).encode()
    layer = b"layer-bytes" * 1000
    image_manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": descriptor("application/vnd.oci.image.config.v1+json", config),
            "layers": [descriptor("application/vnd.oci.image.layer.v1.tar+gzip", layer)],
        }
    ).encode()
    image_descriptor = descriptor(OCI_MANIFEST, image_manifest, platform={"architecture": "amd64", "os": "linux"})
    attestation_config = b"{}"
    sbom = json.dumps({"predicateType": "https://spdx.dev/Document"}).encode()
    provenance = json.dumps({"predicateType": "https://slsa.dev/provenance/v1"}).encode()
    attestation_manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": descriptor("application/vnd.oci.image.config.v1+json", attestation_config),
            "layers": [
                descriptor("application/vnd.in-toto+json", sbom),
                descriptor("application/vnd.in-toto+json", provenance),
            ],
        }
    ).encode()
    attestation_descriptor = descriptor(
        OCI_MANIFEST,
        attestation_manifest,
        annotations={
            "vnd.docker.reference.digest": image_descriptor["digest"],
            "vnd.docker.reference.type": "attestation-manifest",
        },
        platform={"architecture": "unknown", "os": "unknown"},
    )
    index = json.dumps(
        {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [image_descriptor, attestation_descriptor]}
    ).encode()
    index_descriptor = descriptor(OCI_INDEX, index, annotations={"org.opencontainers.image.ref.name": TAG})
    (root / "oci-layout").write_text(json.dumps({"imageLayoutVersion": "1.0.0"}), encoding="utf-8")
    (root / "index.json").write_text(
        json.dumps({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [index_descriptor]}),
        encoding="utf-8",
    )
    return {
        "index": str(index_descriptor["digest"]),
        "image": str(image_descriptor["digest"]),
        "attestation": str(attestation_descriptor["digest"]),
        "layer": _digest(layer),
        "sbom": _digest(sbom),
        "provenance": _digest(provenance),
    }


class PushOciLayoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.layout = Path(self.tmp.name) / "layout"
        self.digests = write_layout(self.layout)
        self.warnings: list[str] = []

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def push(self, registry: FakeRegistry, **kwargs: object) -> object:
        options: dict[str, object] = {
            "username": USERNAME,
            "password": PASSWORD,
            "max_auth_retries": 3,
            "plain_http": True,
            "sleep": lambda _seconds: None,
            "emit": self.warnings.append,
        }
        options.update(kwargs)
        return MODULE.push_oci_layout(
            self.layout,
            f"{registry.host}/{REPOSITORY}:{TAG}",
            self.digests["index"],
            **options,
        )

    def test_publishes_full_graph_with_attestations_under_the_same_digest(self) -> None:
        with FakeRegistry() as registry:
            result = self.push(registry)

            self.assertEqual(self.digests["index"], result.digest)
            self.assertEqual(self.digests["index"], registry.tags[TAG])
            for key in ("image", "attestation", "index"):
                self.assertIn(self.digests[key], registry.manifests)
            for key in ("layer", "sbom", "provenance"):
                self.assertIn(self.digests[key], registry.blobs)
            self.assertEqual(0, result.auth_refreshes)

    def test_authenticates_freshly_before_the_first_registry_write(self) -> None:
        with FakeRegistry() as registry:
            self.push(registry)

            first_token = registry.requests.index(("GET", "/token"))
            first_write = next(
                position
                for position, (method, _path) in enumerate(registry.requests)
                if method in {"POST", "PUT"}
            )
            self.assertLess(first_token, first_write)

    def test_refreshes_credentials_and_retries_after_a_mid_push_401(self) -> None:
        with FakeRegistry() as registry:
            registry.revoke_tokens_on.add(("HEAD", f"/v2/{REPOSITORY}/blobs/{self.digests['sbom']}"))

            result = self.push(registry)

            self.assertEqual(1, result.auth_refreshes)
            self.assertEqual(self.digests["index"], registry.tags[TAG])
            self.assertTrue(any("401" in warning for warning in self.warnings))

    def test_401_on_upload_restarts_the_upload_session(self) -> None:
        with FakeRegistry() as registry:
            registry.revoke_tokens_on.add(("PUT", f"/v2/{REPOSITORY}/blobs/uploads/"))

            result = self.push(registry)

            self.assertEqual(1, result.auth_refreshes)
            self.assertEqual(self.digests["index"], registry.tags[TAG])
            self.assertIn(self.digests["layer"], registry.blobs)

    def test_blob_head_redirect_counts_as_present_without_following_it(self) -> None:
        with FakeRegistry() as registry:
            self.push(registry)
            registry.redirect_blob_head = True
            uploads_before = registry.requests.count(("POST", f"/v2/{REPOSITORY}/blobs/uploads/"))

            self.push(registry)

            uploads_after = registry.requests.count(("POST", f"/v2/{REPOSITORY}/blobs/uploads/"))
            self.assertEqual(uploads_before, uploads_after)

    def test_persistent_401_fails_closed_after_the_bounded_refreshes(self) -> None:
        with FakeRegistry() as registry:
            registry.always_unauthorized = True

            with self.assertRaisesRegex(MODULE.PushError, "401"):
                self.push(registry, max_auth_retries=2)

            self.assertLessEqual(registry.token_requests, 3)
            self.assertNotIn(TAG, registry.tags)

    def test_non_auth_registry_errors_are_not_retried(self) -> None:
        with FakeRegistry() as registry:
            registry.forbidden = True

            with self.assertRaisesRegex(MODULE.PushError, "403"):
                self.push(registry)

            self.assertEqual(1, registry.token_requests)

    def test_rejects_a_layout_that_does_not_match_the_built_digest(self) -> None:
        with FakeRegistry() as registry:
            with self.assertRaisesRegex(MODULE.PushError, "does not match"):
                MODULE.push_oci_layout(
                    self.layout,
                    f"{registry.host}/{REPOSITORY}:{TAG}",
                    "sha256:" + "0" * 64,
                    username=USERNAME,
                    password=PASSWORD,
                    plain_http=True,
                )

            self.assertEqual([], registry.requests)

    def test_retry_skips_blobs_already_present_in_the_registry(self) -> None:
        with FakeRegistry() as registry:
            self.push(registry)
            uploads_before = registry.requests.count(("POST", f"/v2/{REPOSITORY}/blobs/uploads/"))

            self.push(registry)

            uploads_after = registry.requests.count(("POST", f"/v2/{REPOSITORY}/blobs/uploads/"))
            self.assertEqual(uploads_before, uploads_after)

    def test_missing_local_blob_fails_closed(self) -> None:
        (self.layout / "blobs" / "sha256" / self.digests["layer"].split(":", 1)[1]).unlink()
        with FakeRegistry() as registry:
            with self.assertRaisesRegex(MODULE.PushError, "missing"):
                self.push(registry)

            self.assertNotIn(TAG, registry.tags)

    def test_tampered_local_blob_fails_closed(self) -> None:
        path = self.layout / "blobs" / "sha256" / self.digests["layer"].split(":", 1)[1]
        path.write_bytes(b"tampered")
        with FakeRegistry() as registry:
            with self.assertRaisesRegex(MODULE.PushError, "digest"):
                self.push(registry)

            self.assertNotIn(TAG, registry.tags)

    def test_registry_reporting_another_manifest_digest_fails_closed(self) -> None:
        with FakeRegistry() as registry:
            registry.wrong_manifest_digest = True

            with self.assertRaisesRegex(MODULE.PushError, "digest"):
                self.push(registry)

    def test_plain_http_is_limited_to_loopback_registries(self) -> None:
        with self.assertRaisesRegex(MODULE.PushError, "loopback"):
            MODULE.push_oci_layout(
                self.layout,
                f"ghcr.io/{REPOSITORY}:{TAG}",
                self.digests["index"],
                username=USERNAME,
                password=PASSWORD,
                plain_http=True,
            )

    def test_rejects_unbounded_retry_configuration(self) -> None:
        for value in (-1, 6):
            with self.subTest(value=value):
                with self.assertRaisesRegex(MODULE.PushError, "max_auth_retries"):
                    MODULE.push_oci_layout(
                        self.layout,
                        f"ghcr.io/{REPOSITORY}:{TAG}",
                        self.digests["index"],
                        username=USERNAME,
                        password=PASSWORD,
                        max_auth_retries=value,
                    )

    def test_cli_reads_credentials_from_environment_and_writes_outputs(self) -> None:
        output_file = Path(self.tmp.name) / "github_output"
        with FakeRegistry() as registry:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = MODULE.main(
                    [
                        "--layout",
                        str(self.layout),
                        "--image-ref",
                        f"{registry.host}/{REPOSITORY}:{TAG}",
                        "--expected-digest",
                        self.digests["index"],
                        "--plain-http-loopback",
                    ],
                    environ={
                        "REGISTRY_USERNAME": USERNAME,
                        "REGISTRY_PASSWORD": PASSWORD,
                        "GITHUB_OUTPUT": str(output_file),
                    },
                )

        self.assertEqual(0, code)
        outputs = output_file.read_text(encoding="utf-8")
        self.assertIn(f"digest={self.digests['index']}\n", outputs)
        self.assertIn("auth_refreshes=0\n", outputs)
        self.assertNotIn(PASSWORD, stdout.getvalue() + stderr.getvalue() + outputs)

    def test_cli_fails_without_credentials(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = MODULE.main(
                [
                    "--layout",
                    str(self.layout),
                    "--image-ref",
                    f"ghcr.io/{REPOSITORY}:{TAG}",
                    "--expected-digest",
                    self.digests["index"],
                ],
                environ={},
            )

        self.assertEqual(1, code)
        self.assertIn("REGISTRY_USERNAME", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
