"""Publish an exported OCI image layout with bounded registry auth refresh.

BuildKit can push directly from its exporter, but a long build then pushes with
an authentication context that was established before the build started. This
publisher pushes an already exported OCI layout (image index, platform image,
and SBOM/provenance attestation manifests) byte-for-byte, so the registry digest
is the digest BuildKit produced. It fetches a fresh registry token immediately
before the first write and, only when the registry answers ``401``, refreshes
the token and retries the same request a bounded number of times. Every other
registry error fails closed without retry.

Only the Python standard library is used so the script runs unchanged on hosted
and self-hosted runners.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
MAX_AUTH_RETRIES_LIMIT = 5
DEFAULT_MAX_AUTH_RETRIES = 3
DEFAULT_TIMEOUT_SECONDS = 300.0
CHUNK_SIZE = 1024 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


class PushError(RuntimeError):
    """Raised when the exported image cannot be published exactly."""


class _Unauthorized(Exception):
    pass


@dataclass(frozen=True)
class PushResult:
    digest: str
    auth_refreshes: int


@dataclass(frozen=True)
class _Node:
    media_type: str
    digest: str
    data: bytes


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward registry credentials to a redirect target."""

    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def parse_image_ref(image_ref: str) -> tuple[str, str, str]:
    """Split ``host/repository:tag`` into its parts."""
    host, _, remainder = image_ref.partition("/")
    if not host or not remainder or ("." not in host and ":" not in host and host != "localhost"):
        raise PushError("image reference must include a registry host and repository")
    repository, sep, tag = remainder.rpartition(":")
    if not sep or "/" in tag or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag):
        raise PushError("image reference must end with a valid tag")
    if not re.fullmatch(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*", repository):
        raise PushError("image repository contains unsupported characters")
    return host, repository, tag


def _blob_path(layout: Path, digest: str) -> Path:
    """Return a local blob path after verifying its content digest in chunks."""
    if not DIGEST_RE.fullmatch(digest):
        raise PushError(f"layout references a non-sha256 digest: {digest}")
    path = layout / "blobs" / "sha256" / digest.split(":", 1)[1]
    if not path.is_file():
        raise PushError(f"exported layout is missing blob {digest}")
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            hasher.update(chunk)
    if "sha256:" + hasher.hexdigest() != digest:
        raise PushError(f"exported blob content does not match digest {digest}")
    return path


def _read_blob(layout: Path, digest: str) -> bytes:
    return _blob_path(layout, digest).read_bytes()


def _load_graph(layout: Path, expected_digest: str) -> tuple[list[str], list[_Node], _Node]:
    """Return blobs, child manifests (dependency order), and the root node."""
    try:
        top = json.loads((layout / "index.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise PushError(f"exported layout has no readable index.json: {error}") from error
    roots = top.get("manifests") or []
    if len(roots) != 1:
        raise PushError("exported layout must contain exactly one root manifest")
    root_descriptor = roots[0]
    if root_descriptor.get("digest") != expected_digest:
        raise PushError("exported layout digest does not match the built image digest")

    blobs: list[str] = []
    manifests: list[_Node] = []
    seen: set[str] = set()

    def visit(descriptor: Mapping[str, object]) -> _Node:
        digest = str(descriptor.get("digest", ""))
        media_type = str(descriptor.get("mediaType", ""))
        data = _read_blob(layout, digest)
        node = _Node(media_type, digest, data)
        if digest in seen:
            return node
        seen.add(digest)
        document = json.loads(data)
        if media_type in INDEX_MEDIA_TYPES:
            for child in document.get("manifests") or []:
                child_node = visit(child)
                if child_node.digest not in {item.digest for item in manifests}:
                    manifests.append(child_node)
        elif media_type in MANIFEST_MEDIA_TYPES:
            for item in [document.get("config")] + list(document.get("layers") or []):
                if not isinstance(item, Mapping):
                    raise PushError(f"manifest {digest} has an invalid descriptor")
                blob = str(item.get("digest", ""))
                _blob_path(layout, blob)
                if blob not in blobs:
                    blobs.append(blob)
        else:
            raise PushError(f"unsupported manifest media type: {media_type}")
        return node

    root = visit(root_descriptor)
    return blobs, manifests, root


class _RegistryClient:
    def __init__(
        self,
        host: str,
        repository: str,
        *,
        username: str,
        password: str,
        scheme: str,
        max_auth_retries: int,
        timeout: float,
        sleep: Callable[[float], None],
        emit: Callable[[str], None],
    ) -> None:
        self.base = f"{scheme}://{host}"
        self.repository = repository
        self.basic = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self.max_auth_retries = max_auth_retries
        self.timeout = timeout
        self.sleep = sleep
        self.emit = emit
        self.authorization: str | None = None
        self.challenge: dict[str, str] | None = None
        self.auth_refreshes = 0
        self.opener = urllib.request.build_opener(_NoRedirect)

    def _raw(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | Path | None
    ) -> tuple[int, Mapping[str, str], bytes]:
        handle = body.open("rb") if isinstance(body, Path) else None
        request = urllib.request.Request(
            url, data=handle if handle else body, method=method, headers=dict(headers)
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            with error:
                return error.code, error.headers, error.read() if error.fp else b""
        except (urllib.error.URLError, OSError) as error:
            raise PushError(f"{method} {urllib.parse.urlsplit(url).path} failed: {error}") from error
        finally:
            if handle:
                handle.close()

    def _parse_challenge(self, header: str) -> dict[str, str]:
        scheme, _, params = header.partition(" ")
        values = dict(re.findall(r'(\w+)="([^"]*)"', params))
        values["scheme"] = scheme.lower()
        return values

    def authenticate(self) -> None:
        """Obtain fresh registry credentials from the registry's challenge."""
        if self.challenge is None:
            status, headers, _ = self._raw("GET", f"{self.base}/v2/", {}, None)
            header = headers.get("WWW-Authenticate", "") if status == 401 else ""
            self.challenge = self._parse_challenge(header) if header else {"scheme": "none"}
        if self.challenge["scheme"] == "basic":
            self.authorization = self.basic
            return
        if self.challenge["scheme"] != "bearer":
            self.authorization = None
            return
        realm = self.challenge.get("realm", "")
        if not realm.startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise PushError("registry token realm must use https")
        query = urllib.parse.urlencode(
            {
                "service": self.challenge.get("service", ""),
                "scope": f"repository:{self.repository}:pull,push",
            }
        )
        status, _, body = self._raw("GET", f"{realm}?{query}", {"Authorization": self.basic}, None)
        if status != 200:
            raise PushError(f"registry token request failed with HTTP {status}")
        try:
            payload = json.loads(body)
        except ValueError as error:
            raise PushError("registry token response is not JSON") from error
        token = payload.get("token") or payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise PushError("registry token response did not contain a token")
        self.authorization = f"Bearer {token}"

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | Path | None = None,
        expected: Sequence[int],
        retry_in_place: bool = True,
    ) -> tuple[int, Mapping[str, str]]:
        """Send a request, refreshing credentials on HTTP 401 within the bound.

        With ``retry_in_place`` false the refreshed credentials are kept but
        ``_Unauthorized`` is raised so the caller can restart a multi-request
        operation (an upload session may not survive a credential change).
        """
        url = path_or_url if "://" in path_or_url else self.base + path_or_url
        while True:
            request_headers = dict(headers or {})
            if self.authorization:
                request_headers["Authorization"] = self.authorization
            status, response_headers, _ = self._raw(method, url, request_headers, body)
            if status != 401:
                break
            if self.auth_refreshes >= self.max_auth_retries:
                raise PushError(
                    f"{method} {urllib.parse.urlsplit(url).path} returned HTTP 401 after "
                    f"{self.auth_refreshes} credential refresh(es)"
                )
            self.auth_refreshes += 1
            self.emit(
                f"::warning::registry returned HTTP 401 for {method} {urllib.parse.urlsplit(url).path}; "
                f"refreshing credentials and retrying ({self.auth_refreshes}/{self.max_auth_retries})"
            )
            challenge = response_headers.get("WWW-Authenticate")
            if challenge:
                self.challenge = self._parse_challenge(challenge)
            self.sleep(min(2 ** (self.auth_refreshes - 1), 30))
            self.authenticate()
            if not retry_in_place:
                raise _Unauthorized
        if status not in expected:
            raise PushError(f"{method} {urllib.parse.urlsplit(url).path} returned HTTP {status}")
        return status, response_headers

    def push_blob(self, digest: str, path: Path) -> None:
        name = self.repository
        status, _ = self.request(
            "HEAD", f"/v2/{name}/blobs/{digest}", expected=(200, 302, 307, 404)
        )
        if status != 404:
            return
        while True:
            try:
                self._upload_blob(digest, path)
                return
            except _Unauthorized:
                continue

    def _upload_blob(self, digest: str, path: Path) -> None:
        name = self.repository
        _, headers = self.request(
            "POST", f"/v2/{name}/blobs/uploads/", body=b"", expected=(202,), retry_in_place=False
        )
        location = headers.get("Location", "")
        if not location:
            raise PushError("registry did not return an upload location")
        location = urllib.parse.urljoin(self.base + "/", location)
        if urllib.parse.urlsplit(location).netloc != urllib.parse.urlsplit(self.base).netloc:
            raise PushError("registry upload location points to another host")
        separator = "&" if "?" in location else "?"
        self.request(
            "PUT",
            f"{location}{separator}digest={urllib.parse.quote(digest)}",
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(path.stat().st_size),
            },
            body=path,
            expected=(201,),
            retry_in_place=False,
        )

    def push_manifest(self, reference: str, node: _Node) -> None:
        _, headers = self.request(
            "PUT",
            f"/v2/{self.repository}/manifests/{reference}",
            headers={"Content-Type": node.media_type},
            body=node.data,
            expected=(201,),
        )
        reported = headers.get("Docker-Content-Digest")
        if reported and reported != node.digest:
            raise PushError(
                f"registry stored manifest {reference} with digest {reported}, expected {node.digest}"
            )

    def verify_tag(self, tag: str, node: _Node) -> None:
        _, headers = self.request(
            "HEAD",
            f"/v2/{self.repository}/manifests/{tag}",
            headers={"Accept": node.media_type},
            expected=(200,),
        )
        if headers.get("Docker-Content-Digest") != node.digest:
            raise PushError(f"published tag {tag} does not resolve to digest {node.digest}")


def push_oci_layout(
    layout: Path | str,
    image_ref: str,
    expected_digest: str,
    *,
    username: str,
    password: str,
    max_auth_retries: int = DEFAULT_MAX_AUTH_RETRIES,
    plain_http: bool = False,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    emit: Callable[[str], None] = print,
) -> PushResult:
    """Push the exported layout and return the verified registry digest."""
    if not DIGEST_RE.fullmatch(expected_digest):
        raise PushError("expected digest is not a valid immutable sha256 digest")
    if not 0 <= max_auth_retries <= MAX_AUTH_RETRIES_LIMIT:
        raise PushError(f"max_auth_retries must be between 0 and {MAX_AUTH_RETRIES_LIMIT}")
    if not username or not password:
        raise PushError("registry credentials are required")
    host, repository, tag = parse_image_ref(image_ref)
    if plain_http and host.rsplit(":", 1)[0] not in LOOPBACK_HOSTS:
        raise PushError("plain HTTP is only allowed for loopback test registries")

    blobs, manifests, root = _load_graph(Path(layout), expected_digest)
    client = _RegistryClient(
        host,
        repository,
        username=username,
        password=password,
        scheme="http" if plain_http else "https",
        max_auth_retries=max_auth_retries,
        timeout=timeout,
        sleep=sleep,
        emit=emit,
    )
    client.authenticate()
    for digest in blobs:
        client.push_blob(digest, _blob_path(Path(layout), digest))
    for node in manifests:
        client.push_manifest(node.digest, node)
    client.push_manifest(tag, root)
    client.verify_tag(tag, root)
    return PushResult(digest=root.digest, auth_refreshes=client.auth_refreshes)


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--layout", required=True)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--max-auth-retries", type=int, default=DEFAULT_MAX_AUTH_RETRIES)
    parser.add_argument("--plain-http-loopback", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ

    username = env.get("REGISTRY_USERNAME", "")
    password = env.get("REGISTRY_PASSWORD", "")
    if not username or not password:
        print("::error::REGISTRY_USERNAME and REGISTRY_PASSWORD are required", file=sys.stderr)
        return 1
    try:
        result = push_oci_layout(
            args.layout,
            args.image_ref,
            args.expected_digest,
            username=username,
            password=password,
            max_auth_retries=args.max_auth_retries,
            plain_http=args.plain_http_loopback,
        )
    except PushError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    print(f"Published {args.image_ref}@{result.digest} (credential refreshes: {result.auth_refreshes})")
    output = env.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"digest={result.digest}\n")
            handle.write(f"auth_refreshes={result.auth_refreshes}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
