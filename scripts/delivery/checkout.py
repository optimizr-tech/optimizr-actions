"""Prepare a clean checkout whose HEAD is a trusted exact commit."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import urlsplit

from .request import DeployRequest


class CheckoutError(ValueError):
    """Raised when an exact-SHA checkout cannot be prepared safely."""


GitRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]
SCP_REMOTE_RE = re.compile(r"^git@[A-Za-z0-9.-]+:[A-Za-z0-9._/-]+$")


@dataclass(frozen=True)
class CheckoutSpec:
    """Adapter-resolved checkout inputs; the request remains the authority."""

    request: DeployRequest
    remote: str
    destination: Path
    allowed_root: Path


@dataclass(frozen=True)
class CheckoutResult:
    """Secret-free result returned after the checkout identity is verified."""

    path: Path
    head_sha: str
    trusted_ref: str


def _absolute(path: Path) -> Path:
    if path.is_absolute():
        return path
    return Path.cwd() / path


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            raise CheckoutError("checkout path must not contain symlink components")


def _validate_paths(spec: CheckoutSpec) -> tuple[Path, Path]:
    try:
        root = spec.allowed_root.resolve(strict=True)
    except OSError as exc:
        raise CheckoutError("allowed checkout root could not be resolved") from exc
    if not root.is_dir():
        raise CheckoutError("allowed checkout root must be a directory")

    raw_destination = _absolute(spec.destination)
    _reject_symlink_components(raw_destination)
    try:
        destination = raw_destination.resolve(strict=False)
    except OSError as exc:
        raise CheckoutError("checkout destination could not be resolved") from exc
    if root == destination or root not in destination.parents:
        raise CheckoutError("checkout destination must remain below the allowed root")
    if destination.exists():
        raise CheckoutError("checkout destination must not already exist")
    if not destination.parent.is_dir():
        raise CheckoutError("checkout destination parent must be a directory")
    return root, destination


def _validate_remote(remote: str) -> None:
    if not isinstance(remote, str) or not remote or remote != remote.strip():
        raise CheckoutError("remote must be an adapter-resolved network Git URL")
    if remote.startswith(("-", "ext::", "file:", "file://")) or any(
        character.isspace() or ord(character) < 32 for character in remote
    ):
        raise CheckoutError("remote must be an adapter-resolved network Git URL")

    if remote.startswith(("https://", "ssh://")):
        try:
            parsed = urlsplit(remote)
            valid_url = (
                parsed.scheme in {"https", "ssh"}
                and parsed.hostname is not None
                and bool(parsed.path)
                and not parsed.query
                and not parsed.fragment
                and ".." not in parsed.path
                and "\\" not in parsed.path
                and parsed.password is None
            )
            if parsed.scheme == "https" and parsed.username is not None:
                valid_url = False
        except ValueError:
            valid_url = False
        if valid_url:
            return
    elif SCP_REMOTE_RE.fullmatch(remote) and ".." not in remote:
        return
    raise CheckoutError("remote must be an adapter-resolved network Git URL")


def _run_git(
    destination: Path,
    arguments: list[str],
    run: GitRunner,
) -> str:
    command = ["git", "-C", str(destination), *arguments]
    try:
        completed = run(command)
    except OSError as exc:
        raise CheckoutError("git command could not be started") from exc
    if completed.returncode != 0:
        raise CheckoutError("git command failed")
    return (completed.stdout or "").strip()


def _cleanup_created_destination(destination: Path) -> None:
    if destination.is_dir() and not destination.is_symlink():
        shutil.rmtree(destination, ignore_errors=True)


def checkout_exact_sha(
    spec: CheckoutSpec,
    *,
    run: GitRunner | None = None,
) -> CheckoutResult:
    """Fetch a trusted ref and check out only its reachable candidate commit.

    The adapter must resolve ``remote`` from an allowlisted repository identity.
    This primitive never consumes credentials and never invokes a shell.
    """

    if not isinstance(spec.request, DeployRequest):
        raise CheckoutError("checkout request must be a validated DeployRequest")
    _validate_remote(spec.remote)
    _, destination = _validate_paths(spec)
    runner = run or _default_runner
    created = False
    try:
        destination.mkdir(mode=0o700)
        created = True
        _run_git(destination, ["init", "--quiet"], runner)
        _run_git(destination, ["remote", "add", "origin", spec.remote], runner)
        _run_git(
            destination,
            ["fetch", "--no-tags", "--force", "origin", spec.request.trusted_ref],
            runner,
        )
        _run_git(
            destination,
            ["cat-file", "-e", f"{spec.request.candidate_sha}^{{commit}}"],
            runner,
        )
        _run_git(
            destination,
            [
                "merge-base",
                "--is-ancestor",
                spec.request.candidate_sha,
                "FETCH_HEAD",
            ],
            runner,
        )
        _run_git(
            destination,
            ["checkout", "--detach", "--force", spec.request.candidate_sha],
            runner,
        )
        head_sha = _run_git(destination, ["rev-parse", "HEAD"], runner)
        if head_sha != spec.request.candidate_sha:
            raise CheckoutError("checked out HEAD does not match candidate SHA")
        return CheckoutResult(
            path=destination,
            head_sha=head_sha,
            trusted_ref=spec.request.trusted_ref,
        )
    except CheckoutError:
        if created:
            _cleanup_created_destination(destination)
        raise


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
