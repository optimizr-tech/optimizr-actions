"""Prepare a local Docker image for an unprivileged Trivy scan."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Callable, Sequence


_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$", re.IGNORECASE)
_MODES = frozenset({"auto", "direct", "sudo"})
CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class ImageTransport:
    status: str
    transport: str
    identity: str = ""
    lineage_digests: tuple[str, ...] = ()
    scan_args: tuple[str, ...] = ()
    failure_reason: str = ""


def _subprocess_runner(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
    )


def _run(argv: Sequence[str], runner: CommandRunner) -> subprocess.CompletedProcess[str] | None:
    try:
        return runner(argv)
    except OSError:
        return None


def _inspect(
    target: str,
    prefix: Sequence[str],
    runner: CommandRunner,
) -> tuple[str, str, tuple[str, ...]]:
    argv = [*prefix, "docker", "image", "inspect", "--format", "{{json .}}", target]
    result = _run(argv, runner)
    if result is None or result.returncode != 0:
        return "", "inspect_failed", ()
    raw = (result.stdout or "").strip().splitlines()[0] if result.stdout else ""
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        # Keep compatibility with simple Docker-compatible runners that return
        # only the old formatted image ID.
        identity = raw
        lineage_digests: tuple[str, ...] = ()
    else:
        if not isinstance(payload, dict):
            return "", "inspect_invalid", ()
        identity = str(payload.get("Id", "")).strip()
        candidates: list[str] = []
        config = payload.get("Config")
        labels = config.get("Labels", {}) if isinstance(config, dict) else {}
        if isinstance(labels, dict):
            base_digest = labels.get("org.opencontainers.image.base.digest")
            if isinstance(base_digest, str):
                candidates.append(base_digest.strip())
        repo_digests = payload.get("RepoDigests", [])
        if isinstance(repo_digests, list):
            for repo_digest in repo_digests:
                if isinstance(repo_digest, str) and "@" in repo_digest:
                    candidates.append(repo_digest.rsplit("@", 1)[1].strip())
        lineage_digests = tuple(
            sorted(
                {
                    digest.lower()
                    for digest in candidates
                    if _IMAGE_ID.fullmatch(digest)
                }
            )
        )
    if not _IMAGE_ID.fullmatch(identity):
        return "", "identity_invalid", ()
    return identity, "", lineage_digests


def _failed(reason: str) -> ImageTransport:
    return ImageTransport(status="failed", transport="", failure_reason=reason)


def prepare_image_transport(
    target: str,
    *,
    mode: str,
    archive: Path,
    runner: CommandRunner = _subprocess_runner,
    uid: int | None = None,
    gid: int | None = None,
) -> ImageTransport:
    """Resolve an immutable image ID and prepare the safest scan arguments.

    ``direct`` keeps Trivy on the local image path when the runner can read the
    Docker daemon. ``sudo`` always exports through non-interactive sudo so
    Trivy remains unprivileged. ``auto`` preserves the old compatibility path
    by trying direct access before the sudo archive fallback.
    """
    if mode not in _MODES:
        return _failed("docker_mode_invalid")
    if not target.strip():
        return _failed("docker_target_missing")

    identity = ""
    if mode in {"auto", "direct"}:
        identity, inspect_error, lineage_digests = _inspect(target, (), runner)
        if identity:
            return ImageTransport(
                status="ready",
                transport="direct",
                identity=identity,
                lineage_digests=lineage_digests,
            )
        if mode == "direct":
            return _failed(
                "docker_identity_invalid"
                if inspect_error == "identity_invalid"
                else "docker_direct_inspect_failed"
            )

    identity, inspect_error, lineage_digests = _inspect(target, ("sudo", "-n"), runner)
    if not identity:
        if inspect_error == "identity_invalid":
            return _failed("docker_identity_invalid")
        return _failed("docker_sudo_inspect_failed" if mode == "sudo" else "docker_access_failed")

    uid_text = str(os.getuid() if uid is None and hasattr(os, "getuid") else (uid or 0))
    gid_text = str(os.getgid() if gid is None and hasattr(os, "getgid") else (gid or 0))
    try:
        archive.parent.mkdir(parents=True, exist_ok=True)
        archive.unlink(missing_ok=True)
    except OSError:
        return _failed("docker_archive_prepare_failed")

    save = _run(
        ["sudo", "-n", "docker", "save", target, "-o", str(archive)],
        runner,
    )
    if save is None or save.returncode != 0:
        archive.unlink(missing_ok=True)
        return _failed("docker_save_failed")
    if not archive.is_file() or archive.is_symlink():
        archive.unlink(missing_ok=True)
        return _failed("docker_archive_missing")

    chown = _run(
        ["sudo", "-n", "chown", f"{uid_text}:{gid_text}", str(archive)],
        runner,
    )
    if chown is None or chown.returncode != 0:
        archive.unlink(missing_ok=True)
        return _failed("docker_archive_ownership_failed")

    return ImageTransport(
        status="ready",
        transport="archive",
        identity=identity,
        lineage_digests=lineage_digests,
        scan_args=("--input", str(archive)),
    )


def _write_result(path: Path, result: ImageTransport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("transport output must not be a symbolic link")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(
            {key: value for key, value in asdict(result).items() if key != "scan_args"},
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--mode", choices=sorted(_MODES), required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--uid", type=int)
    parser.add_argument("--gid", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = prepare_image_transport(
        args.target,
        mode=args.mode,
        archive=args.archive,
        uid=args.uid,
        gid=args.gid,
    )
    _write_result(args.output, result)
    if result.status == "ready":
        return 0
    print(result.failure_reason)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
