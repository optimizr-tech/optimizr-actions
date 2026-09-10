"""Synchronize a trusted checkout without overwriting runtime state."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile

from .checkout import _absolute, _reject_symlink_components


class SyncError(ValueError):
    """Raised when a protected deployment synchronization cannot proceed."""


RsyncRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]
SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.tar\.gz$")
PRIVATE_SUFFIXES = (".pem", ".key", ".p12", ".pfx")


@dataclass(frozen=True)
class SyncSpec:
    """Validated paths and adapter options for one deployment synchronization."""

    source: Path
    destination: Path
    snapshot_root: Path
    source_root: Path
    destination_root: Path
    snapshot_enabled: bool = True
    deployignore: Path | None = None
    exclude_compose_file: str | None = None
    snapshot_name: str | None = None


@dataclass(frozen=True)
class SyncResult:
    """Secret-free outcome of a dry-run, optional snapshot, and synchronization."""

    changed: bool
    changed_entries: int
    snapshot_created: bool
    snapshot_name: str | None
    synced: bool


def _existing_directory(path: Path, label: str) -> Path:
    raw_path = _absolute(path)
    _reject_symlink_components(raw_path)
    try:
        resolved = raw_path.resolve(strict=True)
    except OSError as exc:
        raise SyncError(f"{label} could not be resolved") from exc
    if not resolved.is_dir():
        raise SyncError(f"{label} must be a directory")
    return resolved


def _directory_below(path: Path, root: Path, label: str) -> Path:
    raw_path = _absolute(path)
    _reject_symlink_components(raw_path)
    try:
        resolved = raw_path.resolve(strict=True)
    except OSError as exc:
        raise SyncError(f"{label} could not be resolved") from exc
    if resolved == root or root not in resolved.parents:
        raise SyncError(f"{label} must remain below its declared root")
    if not resolved.is_dir():
        raise SyncError(f"{label} must be a directory")
    return resolved


def _validate_deployignore(path: Path, source: Path) -> Path:
    raw_path = _absolute(path)
    _reject_symlink_components(raw_path)
    try:
        resolved = raw_path.resolve(strict=True)
    except OSError as exc:
        raise SyncError("deployignore could not be resolved") from exc
    if source not in resolved.parents or not resolved.is_file():
        raise SyncError("deployignore must be a regular file below the source")
    return resolved


def _validate_compose_exclude(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or value != value.strip():
        raise SyncError("excluded compose file must be a relative path")
    if value.startswith(("/", "\\")) or "\\" in value:
        raise SyncError("excluded compose file must be a relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SyncError("excluded compose file must be a relative path")
    return path.as_posix()


def _snapshot_name(value: str | None) -> str:
    name = value or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ.tar.gz")
    if not SNAPSHOT_NAME_RE.fullmatch(name):
        raise SyncError("snapshot name must be a safe .tar.gz filename")
    return name


def _validate_spec(
    spec: SyncSpec,
) -> tuple[Path, Path, Path, Path | None, str | None, str]:
    if not isinstance(spec, SyncSpec):
        raise SyncError("synchronization specification is invalid")
    source_root = _existing_directory(spec.source_root, "source root")
    destination_root = _existing_directory(spec.destination_root, "destination root")
    source = _directory_below(spec.source, source_root, "source")
    destination = _directory_below(spec.destination, destination_root, "destination")
    snapshot_root = _existing_directory(spec.snapshot_root, "snapshot root")
    deployignore = (
        None
        if spec.deployignore is None
        else _validate_deployignore(spec.deployignore, source)
    )
    compose_exclude = _validate_compose_exclude(spec.exclude_compose_file)
    return (
        source,
        destination,
        snapshot_root,
        deployignore,
        compose_exclude,
        _snapshot_name(spec.snapshot_name),
    )


def _rsync_command(
    source: Path,
    destination: Path,
    *,
    deployignore: Path | None,
    compose_exclude: str | None,
    dry_run: bool,
) -> list[str]:
    command = [
        "rsync",
        "-a",
        "--delete",
        "--exclude=.git",
        "--exclude=.github",
        "--exclude=.env",
        "--exclude=.env.*",
        "--exclude=.secrets",
        "--exclude=.secrets/",
        "--exclude=*.pem",
        "--exclude=*.key",
        "--exclude=*.p12",
        "--exclude=*.pfx",
        "--exclude=*.tar.gz",
        "--exclude=backup/",
    ]
    if compose_exclude is not None:
        command.append(f"--exclude={compose_exclude}")
    if deployignore is not None:
        command.append(f"--exclude-from={deployignore}")
    if dry_run:
        command.extend(("--dry-run", "--itemize-changes", "--out-format=%i"))
    command.extend(
        (f"{source.as_posix().rstrip('/')}/", f"{destination.as_posix().rstrip('/')}/")
    )
    return command


def _run_rsync(
    command: list[str], run: RsyncRunner
) -> subprocess.CompletedProcess[str]:
    try:
        completed = run(command)
    except OSError as exc:
        raise SyncError("rsync command could not be started") from exc
    if completed.returncode != 0:
        raise SyncError("rsync command failed")
    return completed


def _snapshot_filter(member: tarfile.TarInfo) -> tarfile.TarInfo | None:
    if member.name == ".":
        return member
    components = tuple(
        component
        for component in PurePosixPath(member.name.replace("\\", "/")).parts
        if component not in {"", "."}
    )
    if any(
        component == ".secrets"
        or component == ".env"
        or component.startswith(".env.")
        or component.lower().endswith(PRIVATE_SUFFIXES)
        or component.lower().endswith(".tar.gz")
        for component in components
    ):
        return None
    if member.issym() or member.islnk():
        return None
    return member


def _create_snapshot(destination: Path, snapshot_root: Path, name: str) -> None:
    snapshot = snapshot_root / name
    if snapshot.exists():
        raise SyncError("snapshot already exists")
    temporary_fd, temporary_name = tempfile.mkstemp(
        prefix=".snapshot-",
        suffix=".tmp",
        dir=snapshot_root,
    )
    os.close(temporary_fd)
    temporary = Path(temporary_name)
    try:
        with tarfile.open(temporary, mode="w:gz", dereference=False) as archive:
            archive.add(
                destination,
                arcname=".",
                recursive=True,
                filter=_snapshot_filter,
            )
        os.chmod(temporary, 0o600)
        os.replace(temporary, snapshot)
    except (OSError, tarfile.TarError) as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise SyncError("snapshot could not be created") from exc


def sync_deployment(
    spec: SyncSpec,
    *,
    run: RsyncRunner | None = None,
) -> SyncResult:
    """Dry-run, snapshot protected runtime state, and synchronize a deployment.

    The source and destination are explicit, confined paths. The command runner
    receives argv directly; shell interpolation and command output never leave
    this primitive.
    """

    source, destination, snapshot_root, deployignore, compose_exclude, name = (
        _validate_spec(spec)
    )
    runner = run or _default_runner
    dry_run = _run_rsync(
        _rsync_command(
            source,
            destination,
            deployignore=deployignore,
            compose_exclude=compose_exclude,
            dry_run=True,
        ),
        runner,
    )
    changed_entries = len((dry_run.stdout or "").splitlines())
    changed = bool((dry_run.stdout or "").strip())
    if not changed:
        return SyncResult(
            changed=False,
            changed_entries=0,
            snapshot_created=False,
            snapshot_name=None,
            synced=False,
        )

    snapshot_created = False
    snapshot_name = None
    if spec.snapshot_enabled:
        _create_snapshot(destination, snapshot_root, name)
        snapshot_created = True
        snapshot_name = name

    _run_rsync(
        _rsync_command(
            source,
            destination,
            deployignore=deployignore,
            compose_exclude=compose_exclude,
            dry_run=False,
        ),
        runner,
    )
    return SyncResult(
        changed=True,
        changed_entries=changed_entries,
        snapshot_created=snapshot_created,
        snapshot_name=snapshot_name,
        synced=True,
    )


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
