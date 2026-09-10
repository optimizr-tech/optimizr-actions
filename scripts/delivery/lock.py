"""Provide an exclusive, provider-neutral lock for one delivery service."""

from __future__ import annotations

from contextlib import contextmanager
import math
import os
from pathlib import Path
import re
import time
from collections.abc import Iterator

from .checkout import CheckoutError, _absolute, _reject_symlink_components


class DeliveryLockError(ValueError):
    """Raised when a delivery service cannot acquire its protected lock."""


SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_LOCK_TIMEOUT_SECONDS = 3600.0


def _validate_timeout(timeout_seconds: float) -> float:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds < 0
        or timeout_seconds > MAX_LOCK_TIMEOUT_SECONDS
    ):
        raise DeliveryLockError("lock timeout must be between 0 and 3600 seconds")
    return float(timeout_seconds)


def _validate_root(lock_root: Path) -> Path:
    raw_root = _absolute(Path(lock_root))
    try:
        _reject_symlink_components(raw_root)
    except CheckoutError as exc:
        raise DeliveryLockError(
            "lock root must not contain symlink components"
        ) from exc
    try:
        root = raw_root.resolve(strict=True)
    except OSError as exc:
        raise DeliveryLockError("lock root could not be resolved") from exc
    if not root.is_dir() or root.parent == root:
        raise DeliveryLockError("lock root must be an existing non-root directory")
    return root


def _validate_service(service: str) -> str:
    if not isinstance(service, str) or not SERVICE_RE.fullmatch(service):
        raise DeliveryLockError("service must be a bounded identifier")
    return service


def _try_lock(fd: int) -> bool:
    if os.name == "nt":
        import msvcrt

        if os.fstat(fd).st_size == 0:
            os.write(fd, b"0")
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - unsupported runtime
        raise DeliveryLockError("runtime does not support file locking") from exc

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    except OSError as exc:
        if exc.errno in {11, 13}:  # EAGAIN/EACCES on supported POSIX hosts.
            return False
        raise DeliveryLockError("service lock could not be acquired") from exc
    return True


def _unlock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def service_lock(
    lock_root: Path,
    service: str,
    *,
    timeout_seconds: float = 0,
) -> Iterator[None]:
    """Hold an advisory OS lock scoped to one validated service name.

    Lock files are intentionally retained after release. POSIX ``flock`` and
    the Windows equivalent release the active lock when the descriptor closes,
    so stale process files do not block later deployments.
    """

    root = _validate_root(lock_root)
    service_name = _validate_service(service)
    timeout = _validate_timeout(timeout_seconds)
    lock_path = root / f"{service_name}.lock"
    if lock_path.is_symlink():
        raise DeliveryLockError("service lock path must not be a symlink")

    flags = os.O_RDWR | os.O_CREAT
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(lock_path, flags | no_follow, 0o600)
    except OSError as exc:
        raise DeliveryLockError("service lock could not be opened") from exc

    acquired = False
    deadline = time.monotonic() + timeout
    try:
        os.chmod(lock_path, 0o600)
        while True:
            if _try_lock(fd):
                acquired = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeliveryLockError("timed out waiting for service lock")
            time.sleep(min(0.05, remaining))

        try:
            yield
        finally:
            if acquired:
                _unlock(fd)
    finally:
        os.close(fd)
