"""Verify that a promoted OCI tag resolves to the expected immutable digest."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence


DIGEST_PATTERN = re.compile(r"^\s*Digest:\s+(sha256:[0-9a-f]{64})\s*$", re.MULTILINE)
DEFAULT_ATTEMPTS = 5
DEFAULT_INITIAL_DELAY_SECONDS = 2.0


class DigestVerificationError(RuntimeError):
    """Raised when a promoted tag never resolves to the verified digest."""


def extract_digest(output: str) -> str | None:
    """Extract the digest printed by ``docker buildx imagetools inspect``."""
    match = DIGEST_PATTERN.search(output)
    return match.group(1) if match else None


def verify_published_digest(
    image_ref: str,
    expected_digest: str,
    *,
    attempts: int = DEFAULT_ATTEMPTS,
    initial_delay_seconds: float = DEFAULT_INITIAL_DELAY_SECONDS,
    run_command: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    sleep: Callable[[float], None] = time.sleep,
    emit: Callable[[str], None] = print,
) -> str:
    """Verify a registry tag with bounded retries for read-after-write lag.

    A successful first inspection remains a single registry read. Retries are
    used only when inspection fails or returns a different/missing digest.
    The function never accepts a mismatched digest and remains fail-closed
    after the bounded retry window.
    """
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest):
        raise DigestVerificationError("expected digest is not a valid immutable sha256 digest")
    if attempts < 1:
        raise DigestVerificationError("attempts must be at least 1")
    if initial_delay_seconds < 0:
        raise DigestVerificationError("initial delay must not be negative")

    last_output = ""
    last_returncode: int | None = None
    delay = initial_delay_seconds

    for attempt in range(1, attempts + 1):
        completed = run_command(
            ["docker", "buildx", "imagetools", "inspect", image_ref],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        last_output = completed.stdout or ""
        last_returncode = completed.returncode
        observed_digest = extract_digest(last_output)

        if completed.returncode == 0 and observed_digest == expected_digest:
            return observed_digest

        if attempt < attempts:
            reason = (
                f"command exit {completed.returncode}"
                if completed.returncode != 0
                else f"observed digest {observed_digest or '<missing>'}"
            )
            emit(
                "::warning::GHCR digest verification attempt "
                f"{attempt}/{attempts} failed ({reason}); retrying"
            )
            sleep(delay)
            delay *= 2

    detail = " ".join(last_output.split())[-400:]
    suffix = f"; last output: {detail}" if detail else ""
    raise DigestVerificationError(
        f"promoted image digest did not match after {attempts} attempt(s) "
        f"(last exit {last_returncode}){suffix}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    parser.add_argument(
        "--initial-delay-seconds",
        type=float,
        default=DEFAULT_INITIAL_DELAY_SECONDS,
    )
    args = parser.parse_args(argv)

    try:
        verify_published_digest(
            args.image_ref,
            args.expected_digest,
            attempts=args.attempts,
            initial_delay_seconds=args.initial_delay_seconds,
        )
    except DigestVerificationError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
