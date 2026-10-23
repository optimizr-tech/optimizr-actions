"""Run one registry/network command with bounded retry on transient failures.

Self-hosted runners can lose DNS or egress for a few seconds when the host is
saturated ("no route to host", "Could not resolve host"). This wrapper retries
only failures whose output matches a known transient network signature, with a
short exponential backoff and a hard attempt cap. Everything else fails closed
on the first attempt:

* ``permanent`` -- authentication, authorization, missing manifest/tag, or an
  invalid reference. Retrying cannot help and would only hide the cause.
* ``unclassified`` -- no known signature. Treated as non-retryable so an
  unknown failure is never masked by repetition.
* ``transient_exhausted`` -- every attempt failed with a transient signature.

The command is executed without a shell. Standard output is buffered per
attempt and emitted only on success, so a redirect such as ``> index.json``
never receives partial output from a failed attempt. A secret needed on stdin
(``docker login --password-stdin``) is read from an environment variable named
by ``--stdin-env`` so it never appears in argv or logs.

Exit codes: the wrapped command's exit code on failure (127 when it cannot be
executed, 1 when it was killed by a signal), 2 for invalid wrapper arguments.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

MIN_ATTEMPTS = 1
MAX_ATTEMPTS = 5
MAX_BACKOFF_SECONDS = 30
MAX_SLEEP_SECONDS = 60
DEFAULT_ATTEMPTS = 3
DEFAULT_BACKOFF_SECONDS = 5

# Permanent signatures win over transient ones: an "unauthorized" response that
# also mentions a reset connection is still a credential problem.
PERMANENT_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bunauthorized\b",
        r"authentication required",
        r"incorrect username or password",
        r"\bdenied\b",
        r"\b(?:401|403)\b",
        r"\bforbidden\b",
        r"manifest unknown",
        r"name unknown",
        r"no such manifest",
        r"\bnot found\b",
        r"invalid reference format",
        r"repository name must be lowercase",
    )
)
TRANSIENT_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"no route to host",
        r"network is unreachable",
        r"could not resolve host",
        r"temporary failure in name resolution",
        r"no such host",
        r"server misbehaving",
        r"i/o timeout",
        r"tls handshake timeout",
        r"context deadline exceeded",
        r"(?:operation|connection) timed out",
        r"timeout exceeded while awaiting headers",
        r"connection reset by peer",
        r"connection refused",
        r"broken pipe",
        r"unexpected eof",
        r"request canceled",
        r"\b(?:502 bad gateway|503 service unavailable|504 gateway timeout)\b",
        r"unexpected (?:http )?status(?: code)?:? (?:429|5\d\d)",
        r"toomanyrequests|too many requests",
    )
)

Runner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class RetryResult:
    returncode: int
    attempts: int
    classification: str
    stdout: str = ""


def classify(output: str) -> str:
    """Return ``permanent``, ``transient`` or ``unclassified`` for a failure."""
    if any(pattern.search(output) for pattern in PERMANENT_PATTERNS):
        return "permanent"
    if any(pattern.search(output) for pattern in TRANSIENT_PATTERNS):
        return "transient"
    return "unclassified"


def backoff_delay(base_seconds: int, attempt: int) -> int:
    """Exponential delay after ``attempt`` (1-based), capped at 60 seconds."""
    return min(base_seconds * (2 ** (attempt - 1)), MAX_SLEEP_SECONDS)


def validate_bounds(attempts: int, backoff_seconds: int) -> None:
    if not MIN_ATTEMPTS <= attempts <= MAX_ATTEMPTS:
        raise ValueError(f"retry attempts must be an integer between {MIN_ATTEMPTS} and {MAX_ATTEMPTS}")
    if not 0 <= backoff_seconds <= MAX_BACKOFF_SECONDS:
        raise ValueError(f"retry backoff seconds must be an integer between 0 and {MAX_BACKOFF_SECONDS}")


def run_with_retry(
    command: Sequence[str],
    *,
    label: str,
    attempts: int = DEFAULT_ATTEMPTS,
    backoff_seconds: int = DEFAULT_BACKOFF_SECONDS,
    stdin_text: str | None = None,
    prior_failed_attempts: int = 0,
    runner: Runner = subprocess.run,
    sleep: Callable[[float], None] = time.sleep,
    emit: Callable[[str], None] = lambda message: print(message, file=sys.stderr, flush=True),
) -> RetryResult:
    """Run ``command`` and retry only transient network failures."""
    validate_bounds(attempts, backoff_seconds)
    if not command:
        raise ValueError("a command is required after --")
    if not 0 <= prior_failed_attempts < MAX_ATTEMPTS:
        raise ValueError(f"prior failed attempts must be an integer between 0 and {MAX_ATTEMPTS - 1}")

    if prior_failed_attempts >= attempts:
        emit(
            f"::error title=Registry network operation failed::{label} failed "
            f"[classification=retry_disabled, attempts={prior_failed_attempts}/{attempts}]: "
            "the initial attempt failed and no retry budget remains"
        )
        return RetryResult(1, prior_failed_attempts, "retry_disabled")
    if prior_failed_attempts:
        # The caller already spent attempts (for example a docker/login-action
        # step); honour the same backoff before continuing the sequence.
        delay = backoff_delay(backoff_seconds, prior_failed_attempts)
        emit(
            f"::warning title=Retrying network operation::{label} initial attempt failed; "
            f"retrying in {delay}s (attempt {prior_failed_attempts + 1}/{attempts})"
        )
        sleep(delay)

    classification = "unclassified"
    returncode = 1
    attempt = prior_failed_attempts
    for attempt in range(prior_failed_attempts + 1, attempts + 1):
        try:
            completed = runner(
                list(command),
                input=stdin_text,
                capture_output=True,
                text=True,
                check=False,
            )
            returncode = completed.returncode
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
        except OSError as error:
            returncode, stdout, stderr = 127, "", f"{label}: {error}"
        if stderr:
            emit(stderr.rstrip("\n"))
        if returncode == 0:
            if attempt > 1:
                emit(f"::notice title=Transient network failure recovered::{label} succeeded on attempt {attempt}/{attempts}")
            return RetryResult(0, attempt, "success" if attempt == 1 else "recovered", stdout)

        returncode = returncode if returncode > 0 else 1
        classification = classify(f"{stdout}\n{stderr}")
        if classification != "transient":
            break
        if attempt < attempts:
            delay = backoff_delay(backoff_seconds, attempt)
            emit(
                f"::warning title=Transient network failure::{label} failed with a transient network error "
                f"(exit {returncode}, attempt {attempt}/{attempts}); retrying in {delay}s"
            )
            sleep(delay)

    final = "transient_exhausted" if classification == "transient" else classification
    reason = {
        "transient_exhausted": f"transient network failure persisted after {attempt} attempt(s)",
        "permanent": "permanent registry error (authentication, authorization, or missing reference); not retried",
        "unclassified": "failure did not match a known transient network signature; not retried",
    }[final]
    emit(
        f"::error title=Registry network operation failed::{label} failed "
        f"[classification={final}, attempts={attempt}/{attempts}, exit={returncode}]: {reason}"
    )
    return RetryResult(returncode, attempt, final)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--label", required=True)
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    parser.add_argument("--backoff-seconds", type=int, default=DEFAULT_BACKOFF_SECONDS)
    parser.add_argument("--stdout-file", default="")
    parser.add_argument("--stdin-env", default="")
    parser.add_argument("--prior-failed-attempts", type=int, default=0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    stdin_text = None
    if args.stdin_env:
        if args.stdin_env not in os.environ:
            print(f"::error::{args.stdin_env} is not set for {args.label}", file=sys.stderr)
            return 2
        stdin_text = os.environ[args.stdin_env]
    try:
        result = run_with_retry(
            command,
            label=args.label,
            attempts=args.attempts,
            backoff_seconds=args.backoff_seconds,
            stdin_text=stdin_text,
            prior_failed_attempts=args.prior_failed_attempts,
        )
    except ValueError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 2
    if result.returncode == 0:
        if args.stdout_file:
            with open(args.stdout_file, "w", encoding="utf-8", newline="") as handle:
                handle.write(result.stdout)
        else:
            sys.stdout.write(result.stdout)
            sys.stdout.flush()
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
