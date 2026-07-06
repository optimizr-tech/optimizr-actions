#!/usr/bin/env python3
"""Validate required GitHub Actions secrets/vars before deploy ``prepare-env``.

Consumers pass the key list via ``--required-keys`` (CSV) or the
``REQUIRED_DEPLOY_KEYS`` environment variable. Used by the
``validate-deploy-env`` composite action (issue #93).
"""

from __future__ import annotations

import argparse
import os
import sys


def _parse_keys(raw: str) -> tuple[str, ...]:
    return tuple(k.strip() for k in raw.split(",") if k.strip())


def missing_required(
    required_keys: tuple[str, ...],
    env: dict[str, str] | None = None,
) -> list[str]:
    """Return names of required deploy keys that are absent or blank.

    Parameters
    ----------
    required_keys:
        Keys that must be non-empty in ``env``.
    env:
        Environment mapping to inspect. Defaults to ``os.environ``.

    Returns
    -------
    list[str]
        Sorted list of missing key names. Empty when all required keys are set.
    """
    source = env if env is not None else os.environ
    missing: list[str] = []
    for key in required_keys:
        if not (source.get(key) or "").strip():
            missing.append(key)
    return sorted(missing)


def validate(required_keys: tuple[str, ...], env: dict[str, str] | None = None) -> None:
    """Raise ``SystemExit(1)`` when any required deploy key is missing.

    Parameters
    ----------
    required_keys:
        Keys that must be non-empty in ``env``.
    env:
        Environment mapping to inspect. Defaults to ``os.environ``.

    Raises
    ------
    SystemExit
        Exit code ``1`` when one or more required keys are missing.
    """
    absent = missing_required(required_keys, env)
    if absent:
        print(f"Missing required GitHub Secrets/Variables: {' '.join(absent)}", file=sys.stderr)
        raise SystemExit(1)


def resolve_required_keys(cli_keys: str | None) -> tuple[str, ...]:
    """Resolve required keys from CLI CSV or ``REQUIRED_DEPLOY_KEYS`` env."""
    raw = (cli_keys or os.environ.get("REQUIRED_DEPLOY_KEYS") or "").strip()
    if not raw:
        raise SystemExit(
            "No required keys configured. Pass --required-keys or set REQUIRED_DEPLOY_KEYS."
        )
    return _parse_keys(raw)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for workflow ``prepare-env`` validation step."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--required-keys",
        default=None,
        help="Comma-separated secret/var names (fallback: REQUIRED_DEPLOY_KEYS env)",
    )
    args = parser.parse_args(argv)
    keys = resolve_required_keys(args.required_keys)
    validate(keys)
    print(f"All required deploy secrets/vars present ({len(keys)} keys).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
