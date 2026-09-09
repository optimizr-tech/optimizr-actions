"""Validate the trust boundary for a hosted TestSprite run."""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import re
import sys
from urllib.parse import urlsplit


class ContractError(ValueError):
    """Raised when a TestSprite execution contract is unsafe or incomplete."""


def _parse_json_list(raw: str, field: str) -> list[str]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ContractError(f"{field} must be a JSON array") from exc
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ContractError(f"{field} must be a non-empty JSON array of strings")
    return [item.strip() for item in value]


def _validate_url(value: str, field: str) -> str:
    if not value or any(character.isspace() for character in value):
        raise ContractError(f"{field} must be a non-empty URL without whitespace")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
    except ValueError as exc:
        raise ContractError(f"{field} is not a valid URL") from exc
    if parsed.scheme.lower() != "https":
        raise ContractError(f"{field} must use HTTPS")
    if not hostname or parsed.username or parsed.password:
        raise ContractError(f"{field} must contain only a public HTTPS target")
    if parsed.query or parsed.fragment:
        raise ContractError(f"{field} must not contain a query or fragment")

    host = hostname.rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(
        (".localhost", ".local", ".internal")
    ):
        raise ContractError(f"{field} must not target a local hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ContractError(f"{field} must use a DNS hostname, not an IP address")
    return host


def _validate_environment(environment_name: str) -> None:
    normalized = environment_name.strip().lower()
    if not normalized:
        raise ContractError("environment_name is required")
    if re.search(r"(?:^|[-_])(prod|production)(?:$|[-_])", normalized):
        raise ContractError("environment_name must not identify production")
    if not re.search(r"(?:staging|preview|test|qa|homolog|sandbox)", normalized):
        raise ContractError(
            "environment_name must identify a non-production test environment"
        )


def _validate_forbidden_hosts(raw: str, hostname: str) -> None:
    patterns = _parse_json_list(raw, "forbidden_hosts_json") if raw else []
    for pattern in patterns:
        normalized = pattern.lower()
        if any(character.isspace() for character in normalized) or "/" in normalized:
            raise ContractError("forbidden_hosts_json must contain host patterns only")
        if fnmatch.fnmatchcase(hostname, normalized):
            raise ContractError("base_url matches a forbidden host pattern")


def validate_contract(
    *,
    base_url: str,
    expected_base_url: str,
    runner_json: str,
    environment_name: str,
    forbidden_hosts_json: str = "[]",
    event_name: str,
    ref: str,
    suite_path: str = "testsprite_tests",
) -> None:
    """Validate all inputs that must hold before a secret-bearing job starts."""

    if event_name not in {"push", "workflow_dispatch"} or ref != "refs/heads/main":
        raise ContractError("TestSprite runs are restricted to trusted main execution")

    labels = {label.lower() for label in _parse_json_list(runner_json, "runner_json")}
    if "self-hosted" not in labels or "linux" not in labels:
        raise ContractError("runner_json must include self-hosted and Linux labels")

    _validate_environment(environment_name)
    base_host = _validate_url(base_url, "base_url")
    expected_host = _validate_url(expected_base_url, "expected_base_url")
    if base_url != expected_base_url:
        raise ContractError("base_url must exactly match expected_base_url")
    if base_host != expected_host:
        raise ContractError("base_url and expected_base_url hostnames differ")
    _validate_forbidden_hosts(forbidden_hosts_json, base_host)

    if (
        not suite_path
        or suite_path.startswith(("/", "\\"))
        or "\\" in suite_path
        or any(part in {"", ".", ".."} for part in suite_path.split("/"))
    ):
        raise ContractError("suite_path must be a relative POSIX path without traversal")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--expected-base-url", required=True)
    parser.add_argument("--runner-json", required=True)
    parser.add_argument("--environment-name", required=True)
    parser.add_argument("--forbidden-hosts-json", default="[]")
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--suite-path", default="testsprite_tests")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        validate_contract(**vars(args))
    except ContractError as exc:
        print(f"TestSprite contract rejected: {exc}", file=sys.stderr)
        return 1
    print("TestSprite contract validated for a trusted non-production target")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
