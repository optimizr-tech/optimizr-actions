"""Run one bounded Docker Compose pull and rebuild remediation attempt."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Callable, Sequence


_ALLOWED_ROOT = Path("/opt/optimizr")
_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_COMMAND_TIMEOUT = 1800


class RebuildError(ValueError):
    """Raised when rebuild inputs or fixed Docker commands violate the contract."""


Runner = Callable[[Sequence[str], Path], int]


def _run(argv: Sequence[str], cwd: Path) -> int:
    try:
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            check=False,
            timeout=_COMMAND_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RebuildError(f"Docker command unavailable: {type(exc).__name__}") from exc
    return completed.returncode


def _validate_deploy_path(deploy_path: Path, allowed_root: Path) -> Path:
    if not deploy_path.is_absolute():
        raise RebuildError("deploy_path must be absolute")
    root = allowed_root.resolve(strict=True)
    resolved = deploy_path.resolve(strict=True)
    if resolved == root or not resolved.is_relative_to(root):
        raise RebuildError("deploy_path must remain below /opt/optimizr")
    current = Path(resolved.anchor)
    for part in resolved.parts[1:]:
        current /= part
        if current.is_symlink():
            raise RebuildError("deploy_path must not contain symlink components")
    if not resolved.is_dir():
        raise RebuildError("deploy_path must be an existing directory")
    return resolved


def _validate_compose_file(deploy_path: Path, compose_file: str) -> str:
    if not compose_file or "\\" in compose_file:
        raise RebuildError("compose_file must be repository relative")
    pure = PurePosixPath(compose_file)
    if pure.is_absolute() or ".." in pure.parts:
        raise RebuildError("compose_file must remain below deploy_path")
    candidate = deploy_path / pure.as_posix()
    resolved = candidate.resolve(strict=True)
    if (
        candidate.is_symlink()
        or not resolved.is_file()
        or not resolved.is_relative_to(deploy_path)
    ):
        raise RebuildError(
            "compose_file must be a regular non-symlink file below deploy_path"
        )
    return pure.as_posix()


def _services(raw: str) -> list[str]:
    values = raw.split()
    if len(values) > 100:
        raise RebuildError("service list exceeds 100 entries")
    if any(not _SERVICE_RE.fullmatch(value) for value in values):
        raise RebuildError("invalid Compose service name")
    return list(dict.fromkeys(values))


def run_remediation(
    *,
    deploy_path: Path,
    compose_file: str,
    build_all: bool,
    required_services: str,
    optional_services: str,
    no_cache: bool,
    allowed_root: Path = _ALLOWED_ROOT,
    runner: Runner = _run,
) -> str:
    """Execute exactly one fixed pull/build pass and return optional build state."""
    root = _validate_deploy_path(deploy_path, allowed_root)
    compose = _validate_compose_file(root, compose_file)
    required = _services(required_services)
    optional = _services(optional_services)
    if build_all and (required or optional):
        raise RebuildError("build_all cannot be combined with service lists")
    if not build_all and not required and not optional:
        # Pull-only remediation remains useful for Compose services using registry images.
        pass

    prefix = ["sudo", "docker", "compose", "-f", compose]
    if runner([*prefix, "pull", "--ignore-buildable"], root) != 0:
        raise RebuildError("Compose pull failed")

    build_options = ["--pull"]
    if no_cache:
        build_options.append("--no-cache")

    if build_all:
        if runner([*prefix, "build", *build_options], root) != 0:
            raise RebuildError("Compose rebuild failed")
    else:
        for service in required:
            if runner([*prefix, "build", *build_options, service], root) != 0:
                raise RebuildError(f"required service rebuild failed: {service}")

    optional_result = "skipped"
    if optional:
        optional_result = "passed"
        for service in optional:
            if runner([*prefix, "build", *build_options, service], root) != 0:
                print(
                    f"::warning title={service} remediation build failed::"
                    "Keeping the previous image"
                )
                optional_result = "failed"
    return optional_result


def _boolean(raw: str) -> bool:
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise argparse.ArgumentTypeError("boolean value must be true or false")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deploy-path", type=Path, required=True)
    parser.add_argument("--compose-file", default="docker-compose.yml")
    parser.add_argument("--build-all", type=_boolean, default=False)
    parser.add_argument("--required-services", default="")
    parser.add_argument("--optional-services", default="")
    parser.add_argument("--no-cache", type=_boolean, default=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = run_remediation(
            deploy_path=args.deploy_path,
            compose_file=args.compose_file,
            build_all=args.build_all,
            required_services=args.required_services,
            optional_services=args.optional_services,
            no_cache=args.no_cache,
        )
        print(f"optional_build_result={result}")
        return 0
    except (OSError, RebuildError) as exc:
        print(f"security rebuild error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
