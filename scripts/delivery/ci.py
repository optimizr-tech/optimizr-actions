"""Thin protected CI adapters for the shared delivery executor."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
import re

from .checkout import checkout_exact_sha
from .executor import (
    DeliveryExecutorResult,
    DeliveryExecutorSpec,
    CheckoutRunner,
    GateRunner,
    SyncRunner,
    execute_delivery,
)
from .plan import DeliveryPathSpec, DeliveryPlanError, build_executor_spec
from .request import DeployRequest, RequestError, load_request
from .snapshot_sync import sync_deployment


class CiAdapterError(ValueError):
    """Raised when a CI adapter cannot prove protected execution."""


CI_PROVIDERS = frozenset({"github-actions", "gitlab-ci"})
SECRET_LIKE_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|authorization|cookie|"
    r"private[_ .-]?key)\s*[:=]|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
)


@dataclass(frozen=True)
class CiAdapterSpec:
    """Provider signals and host paths required for one protected CI run."""

    provider: str
    request_path: Path
    request_root: Path
    remote_allowlist: Mapping[str, str]
    checkout_root: Path
    deploy_root: Path
    snapshot_root: Path
    lock_root: Path
    runner_name: str
    protected_ref: bool
    protected_runner: bool
    snapshot_enabled: bool = True
    deployignore: Path | None = None
    exclude_compose_file: str | None = None
    snapshot_name: str | None = None
    lock_timeout_seconds: float = 0


@dataclass(frozen=True)
class CiDeliveryPlan:
    """Validated CI identity and the shared executor specification."""

    provider: str
    runner_name: str
    protected_ref: bool
    protected_runner: bool
    request: DeployRequest
    executor: DeliveryExecutorSpec


def _runner_name(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CiAdapterError("runner_name must be a non-empty trimmed string")
    if "\n" in value or "\r" in value:
        raise CiAdapterError("runner_name must be single-line")
    if len(value) > 256:
        raise CiAdapterError("runner_name exceeds 256 characters")
    if SECRET_LIKE_RE.search(value):
        raise CiAdapterError("runner_name contains prohibited secret-like data")
    return value


def _load_ci_request(config: CiAdapterSpec) -> DeployRequest:
    try:
        request = load_request(config.request_path, config.request_root)
    except (RequestError, OSError, TypeError) as exc:
        raise CiAdapterError("CI delivery request rejected") from exc
    if request.adapter != config.provider:
        raise CiAdapterError("request adapter does not match the CI provider")
    return request


def _resolve_remote(
    request: DeployRequest,
    remote_allowlist: Mapping[str, str],
) -> str:
    if not isinstance(remote_allowlist, Mapping):
        raise CiAdapterError("repository remote allowlist is required")
    try:
        remote = remote_allowlist[request.repository]
    except (KeyError, TypeError) as exc:
        raise CiAdapterError("repository is not in the CI remote allowlist") from exc
    if not isinstance(remote, str) or not remote:
        raise CiAdapterError("CI remote allowlist entry is invalid")
    return remote


def build_ci_plan(config: CiAdapterSpec) -> CiDeliveryPlan:
    """Require protected provider signals before building the shared plan."""

    if not isinstance(config, CiAdapterSpec):
        raise CiAdapterError("CI adapter specification is invalid")
    if config.provider not in CI_PROVIDERS:
        raise CiAdapterError("provider must be GitHub Actions or GitLab CI")
    if not isinstance(config.protected_ref, bool) or not config.protected_ref:
        raise CiAdapterError("protected ref is required")
    if not isinstance(config.protected_runner, bool) or not config.protected_runner:
        raise CiAdapterError("protected runner is required")
    runner_name = _runner_name(config.runner_name)
    request = _load_ci_request(config)
    remote = _resolve_remote(request, config.remote_allowlist)
    try:
        executor = build_executor_spec(
            request,
            remote,
            DeliveryPathSpec(
                checkout_root=config.checkout_root,
                deploy_root=config.deploy_root,
                snapshot_root=config.snapshot_root,
                lock_root=config.lock_root,
                snapshot_enabled=config.snapshot_enabled,
                deployignore=config.deployignore,
                exclude_compose_file=config.exclude_compose_file,
                snapshot_name=config.snapshot_name,
                lock_timeout_seconds=config.lock_timeout_seconds,
            ),
        )
    except DeliveryPlanError as exc:
        raise CiAdapterError("CI delivery paths are invalid") from exc
    return CiDeliveryPlan(
        provider=config.provider,
        runner_name=runner_name,
        protected_ref=config.protected_ref,
        protected_runner=config.protected_runner,
        request=request,
        executor=executor,
    )


def execute_ci_delivery(
    config: CiAdapterSpec,
    *,
    run_gates: GateRunner,
    checkout: CheckoutRunner = checkout_exact_sha,
    sync: SyncRunner = sync_deployment,
) -> DeliveryExecutorResult:
    """Execute a protected CI plan through the shared executor only."""

    plan = build_ci_plan(config)
    return execute_delivery(
        plan.executor,
        run_gates=run_gates,
        checkout=checkout,
        sync=sync,
    )
