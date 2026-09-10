"""Build a protected manual adapter around the shared delivery executor."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .checkout import CheckoutSpec, checkout_exact_sha
from .executor import (
    DeliveryExecutorResult,
    DeliveryExecutorSpec,
    CheckoutRunner,
    GateRunner,
    SyncRunner,
    execute_delivery,
)
from .request import DeployRequest, RequestError, load_request
from .snapshot_sync import SyncSpec, sync_deployment


class ManualAdapterError(ValueError):
    """Raised when a reviewed manual delivery request is unsafe."""


@dataclass(frozen=True)
class ManualAdapterSpec:
    """Explicit, host-supplied configuration for one manual delivery."""

    request_path: Path
    request_root: Path
    confirmation: str
    remote_allowlist: Mapping[str, str]
    checkout_root: Path
    deploy_root: Path
    snapshot_root: Path
    lock_root: Path
    snapshot_enabled: bool = True
    deployignore: Path | None = None
    exclude_compose_file: str | None = None
    snapshot_name: str | None = None
    lock_timeout_seconds: float = 0


@dataclass(frozen=True)
class ManualDeliveryPlan:
    """Validated request plus the shared executor specification it produces."""

    request: DeployRequest
    executor: DeliveryExecutorSpec


def confirmation_for(request: DeployRequest) -> str:
    """Return the literal confirmation required for this exact service/SHA."""

    return f"DEPLOY {request.service} {request.candidate_sha}"


def _load_manual_request(config: ManualAdapterSpec) -> DeployRequest:
    try:
        request = load_request(config.request_path, config.request_root)
    except (RequestError, OSError, TypeError) as exc:
        raise ManualAdapterError("manual request rejected") from exc
    if request.adapter != "manual":
        raise ManualAdapterError("manual adapter requires a manual request")
    if config.confirmation != confirmation_for(request):
        raise ManualAdapterError("confirmation must match the exact service and SHA")
    return request


def _resolve_remote(
    request: DeployRequest,
    remote_allowlist: Mapping[str, str],
) -> str:
    if not isinstance(remote_allowlist, Mapping):
        raise ManualAdapterError("remote allowlist is required")
    try:
        remote = remote_allowlist[request.repository]
    except (KeyError, TypeError) as exc:
        raise ManualAdapterError(
            "repository is not in the manual remote allowlist"
        ) from exc
    if not isinstance(remote, str) or not remote:
        raise ManualAdapterError("manual remote allowlist entry is invalid")
    return remote


def build_manual_plan(config: ManualAdapterSpec) -> ManualDeliveryPlan:
    """Validate manual authorization and build, but do not execute, a plan."""

    if not isinstance(config, ManualAdapterSpec):
        raise ManualAdapterError("manual adapter specification is invalid")
    if not isinstance(config.snapshot_enabled, bool):
        raise ManualAdapterError("snapshot_enabled must be boolean")

    request = _load_manual_request(config)
    remote = _resolve_remote(request, config.remote_allowlist)
    try:
        checkout_destination = (
            Path(config.checkout_root)
            / f"{request.service}-{request.candidate_sha}"
        )
        destination = Path(config.deploy_root) / request.service
        checkout = CheckoutSpec(
            request=request,
            remote=remote,
            destination=checkout_destination,
            allowed_root=Path(config.checkout_root),
        )
        sync = SyncSpec(
            source=checkout_destination,
            destination=destination,
            snapshot_root=Path(config.snapshot_root),
            source_root=Path(config.checkout_root),
            destination_root=Path(config.deploy_root),
            snapshot_enabled=config.snapshot_enabled,
            deployignore=config.deployignore,
            exclude_compose_file=config.exclude_compose_file,
            snapshot_name=config.snapshot_name,
        )
        executor = DeliveryExecutorSpec(
            checkout=checkout,
            sync=sync,
            lock_root=Path(config.lock_root),
            lock_timeout_seconds=config.lock_timeout_seconds,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise ManualAdapterError("manual delivery paths are invalid") from exc
    return ManualDeliveryPlan(request=request, executor=executor)


def execute_manual_delivery(
    config: ManualAdapterSpec,
    *,
    run_gates: GateRunner,
    checkout: CheckoutRunner = checkout_exact_sha,
    sync: SyncRunner = sync_deployment,
) -> DeliveryExecutorResult:
    """Execute a confirmed manual plan through the shared executor only."""

    plan = build_manual_plan(config)
    return execute_delivery(
        plan.executor,
        run_gates=run_gates,
        checkout=checkout,
        sync=sync,
    )
