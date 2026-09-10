"""Build shared executor specifications for provider-specific adapters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .checkout import CheckoutSpec
from .executor import DeliveryExecutorSpec
from .request import DeployRequest
from .snapshot_sync import SyncSpec


class DeliveryPlanError(ValueError):
    """Raised when an adapter cannot construct a shared delivery plan."""


@dataclass(frozen=True)
class DeliveryPathSpec:
    """Host paths and synchronization options shared by all adapters."""

    checkout_root: Path
    deploy_root: Path
    snapshot_root: Path
    lock_root: Path
    snapshot_enabled: bool = True
    deployignore: Path | None = None
    exclude_compose_file: str | None = None
    snapshot_name: str | None = None
    lock_timeout_seconds: float = 0


def build_executor_spec(
    request: DeployRequest,
    remote: str,
    paths: DeliveryPathSpec,
) -> DeliveryExecutorSpec:
    """Build the one executor specification used by every delivery adapter."""

    if not isinstance(request, DeployRequest):
        raise DeliveryPlanError("delivery request must be validated")
    if not isinstance(remote, str) or not remote:
        raise DeliveryPlanError("delivery remote is invalid")
    if not isinstance(paths, DeliveryPathSpec):
        raise DeliveryPlanError("delivery paths are invalid")
    try:
        checkout_destination = (
            Path(paths.checkout_root)
            / f"{request.service}-{request.candidate_sha}"
        )
        destination = Path(paths.deploy_root) / request.service
        checkout = CheckoutSpec(
            request=request,
            remote=remote,
            destination=checkout_destination,
            allowed_root=Path(paths.checkout_root),
        )
        sync = SyncSpec(
            source=checkout_destination,
            destination=destination,
            snapshot_root=Path(paths.snapshot_root),
            source_root=Path(paths.checkout_root),
            destination_root=Path(paths.deploy_root),
            snapshot_enabled=paths.snapshot_enabled,
            deployignore=paths.deployignore,
            exclude_compose_file=paths.exclude_compose_file,
            snapshot_name=paths.snapshot_name,
        )
        return DeliveryExecutorSpec(
            checkout=checkout,
            sync=sync,
            lock_root=Path(paths.lock_root),
            lock_timeout_seconds=paths.lock_timeout_seconds,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise DeliveryPlanError("delivery paths are invalid") from exc
