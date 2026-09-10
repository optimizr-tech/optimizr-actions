"""Orchestrate the provider-neutral protected delivery preparation flow."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
import re

from .checkout import CheckoutResult, CheckoutSpec, checkout_exact_sha
from .gate_evidence import (
    GateEvidence,
    GateEvidenceError,
    GateEvaluation,
    evaluate_gate_evidence,
)
from .lock import DeliveryLockError, service_lock
from .request import DeployRequest, canonicalize_request
from .snapshot_sync import SyncResult, SyncSpec, sync_deployment


class DeliveryExecutorError(ValueError):
    """Raised when the protected delivery flow cannot continue safely."""


DEFAULT_PREFLIGHT_GATES = ("filesystem", "compose", "security")
DEFAULT_POSTFLIGHT_GATES = ("rollout", "health")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.tar\.gz$")


@dataclass(frozen=True)
class DeliveryExecutorSpec:
    """Explicit inputs for one locked, exact-SHA delivery attempt."""

    checkout: CheckoutSpec
    sync: SyncSpec
    lock_root: Path
    preflight_gates: Sequence[str] = DEFAULT_PREFLIGHT_GATES
    postflight_gates: Sequence[str] = DEFAULT_POSTFLIGHT_GATES
    lock_timeout_seconds: float = 0


@dataclass(frozen=True)
class DeliveryContext:
    """Safe context supplied to a provider-specific gate runner."""

    request: DeployRequest
    checkout: CheckoutResult
    sync: SyncResult | None
    destination: Path


GateRunner = Callable[[DeliveryContext, str], Sequence[GateEvidence]]
CheckoutRunner = Callable[[CheckoutSpec], CheckoutResult]
SyncRunner = Callable[[SyncSpec], SyncResult]


@dataclass(frozen=True)
class DeliveryExecutorResult:
    """Secret-free outcome of the preparation and gate phases."""

    ready: bool
    request: dict[str, str]
    head_sha: str
    trusted_ref: str
    sync: SyncResult | None
    preflight: GateEvaluation
    postflight: GateEvaluation | None
    evidence: tuple[dict[str, str], ...]
    failure_reason: str | None

    @property
    def changed(self) -> bool:
        return bool(self.sync and self.sync.changed)

    @property
    def synced(self) -> bool:
        return bool(self.sync and self.sync.synced)

    @property
    def snapshot_created(self) -> bool:
        return bool(self.sync and self.sync.snapshot_created)

    @property
    def snapshot_name(self) -> str | None:
        return self.sync.snapshot_name if self.sync else None


def _validate_spec(spec: DeliveryExecutorSpec) -> None:
    if not isinstance(spec, DeliveryExecutorSpec):
        raise DeliveryExecutorError("executor specification is invalid")
    if not isinstance(spec.checkout.request, DeployRequest):
        raise DeliveryExecutorError("executor request must be validated")
    if not isinstance(spec.sync, SyncSpec):
        raise DeliveryExecutorError("executor synchronization specification is invalid")
    try:
        evaluate_gate_evidence((), required_gates=spec.preflight_gates)
        evaluate_gate_evidence((), required_gates=spec.postflight_gates)
    except (GateEvidenceError, TypeError) as exc:
        raise DeliveryExecutorError("executor gate profile is invalid") from exc
    if set(spec.preflight_gates) & set(spec.postflight_gates):
        raise DeliveryExecutorError("executor gate phases must use distinct gates")


def _validate_checkout_result(
    result: CheckoutResult,
    spec: DeliveryExecutorSpec,
) -> CheckoutResult:
    if not isinstance(result, CheckoutResult):
        raise DeliveryExecutorError("checkout did not return a verified result")
    request = spec.checkout.request
    if (
        result.head_sha != request.candidate_sha
        or not SHA_RE.fullmatch(result.head_sha)
    ):
        raise DeliveryExecutorError("checkout result does not match candidate SHA")
    if result.trusted_ref != request.trusted_ref:
        raise DeliveryExecutorError("checkout result does not match trusted ref")
    try:
        expected = spec.checkout.destination
        if not expected.is_absolute():
            expected = Path.cwd() / expected
        expected = expected.resolve(strict=False)
        actual = Path(result.path)
        if not actual.is_absolute():
            raise DeliveryExecutorError("checkout result path must be absolute")
        current = Path(actual.anchor)
        for component in actual.parts[1:]:
            current /= component
            if current.is_symlink():
                raise DeliveryExecutorError(
                    "checkout result path must not contain symlinks"
                )
        actual = actual.resolve(strict=True)
    except DeliveryExecutorError:
        raise
    except (OSError, RuntimeError, TypeError) as exc:
        raise DeliveryExecutorError(
            "checkout result path could not be verified"
        ) from exc
    if actual != expected or not actual.is_dir():
        raise DeliveryExecutorError(
            "checkout result path is not the requested destination"
        )
    return replace(result, path=actual)


def _run_gates(
    runner: GateRunner,
    context: DeliveryContext,
    phase: str,
    required_gates: Sequence[str],
) -> GateEvaluation:
    try:
        evidence = tuple(runner(context, phase))
        return evaluate_gate_evidence(evidence, required_gates=required_gates)
    except GateEvidenceError as exc:
        raise DeliveryExecutorError("gate evidence could not be evaluated") from exc
    except Exception as exc:
        raise DeliveryExecutorError("gate runner failed") from exc


def _validate_sync_result(result: SyncResult) -> SyncResult:
    if not isinstance(result, SyncResult):
        raise DeliveryExecutorError("synchronization did not return a verified result")
    if not all(
        isinstance(value, bool)
        for value in (result.changed, result.snapshot_created, result.synced)
    ):
        raise DeliveryExecutorError("synchronization result contains invalid flags")
    if (
        isinstance(result.changed_entries, bool)
        or not isinstance(result.changed_entries, int)
        or result.changed_entries < 0
    ):
        raise DeliveryExecutorError("synchronization result contains invalid counts")
    if result.snapshot_name is not None and (
        not isinstance(result.snapshot_name, str)
        or not SNAPSHOT_NAME_RE.fullmatch(result.snapshot_name)
    ):
        raise DeliveryExecutorError("synchronization result contains an unsafe snapshot")
    if result.synced and not result.changed:
        raise DeliveryExecutorError("synchronization result is inconsistent")
    return result


def _result(
    request: DeployRequest,
    checkout: CheckoutResult,
    sync: SyncResult | None,
    preflight: GateEvaluation,
    postflight: GateEvaluation | None,
) -> DeliveryExecutorResult:
    evidence = (*preflight.evidence, *(postflight.evidence if postflight else ()))
    failure_reason = (
        postflight.failure_reason
        if postflight is not None and not postflight.passed
        else preflight.failure_reason
    )
    ready = preflight.passed and postflight is not None and postflight.passed
    return DeliveryExecutorResult(
        ready=ready,
        request=canonicalize_request(request),
        head_sha=checkout.head_sha,
        trusted_ref=checkout.trusted_ref,
        sync=sync,
        preflight=preflight,
        postflight=postflight,
        evidence=evidence,
        failure_reason=failure_reason,
    )


def execute_delivery(
    spec: DeliveryExecutorSpec,
    *,
    run_gates: GateRunner,
    checkout: CheckoutRunner = checkout_exact_sha,
    sync: SyncRunner = sync_deployment,
) -> DeliveryExecutorResult:
    """Run the locked checkout, preflight, sync, and postflight contract.

    The provider supplies the gate runner and owns Docker, Compose, health,
    canary, and rollback commands. This core only sequences those callbacks,
    never invokes a shell, and never reports readiness for missing/failed gates.
    """

    _validate_spec(spec)
    if not callable(run_gates):
        raise DeliveryExecutorError("a provider gate runner is required")

    request = spec.checkout.request
    try:
        with service_lock(
            spec.lock_root,
            request.service,
            timeout_seconds=spec.lock_timeout_seconds,
        ):
            try:
                checkout_result = _validate_checkout_result(
                    checkout(spec.checkout),
                    spec,
                )
            except DeliveryExecutorError:
                raise
            except Exception as exc:
                raise DeliveryExecutorError("exact-SHA checkout failed") from exc

            context = DeliveryContext(
                request=request,
                checkout=checkout_result,
                sync=None,
                destination=spec.sync.destination,
            )
            preflight = _run_gates(
                run_gates,
                context,
                "preflight",
                spec.preflight_gates,
            )
            if not preflight.passed:
                return _result(request, checkout_result, None, preflight, None)

            effective_sync = replace(spec.sync, source=checkout_result.path)
            try:
                sync_result = sync(effective_sync)
            except Exception as exc:
                raise DeliveryExecutorError(
                    "deployment synchronization failed"
                ) from exc
            sync_result = _validate_sync_result(sync_result)

            postflight = _run_gates(
                run_gates,
                replace(context, sync=sync_result),
                "postflight",
                spec.postflight_gates,
            )
            return _result(
                request,
                checkout_result,
                sync_result,
                preflight,
                postflight,
            )
    except DeliveryLockError as exc:
        raise DeliveryExecutorError("delivery lock could not be acquired") from exc
