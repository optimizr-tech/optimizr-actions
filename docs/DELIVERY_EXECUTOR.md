# Provider-neutral delivery executor

The delivery executor is deliberately separate from GitHub Actions context,
GitLab context, Ansible, and private VPS configuration. Its shared runtime
contract validates identity, prepares an exact commit, serializes one service,
protects synchronization, and evaluates adapter-provided gates. It does not
know credentials, invoke a shell, choose a provider, or wire any production
workflow.

## Request schema

```json
{
  "repository": "owner/service",
  "service": "service",
  "candidate_sha": "0123456789abcdef0123456789abcdef01234567",
  "trusted_ref": "refs/heads/main",
  "compose_file": "docker-compose.yml",
  "container_name": "service",
  "adapter": "github-actions",
  "reason": "reviewed main promotion"
}
```

The request is secret-free and accepts only:

- a bounded `owner/service` repository identity;
- a lowercase, complete 40-character commit SHA;
- a trusted `refs/heads/...` or `refs/tags/...` ref, never a pull-request ref;
- a relative POSIX Compose YAML path without traversal;
- bounded service/container identifiers;
- one of the protected adapter identities: `github-actions`, `gitlab-ci`,
  `ansible`, or `manual`;
- an optional bounded reason with no secret-like assignments.

Unknown fields are rejected so a later adapter cannot silently introduce
authorization or credential inputs into the shared contract.

## CLI

Validate a request file below an explicit root and emit its canonical JSON:

```bash
python -m scripts.delivery.request --request artifacts/delivery-request.json --root artifacts
```

The CLI prints only the canonical request. Errors are written to stderr and
return a non-zero status. Adapters can consume this interface without relying
on `${{ github.* }}`, `GITHUB_WORKSPACE`, or GitHub APIs.

## Exact-SHA checkout

The checkout primitive is adapter-neutral and receives a network Git remote
resolved from an allowlisted repository identity. It creates a new destination
only below an explicit root, initializes a clean repository, fetches the
trusted ref without tags, verifies that the candidate is a commit reachable
from `FETCH_HEAD`, checks it out detached, and confirms `git rev-parse HEAD`
equals the requested SHA.

Git is invoked with an argument array and captured output; no shell is used and
Git output or remote credentials are not returned in `CheckoutResult`. Unsafe
remotes, existing destinations, symlink components, root escapes, fetch
failures, ancestry failures and HEAD mismatches fail closed. A destination
created by a failed attempt is removed when cleanup is possible.

This primitive prepares source only. It does not synchronize into a deploy
directory, preserve runtime state, run security gates or change a service.

## Protected snapshot and synchronization

The synchronization primitive receives an exact-SHA checkout, an existing
deployment directory, and explicit roots for both paths. It first runs
`rsync -a --delete --dry-run --itemize-changes` with portable exclusions for
`.git`, `.github`, runtime environment and secret files, private-key suffixes,
archives, and backup data. An optional validated `.deployignore` and prebuilt
Compose filename are added as argument-level excludes; no shell is used.

When the dry-run reports no changes, no snapshot or synchronization is
performed. When it reports changes and snapshots are enabled, the current
deployment directory is archived before the real `rsync`. The archive omits
`.env`, `.env.*`, `.secrets`, private-key suffixes (`.pem`, `.key`, `.p12`,
`.pfx`), and existing `.tar.gz` files. Snapshot names are confined to the
explicit snapshot root, written through a temporary file, and restricted to
mode `0600` where the platform supports Unix modes.

Dry-run failures, unsafe paths, snapshot failures, and synchronization failures
stop the primitive without claiming success. The result contains only booleans,
a change count, and a safe snapshot filename; command output is not returned.
This slice is not wired to production workflows and does not manage Docker,
service health, or host retention.

## Locked executor flow

`execute_delivery` composes the primitives in this order while holding an
exclusive OS-level lock at `<lock-root>/<service>.lock`:

1. checkout the exact candidate SHA from the adapter-resolved remote;
2. run the provider's `preflight` callback for filesystem, Compose, and
   security evidence;
3. stop without synchronization when any preflight gate is absent, skipped, or
   failed;
4. run protected dry-run/snapshot/synchronization using the verified checkout;
5. run the provider's `postflight` callback for rollout and health evidence;
6. return `ready=True` only when every required gate in both phases passed.

The lock root must be an existing, explicit, non-root directory without
symlink components. Lock files remain as harmless coordination files after a
process exits; the OS releases the active lock with the file descriptor. A
timeout is bounded to one hour and a timeout fails closed.

Adapters provide the gate callback:

```python
from scripts.delivery.executor import execute_delivery

result = execute_delivery(
    spec,
    run_gates=lambda context, phase: adapter_gates(context, phase),
)
if not result.ready:
    raise RuntimeError(result.failure_reason or "delivery gates failed")
```

The callback owns provider-specific Compose, image-security, rollout, health,
canary, and rollback commands. The executor receives only sanitized
`GateEvidence`; it never returns command output. A postflight failure leaves
the protected snapshot available for the adapter's separately reviewed
rollback path and never claims the delivery is ready.

The current runtime slice is a library contract with injected operations. It
does not add a CLI, production workflow wiring, provider credentials, or an
automatic rollback policy. Those changes require separate adapter and
cross-repository review.

## Sanitized delivery manifest

`write_delivery_manifest` records the result of the shared executor at an
explicit absolute path. The manifest contains the repository, service, exact
candidate SHA, trusted ref, adapter identity, selected runner metadata, image
digests, synchronization summary, every sanitized gate result, final status,
and an optional rollback reference. It is written through a temporary file,
restricted to the caller's destination, and refuses to overwrite an existing
manifest.

The function accepts only a `DeliveryExecutorResult` produced by the shared
executor. It revalidates the canonical request, SHA, gate evidence, image
digests, synchronization state, and metadata before writing. Command output,
credentials, `.env` values, private keys, and secret-like metadata are never
serialized. A failed or incomplete result is recorded as `status: failure`
and can never be represented as ready.

This is a portable serialization contract only. It does not select a
provider, run Docker, perform rollback, or replace the existing VPS manifest
writer. Provider adapters may consume this result after a separate review.

## Protected rollback plan

`build_rollback_plan` validates a rollback target without changing the host.
The caller supplies explicit existing roots for manifests and snapshots, the
service name, the operator identity, a reason, and the literal confirmation:

```text
ROLLBACK <service> <candidate_sha>
```

The selected manifest must be schema version 1, successful and ready. Its
synchronization evidence must prove that a changed deployment was synced and
that a snapshot was created. The snapshot filename is restricted to a safe
`.tar.gz` basename and the resolved regular file must remain below the
declared snapshot root. Failed, incomplete, outside-root, malformed, or
secret-bearing inputs fail closed.

The returned plan contains only validated metadata and absolute paths to the
approved manifest and snapshot. It does not restore files, invoke Compose,
restart services, or bypass the normal provider gate and health checks. A
trusted host adapter must execute the plan through its separately reviewed
rollback procedure and record the resulting evidence.

## Manual adapter

`scripts.delivery.manual` is the first thin adapter for a protected manual or
Ansible call. It loads the request only below an explicit request root, accepts
only `adapter: manual`, requires the literal confirmation
`DEPLOY <service> <candidate_sha>`, and resolves the repository through an
explicit remote allowlist. It derives one isolated checkout destination from
the validated service and full SHA, then creates the shared
`DeliveryExecutorSpec`.

The host wrapper supplies the prepared roots and the provider gate callback:

```python
from scripts.delivery.manual import ManualAdapterSpec, execute_manual_delivery

result = execute_manual_delivery(
    ManualAdapterSpec(
        request_path=request_path,
        request_root=request_root,
        confirmation="DEPLOY optimizr-serve " + candidate_sha,
        remote_allowlist={
            "owner/service": "https://github.com/owner/service.git",
        },
        checkout_root=checkout_root,
        deploy_root=deploy_root,
        snapshot_root=snapshot_root,
        lock_root=lock_root,
    ),
    run_gates=trusted_gate_runner,
)
```

The adapter does not accept a command string, credential, token, arbitrary
remote, or caller-supplied gate result. The trusted host owns the callback that
executes its fixed filesystem, Compose, security, rollout, health, smoke, and
rollback checks. A wrapper should treat `ready=False` as a failed delivery and
must not bypass the executor with a parallel deploy path.

## Protected CI adapters

`scripts.delivery.ci` provides the shared thin-adapter contract for
`github-actions` and `gitlab-ci`. It loads a request whose adapter identity
matches the provider, resolves the repository only through the explicit remote
allowlist, and requires both `protected_ref=True` and
`protected_runner=True`. The provider wrapper is responsible for deriving
those booleans from its own protected-ref and trusted-runner controls; an
unprotected or ambiguous signal is rejected before checkout.

Both providers build the same `DeliveryExecutorSpec` through
`build_ci_plan` and may execute it only through `execute_ci_delivery`:

```python
from scripts.delivery.ci import CiAdapterSpec, execute_ci_delivery

result = execute_ci_delivery(
    CiAdapterSpec(
        provider="gitlab-ci",
        request_path=request_path,
        request_root=request_root,
        remote_allowlist=remote_allowlist,
        checkout_root=checkout_root,
        deploy_root=deploy_root,
        snapshot_root=snapshot_root,
        lock_root=lock_root,
        runner_name="protected-runner",
        protected_ref=True,
        protected_runner=True,
    ),
    run_gates=trusted_gate_runner,
)
```

The shared path construction is also used by the manual adapter, preventing a
provider from growing a parallel checkout, synchronization, lock, or gate
sequence. Provider-specific wrappers still own their fixed gate callback and
must pass only sanitized `GateEvidence`.

## GitLab include template

`templates/gitlab/optimizr-delivery.yml` is the thin GitLab job skeleton for a
consumer repository. The consumer should include an exact reviewed Actions
commit and extend `.optimizr-delivery`:

```yaml
include:
  - remote: >-
      https://raw.githubusercontent.com/optimizr-tech/optimizr-actions/
      <reviewed-actions-sha>/templates/gitlab/optimizr-delivery.yml

deliver:
  extends: .optimizr-delivery
  variables:
    OPTIMIZR_DELIVERY_SERVICE: optimizr-serve
    OPTIMIZR_DELIVERY_RUNNER_TAG: optimizr-protected
    OPTIMIZR_DELIVERY_ENTRYPOINT: "$CI_PROJECT_DIR/scripts/delivery_gitlab.py"
```

The job is manual, serialized per service, and eligible only for a protected
dedicated `deploy-*` tag. The runner tag must point to a GitLab protected
self-hosted runner, and `OPTIMIZR_DELIVERY_PROTECTED_RUNNER=true` must be
configured as a protected CI/CD variable; the template deliberately does not
define that attestation itself. The entrypoint is confined below
`CI_PROJECT_DIR` and must call `execute_ci_delivery` with
`provider="gitlab-ci"`, both protected signals, and a fixed provider gate
callback. The template never contains Compose, security, rollback, or secret
handling logic.

## Next slices

Follow-up PRs must separately add and verify:

1. provider-specific workflow/templates that derive the protected signals and
   invoke these thin adapters without broadening permissions;
2. canary evidence and adapter parity before any consumer migration.

Each slice must preserve the existing VPS reusable behavior until a reviewed
adapter proves parity.
