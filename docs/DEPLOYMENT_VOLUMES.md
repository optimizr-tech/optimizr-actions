# Deployment volume contracts

The VPS reusable workflows treat required Docker volumes as existing durable
state by default. `_vps-self-hosted-deploy.yml` and
`_vps-monorepo-deploy.yml` both expose the following optional inputs:

| Input | Default | Contract |
| --- | --- | --- |
| `ensure_volumes` | `""` | Whitespace-separated Docker volume names required by the deployment. |
| `create_missing_volumes` | `false` | Legacy broad opt-in: permits creating every missing name in `ensure_volumes`. |
| `create_missing_volumes_allowlist` | `""` | Exact whitespace-separated subset of `ensure_volumes` names permitted for empty creation. |
| `volume_write_probes_json` | `[]` | Strict JSON array of bounded write probes, described below. |

Existing callers keep their current behavior. The helper is fetched from the
exact reusable-workflow revision only when the allowlist or write-probe input
is non-default; it is not part of ordinary deployments. The checkout does not
persist credentials, and its temporary source and validation manifest are
removed at the end of the job.
Opt-in callers need `python3` 3.10 or newer on the deployment runner; the
workflow fails during validation, before volume mutation, if it is unavailable.

## Safe, owner-scoped creation

The default is fail-closed: if a required volume is absent, deployment stops.
The legacy `create_missing_volumes: true` remains supported for compatibility,
but it authorizes creation of *all* missing required volumes. New callers
should prefer the exact allowlist and must not set the legacy boolean at the
same time:

```yaml
with:
  ensure_volumes: "alloy_data metrics_data"
  create_missing_volumes_allowlist: "alloy_data"
```

All new inputs are validated before volume mutations. Every allowlisted name
must be in `ensure_volumes`. The workflow inventories all required volumes
before creating any, and creates only exact missing names authorized by the
allowlist. If another required volume is missing but not authorized, the
deployment fails without creating any volume. Creating an empty volume does
not restore or migrate data; consumers remain responsible for backup,
initialization, and application-level recovery.

## Bounded write probes

Use `volume_write_probes_json` when a consumer needs to prove that the deployed
container can write to a named volume as its configured runtime UID. Each
entry must contain exactly four fields: `container` (Docker container name),
`volume` (an `ensure_volumes` name), `mount_path` (the exact absolute POSIX
mount destination), and `uid` (a JSON integer from 0 through 2147483647).
Unknown or duplicate fields, non-integer UIDs, path traversal, invalid names,
oversized input, and volumes not listed in `ensure_volumes` are rejected.

```yaml
with:
  ensure_volumes: "alloy_data"
  volume_write_probes_json: >-
    [{"container":"alloy","volume":"alloy_data",
      "mount_path":"/var/lib/alloy","uid":65532}]
```

The reusable verifies that the named running container belongs to the current
Compose project, that its Compose service is part of the current monorepo
rollout (when applicable), that the inspected image still resolves to the
container's immutable image ID, and that exactly one writable named-volume
mount matches both `volume` and `mount_path`. It then runs one fixed `sh`
write-and-cleanup probe through `docker exec --user <uid>` against the
inspected container ID. Callers cannot supply a command, helper image, or
permission mutation. A mismatch or failed write fails the deployment.

For the single-service workflow, probes run after Compose rollout/recreation
and before its health wait. For the monorepo workflow, they run after
`services_up` and before the healthcheck gate. Probe volumes must be included
in `ensure_volumes`; the probe does not create a volume by itself. The probe
creates a uniquely named temporary file in the mount and removes it on success
or attempts cleanup on ordinary command failures. Probe-enabled images must
provide `sh`, `mktemp`, and `rm`; the workflow does not inject a helper image.
It does not test application semantics, durability after restart,
backup restoration, or multi-process behavior.

The change is additive under `v1`: both inputs are optional, default behavior
is preserved, and the existing broad boolean remains available. Consumer
adoption and any production volume creation require separate consumer review;
this reusable change does not dispatch deployments, create live volumes, or
change the floating `v1` tag. Roll back by removing the new inputs from the
caller; callers that have already opted into volume creation must separately
review any empty volume created, because deleting a volume is intentionally
outside this contract.
