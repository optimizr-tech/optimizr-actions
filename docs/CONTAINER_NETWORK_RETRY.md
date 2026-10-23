# Container registry network retry

`_container-build-publish.yml`, `_container-candidate-promote.yml`, and the
composite action `resolve-image-manifest` retry registry network operations
that fail with a transient DNS/egress signature, with a short exponential
backoff and a hard attempt cap.

## Problem

On 2026-10-22 saturated self-hosted runners lost DNS/egress for a few seconds:
an `optimizr-payment` run (39767142672) failed with `no route to host` while
reaching GHCR and `optimizr-monitoring` failed with
`Could not resolve host: github.com`. A single attempt turned a seconds-long
blip into a failed release that needed a manual rerun.

## Contract

| Input | Type | Default | Meaning |
| --- | --- | --- | --- |
| `network_retry_attempts` | number (string for the composite action) | `3` | Maximum attempts per registry network operation (1-5). `1` disables retry. |
| `network_retry_backoff_seconds` | number (string for the composite action) | `5` | Backoff base; the delay after attempt *n* is `base * 2^(n-1)` seconds, capped at 60 (defaults: 5 s, then 10 s). Range 0-30. |

No output, secret, or permission changes. Invalid values fail the validation
step before any registry call.

Covered operations:

| Workflow / action | Operation |
| --- | --- |
| `_container-build-publish.yml` | initial and refresh `docker/login-action` (one retry sequence via `docker login --password-stdin`), quarantine `imagetools inspect` (index, SBOM, provenance), `docker pull` of the quarantine digest, `imagetools create` promotion |
| `_container-candidate-promote.yml` | `docker/login-action`, candidate `imagetools inspect` (index, SBOM, provenance), `docker pull` of the candidate digest, `imagetools create` promotion |
| `resolve-image-manifest` | `docker pull` of every Compose service image |

All wrapped commands go through `scripts/container_release/retry_network.py`.
The tag-to-digest read-after-write check keeps its own bounded retry in
`verify_published_digest.py`; HTTP `401` refresh during `export-then-push`
stays in `push_oci_layout.py`.

Not covered on purpose: the BuildKit build itself (`docker/build-push-action`)
and `docker/setup-buildx-action`. Retrying a build would rerun the whole build
and change the meaning of `steps.build.outcome`; use the job rerun for those.

## Classification and failure modes

Each failure is classified from the command output. Only `transient` is
retried; everything else fails closed on that attempt.

| Classification | Signatures (case-insensitive, examples) | Behavior |
| --- | --- | --- |
| `permanent` | `unauthorized`, `denied`, `401`, `403`, `forbidden`, `manifest unknown`, `name unknown`, `not found`, `invalid reference format` | Fail immediately; never retried. Wins over any transient signature in the same output. |
| `transient` | `no route to host`, `network is unreachable`, `could not resolve host`, `temporary failure in name resolution`, `no such host`, `i/o timeout`, `TLS handshake timeout`, `context deadline exceeded`, `connection reset by peer`, `connection refused`, `unexpected EOF`, `502/503/504`, `429`/`toomanyrequests` | Warning annotation, backoff, retry up to `network_retry_attempts`. |
| `unclassified` | anything else | Fail immediately; an unknown failure is never masked by repetition. |
| `transient_exhausted` | transient on every attempt | Fail with the command's exit code. |
| `retry_disabled` | login failed and `network_retry_attempts` is `1` | Fail; the login-action failure is not swallowed. |

The final failure is an `::error title=Registry network operation failed::`
annotation naming the operation, classification, attempt count, and exit code.
A recovery after a retry emits a `::notice`.

Safety properties:

- commands run without a shell; standard output is buffered and written (to
  stdout or `--stdout-file`) only after a successful attempt, so evidence files
  never contain partial output from a failed attempt;
- the registry password is passed on stdin from an environment variable
  (`--stdin-env`), never in argv or logs;
- the login keeps `docker/login-action` (same SHA pin) as the first attempt.
  The step is `continue-on-error` and an unconditional follow-up step runs only
  when it failed: it retries `docker login` for the remaining budget or fails
  the job. The login-action post step still logs out at the end of the job;
- digest, attestation, security, and promotion gates are unchanged; a retried
  operation must still produce the same immutable digest.

## Migration and rollback

No caller change is required; the default (3 attempts) applies on the next
`v1` resolution. A successful first attempt behaves exactly as before.

- Caller opt-out: pass `network_retry_attempts: 1` (composite action:
  `network_retry_attempts: "1"`). Behavior is then single-attempt, as before,
  apart from the classified error annotation.
- Reusable rollback: revert this change. Callers that set either new input
  would then fail on an unknown input, so remove the input from callers first.
