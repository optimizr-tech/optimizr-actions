# Billing-Independent Security Gates Design

## Context

Optimizr consumer repositories currently use `[skip-tests]` when GitHub-hosted runner billing is unavailable. The marker must only select a trusted self-hosted execution path; it must never remove security validation. The reusable automation repository is the correct enforcement boundary because it owns both CI contracts and deployment workflows.

## Decision

We will add one portable composite action, `security-gate`, and one reusable workflow, `_security-gate.yml`. The action is runner-neutral and performs the same Trivy contract on GitHub-hosted or trusted self-hosted Linux runners. The workflow selects its runner from a JSON label list and uploads sanitized evidence.

The existing VPS deployment workflows will invoke the action twice by default:

1. a filesystem/configuration/secret scan immediately after checkout and before deployment files are synchronized;
2. an image scan after Docker Compose builds and before any `docker compose up` rollout.

This makes the deployment workflows fail closed even when caller-level hosted jobs were skipped. Existing input names remain valid. New security inputs have safe defaults and may not silently turn a missing tool, missing image, stale database, malformed exception, or scan finding into success.

## Components

### `.github/actions/security-gate/action.yml`

The composite action installs a controlled Trivy version through a full-SHA-pinned Aqua installer, refreshes the vulnerability database, validates database freshness, validates time-bounded exceptions, runs table, JSON, and SARIF reports, and writes evidence tied to the repository SHA and scanned target.

### `scripts/security_gate/evidence.py`

A Python standard-library helper validates Trivy database metadata and the Optimizr exception policy, renders a Trivy-compatible YAML ignore document as JSON/YAML, resolves image identity from Trivy JSON or Docker, hashes reports, and writes sanitized evidence atomically.

### `.github/workflows/_security-gate.yml`

The reusable workflow accepts `runner_json`, allowing the same gate to execute on `ubuntu-latest` or labels such as `["self-hosted","Linux","security"]`. It checks out the exact caller revision, invokes the composite action, and uploads evidence regardless of scan success.

### VPS deploy workflows

Both deployment workflows run the filesystem gate before synchronization. After their existing build stage, they discover local image IDs from Docker Compose and run the image gate before rollout. Image discovery is mandatory when image scanning is enabled. Security evidence is uploaded before workspace cleanup.

## Exception policy

Consumers may provide a JSON policy file containing vulnerability entries. Every entry must include:

- `id`;
- `owner`;
- `statement`;
- `compensating_control`;
- `expires` in `YYYY-MM-DD` format;
- optional `paths`, `purls`, and `targets` scopes.

Expired, malformed, unowned, or unscoped exceptions fail closed. Only entries matching the current target are rendered for Trivy. `ignore_unfixed` remains an explicit input and defaults to `false`.

## Evidence

Each target produces evidence containing repository identity, exact commit SHA, scan type, target, image digest or image ID when applicable, Trivy version, database timestamps, exception policy digest, report digests, severity policy, `ignore_unfixed`, result, and creation timestamp. Environment values and credentials are never recorded.

## Failure behavior

The gate fails when:

- Trivy setup or database refresh fails;
- database metadata is missing, invalid, from the future, or older than the configured threshold;
- the exception policy is invalid or expired;
- an image scan has no resolvable image identity;
- Trivy reports an unexcepted finding at the configured severity;
- a required image cannot be discovered after build.

Reports and evidence are still retained when a scan fails.

## Compatibility and rollout

The new reusable workflow is additive. Existing deploy workflow inputs remain intact; the deployment contract becomes stricter by adding mandatory security gates, which is the intended remediation authorized for issue #19. Consumers with unusual no-build deployments may explicitly set `security_require_image_scan: false`, which remains visible and reviewable in their workflow.

Rollback consists of pinning consumers to the previous known-good `optimizr-actions` commit or reverting the deployment-workflow integration while retaining the standalone gate.

## Testing

Python unit tests cover database freshness, exception validation, target scoping, image identity, and evidence generation. Static contract tests assert SHA pinning, blocking exit behavior, report formats, dynamic runner selection, pre-sync filesystem scanning, post-build image scanning, and pre-rollout enforcement. The full repository suite, YAML validation, actionlint, secret scanning, and branch comparison remain required before merge.
