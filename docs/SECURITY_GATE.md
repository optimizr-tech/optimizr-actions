# Billing-independent security gate

The Optimizr security gate provides one blocking Trivy contract for GitHub-hosted and trusted self-hosted Linux runners. A billing marker such as `[skip-tests]` may select the self-hosted path, but it must not remove security validation.

## Security invariant

A production rollout is permitted only after:

1. the exact candidate commit passes a filesystem, configuration, and secret scan;
2. every Docker Compose image selected for rollout passes an image scan;
3. the vulnerability database is present and within the accepted age;
4. every applied exception is owned, justified, compensated, scoped, and unexpired;
5. evidence is written for the exact commit and immutable image identity.

The reusable VPS deploy workflows enable the gate by default. They perform the filesystem scan before `rsync`, image scans after build, and only then invoke `docker compose up`.

## Standalone reusable workflow

### GitHub-hosted runner

```yaml
jobs:
  security:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_security-gate.yml@v1
    with:
      runner_json: '["ubuntu-latest"]'
      scan_type: fs
      scan_ref: .
      severity: HIGH,CRITICAL
```

### Trusted self-hosted runner

```yaml
jobs:
  security:
    if: contains(github.event.head_commit.message, '[skip-tests]')
    uses: optimizr-tech/optimizr-actions/.github/workflows/_security-gate.yml@v1
    with:
      runner_json: '["self-hosted","Linux","security"]'
      scan_type: fs
      scan_ref: .
      severity: HIGH,CRITICAL
```

The deployment job must depend on the applicable hosted or self-hosted job and must never accept both paths as skipped.

## Deploy integration

`_vps-self-hosted-deploy.yml` and `_vps-monorepo-deploy.yml` expose these additive inputs:

| Input | Default | Meaning |
|---|---:|---|
| `security_require_image_scan` | `true` | Require at least one Compose image and scan it before rollout. |
| `security_severity` | `HIGH,CRITICAL` | Severities that block deployment. |
| `security_ignore_unfixed` | `false` | Explicit policy for vulnerabilities without a fix. |
| `security_exceptions_file` | empty | Optional Optimizr exception-policy JSON path. |
| `security_trivy_version` | `v0.70.0` | Controlled Trivy version. |
| `security_db_max_age_hours` | `30` | Maximum accepted database download age. |

The filesystem gate has no bypass input and always runs before the deploy workflow mutates the target environment. A consumer that intentionally deploys configuration without a Docker image may set `security_require_image_scan: false`; this is a visible policy exception and should be reviewed in the consumer pull request.

## Exception policy

Exceptions use JSON so they can be validated with the Python standard library before Trivy receives a generated `.yaml` ignore document.

```json
{
  "version": 1,
  "vulnerabilities": [
    {
      "id": "CVE-2026-0001",
      "owner": "platform-security",
      "statement": "The vulnerable endpoint is not reachable in this deployment",
      "compensating_control": "The edge proxy blocks the affected route",
      "expires": "2026-08-19",
      "targets": ["registry.example/app:candidate"],
      "purls": ["pkg:apk/alpine/example@1.0"]
    }
  ]
}
```

Required fields are `id`, `owner`, `statement`, `compensating_control`, `expires`, and a non-empty `targets` array. `paths` and `purls` are optional Trivy scopes. `*` may be used only when a repository-wide exception is deliberately approved. Expired or malformed entries fail the gate; they are never silently ignored.

## Evidence

Each target produces:

- a human-readable table report;
- a JSON report;
- a SARIF report;
- validated database metadata;
- exception-policy metadata and digest;
- a sanitized evidence record.

The evidence record contains the repository name, exact 40-character commit SHA, scan type, target, immutable image identity where applicable, Trivy version, database timestamps, report hashes, severity policy, `ignore_unfixed`, result, and timestamp. It intentionally excludes environment values, credentials, host addresses, and production configuration.

Standalone and deploy workflows upload the evidence as a GitHub Actions artifact with 30-day retention. Evidence upload uses `if: always()` so failed scans retain their reports.

## Runner requirements

A self-hosted security runner must:

- execute only trusted commits already present on the protected deployment branch;
- be restricted by runner group and labels to approved repositories/workflows;
- use read-only repository permissions for validation;
- receive no production secrets in the security job;
- provide Bash, Python 3, Git, Docker/Compose, `sha256sum`, `sed`, and passwordless `sudo docker` when the runner user is not in the Docker group;
- clean workspace and temporary image archives after execution;
- preferably be ephemeral or isolated from the production runner.

The action runs Trivy as the unprivileged runner user. When Docker is only available through passwordless sudo, it saves the candidate image to a temporary archive and scans that archive without running Trivy as root.

## Failure modes

The gate fails closed when Trivy cannot be installed, the database cannot be refreshed, database metadata is missing or stale, an exception is malformed or expired, no required image is found, an image identity cannot be resolved, a report cannot be written, or an unexcepted finding meets the blocking severity.

`security_ignore_unfixed` is never inferred. Changing it from `false` requires an explicit caller change and review.

## Billing-outage operation

1. Hosted validation jobs are skipped only through the reviewed caller condition.
2. The equivalent `_security-gate.yml` job runs on the trusted self-hosted runner for the exact `main` commit.
3. Deployment requires the self-hosted gate result to be `success`.
4. The deploy reusable independently runs its own filesystem and image gates before rollout.

The last step provides defense in depth against caller condition mistakes.

## Migration

1. Remove repository-specific Trivy installation and `ALLOW_MISSING_TRIVY` behavior.
2. Replace the local fallback job with `_security-gate.yml@v1` or retain product-specific tests and let the deploy reusable own the canonical Trivy gate.
3. Keep hosted gates blocking when billing is available.
4. Confirm the caller has not disabled `security_require_image_scan` unless the deploy genuinely produces no image.
5. Confirm image discovery returns the exact candidate images.
6. Validate artifacts contain both filesystem and image evidence before merge.

## Rollback

Before merging, record the previous known-good `optimizr-actions` commit. If the new contract causes an operational regression, pin the consumer to that commit or revert the deploy integration. Do not restore a deploy path that accepts all security jobs as skipped; retain a blocking local gate during rollback.

The self-hosted Trivy cache is repository-scoped, runner-owned, mode `0700`, and protected by `flock`.
