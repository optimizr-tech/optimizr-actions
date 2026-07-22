# Billing-independent security gate

The Optimizr security gate provides one blocking Trivy contract for GitHub-hosted and trusted self-hosted Linux runners. A billing marker such as `[skip-tests]` may select the self-hosted path, but it must not remove security validation.

## Security invariant

A production rollout is permitted only after:

1. the exact candidate commit passes a filesystem, configuration, and secret scan;
2. every Docker Compose image selected for rollout passes an image scan;
3. the vulnerability database is present and within the accepted age;
4. every applied exception is owned, justified, compensated, scoped, and unexpired;
5. evidence is written for the exact commit and immutable image identity.

The reusable VPS deploy workflows enable the gate by default. They perform the filesystem scan before `rsync`, build local services, pull declared runtime images with `docker compose pull --ignore-buildable`, resolve immutable image IDs, and only then invoke the image scans and `docker compose up`.

### Scan ownership

The filesystem source gate owns configuration analysis: it runs Trivy
`vuln,misconfig,secret` against the candidate repository before synchronization.
The image gate owns runtime packages and secrets: it runs only `vuln,secret`
against each immutable candidate image. Image layers can contain archived tools,
examples, or development Dockerfiles that are not the deployment configuration;
those files are deliberately evaluated at their source by the filesystem gate,
not reclassified as an effective runtime misconfiguration by the image gate.

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
| `security_ignore_unfixed` | `false` | Deprecated caller compatibility value; unfixed findings remain signal-only centrally. |
| `security_exceptions_file` | empty | Optional Optimizr exception-policy JSON path. |
| `security_trivy_version` | `v0.70.0` | Controlled Trivy version. |
| `security_db_max_age_hours` | `30` | Maximum accepted database download age. |
| `security_rebuild_retry_enabled` | `true` | Permit one deterministic pull, rebuild and rescan for actionable image findings. |
| `security_rebuild_retry_no_cache` | `true` | Disable the build cache during the bounded remediation retry. |

The filesystem gate has no bypass input and always runs before the deploy workflow mutates the target environment. A consumer that intentionally deploys configuration without a Docker image may set `security_require_image_scan: false`; this is a visible policy exception and should be reviewed in the consumer pull request.

Before the initial image scan, both VPS deploy reusables pull every Compose service that declares an external `image:` while ignoring buildable services. This guarantees that digest-pinned sidecars and operational tools are locally available for immutable-ID discovery without replacing images built from the candidate source. A missing or unavailable declared image fails closed before rollout.

## Bounded automatic remediation

The deploy reusables capture the first image-gate outcome without promoting the candidate. A retry is attempted only when all of the following are true:

- the image gate failed;
- its sanitized `classification` is exactly `actionable_vulnerability`;
- `security_rebuild_retry_enabled` is `true`.

The retry calls the reviewed `security-rebuild` composite once. It pulls referenced images, builds with `--pull`, optionally disables cache, resolves the rebuilt immutable image IDs, and invokes the same security gate again. The final enforcement step is ordered before every `docker compose up` command.

A successful Compose rebuild step is evidence only that Docker accepted the command; it is not evidence that a dependency or image changed. Before promotion, the reusable validates every reference as exactly `sha256:` plus 64 hexadecimal characters, then compares the sorted sets of initial and remediated immutable image IDs. A malformed set produces `gate_error`; equal non-empty sets produce `rebuild_result=no_change`, retain the initial actionable classification, and fail closed without rollout. This makes immutable external-image retries explicit instead of reporting a command success as remediation.

### Retry-result action contract

`security-retry-result` is an internal portable composite used by both deploy
reusables. It accepts the initial/retry/final step outcomes and classifications,
the caller's retry policy, and newline-separated immutable ID sets from before
and after the retry. Its outputs are `initial_result`,
`rebuild_attempted`, `rebuild_result`, `final_result`, and `passed`.
`rebuild_result` remains additive evidence: `passed`, `failed`, `skipped`, or
`no_change`. `passed=true` is emitted only for a non-empty changed ID set whose
final gate succeeded with `clean` or `unfixed_warning`. An initial step outcome
of `success` is accepted only with one of those two passing classifications and
a valid non-empty initial image set; missing or contradictory data fails closed.

The action returns non-zero for every non-promotable state, but the calling
step uses `continue-on-error` so its sanitized outputs are retained in the
deployment manifest. The immediately following enforcement step still fails
the job, so this does not downgrade the security policy. To roll back the
contract, pin a consumer to the prior reviewed `optimizr-actions` commit or
move governed `v1` only after release validation; do not bypass the final gate.

### Source persistence

Runtime remediation does not write dependency updates back to Git. Pulling a
mutable tag or rebuilding with a fresher base can prove whether a candidate is
deployable, but that runner-local result is deliberately disposable and must
not create an unreviewed source commit.

Persistent remediation remains consumer-owned:

1. declare explicit image versions and, for production, reviewed manifest
   digests in Compose or Dockerfiles;
2. use the repository's Docker ecosystem entry in Dependabot to propose source
   updates;
3. validate the new pins with consumer contract tests and the same security
   gate;
4. merge the reviewed PR before the new artifact can become the declared
   production candidate.

When the newest upstream image still contains fixable dependencies, the gate
remains closed. A derived image or a scoped, accountable, expiring exception
requires a separate security review; the retry loop does not pretend that the
source was fixed.

Secrets, misconfigurations, malformed policies, stale databases, scanner errors and filesystem findings never trigger a rebuild. They remain fail-closed because rebuilding the same image inputs cannot safely correct them. A failed retry leaves the currently running known-good deployment unchanged.

The `security-gate` action preserves `result=passed|failed` for `v1` compatibility and adds sanitized outputs:

- `classification`: `clean`, `actionable_vulnerability`, `unfixed_warning` or `gate_error`;
- `fixable_vulnerability_count`;
- `unfixed_vulnerability_count`;
- `misconfiguration_count`;
- `secret_count`.

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
- a blocking JSON report;
- a SARIF report;
- validated database metadata;
- exception-policy metadata and digest;
- a sanitized finding summary;
- a sanitized evidence record.

The evidence record contains the repository name, exact 40-character commit SHA, scan type, target, immutable image identity where applicable, Trivy version, database timestamps, report hashes, severity policy, result, and timestamp. It intentionally excludes environment values, credentials, host addresses, production configuration, vulnerability descriptions and source snippets.

When deploy manifests are enabled, they also record only these remediation states: initial classification, whether rebuild was attempted, rebuild result and final classification. `security_rebuild_result` is `passed`, `failed`, `skipped`, or `no_change`; only `passed` means that changed immutable IDs passed the final security gate. Failed or unchanged remediation never replaces `last-successful.json`.

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

Every Optimizr action installs the controlled Trivy binary below a path unique
to the workflow run, attempt, and job in `runner.temp`. Multiple runner services
may share the same operating-system user, so the setup action's default
`$HOME/.local/bin/trivy-bin` is not safe for concurrent jobs: one setup can
replace an executable while another job is scanning and produce Linux
`ETXTBSY` (`Text file busy`). The per-job path is added to `PATH` by
`aquasecurity/setup-trivy` and is disposable with the runner's temporary data.
The repository-scoped vulnerability database cache remains separately protected
by `flock`.

## Failure modes

The gate fails closed when Trivy cannot be installed, the database cannot be refreshed, database metadata is missing or stale, an exception is malformed or expired, no required image is found, an image identity cannot be resolved, a report cannot be written, or an unexcepted finding meets the blocking severity.

An actionable initial image result may enter the one-attempt remediation path. Promotion still fails closed unless a changed set of rebuilt immutable image IDs passes the final gate. A missing image set, missing or malformed classification, unchanged image set, or failed final scan is treated as a non-promotable result; malformed data is reported as `gate_error`.

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
6. Leave the bounded retry enabled unless the consumer has a documented incompatibility with pulling base images.
7. Validate artifacts contain filesystem, initial-image and any remediated-image evidence before merge.

## Rollback

Before merging, record the previous known-good `optimizr-actions` commit. If the new contract causes an operational regression, pin the consumer to that commit or move governed `v1` back to it. Do not restore a deploy path that accepts all security jobs as skipped. Failed or unchanged remediation does not mutate the running stack, and the previous `last-successful.json` remains available.

The self-hosted Trivy database cache is repository-scoped, runner-owned, mode
`0700`, and protected by `flock`. The Trivy executable itself is isolated per
job under `runner.temp`.
