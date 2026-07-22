# Security self-healing deploy design

## Context

The current Optimizr security gate correctly prevents promotion of candidates that contain actionable HIGH or CRITICAL vulnerabilities. PR #57 also separates actionable findings from vulnerabilities that do not yet have an available fix. The remaining operational problem is that a fixable finding currently stops the deployment path and may require a person to rerun or repair each repository manually.

This design adds the smallest useful automatic recovery loop by reusing the existing deploy reusables, Trivy gate, deploy manifests, governed `v1` publication, repository validation, Dependabot, and GitHub auto-merge. It deliberately does not introduce Ogozu, a custom GitHub App, an external remediation service, or AI-written patches.

## Goals

1. Never promote a candidate image with an actionable HIGH or CRITICAL vulnerability.
2. Avoid requiring manual intervention for vulnerabilities that can be resolved by refreshing base images or applying an existing Dependabot security update.
3. Preserve the currently deployed known-good version when remediation cannot be completed automatically.
4. Reuse the existing Optimizr Actions contracts and evidence instead of creating a parallel deployment system.
5. Keep the first delivery backward-compatible with governed `v1` consumers.

## Non-goals

- Automatically rewrite application code.
- Replace libraries when a compatible update is unavailable.
- Create a custom remediation agent or queue.
- Automatically accept exceptions or weaken security severity.
- Promote a vulnerable candidate merely to keep a workflow green.
- Guarantee remediation when upstream packages do not publish a fix.

## Existing components reused

- `.github/actions/security-gate/action.yml` for reporting and enforcement.
- `.github/workflows/_vps-self-hosted-deploy.yml` for generic VPS deployments.
- `.github/workflows/_vps-monorepo-deploy.yml` for monorepo deployments.
- Existing deployment manifests and `last-successful.json` behavior.
- Existing PR validation, actionlint, contract tests, and governed `v1` publication.
- Dependabot security updates for repository dependency changes.
- GitHub native auto-merge after required checks pass.
- Organization adoption audit for configuration drift reporting.

## Architecture

### Layer 1: deterministic rebuild remediation

The deploy reusable builds and scans the candidate exactly as it does today. When the image scan fails only because of actionable package vulnerabilities, the reusable performs one bounded remediation retry:

1. Pull current base and referenced images.
2. Rebuild the same candidate with cache disabled.
3. Resolve the rebuilt immutable image IDs.
4. Run the same security gate again.
5. Promote only if the second scan succeeds.

The retry is bounded to one attempt. Repeating indefinitely would hide persistent failures, consume runner capacity, and produce no new source inputs.

The rebuild path must not run for:

- detected secrets;
- misconfigurations;
- malformed or expired exception policy;
- stale or unavailable vulnerability database;
- scanner installation or evidence failures;
- filesystem findings that require repository changes.

Those conditions remain fail-closed because rebuilding the same source cannot safely correct them.

### Layer 2: Dependabot security remediation

When the actionable finding requires a repository dependency, lockfile, Dockerfile, or GitHub Actions reference update, Dependabot remains the source of the patch. Each consumer repository is expected to enable Dependabot security updates for its supported ecosystems.

A small reusable auto-merge workflow may be provided by `optimizr-actions`. Consumer callers remain explicit because `optimizr-actions` cannot independently receive another repository's `pull_request` event.

The caller will:

1. Run only for Dependabot-authored pull requests.
2. Use read-only permissions while validating PR metadata.
3. Require existing repository tests and security gates to complete successfully.
4. Enable GitHub native auto-merge rather than merging before checks.
5. Never expose deployment or production secrets to pull-request code.

A successful merge to the protected deployment branch triggers the existing deployment workflow. No separate deployment mechanism is introduced.

### Layer 3: organizational signal

The existing organization adoption audit gains checks for configuration drift where the GitHub API exposes enough information safely. It should signal, not mutate, repositories that:

- do not use governed first-party `@v1` references;
- lack the approved Dependabot configuration or security-update adoption marker;
- lack the approved Dependabot auto-merge caller;
- bypass the canonical security/deploy reusable.

Repository security settings that are not visible through the current token/API contract must be documented as manual organization configuration rather than guessed from source files.

## Data flow

```text
candidate commit
    -> existing filesystem gate
    -> existing Compose build
    -> existing image gate
        -> success: promote candidate
        -> actionable image vulnerability:
             pull base images
             rebuild once without cache
             rescan rebuilt immutable image IDs
                 -> success: promote remediated rebuild
                 -> failure: retain current production version and evidence
        -> non-rebuildable security failure:
             retain current production version and evidence

Dependabot security PR
    -> existing repository CI and security gates
    -> GitHub native auto-merge enabled only after policy checks
    -> protected branch update
    -> normal deployment flow above
```

## Required contract changes

### Deploy reusable inputs

Add optional compatible inputs with safe defaults:

- `security_rebuild_retry_enabled`: boolean, default `true`.
- `security_rebuild_retry_no_cache`: boolean, default `true`.

No caller-provided shell command is accepted. Build behavior remains implemented by reviewed fixed commands inside the reusable.

### Security gate outputs

Expose additive machine-readable outputs sufficient for the deploy reusable to distinguish an actionable vulnerability result from other failures. At minimum:

- `result`: `clean`, `actionable_vulnerability`, `unfixed_warning`, or `gate_error`.
- `fixable_vulnerability_count`.
- `unfixed_vulnerability_count`.
- `misconfiguration_count`.
- `secret_count`.

Existing failing behavior remains authoritative for standalone callers. Deploy reusables may capture the step outcome, inspect the sanitized outputs, perform the single approved rebuild retry, and enforce the final result.

### Deploy evidence

Extend existing sanitized deploy/security evidence with additive fields:

- `security_initial_result`;
- `security_rebuild_attempted`;
- `security_rebuild_result`;
- `security_final_result`;
- initial and final immutable image identities where already permitted by the evidence schema.

The evidence must not include host paths, secrets, private origins, environment values, raw vulnerability descriptions, or source snippets.

## Error handling

- If the initial gate succeeds, no retry occurs.
- If the initial gate reports only actionable image vulnerabilities, one rebuild retry is allowed.
- If the retry succeeds, deployment proceeds using only the rebuilt image IDs.
- If the retry fails, `docker compose up` is not invoked and the current production deployment remains unchanged.
- If failure classification is missing, malformed, or inconsistent, treat it as `gate_error` and do not deploy.
- If an optional build in a monorepo is not selected for deployment, its existing optional semantics are preserved; security behavior for promoted images remains mandatory.
- A Dependabot PR that cannot pass required checks remains open and does not deploy. The organization audit may report prolonged drift, but it does not merge or create exceptions.

## Security boundaries

- Pull-request code must never execute on a production-capable self-hosted runner.
- Auto-merge must be limited to Dependabot-authored PRs and GitHub's protected-branch checks.
- The reusable does not grant itself cross-repository write access.
- Consumer repositories explicitly own event triggers and write permissions.
- The rebuild retry never edits repository source or lockfiles.
- No vulnerability severity or exception policy is relaxed.
- Unfixed findings retain the signal-only policy introduced by PR #57; actionable findings remain promotion-blocking until the retry or dependency PR produces a clean candidate.

## Testing strategy

### Security gate contract tests

- additive outputs are always initialized;
- fixable and unfixed findings are classified separately;
- secrets and misconfigurations can never produce `actionable_vulnerability`;
- malformed reports produce `gate_error`;
- existing standalone blocking behavior is preserved.

### Deploy reusable contract tests

- initial successful scan performs no rebuild retry;
- only `actionable_vulnerability` can trigger the retry;
- retry uses Compose pull/build with fixed argv and no arbitrary caller command;
- rebuilt images are resolved again to immutable IDs;
- `docker compose up` is unreachable after a failed final scan;
- retry occurs at most once;
- existing backup, synchronization, manifest, and rollback ordering is preserved.

### Dependabot auto-merge contract tests

- workflow rejects non-Dependabot actors;
- permissions are least privilege;
- no production secrets are inherited;
- merge is enabled only through GitHub native auto-merge after required checks;
- third-party actions remain pinned to immutable SHAs.

### Repository validation

The exact PR SHA must pass the full Python contract suite, Python compilation, actionlint, YAML validation, and candidate diff checks before publication through `v1`.

## Rollout

1. Add security-gate outputs and tests without changing deployment behavior.
2. Add the bounded rebuild retry to the generic deploy reusable and validate it with fake Docker contract tests.
3. Apply the same contract to the monorepo deploy reusable.
4. Add the optional Dependabot auto-merge reusable and consumer template.
5. Extend documentation and the organization adoption audit.
6. Publish through governed `v1` only after exact-SHA validation succeeds.
7. Adopt the consumer caller incrementally; existing consumers immediately receive only backward-compatible central fixes through `@v1`.

## Rollback

Move governed `v1` to the previous reviewed commit or pin a consumer to the previous immutable SHA. The last successful production deployment remains intact because failed remediation never reaches rollout. Dependabot auto-merge callers can be disabled independently without disabling vulnerability detection or deployment gates.

## Success criteria

- A stale but fixable operating-system package in a built image is corrected by one pull/rebuild/rescan cycle without human action.
- A dependency change supplied by Dependabot can merge automatically only after the consumer's required tests and security gates pass.
- A candidate that remains vulnerable after retry is not deployed, while the current known-good deployment remains available.
- The implementation introduces no Ogozu service, custom GitHub App, external queue, or arbitrary command input.
