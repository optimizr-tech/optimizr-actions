# Runner compatibility and trust boundaries

How to choose between hosted, self-hosted persistent and self-hosted
ephemeral runners, and which trust boundary applies to each artifact in the
capability catalog (`catalog/capabilities.json`).

## Runner kinds

| Runner | Execution model | When to use |
| --- | --- | --- |
| `hosted` | Fresh GitHub-managed VM per job; no long-lived state | Default for validation, lint, tests and gates on trusted PRs; deterministic, no secret exposure beyond scoped secrets |
| `self-hosted-persistent` | Long-lived machine; shared Docker daemon, caches and volumes; can hold deployment state | Deploy, post-deploy verification, negative probes, postgres migration and any step that needs persistent infrastructure or docker compose state |
| `self-hosted-ephemeral` | Self-hosted image of the validation contract on disposable runners; no shared state | Self-hosted PR validation of candidate code (directive #159): the only self-hosted mode that may execute untrusted PR code, with the same evidence |

### Hosted

- Ephemeral per job, managed by GitHub; the cheapest correct default.
- Best for anything that only reads the repository and writes artifacts.
- Never assume the ability to reuse Docker images, caches or volumes across
  jobs.

### Self-hosted persistent

- Long-lived machine with shared caches and infrastructure; the only kind
  that can meaningfully hold deployment state.
- **Trust boundary**: only `trusted-push` and (with explicit review)
  `trusted-pr` paths may run here. Unverified PR code must not reach a
  persistent runner; see `docs/VALIDATION_AUTHORIZATION.md`.
- Preferred for: `_vps-*-deploy`, `_post-deploy-verification`,
  `_negative-probes`, `_postgres-major-logical-migration`.

### Self-hosted ephemeral

- The same self-hosted execution surface on disposable runners: equivalent
  evidence, no shared state, no persistent exposure.
- The correct mode for validating untrusted PR code on self-hosted runners
  (directive #159); metadata-only PR validation uses `metadata-pr` instead
  (see `docs/CI_SKIP_CONTRACT.md` for the historical `[skip-tests]`
  contract, superseded by directive #159).

## Trust boundaries

| Boundary | Meaning |
| --- | --- |
| `trusted-push` | Pushes to protected branches; deployment-like and evidence-producing contracts |
| `trusted-pr` | Pull requests from trusted actors/approvers that already passed authorization |
| `untrusted-pr` | Pull requests from forks or otherwise unverified actors; validation only, no secrets |

Rules of thumb:

- A contract tagged `untrusted-pr` must never require secrets; on self-hosted
  runners it runs only in `ephemeral-pr` mode, with one deliberate exception:
  `_pr-metadata.yml` also keeps `metadata-pr` (persistent, read-only metadata)
  because it never checks out or executes candidate code and holds no secrets.
- A contract tagged `trusted-pr` may run on hosted or on self-hosted only
  behind `validation-authorization`.
- A contract tagged `trusted-push` is for push/deploy paths; when a reusable
  also supports `trusted-pr`, the authorization action decides the actual
  boundary at runtime.

## Default matrix

51 of 64 artifacts support all three runner kinds with the caller-selectable
`runner_json` input; their trust boundary is the union
(`trusted-push`/`trusted-pr`/`untrusted-pr`) and the caller restricts it via
`validation-authorization`.

Notable restrictions recorded in the catalog:

| Artifact | Runner | Boundary | Why |
| --- | --- | --- | --- |
| `_semantic-release.yml` | hosted | trusted-push | Release orchestration must run on managed runners |
| `_dependabot-security-automerge.yml` | hosted | trusted-push | Dependabot-triggered native auto-merge |
| `_quality-gate.yml` | hosted | trusted-pr | Gate over PR evaluation on managed runners |
| `pnpm-setup` action | hosted | trusted-pr | Node package-manager bootstrap |
| `_vps-self-hosted-deploy.yml`, `_vps-monorepo-deploy.yml` | self-hosted-persistent | trusted-push | Deploy requires persistent infrastructure state |
| `_post-deploy-verification.yml`, `_negative-probes.yml` | self-hosted-persistent | trusted-push | Probe and verify the deployed system |
| `_postgres-major-logical-migration.yml` | self-hosted-persistent | trusted-push | Database migration against the live instance |
| `templates/validate-pr.yml`, `templates/commitlint.yml` | hosted | untrusted-pr | Templates for PR validation on managed runners |

## Reading the catalog

Each artifact in `catalog/capabilities.json` declares `runner` (the matrix
above) and `trust_boundary` (the strictest boundary the contract is
authorized for). The consumer picks the weakest runner that satisfies the
boundary:

1. Read the artifact's `trust_boundary`.
2. Pick the cheapest compatible runner kind from its `runner` list.
3. For PRs on self-hosted, pass through `validation-authorization`.

The organization audit flags reusables that support self-hosted runners but
are only ever called from hosted jobs in repositories that already run
self-hosted jobs (`HOSTED_ONLY_REUSABLE`).
