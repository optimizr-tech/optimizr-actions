# Governed Validation Runners Design

## Goal

Allow private consumers to run the same reusable validation contracts on GitHub-hosted or governed self-hosted runners without making `[skip-tests]` a functional bypass.

## Billing boundary

`optimizr-actions` is public and does not interpret `[skip-tests]`. A private caller decides whether to allocate a hosted runner. The selected path must preserve the required validation set.

## Runner modes

Every portable reusable accepts `runner_json` and `self_hosted_mode`.

- `none`: exactly `["ubuntu-latest"]`.
- `trusted-main`: self-hosted Linux, allowed only for `push` or protected `workflow_dispatch` on `refs/heads/main`.
- `ephemeral-pr`: self-hosted Linux with an explicit `ephemeral` label, allowed only for `pull_request`.

Commitlint and PR convention validation execute candidate repository content and therefore prohibit `trusted-main`; their only self-hosted mode is `ephemeral-pr`.

## Skip contract

Reusable workflows never inspect PR titles, commit messages, or `[skip-tests]`. The legacy explicit `skip` input remains only on Compose and Trivy for backward compatibility with technically optional caller decisions. It is not a billing policy.

## Aggregation

The security-suite summary computes required jobs from the selected profile and whether image references were supplied. Every required job must be `success`. `skipped`, `cancelled`, `failure`, or an absent/unknown result is blocking. Optional jobs may be skipped only when not applicable.

## Compatibility

Defaults preserve hosted execution. Consumers continue using `@v1`; no consumer is forced to pin a SHA. Third-party actions remain immutable.
