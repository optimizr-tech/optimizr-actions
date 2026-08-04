# Validation Gate Runner Mode Propagation Design

## Context

`_validation-gate.yml` selects hosted, persistent self-hosted, reviewed-emergency, or ephemeral PR execution through `validation_path` and `runner_json`. Its `security-suite` child now enforces a separate `self_hosted_mode` trust contract, but the parent gate does not pass that input. Self-hosted consumers therefore reach the child with `self_hosted_mode=none` and fail before the governed validation matrix can complete.

## Decision

Derive the child trust mode directly from the already-reviewed parent `validation_path`:

| validation_path | security self_hosted_mode |
| --- | --- |
| `hosted` | `none` |
| `ephemeral-pr` | `ephemeral-pr` |
| `self-hosted` | `trusted-main` |
| `reviewed-emergency` | `trusted-main` |

The mapping remains inside `_validation-gate.yml`; no new public input is added. This prevents callers from supplying conflicting parent and child trust declarations.

## Scope

- add a static contract test for the exact mapping;
- pass the derived value to `_security-suite.yml@v1`;
- preserve every existing gate input, output, attestation field and runner preflight;
- make no consumer, runner, release, tag or deployment change.

## Failure behavior

Unknown `validation_path` values continue to fail in the existing preflight. Hosted execution remains restricted to `ubuntu-latest`; PR candidate execution remains restricted to an ephemeral self-hosted Linux runner; persistent and reviewed-emergency execution remain trusted-main paths.

## Verification

- focused RED test must fail against the published parent workflow;
- focused GREEN test and the complete validation-gate contract suite must pass after the mapping is added;
- GitHub workflow parsing and repository CI remain authoritative before merge.
