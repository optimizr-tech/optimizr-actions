# Portable local validation contract

## Decision

Local-first validation is an organization capability, not a Fiscal-only
execution model. This public repository will provide one portable, versioned
contract that consumer repositories invoke locally. A Fiscal preset is the
first strict consumer of that contract.

GitHub reusable workflows remain optional adapters. They must delegate to the
same contract and must not become the authoritative implementation.

The public boundary permits generic commands, version requirements, service
roles, paths supplied as inputs, and reusable validation logic. It forbids
credentials, host addresses, customer data, production-specific configuration,
and assumptions that require access to a private repository. Private product
repositories remain the owners of their secrets and service lifecycle.

## Components

1. `scripts/local_validation/` contains a dependency-free Python command that
   reads a named preset, records the repository state and tool versions, runs
   an ordered command list, and writes a machine-readable JSON evidence file.
2. `presets/fiscal.json` declares the Fiscal runtime contract: Python 3.14,
   PostgreSQL 18, RabbitMQ 4.3, MinIO with versioning/Object Lock, Keycloak,
   no Redis, required command targets, and fail-closed policy for required or
   unknown results.
3. `docs/LOCAL_VALIDATION.md` documents the organization capability, consumer
   integration, evidence schema, safety rules, and the Fiscal preset.
4. `_python-uv-test.yml` gains a Fiscal adapter only after the local command
   and preset are independently testable. The adapter calls the same command
   and does not duplicate thresholds or service semantics.

## Execution model

The consumer runs `python -m scripts.local_validation.run` from its repository
and passes the preset path plus its local gate command. The runner checks for a
clean worktree, captures HEAD/base SHA, lock-file checksum and executable
versions, then executes commands in order. Each command records argv, exit
code, duration and status. Failure of a required command stops with a non-zero
exit status; unknown required results are also failures.

The preset describes expected services and validates discovered service
versions/digests supplied by the local environment. It records whether a real
service or a fake was used. The contract does not start containers itself:
the consumer remains responsible for its Compose lifecycle and credentials.
This keeps the shared layer portable and avoids secret handling.

## Fiscal acceptance mapping

The Fiscal preset requires the listed `uv` checks, migration/RLS verification,
unit/integration/security/recovery/conformance targets, and real PostgreSQL,
RabbitMQ, MinIO and Keycloak services. It explicitly forbids Redis unless an
opt-in consumer override is documented. The evidence records the exact commit,
cleanliness, tool/service versions, command results, coverage/security results
and unresolved gaps, without recording environment values or secrets.

RLS assertions remain owned by the Fiscal consumer because they require its
schemas, roles and policies. The preset declares them mandatory so they cannot
be silently omitted.

## Validation and rollout

Unit tests cover preset validation, evidence redaction, clean-worktree policy,
fail-closed handling and command-result serialization. The actionlint repair
has separate static regression coverage. The release workflow only moves `v1`
after these checks are green. Existing Serve consumers keep their current
inputs and behavior.

## Non-goals

- Provisioning production infrastructure or secrets.
- Running a production deploy runner as a general test runner.
- Implementing the Fiscal application or its RLS policies in this repository.
- Requiring GitHub-hosted runners.
