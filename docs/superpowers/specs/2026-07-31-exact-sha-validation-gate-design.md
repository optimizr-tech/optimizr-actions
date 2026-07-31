# Exact-SHA Validation Gate Design

## Goal

Provide one validation result for one exact consumer commit that downstream release and deploy jobs consume directly in the same caller workflow.

## Architecture

`_validation-gate.yml` selects a hosted, trusted self-hosted, or reviewed emergency path. It executes:

1. the consumer-owned repository validation entrypoint through `_repository-validation.yml`;
2. the governed profile through `_security-suite.yml`;
3. one exact-SHA attestation after both child contracts finish.

The caller places release and deploy downstream of the same validation job. They compare `result == passed` and `validated_sha == github.sha`; they do not poll workflow runs or reinterpret billing markers.

## Evidence

The attestation contains:

- consumer repository and exact validated SHA;
- selected validation path;
- required child checks and their conclusions;
- blocking checks;
- exact `optimizr-actions` workflow repository, `@v1` ref, and resolved workflow SHA;
- run ID and a SHA-256 digest over canonical evidence.

The resolved workflow SHA is audit data. Consumers continue using the floating `@v1` compatibility tag.

## Trust boundary

- hosted validation requires exactly `ubuntu-latest`;
- persistent self-hosted validation requires Linux and trusted `main` push/dispatch;
- reviewed emergency additionally requires a protected Environment;
- the candidate SHA must equal the caller context SHA;
- any skipped, failed, cancelled, missing, or mismatched required check blocks attestation success;
- deployment reusables retain independent filesystem and final-image gates.

## Migration

Consumers with separate CI, release, and deploy interpretations should replace them with one orchestrator workflow whose downstream release and deploy jobs both depend on `_validation-gate.yml@v1` outputs. Consumer-specific entrypoints, coverage thresholds, integration topology, and post-deploy checks remain owned by each consumer.
