# Fiscal Local Validation V2 Design

## Goal

Provide a portable local-first contract that proves Fiscal validation used the required real topology instead of trusting service/version strings supplied by a caller.

## Architecture

The versioned preset defines:

- repository-owned entrypoint and allowlisted interpreter;
- Python, lockfile and tool requirements;
- required/forbidden services and version/digest constraints;
- mandatory check and conformance identifiers.

The adapter validates all repository paths, executes the entrypoint as argv, and supplies only a temporary metadata path. The consumer entrypoint owns Docker Compose, credentials, migrations and tests and writes a strict metadata document after execution.

The runner validates that metadata and atomically writes evidence bound to preset, entrypoint, lockfile and repository hashes.

## Trust boundary

The portable action never receives service credentials, environment values or arbitrary commands. Service claims come from a reviewed repository entrypoint that inspects and exercises the real local topology. Evidence records immutable image IDs and status IDs, not connection strings or logs.

## Fail-closed rules

- unsafe paths, symlinks and malformed JSON fail;
- Python/toolchain mismatch fails;
- dirty worktree fails unless explicitly allowed for local development;
- missing/forbidden services or mutable digests fail;
- non-passed checks/conformance fail;
- failed entrypoint or missing metadata fails;
- evidence is still produced for a completed failing entrypoint.

## Fiscal constraints

The preset requires PostgreSQL 18, RabbitMQ 4.3, a MinIO release image with Object Lock coverage, Keycloak 26, Python 3.14, uv/Ruff/mypy/Alembic/pytest, identity separation, RLS fail-closed, real-service integration, recovery and security checks. Redis remains forbidden.
