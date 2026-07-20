# Static-Site Deployment Design

## Goal
Replace inline static-volume deployment with a reusable build, verify, backup, promote and rollback contract.

## Architecture
A manifest defines bounded paths and identifiers. A Python engine stages source, builds a Compose builder against a candidate volume, verifies declared outputs with fixed Docker argv, snapshots the stable volume, promotes candidate contents, verifies again and atomically promotes source.

## Security
The workflow is protected and self-hosted, binds to an exact SHA, rejects symlinks/traversal, does not accept commands, and records only service alias, SHA, builder image ID and hashes of required output paths.

## Testing
A fake Docker executable captures argv and simulates builder success/failure. Tests verify candidate/backup usage, absence of shell execution, source promotion, failed evidence and retention of the prior source on build failure.
