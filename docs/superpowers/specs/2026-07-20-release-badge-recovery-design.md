# Release Badge Recovery Design

## Goal
Replace duplicated fallback badge workflows with one serialized reusable while keeping semantic-release primary.

## Architecture
The reusable checks out the explicit badge branch, resolves a validated explicit/event/latest semver tag, and delegates SVG mutation plus idempotent commit/push to the existing composite action.

## Security
Only `contents: write` is granted. Inputs are validated, no secrets are inherited, third-party checkout is SHA-pinned, and concurrency is non-cancelling to avoid competing pushes.

## Testing
Tests validate semver, branch and path rejection plus latest-tag resolution in a real temporary Git repository. Contract tests enforce permissions, concurrency and action references.
