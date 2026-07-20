# Repository validation gate design

## Goal

Provide a reusable, billing-independent way to execute an exact repository-owned validation entrypoint with commit-bound evidence and a protected manual emergency path.

## Design

A composite action validates a relative executable path, rejects traversal and symlinks, decodes arguments as a bounded JSON string array, and launches the process through Python `subprocess` without a shell. A reusable workflow supports normal `workflow_call` execution and a separate `workflow_dispatch` job guarded by a GitHub Environment. Persistent self-hosted execution always verifies that the exact candidate is reachable from a configured trusted branch.

Evidence is a small JSON document containing executable plus hashed argument metadata, optional immutable image IDs, tool versions, SHAs, duration, timeout and exit status. Environment values and command output are deliberately excluded. Checkout and artifact actions are immutable-SHA pinned and permissions remain `contents: read`.

## Testing

Unit tests cover path confinement, symlink and executable checks, argument decoding, literal argv execution, and evidence sanitization. Static tests cover both triggers, protected environment use, dynamic runner labels, immutable actions, and absence of arbitrary shell evaluation.
