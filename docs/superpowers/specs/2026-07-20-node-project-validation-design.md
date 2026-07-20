# Node Project Validation Design

## Goal
Replace repeated npm/pnpm validation jobs with one bounded reusable workflow.

## Architecture
A prepare job validates and normalizes a maximum-ten-project JSON matrix. Each matrix entry receives a clean checkout and pinned Node/pnpm setup, then a composite action executes frozen installation and allowlisted package scripts through Python `subprocess` argv. Declared artifacts are copied into a controlled evidence tree.

## Security
Paths remain inside the workspace, symlinks are rejected, script names are identifiers rather than command strings, no secrets are inherited and default permissions are read-only.

## Testing
Unit tests exercise traversal rejection, argv execution, artifact copying and symlink denial. Contract tests enforce pinned actions, bounded matrix validation and absence of arbitrary command inputs.
