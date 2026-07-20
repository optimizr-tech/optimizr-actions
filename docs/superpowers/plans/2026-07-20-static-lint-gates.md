# Static Lint Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add checksum-verified reusable ShellCheck and actionlint validation.

**Architecture:** A composite action installs pinned binaries; a Python runner performs deterministic discovery and evidence generation; a reusable workflow exposes the portable contract.

**Tech Stack:** Python, ShellCheck 0.11.0, actionlint 1.7.12, PyYAML 6.0.2, GitHub Actions.

## Global Constraints

- Third-party archives must be versioned and checksum verified.
- Exclusions must be narrow and repository relative.
- Permissions remain read only and evidence excludes secrets.

### Task 1: Test the contracts
- [x] Add failing tests for architecture pins, discovery, exclusion validation, workflow permissions and evidence upload.

### Task 2: Implement deterministic lint execution
- [x] Add tracked-file discovery and metadata validation.
- [x] Capture bounded diagnostic evidence and fail on findings.

### Task 3: Add reusable Actions interfaces
- [x] Add checksum-verified composite installation.
- [x] Add hosted/self-hosted reusable workflow.

### Task 4: Validate and publish
- [x] Run focused unit, compile and YAML parsing checks.
- [ ] Run the complete repository suite in GitHub CI.
- [ ] Open a draft PR closing #22.
