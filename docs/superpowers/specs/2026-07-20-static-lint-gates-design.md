# Static lint gates design

## Goal

Provide one hosted/self-hosted contract for ShellCheck, actionlint, and composite action metadata validation.

## Design

A composite action downloads architecture-specific ShellCheck 0.11.0 and actionlint 1.7.12 archives and verifies immutable SHA-256 values before extraction. A Python runner discovers only Git-tracked files, applies bounded repository-relative exclusions, invokes each tool without a shell, validates composite metadata with pinned PyYAML, and emits sanitized evidence. The reusable workflow owns read-only checkout and retention.

## Failure model

Unsupported architecture, download failure, checksum mismatch, malformed exclusion, missing parser, linter finding, or invalid action metadata fails the job. Evidence upload runs even after failure.
