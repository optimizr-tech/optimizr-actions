# Controlled SAST gate design

## Goal

Add reproducible source-level security analysis for Python and TypeScript without arbitrary remote rules.

## Design

Semgrep is pinned to version 1.170.0. Rule profiles live in the public Actions repository and are selected from a fixed allowlist. A Python runner performs JSON and SARIF scans, validates exact expiring baselines, strips source snippets, hashes rules/reports, and blocks unsuppressed `ERROR` findings. The reusable workflow supports hosted and trusted self-hosted Linux runners with read-only permissions.

## Initial coverage

The first profiles target command injection, dynamic code execution and simple request-to-outbound-client SSRF flows. Additional rules require the normal reviewed release process and contract tests.
