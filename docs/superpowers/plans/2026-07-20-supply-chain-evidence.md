# Supply-Chain Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Generate digest-bound CycloneDX, SPDX and provenance artifacts for promoted images.

**Architecture:** Trivy generates SBOMs; Docker inspection provides immutable identity; a Python writer creates sanitized SLSA-compatible provenance; a reusable workflow retains evidence.

**Tech Stack:** Trivy, Docker, Python, in-toto Statement, SLSA provenance, GitHub Actions.

## Global Constraints

- Reject mutable-only image identities.
- Do not retain raw private image names, endpoints or environment values.
- Preserve read-only workflow permissions and immutable third-party action pins.

### Task 1: Define evidence tests
- [x] Add failing tests for digest resolution, fallback image ID, artifact hashes and sanitization.

### Task 2: Implement provenance writer
- [x] Validate commit and digest formats.
- [x] Hash SBOM artifacts and emit a SLSA-compatible statement.

### Task 3: Add SBOM workflow
- [x] Generate CycloneDX and SPDX documents for each target.
- [x] Support normal and passwordless-sudo Docker access without running Trivy as root.
- [x] Upload evidence even on failure.

### Task 4: Validate and publish
- [x] Run focused unit, compile and YAML parsing checks.
- [ ] Run complete repository CI.
- [ ] Open a draft PR closing #24.
