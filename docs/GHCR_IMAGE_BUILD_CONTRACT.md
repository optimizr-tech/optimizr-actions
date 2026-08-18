# GHCR image build and promotion contract

## Status

This document is a reviewable contract proposal. It does not change a
reusable workflow, publish a package, move the `v1` tag, or deploy an image.
Those actions require a separate implementation PR and human approval.

## Problem

Consumers that rebuild upstream Go-based images need a deterministic place to
compile and scan those images. Building them during a production deployment
puts compilation time, disk pressure, and the security remediation loop on a
self-hosted runner. It also makes a successful deployment depend on the
runner having enough CPU, memory, cache, and network capacity at that moment.

The proposed boundary is:

```text
consumer source SHA
        |
        v
trusted CI build + SBOM/provenance + Trivy gate
        |
        v
GHCR image digest
        |
        v
deploy pulls and verifies the exact digest, then rolls out
```

## Ownership

| Concern | Owner |
| --- | --- |
| Generic build/publish/verification reusable | `optimizr-actions` |
| Consumer Dockerfiles, versions, source commits, and Compose topology | Consumer repository |
| Registry package visibility and environment configuration | Consumer/repository administrators |
| VPS provisioning, runner, Docker Engine, backups, and operational runbooks | `optimizr-infra-ops` |
| Human approval and merge/deploy decision | Repository maintainer |

No reusable in this repository may contain a customer name, host address,
credential, private repository dependency, or production `.env` value.

## Required consumer inputs

A consumer adopting the contract supplies a reviewed manifest containing:

- the service name and Dockerfile context;
- the exact source tag and source commit used by the Dockerfile;
- the build arguments that affect the toolchain and dependencies;
- the candidate Git commit SHA;
- the immutable GHCR image reference or the candidate tag convention;
- the runtime Compose service to which the image belongs.

Mutable tags are allowed as discovery aliases only. Promotion evidence and
deployment input must use a complete `sha256:` digest.

## Build requirements

The implementation PR must:

1. Build on a GitHub-hosted or explicitly trusted build runner, never as the
   default production deployment path.
2. Use `docker/build-push-action` with a bounded GitHub Actions cache where
   possible (`type=gha`), avoiding unbounded runner-local build cache growth.
3. Push only after the image build has passed the consumer's tests and the
   required security checks.
4. Derive the candidate tag from the exact source SHA, or publish the digest
   to a manifest that is itself bound to that SHA.
5. Keep build contexts explicit and exclude secrets through the consumer's
   `.dockerignore` and deploy hygiene rules.

The build must not solve a vulnerability by changing the scan policy,
silently ignoring fixed findings, or copying a host-installed toolchain into
the image. The patched runtime must be present in the final image.

## Supply-chain evidence

The workflow must preserve both:

- an SBOM for every published image; and
- provenance bound to the source repository, exact commit SHA, image digest,
  and build workflow identity.

The implementation must not set `provenance: false` or `sbom: false` merely to
make a registry push succeed. If the registry or action cannot retain the
attestations, the job fails closed and the image is not promoted.

The evidence must be sanitized: it may contain repository names, commit SHAs,
image digests, artifact hashes, and tool versions, but not environment values,
tokens, host addresses, or raw Docker configuration.

## Security gate

Before publication and again before rollout:

- resolve the image to a complete immutable digest;
- scan the exact image with the governed Trivy policy and a fresh database;
- fail on actionable fixed vulnerabilities at the configured blocking
  severities;
- fail if the image, digest, SBOM, provenance, or scan report is missing;
- retain only narrowly reviewed signal-only vendor findings when the policy
  explicitly allows unfixed findings;
- record the candidate SHA, digest, scan result, and evidence artifact hashes.

An image rebuilt from source is not remediation evidence until its immutable
identity changes and the final scan passes. A successful `docker build` or
registry push alone is never a green security result.

## Deploy consumption requirements

The deployment implementation must:

1. Authenticate to GHCR with least-privilege package read access.
2. Pull the exact image reference required by the candidate manifest.
3. Resolve the local image digest after pull and compare it with the reviewed
   digest before `docker compose up`.
4. Scan that exact local image before rollout, even if CI scanned it earlier.
5. Fail closed for a missing package, tag/digest mismatch, missing evidence,
   or actionable vulnerability.
6. Preserve the last known-good digest and make rollback a one-value manifest
   change, without rebuilding on the production runner.

The reusable must not broaden `packages:read` to write access in a deploy job.
Package publication belongs to the CI build job, whose `packages:write`
permission is scoped to the job and reviewed separately.

## Candidate workflow shape

The eventual implementation should be split into reviewable jobs:

```text
validate consumer manifest
  -> build matrix (one service per image)
  -> publish GHCR + attestations
  -> resolve digests + scan exact images
  -> emit sanitized deploy manifest
```

The deployment caller should consume the emitted manifest and should not
compile the same images on the VPS. If a consumer still needs a bounded local
rebuild for an emergency, that path remains an explicit opt-in remediation
fallback and must retain the existing final scan and no-change detection.

## Rollback and migration

The implementation PR must include:

- a consumer migration example from a buildable Compose service to an exact
  GHCR image reference;
- a rollback example to the previous digest;
- a negative test for a missing or mismatched digest;
- a negative test proving that missing SBOM/provenance cannot be promoted;
- a test proving that a fixable Trivy finding blocks publication;
- an explicit statement of which existing callers are unaffected.

The current contract proposal intentionally leaves the reusable workflow and
the `v1` tag unchanged. A later implementation may introduce a new reusable
workflow or a versioned opt-in input; it must preserve existing caller
behavior until the migration is reviewed and complete.

## Open decisions for the implementation review

- Whether the deploy manifest is passed as an artifact, a signed release
  asset, or a repository-local generated file.
- Whether package names are one image per service or one multi-service package
  namespace.
- Which attestation verifier is used on the deployment runner.
- The exact retention period for SBOM, provenance, scan, and deploy-manifest
  artifacts.
- Whether consumers can opt into GHCR publication independently or require a
  reusable workflow major version.

