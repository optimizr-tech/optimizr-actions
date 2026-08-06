# Governed Docker access for Compose validation

## Status

Approved for implementation on 2026-08-06 under issue #145.

## Problem

`_docker-compose-validate.yml` validates runner trust but invokes every Compose command through direct Docker socket access. Persistent service runners may intentionally expose Docker only through non-interactive `sudo -n docker`. Consumer-owned validation already detects both access paths, so the reusable workflow can fail before evaluating the Compose model.

## Decision

Add a `docker_mode` input with `auto`, `direct`, and `sudo` values. The default `auto` probes direct access first and then non-interactive sudo. The workflow resolves one mode before checkout and routes every shell-based Compose command through that mode.

The resolver fails closed when the requested mode is invalid or unavailable. It never invokes interactive sudo.

## Build boundary

The optional image sanity build continues using `docker/setup-buildx-action` and `docker/build-push-action`. Those actions expect direct Docker socket access, so `build_image=true` is accepted only when the resolved mode is `direct`. A sudo-only runner may validate Compose configuration but cannot claim Buildx support through this workflow.

## Compatibility

- hosted and direct-access runners retain their current behavior;
- sudo-only trusted-main runners gain Compose configuration validation;
- callers do not need to set the new input because `auto` is backward compatible;
- no runner trust mode, event boundary, skip behavior, consumer, or deployment contract changes.

## Failure behavior

- invalid mode: fail before checkout;
- direct requested but unavailable: fail before checkout;
- sudo requested but `sudo -n docker info` fails: fail before checkout;
- auto with neither path: fail before checkout;
- image build with resolved sudo mode: fail before Buildx setup.

## Publication boundary

The implementation remains on a draft PR. Managed `v1` publication and consumer canaries occur only after review, merge authorization, and complete exact-SHA repository validation.
