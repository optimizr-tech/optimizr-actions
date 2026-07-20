# Post-Deploy Verification Design

## Goal
Centralize positive runtime verification and optional negative security probes after deployment.

## Architecture
A protected reusable workflow checks out the exact deployed commit on a trusted self-hosted runner. A declarative Python engine inspects bounded container state and performs bounded HTTP readiness requests. A separate job optionally calls the negative-probe reusable.

## Security
No arbitrary commands are accepted. HTTP origins come from named secrets, redirects/proxies are disabled, responses are bounded and discarded, and evidence retains aliases rather than private container names or endpoints.

## Testing
Tests use a fake Docker executable and a real local HTTP server, then verify exact argv, pass/fail/unavailable classification, SHA binding and evidence redaction. Contract tests enforce environment protection, self-hosted labels, pinned actions and named secrets.
