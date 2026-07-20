# Post-deploy negative probes design

## Goal

Verify expected denial and exposure properties after rollout without arbitrary shell execution or private topology in this public repository.

## Design

Consumers commit a versioned JSON manifest and pass up to five target origins through named secrets. A standard-library Python runner validates strict method, request-count, timeout, body-size and path bounds; disables redirects; performs status/header/body-policy checks; and writes alias-only evidence tied to the deployed SHA. A protected-environment reusable workflow requires a trusted self-hosted runner with appropriate network reachability.

## Failure model

Manifest errors, missing targets, network unavailability, unexpected statuses, header policy violations, forbidden body markers or safety-bound violations fail the job. Evidence distinguishes failed assertions from unavailable endpoints without exposing URLs or response content.
