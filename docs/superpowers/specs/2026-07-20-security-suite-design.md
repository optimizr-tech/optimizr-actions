# Security Suite Design

## Goal
Expose one reusable workflow that composes Optimizr's portable security contracts through five allowlisted profiles.

## Architecture
A small profile-resolution job maps a literal profile to booleans and the SAST profile. Each child job invokes a versioned reusable workflow; no shell command or secret is forwarded. An always-running summary job records only profile, child job results and the final decision.

## Security
The workflow defaults to `contents: read`, passes no inherited secrets, uses one caller-provided runner contract for every job, and writes sanitized evidence. Unsupported profiles fail before any child gate starts.

## Testing
Contract tests verify profile coverage, fixed child workflow references, read-only permissions, summary artifact retention and absence of arbitrary command inputs.
