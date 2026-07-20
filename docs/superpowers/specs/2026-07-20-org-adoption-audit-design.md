# Organization Adoption Audit Design

## Goal
Continuously identify workflow adoption drift without cloning private repositories or exposing private content from the public Actions repository.

## Architecture
A hosted scheduled workflow reads an explicit secret allowlist and queries GitHub repository metadata plus `.github/workflows` content. Pure audit rules produce findings without source snippets. One job uploads a public redacted artifact; an independent optional job posts the full sanitized report to a marker-delimited private issue.

## Security
Private repository names are hashed in public artifacts. Tokens are separated into read-only audit and issue-write roles. No secrets, environment values, workflow contents, hosts or production paths enter reports or logs.

## Testing
Offline fixture strings exercise every initial rule, public aliasing/report redaction and idempotent issue-section replacement. Contract tests enforce hosted execution, read-only workflow permissions, pinned actions and absence of cloning.
