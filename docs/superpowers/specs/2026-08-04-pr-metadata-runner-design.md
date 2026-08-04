# Persistent PR Metadata Runner Design

## Decision

Allow a persistent self-hosted runner, including one on a production VPS, to validate pull-request metadata only. The workflow must not check out candidate code, install dependencies, invoke Docker, execute consumer scripts, receive production secrets, or access deployment paths.

The trusted `optimizr-actions@v1` implementation fetches the PR object and commit metadata through the read-only GitHub API, verifies the event base/head SHAs, and validates title, body and commit subjects with linear stage-specific errors.

## Trust classes

- `metadata-pr`: persistent or ephemeral self-hosted Linux runner; metadata-only workflow.
- `ephemeral-pr`: candidate-code execution in a disposable sandbox.
- `trusted-main`: protected main validation and delivery on the persistent service runner.

`metadata-pr` does not authorize source validation, release or deploy. It is only a merge convention check.
