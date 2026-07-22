# Trivy security gate policy

The security gate separates **reporting** from **deployment enforcement**.

## Enforcement

The deployment is blocked when the selected severities contain at least one of:

- a vulnerability with an available fixed version;
- a misconfiguration;
- a detected secret.

Misconfiguration analysis is source-owned: the filesystem scan uses Trivy
`vuln,misconfig,secret`. Image scans use `vuln,secret` to evaluate the runtime
package and secret surface without treating source files archived inside an
image layer as the active deployment configuration.

A vulnerability for which the distribution or package source has not published a fixed version is **signal-only**. It does not block deployment because there is no actionable package update for the consumer to apply.

## Reporting and evidence

Every target produces:

- a complete table report containing fixed and unfixed findings;
- a complete SARIF report;
- a complete JSON report;
- a blocking JSON report generated with Trivy `--ignore-unfixed`;
- a sanitized count summary;
- commit-bound evidence containing SHA-256 hashes for every report.

Unfixed findings appear as a GitHub warning and in the job summary. Reviewed exceptions remain target-scoped, accountable and expiring.

## Compatibility

The `ignore_unfixed` input remains accepted so existing callers do not break, but `false` is deprecated. Organization policy always treats vulnerabilities without an available fixed version as signal-only while keeping them visible in complete reports.
