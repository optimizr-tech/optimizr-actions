# Passive DAST baseline

`_dast-baseline.yml` runs the OWASP ZAP baseline Docker scan against a small
set of public HTTPS URLs. It uses the trusted Linux self-hosted runner selected
by `runner_json`, has read-only repository permission, and never receives
secrets. The scanner image is pinned to the multi-platform OCI index digest
`ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af`.

## Inputs and outputs

| Input | Required | Default | Contract |
| --- | --- | --- | --- |
| `targets` | yes | — | JSON array of 1-10 credential-free HTTPS URLs, without query strings or fragments; every resolved address must be public. |
| `max_duration_minutes` | no | `2` | Spider duration per target, from 1 to 5 minutes. The job timeout is 65 minutes. |
| `rules_file` | no | empty | Repository-relative ZAP rules file. `IGNORE` omits a finding, `WARN` reports without failing that rule, and `FAIL` fails on that rule. |
| `fail_on` | no | `high` | Minimum risk level that fails: `high`, `medium`, `low`, or `informational`. Explicit `WARN` and `IGNORE` rules take precedence; explicit `FAIL` always fails. |
| `runner_json` | no | `["self-hosted","Linux"]` | Runner labels. The workflow rejects labels that do not include both `self-hosted` and `Linux`. |

Outputs report counts for high, medium, low, and informational alerts. The job
summary includes those counts, the threshold, and scanner status. The artifact
contains sanitized HTML and JSON: rule ID, alert name, risk level, and instance
count only. Raw ZAP reports are not uploaded. Scanner errors and missing raw
reports fail closed.

## Example weekly consumer

Add a workflow in the consumer repository and replace the example hostnames
with its public storefront and Admin URLs. No credentials or authenticated
routes are supported.

```yaml
name: Weekly passive DAST
on:
  schedule:
    - cron: '23 5 * * 1'
  workflow_dispatch:
jobs:
  zap-baseline:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_dast-baseline.yml@v1
    with:
      targets: '["https://storefront.example.com","https://admin.example.com"]'
      max_duration_minutes: 2
      fail_on: high
      runner_json: '["self-hosted","Linux"]'
```

ZAP baseline performs a time-limited spider followed by passive rule analysis;
it does not run the active scanner. Each target is checked as a public HTTPS
endpoint, and a generated `OUTOFSCOPE` rule prevents spidering other hosts.
The runner/container also get a bounded CPU, memory, and process budget.

## Permissions, failures, and rollback

The workflow only requests `contents: read`; it does not declare or inherit
secrets. It fails for invalid targets or rules paths, missing Docker/scanner
reports, scanner errors, invalid thresholds, and findings above `fail_on`.
Review ZAP rule changes in the consumer repository like code. To roll back,
remove the reusable workflow call (or revert the consumer workflow commit); no
release tag or shared consumer state needs to be changed.

The reusable is additive and leaves existing `v1` contracts untouched. Do not
move the floating `v1` tag until release validation and review are complete.
