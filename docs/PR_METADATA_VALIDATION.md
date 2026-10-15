# PR metadata validation contract

The `pr-metadata-validation` composite action validates pull-request metadata
through read-only GitHub API `GET` requests. It does not check out or execute
candidate code. Its caller interface and permissions remain unchanged.

## Inputs and outputs

The required inputs remain `token` (read-only), `repository`, `pr_number`,
`pr_title`, `pr_body`, `base_sha`, and `head_sha`. Optional
`scan_changed_files` remains `false` by default. Outputs remain `result` and
`commit_count`; no new permission or caller input is required.

## Commit subject length

PR titles and ordinary commit subjects remain limited to 72 characters. A
longer commit subject is accepted only when the GitHub API metadata for that
individual commit shows all of the following:

- the open PR and commit author are the `dependabot[bot]` account, with the
  same GitHub account ID, and the head branch uses the `dependabot/` prefix;
- GitHub maps the signed commit's committer to `web-flow`, its signed author
  email uses the Dependabot bot's GitHub no-reply address, and the API reports
  `verification.verified: true` with `verification.reason: valid`;
- the commit message contains both the generated group summary and the
  `dependency-group` field.

The exception is per commit and capped at 200 characters. Every other subject
rule still applies, including ASCII, conventional format, language, and
trailing-period checks. Missing or inconsistent API fields fail closed. The
PR title is always validated with the normal 72-character limit, even on a
Dependabot PR. Signature-verification fields are read from GitHub's commit API
response; see [REST API commit signature verification](https://docs.github.com/en/rest/commits/commits#signature-verification-object).

## API failure and retry policy

- A request gets at most three total attempts. Only recognized transient
  transport failures are retried: timeouts, connection reset/abort/refusal,
  network-unreachable errors, and temporary DNS resolution (`EAI_AGAIN`).
- Retries wait 2 seconds, then 4 seconds. Retry attempts and waits share one
  30-second retry-only budget across the validation run. The initial attempt
  keeps the existing 30-second `urllib` timeout and does not consume that
  retry-only budget. Retry socket-operation timeouts are capped by the budget
  remaining at that point.
- `urllib` timeouts apply to blocking socket operations; this retry budget is
  not a strict end-to-end wall-clock deadline. The reusable PR metadata job
  retains its existing five-minute job timeout.
- HTTP responses are never retried, including 403, 404, 429, and 5xx. TLS or
  certificate errors, permanent DNS failures, unknown transport errors,
  invalid JSON, validation failures, and SHA/lifecycle failures also fail
  without retry. No caller-provided event value replaces required API data.
- CI diagnostics expose only a fixed error category, attempt count, and (for
  HTTP errors) numeric status. They do not print request URLs, query strings,
  response bodies, headers, tokens, or raw exception details. Exhaustion fails
  the validation closed.

## Compatibility and rollback

This is a narrow backward-compatible validation exception: inputs, outputs,
permissions, and consumer configuration do not change, so consumers need no
migration. It does not waive PR-title validation or any other subject check,
and it does not execute candidate code. The change does not move the floating
`v1` tag; normal release validation and human-approved publication remain
required before consumers receive it. Rollback is to revert the
implementation through the same reviewed release path.
