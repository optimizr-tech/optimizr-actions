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

## Dependabot group PR title compaction

Dependabot names grouped-update PRs `<commit subject> from X to Y in the <group>
group` (for example 109 characters for `actions/create-github-app-token` in
`gha-minor-patch`), while its signed commit subject stays short. The 72-character
limit is **not** raised and nothing is bypassed; the validator instead
*compacts the title it checks*, in memory only:

1. The title is over 72 characters and has no other title defect.
2. The PR and one of its commits satisfy the full verified Dependabot group
   commit check above (bot author/PR/branch, `web-flow` committer, valid
   signature, both group markers).
3. The title is exactly that commit's subject followed only by the generated tail
   `[ from <X> to <Y>] in the <group> group`.

When all hold, the commit subject (which must itself be at most 72 characters,
or at most 200 under the commit rule) replaces the title for validation, and
then the normal strict title rules run on it. If any condition fails, the original
title is validated and a title over 72 characters fails with
`must be at most 72 characters`. Human PRs, edited titles, unverified commits
and arbitrary suffixes are never compacted.

The PR title on GitHub is **not edited**: no write permission, no extra token
scope and no candidate code execution are added (the job keeps
`contents: read` and `pull-requests: read`).

Failure modes: missing/inconsistent API fields or a failed metadata GET fail
closed with the existing sanitized diagnostics; compaction never turns an API
error into a pass.

### Consumer adoption and inventory

No input, output, permission or workflow change is needed: consumers that call
`_pr-metadata.yml` (or the `pr-metadata-validation` action) at `@v1` receive the
behavior when `v1` is moved after release validation and human approval. Callers
found by org code search (may be incomplete): `optimizr-infra-ops`,
`optimizr-serve`, `optimizr-payment`, `optimizr-cdn`, `optimizr-monitoring`,
`optimizr-marketing-site`, `optimizr-corp-docs`, `optimizr-infra-nginx`,
`optimizr-infra-certbot`, `optimizr-infra-keycloak`. Until `v1` moves, grouped
Dependabot PRs such as InfraOps #548 keep failing the title check; rerun the check
after the release. Dependabot configs that already shorten the commit subject
(InfraOps #534) are required, since compaction only matches a verified subject.

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
