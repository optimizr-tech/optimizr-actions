# Reusable ShellCheck and actionlint gates

`_static-lint.yml` discovers tracked shell scripts, GitHub workflows, and composite action metadata. It installs ShellCheck 0.11.0 and actionlint 1.7.12 from versioned release assets, verifies architecture-specific SHA-256 checksums, and blocks on lint errors.

```yaml
jobs:
  static-lint:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_static-lint.yml@v1
    with:
      runner_json: '["self-hosted","Linux","security"]'
      shellcheck_severity: warning
      exclusions: |
        vendor/**
        fixtures/intentional-bad-script.sh
```

Exclusions must be repository-relative glob patterns and may not contain traversal. Keep them narrow and explain them in the consumer PR. The gate retains ShellCheck text, actionlint JSON lines, composite metadata failures, discovered files, versions, and command exit status. It receives no secrets and uses `contents: read`.

## GitHub concurrency queue compatibility

The pinned actionlint 1.7.12 schema predates GitHub Actions' `concurrency.queue` property. Until an official pinned actionlint release supports it, the runner applies a strict companion check before filtering anything:

- `queue` must appear directly under workflow-level `concurrency` or a job's `concurrency` mapping;
- its value must be the literal string `single` or `max`;
- `max` requires `cancel-in-progress` to be omitted or the literal boolean `false` (expressions and quoted strings are rejected conservatively);
- duplicate `queue` or `cancel-in-progress` keys are rejected, as are YAML merge keys in a concurrency mapping that uses `queue` (they could hide inherited settings).

Only actionlint's exact unsupported-`queue` syntax diagnostic at the validated key's file, line, and column is suppressed. Invalid queue contracts, malformed output, and every other actionlint diagnostic remain blocking. The evidence artifact keeps both the original `actionlint.jsonl` and the filtered `actionlint.filtered.jsonl`, and records the raw/effective exit codes and suppression count. The official binary versions and architecture-specific checksums remain unchanged. Remove this compatibility layer after the pinned official release supports the property and the contract tests confirm it.

See [GitHub's concurrency documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency) and the upstream [actionlint queue support PR](https://github.com/rhysd/actionlint/pull/654).

Rollback is to pin the previous `optimizr-actions` commit and preserve equivalent pinned lint tooling. Do not convert failures into global warnings.
