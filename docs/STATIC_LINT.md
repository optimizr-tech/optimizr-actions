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

Rollback is to pin the previous `optimizr-actions` commit and preserve equivalent pinned lint tooling. Do not convert failures into global warnings.
