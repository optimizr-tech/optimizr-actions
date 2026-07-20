# Reusable Node project validation

`_node-project-test.yml` validates one to ten npm/pnpm projects. Each phase is a package-script identifier, never an arbitrary shell command.

```yaml
jobs:
  node:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_node-project-test.yml@v1
    with:
      node_version: "20"
      pnpm_version: "11"
      projects_json: >-
        [
          {
            "name":"storefront",
            "working_directory":"frontend/apps/storefront",
            "package_manager":"pnpm",
            "lint_script":"lint",
            "typecheck_script":"typecheck",
            "test_script":"test",
            "build_script":"build",
            "artifact_paths":["coverage/coverage-summary.json"]
          }
        ]
```

The prepare job rejects traversal, duplicate names, unsupported managers and invalid script names before a matrix runner checks out code. The composite repeats path validation, executes package-manager arguments without a shell, rejects symlink artifacts and copies only declared outputs into a controlled artifact directory.

Rollback by returning the consumer to its prior explicit Node jobs while preserving frozen installs, lint, typecheck, tests and build.
