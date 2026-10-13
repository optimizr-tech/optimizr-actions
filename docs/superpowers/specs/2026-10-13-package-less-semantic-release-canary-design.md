# Package-less semantic-release validation canary

## Status

Approved for implementation in the current task. Scope: PR #332 / issue #328. This document does not authorize merge, release, or movement of the `v1` tag.

## Problem

PR #332 initially added package-less release support and a canary that called the privileged `_semantic-release.yml` reusable workflow with `contents: read`. GitHub rejects that call before starting any job because the reusable workflow requests `contents: write`, `issues: write`, and `pull-requests: write`. A reusable workflow cannot elevate the permissions granted by its caller. The branch now calls the candidate composite action directly, but a second review found that semantic-release 25.0.5 returns early for pull-request events before validating configuration or analyzing commits. A manual run avoids that early return but still checks remote push authorization, which cannot succeed against GitHub with the canary's read-only, credential-free boundary.

The reusable workflow also runs in the caller's workspace. A local action path such as `./.github/actions/...` therefore resolves against the consumer checkout, not automatically against the repository containing the reusable workflow. The production path must explicitly load shared action code from the exact revision of the called workflow, not from a floating `v1` reference.

## Decision

Extract the package-less, non-publishing validation sequence into an internal composite action in `optimizr-actions`. The action will own package-less runtime preparation, plugin/runtime validation, changelog compatibility checks, and semantic-release dry-run. It will not publish releases, tags, or badges.

Use that action in two contexts:

1. The PR/manual canary checks out the candidate revision and invokes the composite action from that checkout. It does not call `_semantic-release.yml`; it grants only `contents: read`, uses a package-less fixture with no publisher plugins, and passes no token input to the composite action. To exercise semantic-release's actual release analysis and note generation on both PR and manual events, the canary prepares an isolated project and a local bare Git remote under `RUNNER_TEMP`, then invokes only the dry-run helper with a child-process `push`/`main` context and `--no-ci`. The local bare repository is populated by a local clone; no GitHub or external remote ref is written. The canary requires output proving that a next version and release notes were generated.
2. `_semantic-release.yml` keeps its existing publishing permissions and release gates. In package-less mode, it validates `job.workflow_repository` and the full `job.workflow_sha`, checks out `optimizr-tech/optimizr-actions` at that exact SHA into a dedicated workspace subdirectory with persisted credentials disabled, and invokes the composite action by local path from that checkout. The production workflow supplies its existing GitHub token only to the dry-run step when the configured plugins need GitHub API access. Publishing remains outside the composite action and retains the existing `validate_only`, release, and badge gates.

The read-only canary tests the proposed composite action at the candidate revision without exercising the privileged publishing workflow or GitHub authentication. The canary-only mode changes only the environment of the `--dry-run` subprocess and fails if a GitHub token is present. Static contract tests must separately prove the exact-SHA production lookup and permission boundaries. If a future runner-supported integration test is needed for the production checkout path, it must remain read-only and must not call the privileged reusable workflow from a low-permission caller.

## Compatibility and public contract

- Preserve `package_mode: node` as the default and leave its dependency-install behavior unchanged.
- Preserve the existing meaning of `validate_only` and all current publishing and badge gates.
- Remove `tokenless_dry_run` and `simulate_default_branch_for_dry_run` from the reusable workflow inputs. They were introduced only by this unvalidated draft; token omission is an internal canary property, and local branch simulation belongs in the canary rather than the reusable release contract.
- Do not add a new consumer-facing workflow input for the shared action. Map existing reusable inputs to internal composite-action inputs.
- The composite action's canary-only mode defaults to `false`, is not exposed by `_semantic-release.yml`, rejects a non-empty GitHub token, and affects only the always-dry-run helper.
- Do not change required permissions, consumer workflows, supported runner trust, release tagging, or the floating `v1` tag as part of this correction.
- Regenerate `catalog/capabilities.json` when the public reusable input schema changes, and update the semantic-release documentation to match the final contract.

Package-less exact-revision lookup is fail-closed: missing or malformed workflow identity, a repository other than `optimizr-tech/optimizr-actions`, or a non-full SHA must stop before the shared action runs. There is no `v1`, branch, or caller-controlled fallback. GitHub documents `job.workflow_repository` and `job.workflow_sha` for reusable workflows and demonstrates checking out the called workflow's own revision. These identity fields are not available on GitHub Enterprise Server; package-less mode will retain the current GitHub.com-only identity requirement unless GHES support is explicitly designed separately.

## Security and failure boundaries

- The canary uses only a GitHub-hosted runner and `contents: read`; it never receives write permissions, production secrets, or a production runner.
- The canary fixture must not include `@semantic-release/github`, `@semantic-release/npm`, or other publisher plugins. Its isolated project contains only the `.releaserc.json` fixture and a deterministic `feat:` commit, with no Node manifest or lockfile.
- The canary's local bare remote and synthetic `push`/`main` variables exist only in `RUNNER_TEMP` and in the dry-run child process. Do not use a GitHub token, credentials, or an externally reachable remote; assert that dry-run output includes both the planned next version and release notes.
- The production checkout of the central repository uses a fixed, dedicated path under `github.workspace`, `persist-credentials: false`, and the immutable workflow SHA. Before checkout, fail if the target path already exists so the checkout cannot collide with consumer files. The implementation must verify how checkout and local action resolution behave with this nested path on the supported runner.
- The composite action must not publish or mutate remote state. Its optional token input, if required for a production dry-run, is scoped only to the dry-run process and is absent from the canary invocation.
- Invalid package mode, invalid working directory, untrusted workflow identity, dependency installation failure, changelog incompatibility, and dry-run failure remain hard failures. Do not use `continue-on-error` to make the canary green.
- Do not move `v1`, merge, or publish a release as part of implementation or validation.

## Acceptance criteria

1. A PR canary runs the candidate composite action directly and starts with `contents: read`; it does not call the privileged reusable workflow.
2. The fixture has no Node manifest or lockfile and contains only the analyzer and notes-generator plugins needed for dry-run validation.
3. The production reusable workflow accepts package-less mode only after exact repository/full-SHA validation and invokes the checked-out composite action from that same workflow SHA.
4. Tests assert the canary's permissions, absence of a token input and publisher plugins, successful planning against an isolated local bare remote, the exact-SHA checkout contract, fail-closed identity/path guards, actionlint's path-scoped compatibility exception, and preservation of Node mode and publication gates.
5. `catalog/capabilities.json` and semantic-release documentation match the final reusable contract.
6. The hosted runner reports the complete required repository checks as passing. Local test execution remains out of scope; report any check that the runner does not execute rather than treating it as green.
7. The PR remains draft/reviewable. No merge, `v1` tag movement, release, or consumer migration occurs without explicit approval.

## Rollback

If the canary or package-less production validation fails, revert the new composite action and its call sites, remove the canary-specific workflow/test changes, and restore the prior package-less implementation while retaining `package_mode: node` as the default. Do not roll back by granting the canary write permissions or by changing the `v1` tag.

## References

- GitHub reusable-workflow permissions can only be the same or more restrictive than the caller: [Reusing workflow configurations](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations).
- The `job.workflow_repository` / `job.workflow_sha` identity and exact-revision checkout example: [Contexts reference](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#job-context).
- A `./path/to/action` is relative to `github.workspace` and requires checkout: [Using pre-written building blocks in your workflow](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/find-and-customize-actions#adding-an-action-from-the-same-repository).
