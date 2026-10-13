#!/usr/bin/env bash
set -euo pipefail

if [[ "${SEMANTIC_RELEASE_CANARY_MODE:-false}" == "true" ]]; then
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    echo "::error::canary mode must not receive a GitHub token"
    exit 2
  fi

  canary_log="$(mktemp "${RUNNER_TEMP:?}/semantic-release-canary.XXXXXX")"
  env -u GITHUB_HEAD_REF -u GITHUB_BASE_REF -u GITHUB_EVENT_PATH \
    GITHUB_EVENT_NAME=push \
    GITHUB_REF=refs/heads/main \
    GITHUB_REF_NAME=main \
    GITHUB_SHA="$(git rev-parse HEAD)" \
    npx semantic-release --dry-run --no-ci 2>&1 | tee "$canary_log"

  grep -F "The next release version is" "$canary_log" >/dev/null
  grep -F "Release note for version" "$canary_log" >/dev/null
  echo "Package-less canary analyzed commits and generated release notes."
else
  npx semantic-release --dry-run
fi
