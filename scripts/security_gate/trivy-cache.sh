#!/usr/bin/env bash

# Prepare Trivy caches and keep the relevant locks open in the calling step.
# Repository mode preserves the existing exclusive per-repository lock and
# Trivy's normal DB refresh behavior. Shared mode locks that result cache per
# repository, refreshes the versioned DB under an exclusive lock, then holds a
# shared DB lock while read-only scans run concurrently across repositories.
trivy_cache_setup() {
  local action_root="$1"
  local repository="$2"
  local trivy_version="$3"
  local cache_scope="$4"
  local max_age_hours="$5"
  local retention_days="${6:-14}"
  local cache_tool="$action_root/scripts/security_gate/cache.py"
  local shared_cache_root=""
  local shared_cache_dir=""
  local shared_setup_lock_path=""
  local shared_database_lock_path=""
  local database_fresh="false"

  OPTIMIZR_TRIVY_CACHE_ROOT="$(python3 "$cache_tool" root --repository "$repository")"
  OPTIMIZR_TRIVY_CACHE_DIR="$(python3 "$cache_tool" path \
    --repository "$repository" \
    --trivy-version "$trivy_version" \
    --cache-scope "$cache_scope")"
  OPTIMIZR_TRIVY_DB_ARGS=()

  if [[ -L "$OPTIMIZR_TRIVY_CACHE_ROOT" || -L "$OPTIMIZR_TRIVY_CACHE_DIR" ]]; then
    echo "::error::security cache path must not be a symbolic link" >&2
    return 2
  fi
  mkdir -p "$OPTIMIZR_TRIVY_CACHE_ROOT"
  if [[ -L "$OPTIMIZR_TRIVY_CACHE_ROOT" ]]; then
    echo "::error::security cache path must not be a symbolic link" >&2
    return 2
  fi
  if [[ "$(stat -c '%u' "$OPTIMIZR_TRIVY_CACHE_ROOT")" != "$(id -u)" ]]; then
    echo "::error::security cache is not owned by the runner user: $OPTIMIZR_TRIVY_CACHE_ROOT" >&2
    return 2
  fi
  chmod 700 "$OPTIMIZR_TRIVY_CACHE_ROOT"
  if ! command -v flock >/dev/null 2>&1; then
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
      echo "failure_reason=missing_flock" >> "$GITHUB_OUTPUT"
    fi
    echo "::error title=Missing security-gate runner dependency::flock is required to protect the shared Trivy cache. Install util-linux on the self-hosted runner or use a runner image that provides flock; do not bypass the lock." >&2
    return 2
  fi
  if [[ -L "$OPTIMIZR_TRIVY_CACHE_ROOT/gate.lock" ]]; then
    echo "::error::security cache lock must not be a symbolic link" >&2
    return 2
  fi

  # This lock protects the per-repository scan-result cache and its migration.
  exec 8>>"$OPTIMIZR_TRIVY_CACHE_ROOT/gate.lock"
  flock -x 8

  if [[ "$cache_scope" == shared ]]; then
    shared_cache_root="$(python3 "$cache_tool" shared-root)"
    shared_cache_dir="$(python3 "$cache_tool" shared-path --trivy-version "$trivy_version")"
    shared_setup_lock_path="${shared_cache_dir}.setup.lock"
    shared_database_lock_path="${shared_cache_dir}.db.lock"
    if [[ -L "$shared_cache_root" || -L "$shared_cache_dir" || \
          -L "$shared_setup_lock_path" || -L "$shared_database_lock_path" ]]; then
      echo "::error::shared Trivy cache paths must not be symbolic links" >&2
      return 2
    fi
    mkdir -p "$shared_cache_root"
    if [[ -L "$shared_cache_root" ]]; then
      echo "::error::shared Trivy cache path must not be a symbolic link" >&2
      return 2
    fi
    if [[ "$(stat -c '%u' "$shared_cache_root")" != "$(id -u)" ]]; then
      echo "::error::shared Trivy cache is not owned by the runner user: $shared_cache_root" >&2
      return 2
    fi
    chmod 700 "$shared_cache_root"
    if [[ -L "$shared_setup_lock_path" || -L "$shared_database_lock_path" ]]; then
      echo "::error::shared Trivy cache locks must not be symbolic links" >&2
      return 2
    fi

    # Serialize only setup/refresh work. The database lock below stays shared
    # for the duration of scans, so fresh scans can run concurrently.
    exec 10>>"$shared_setup_lock_path"
    flock -x 10
  elif [[ "$cache_scope" != repository ]]; then
    echo "::error::cache_scope must be repository or shared" >&2
    return 2
  fi

  python3 "$cache_tool" prepare \
    --repository "$repository" \
    --trivy-version "$trivy_version" \
    --retention-days "$retention_days" \
    --cache-scope "$cache_scope"
  chmod 700 "$OPTIMIZR_TRIVY_CACHE_ROOT" "$OPTIMIZR_TRIVY_CACHE_DIR"

  if [[ "$cache_scope" == shared ]]; then
    chmod 700 "$shared_cache_dir"
    database_fresh="$(python3 "$cache_tool" database-fresh \
      --database "$shared_cache_dir/db" \
      --max-age-hours "$max_age_hours")"
    exec 9>>"$shared_database_lock_path"
    if [[ "$database_fresh" != true ]]; then
      # Wait for active readers only when a refresh is actually needed.
      flock -x 9
      database_fresh="$(python3 "$cache_tool" database-fresh \
        --database "$shared_cache_dir/db" \
        --max-age-hours "$max_age_hours")"
      if [[ "$database_fresh" != true ]]; then
        python3 "$cache_tool" invalidate-shared-db --trivy-version "$trivy_version"
        trivy --cache-dir "$OPTIMIZR_TRIVY_CACHE_DIR" image --download-db-only
      fi
      database_fresh="$(python3 "$cache_tool" database-fresh \
        --database "$shared_cache_dir/db" \
        --max-age-hours "$max_age_hours")"
      if [[ "$database_fresh" != true ]]; then
        echo "::error::Trivy vulnerability database is missing, stale, or invalid after refresh" >&2
        return 2
      fi
      # flock conversion can release/reacquire; the validation below is after
      # the read lock is held and gates all scanner invocations.
      flock -s 9
    else
      flock -s 9
    fi
    database_fresh="$(python3 "$cache_tool" database-fresh \
      --database "$shared_cache_dir/db" \
      --max-age-hours "$max_age_hours")"
    if [[ "$database_fresh" != true ]]; then
      echo "::error::Trivy vulnerability database became stale before scan" >&2
      return 2
    fi
    # No writer can take the setup lock while another job refreshes. Once this
    # reader lock is held, release setup so other fresh jobs can join as readers.
    flock -u 10
    OPTIMIZR_TRIVY_DB_ARGS=(--skip-db-update)
  fi
}
