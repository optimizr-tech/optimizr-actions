#!/usr/bin/env bash

# Install a controlled Trivy release into a per-job directory.
#
# Downloads are bounded (connect/total timeouts, a fixed number of attempts
# with exponential backoff) so a network blip does not hang or fail a job on
# the first error. Every tarball is verified with SHA-256 before use: reviewed
# digests in trivy-checksums.txt win; versions that are not pinned fall back to
# the upstream release checksums file, which is the trust model of the
# upstream installer. A verified tarball is kept in the runner cache home and
# re-verified on every reuse. Any verification failure fails closed.
#
# Exit codes: 2 invalid input or unsafe runner state, 3 verification failure,
# 4 download failure after all attempts.
set -euo pipefail

readonly RELEASE_BASE_URL="https://github.com/aquasecurity/trivy/releases/download"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pinned_checksums="$script_dir/trivy-checksums.txt"

log() {
  echo "[optimizr-trivy] $*" >&2
}

fail() {
  local code="$1"
  shift
  echo "::error title=Trivy installation failed::$*" >&2
  exit "$code"
}

bounded_integer() {
  local name="$1" value="$2" minimum="$3" maximum="$4"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || ((value < minimum || value > maximum)); then
    fail 2 "$name must be an integer between $minimum and $maximum"
  fi
}

version=""
install_dir=""
while (($#)); do
  if (($# < 2)); then
    fail 2 "missing value for $1"
  fi
  case "$1" in
    --version) version="$2" ;;
    --install-dir) install_dir="$2" ;;
    *) fail 2 "unknown argument: $1" ;;
  esac
  shift 2
done

if [[ ! "$version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  fail 2 "trivy_version must be an exact release such as v0.74.0"
fi
number="${version#v}"
tag="v$number"
if [[ "$install_dir" != /* ]]; then
  fail 2 "--install-dir must be an absolute path"
fi

attempts="${OPTIMIZR_TRIVY_DOWNLOAD_ATTEMPTS:-4}"
retry_delay="${OPTIMIZR_TRIVY_RETRY_DELAY_SECONDS:-5}"
connect_timeout="${OPTIMIZR_TRIVY_CONNECT_TIMEOUT_SECONDS:-20}"
max_time="${OPTIMIZR_TRIVY_MAX_TIME_SECONDS:-180}"
bounded_integer OPTIMIZR_TRIVY_DOWNLOAD_ATTEMPTS "$attempts" 1 10
bounded_integer OPTIMIZR_TRIVY_RETRY_DELAY_SECONDS "$retry_delay" 0 60
bounded_integer OPTIMIZR_TRIVY_CONNECT_TIMEOUT_SECONDS "$connect_timeout" 1 120
bounded_integer OPTIMIZR_TRIVY_MAX_TIME_SECONDS "$max_time" 10 1800

if [[ "$(uname -s)" != Linux ]]; then
  fail 2 "the governed Trivy installer supports Linux runners only"
fi
case "$(uname -m)" in
  x86_64|amd64) platform=Linux-64bit ;;
  aarch64|arm64) platform=Linux-ARM64 ;;
  *) fail 2 "unsupported runner architecture: $(uname -m)" ;;
esac
asset="trivy_${number}_${platform}.tar.gz"

for tool in curl tar sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    fail 2 "$tool is required on the runner to install Trivy"
  fi
done

cache_home="${XDG_CACHE_HOME:-${HOME:?HOME must be set}/.cache}"
binary_cache="$cache_home/optimizr-security-gate/trivy-binaries"
cache_parent="${binary_cache%/*}"
if [[ -L "$cache_parent" || -L "$binary_cache" ]]; then
  fail 2 "Trivy binary cache path must not be a symbolic link: $binary_cache"
fi
mkdir -p "$binary_cache"
if [[ -L "$cache_parent" || -L "$binary_cache" ]]; then
  fail 2 "Trivy binary cache path must not be a symbolic link: $binary_cache"
fi
if [[ "$(stat -c '%u' "$binary_cache")" != "$(id -u)" ]]; then
  fail 2 "Trivy binary cache is not owned by the runner user: $binary_cache"
fi
chmod 700 "$binary_cache"

work_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/optimizr-trivy-download.XXXXXX")"
staging=""
cleanup() {
  rm -rf -- "$work_dir"
  if [[ -n "$staging" ]]; then
    rm -rf -- "$staging"
  fi
}
trap cleanup EXIT

digest_of() {
  sha256sum "$1" | awk '{print $1}'
}

lookup_digest() {
  local file="$1"
  if [[ -f "$file" ]]; then
    awk -v asset="$asset" '$1 !~ /^#/ && $2 == asset {print $1; exit}' "$file"
  fi
}

download() {
  local url="$1" output="$2" attempt=1 status delay
  while :; do
    log "downloading ${url##*/} (attempt $attempt/$attempts)"
    status=0
    curl --fail --silent --show-error --location \
      --proto =https --proto-redir =https --tlsv1.2 \
      --connect-timeout "$connect_timeout" --max-time "$max_time" \
      --speed-limit 10240 --speed-time 30 \
      --retry 0 \
      --output "$output" "$url" || status=$?
    if ((status == 0)); then
      return 0
    fi
    rm -f -- "$output"
    if ((attempt >= attempts)); then
      fail 4 "could not download ${url##*/} after $attempts attempts (last curl exit code $status)"
    fi
    delay=$((retry_delay * (1 << (attempt - 1))))
    if ((delay > 60)); then
      delay=60
    fi
    log "curl exit code $status; retrying in ${delay}s"
    sleep "$delay"
    attempt=$((attempt + 1))
  done
}

expected="$(lookup_digest "$pinned_checksums")"
pinned=true
if [[ -z "$expected" ]]; then
  pinned=false
fi

cached="$binary_cache/$asset"
cached_digest_file="$cached.sha256"
tarball=""
if [[ -L "$cached" || -L "$cached_digest_file" ]]; then
  log "discarding cached $asset: symbolic links are not trusted"
  rm -f -- "$cached" "$cached_digest_file"
elif [[ -f "$cached" ]]; then
  cache_expected="$expected"
  if [[ "$pinned" != true && -f "$cached_digest_file" ]]; then
    cache_expected="$(head -n 1 "$cached_digest_file")"
  fi
  if [[ "$cache_expected" =~ ^[0-9a-f]{64}$ && "$(digest_of "$cached")" == "$cache_expected" ]]; then
    log "using verified cached $asset"
    expected="$cache_expected"
    tarball="$cached"
  else
    log "discarding cached $asset: checksum mismatch or missing digest"
    rm -f -- "$cached" "$cached_digest_file"
  fi
fi

if [[ -z "$tarball" ]]; then
  if [[ "$pinned" != true ]]; then
    echo "::warning title=Unpinned Trivy version::$tag is not pinned in scripts/security_gate/trivy-checksums.txt; verifying against the upstream release checksums file" >&2
    download "$RELEASE_BASE_URL/$tag/trivy_${number}_checksums.txt" "$work_dir/checksums.txt"
    expected="$(lookup_digest "$work_dir/checksums.txt")"
  fi
  if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
    fail 3 "no SHA-256 digest is available for $asset"
  fi
  download "$RELEASE_BASE_URL/$tag/$asset" "$work_dir/$asset"
  actual="$(digest_of "$work_dir/$asset")"
  if [[ "$actual" != "$expected" ]]; then
    fail 3 "checksum mismatch for $asset (expected $expected, got $actual)"
  fi
  log "verified $asset sha256 $actual"
  tarball="$work_dir/$asset"
fi

mkdir -p "$install_dir"
staging="$(mktemp -d "$install_dir/trivy-bin.staging.XXXXXX")"
tar -xzf "$tarball" -C "$staging" --no-same-owner
if [[ ! -f "$staging/trivy" || -L "$staging/trivy" ]]; then
  fail 3 "$asset does not contain a regular trivy binary"
fi
chmod 755 "$staging/trivy"
if ! "$staging/trivy" --version 2>/dev/null | grep -qx "Version: $number"; then
  fail 3 "installed Trivy reports an unexpected version (expected $number)"
fi

if [[ "$tarball" != "$cached" ]]; then
  # Cache only artifacts that passed digest and version checks. Writes are
  # atomic renames, so a concurrent reader sees either nothing or a complete
  # file and always re-verifies it.
  if cp -- "$tarball" "$cached.tmp.$$" && mv -f -- "$cached.tmp.$$" "$cached"; then
    if [[ "$pinned" != true ]]; then
      printf '%s\n' "$expected" > "$cached_digest_file.tmp.$$"
      mv -f -- "$cached_digest_file.tmp.$$" "$cached_digest_file"
    fi
  else
    rm -f -- "$cached.tmp.$$"
    log "could not store $asset in the runner cache; continuing without cache"
  fi
fi

target="$install_dir/trivy-bin"
rm -rf -- "$target"
mv -- "$staging" "$target"
staging=""
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "$target" >> "$GITHUB_PATH"
fi
log "installed Trivy $tag at $target/trivy"
