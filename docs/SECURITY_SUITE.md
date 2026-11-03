# Reusable security suite

`_security-suite.yml` provides one caller contract for the portable Optimizr security gates.

Profiles:

| Profile | Static lint | Filesystem scan | Dependency policy | SAST | Image evidence |
|---|---:|---:|---:|---:|---:|
| `python` | yes | yes | yes | Python | no |
| `node` | yes | yes | yes | TypeScript/JavaScript | no |
| `compose` | yes | yes | no | no | when `image_refs` is supplied |
| `infra` | yes | yes | no | no | when `image_refs` is supplied |
| `monorepo` | yes | yes | yes | all | when `image_refs` is supplied |

```yaml
jobs:
  security:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_security-suite.yml@v1
    with:
      profile: node
      runner_json: '["ubuntu-latest"]'
      dependency_working_directory: app
      dependency_policy_file: .github/security/dependency-policy.json
      sast_baseline_file: .github/security/sast-baseline.json
      exceptions_file: .github/security/trivy-exceptions.json
```

`dependency_working_directory` defaults to the repository root and is passed to the dependency-policy gate, which resolves and confines it with `realpath`. SAST and filesystem scanning continue to cover the entire repository so shared code and workflow files are not silently omitted.

## Result outputs and evidence integrity

The suite keeps the existing `result` and `evidence_path` outputs and adds
`conclusion`, `repository`, `run_id`, `run_attempt`, `producer`,
`producer_ref`, `producer_sha`, `source_sha`, `evidence_sha256`, `evidence_manifest_path`,
`evidence_artifact_name`, `evidence_artifact_id`, and
`evidence_artifact_digest`. The aggregate artifact contains `summary.json`
and a `manifest.json` sidecar. The sidecar binds the summary's raw bytes to
the caller repository, run and attempt, the reusable workflow file and its
resolved commit, the verified caller checkout SHA, and artifact name.

`evidence_sha256` hashes the raw summary JSON. `evidence_artifact_digest`
hashes the uploaded archive; the two values describe different files. A
consumer can independently check the downloaded summary against the sidecar:

```bash
expected="$(jq -r .evidence_sha256 manifest.json)"
actual="$(sha256sum summary.json | cut -d' ' -f1)"
test "$expected" = "$actual"
```

Each child gate keeps its existing artifact and adds an
`evidence-manifest.json` that records every raw file's relative path, size,
and SHA-256. Its reusable-workflow outputs expose a compact identity record,
the raw manifest SHA-256, artifact name and ID, and the uploaded archive
digest. The suite summary carries these values for every child that ran;
expected skips are `null`, and a required skip or missing/mismatched child
record makes the suite fail. The child producer repository, file, ref, and
resolved commit remain in each record so callers can compare them with the
downloaded manifest without relying on the aggregate summary hash.

For each downloaded child artifact, compare the raw manifest hash from the
suite's `child_evidence` record with `sha256sum evidence-manifest.json`, then
verify each file against that manifest's `evidence_files` entries. For
example, after downloading the `security-suite-sast` artifact:

```bash
expected="$(jq -r '.child_evidence.sast.evidence_sha256' security-suite/summary.json)"
CHILD_EVIDENCE_DIR=downloaded/sast EXPECTED_MANIFEST_SHA256="$expected" python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path, PurePosixPath

root = Path(os.environ["CHILD_EVIDENCE_DIR"]).resolve()
manifest_bytes = (root / "evidence-manifest.json").read_bytes()
if hashlib.sha256(manifest_bytes).hexdigest() != os.environ["EXPECTED_MANIFEST_SHA256"]:
    raise SystemExit("evidence manifest SHA-256 mismatch")
manifest = json.loads(manifest_bytes)
for item in manifest["evidence_files"]:
    relative = PurePosixPath(item["path"])
    path = (root / Path(*relative.parts)).resolve()
    path.relative_to(root)
    contents = path.read_bytes()
    if len(contents) != item["size_bytes"]:
        raise SystemExit(f"evidence size mismatch: {item['path']}")
    if hashlib.sha256(contents).hexdigest() != item["sha256"]:
        raise SystemExit(f"evidence SHA-256 mismatch: {item['path']}")
PY
```

The `artifact_digest` separately identifies the uploaded artifact archive.
For image scans, `source_sha` records the caller checkout used by the
workflow; it does not prove which source revision produced a prebuilt image
reference.

If the initial profile job fails its runner-trust check, the workflow writes a
status-only failure summary and uploads it without checking out caller content.
The summary records `source_checked: false`, leaves the `source_sha` output and
manifest path empty, and identifies the failed trust check. The same fallback
is used if either identity checkout fails, so the legacy `result` and
`evidence_path` outputs and summary artifact remain available without claiming
that an unverified caller revision was scanned. Failures in child security
gates still produce the full aggregate failure summary and artifact.

The standalone `_trivy-scan.yml` exposes the same run, producer, checkout,
and artifact identity fields, plus the raw report path and SHA-256. Its
existing `upload_artifact: false` option remains available; the evidence
artifact ID and archive digest are then empty. With `skip: true`, its result
and conclusion are `skipped`, and no artifact is created. When a report is
absent, the workflow uploads a failed manifest when possible and fails the
scan instead of reporting a pass.

The suite does not accept shell commands or secrets. Consumer-owned project, policy and baseline paths remain repository relative. For image evidence, build the final image first on the selected runner and pass only local image references.

Merge order: publish the static-lint, dependency-policy, SAST and supply-chain contracts before publishing the suite through `v1`. Rollback by pinning the preceding compatible Actions commit while retaining equivalent mandatory gates.
