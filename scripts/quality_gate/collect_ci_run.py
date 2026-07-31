"""Download the successful CI artifact set for an exact commit SHA."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path, PurePosixPath
import shutil
from typing import Any
from urllib import error, request
import zipfile

API = "https://api.github.com"


def _request(url: str, token: str, *, accept: str = "application/vnd.github+json") -> bytes:
    req = request.Request(
        url,
        headers={
            "Accept": accept,
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "optimizr-quality-gate",
        },
    )
    try:
        with request.urlopen(req, timeout=60) as response:
            return response.read()
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"GitHub API {exc.code}: {detail}") from exc


def _json(url: str, token: str) -> dict[str, Any]:
    payload = json.loads(_request(url, token))
    if not isinstance(payload, dict):
        raise RuntimeError("GitHub API response was not an object")
    return payload


def _safe_extract(archive: bytes, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        for info in zipped.infolist():
            path = PurePosixPath(info.filename)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("artifact archive contains an unsafe path")
            target = (destination / Path(*path.parts)).resolve()
            try:
                target.relative_to(root)
            except ValueError as exc:
                raise ValueError("artifact archive escapes destination") from exc
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zipped.open(info) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def collect(
    repository: str,
    workflow_file: str,
    head_sha: str,
    token: str,
    destination: Path,
) -> None:
    runs = _json(
        f"{API}/repos/{repository}/actions/workflows/{workflow_file}/runs"
        f"?event=pull_request&head_sha={head_sha}&status=completed&per_page=100",
        token,
    ).get("workflow_runs", [])
    candidates = [
        run
        for run in runs
        if isinstance(run, dict)
        and run.get("head_sha") == head_sha
        and run.get("conclusion") == "success"
    ]
    if not candidates:
        raise RuntimeError(f"no successful {workflow_file} run found for {head_sha}")
    run = max(candidates, key=lambda item: int(item.get("run_number", 0)))
    run_id = int(run["id"])
    artifacts = _json(
        f"{API}/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100",
        token,
    ).get("artifacts", [])
    active = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict) and not artifact.get("expired", False)
    ]
    if not active:
        raise RuntimeError(f"successful CI run {run_id} has no active artifacts")
    destination.mkdir(parents=True, exist_ok=True)
    for artifact in active:
        artifact_id = int(artifact["id"])
        artifact_name = str(artifact.get("name", artifact_id))
        archive = _request(
            f"{API}/repos/{repository}/actions/artifacts/{artifact_id}/zip",
            token,
            accept="application/vnd.github+json",
        )
        _safe_extract(archive, destination / artifact_name)
    (destination / "ci-run.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repository": repository,
                "workflow_file": workflow_file,
                "head_sha": head_sha,
                "run_id": run_id,
                "artifact_count": len(active),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-file", default="ci.yml")
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args(argv)
    token = args.token_file.read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError("GitHub token is empty")
    collect(
        args.repository,
        args.workflow_file,
        args.head_sha,
        token,
        args.destination,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
