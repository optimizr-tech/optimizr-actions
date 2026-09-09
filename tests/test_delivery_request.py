import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest

from scripts.delivery.request import (
    DeployRequest,
    RequestError,
    canonicalize_request,
    load_request,
    main,
    parse_request,
)


class DeployRequestContractTests(unittest.TestCase):
    def valid_payload(self) -> dict[str, str]:
        return {
            "repository": "optimizr-tech/optimizr-serve",
            "service": "optimizr-serve",
            "candidate_sha": "a" * 40,
            "trusted_ref": "refs/heads/main",
            "compose_file": "docker-compose.yml",
            "container_name": "optimizr-serve",
            "adapter": "github-actions",
            "reason": "reviewed main promotion",
        }

    def test_accepts_canonical_provider_neutral_request(self) -> None:
        request = parse_request(self.valid_payload())

        self.assertIsInstance(request, DeployRequest)
        self.assertEqual("optimizr-tech/optimizr-serve", request.repository)
        self.assertEqual("github-actions", request.adapter)
        self.assertEqual(
            {
                "adapter": "github-actions",
                "candidate_sha": "a" * 40,
                "compose_file": "docker-compose.yml",
                "container_name": "optimizr-serve",
                "reason": "reviewed main promotion",
                "repository": "optimizr-tech/optimizr-serve",
                "service": "optimizr-serve",
                "trusted_ref": "refs/heads/main",
            },
            canonicalize_request(request),
        )

    def test_accepts_each_protected_adapter_identity(self) -> None:
        for adapter in ("github-actions", "gitlab-ci", "ansible", "manual"):
            values = self.valid_payload()
            values["adapter"] = adapter
            with self.subTest(adapter=adapter):
                self.assertEqual(adapter, parse_request(values).adapter)

    def test_rejects_unknown_or_missing_fields(self) -> None:
        values = self.valid_payload()
        values["unexpected"] = "value"
        with self.assertRaisesRegex(RequestError, "unknown"):
            parse_request(values)

        values = self.valid_payload()
        del values["candidate_sha"]
        with self.assertRaisesRegex(RequestError, "candidate_sha"):
            parse_request(values)

    def test_rejects_untrusted_revision_and_invalid_identity(self) -> None:
        values = self.valid_payload()
        values["candidate_sha"] = "A" * 40
        with self.assertRaisesRegex(RequestError, "candidate_sha"):
            parse_request(values)

        values = self.valid_payload()
        values["trusted_ref"] = "refs/pull/42/merge"
        with self.assertRaisesRegex(RequestError, "trusted_ref"):
            parse_request(values)

        values = self.valid_payload()
        values["repository"] = "optimizr-tech/../../serve"
        with self.assertRaisesRegex(RequestError, "repository"):
            parse_request(values)

    def test_rejects_unsafe_paths_identifiers_and_secret_like_reason(self) -> None:
        values = self.valid_payload()
        values["compose_file"] = "../docker-compose.yml"
        with self.assertRaisesRegex(RequestError, "compose_file"):
            parse_request(values)

        values = self.valid_payload()
        values["container_name"] = "service;docker rm -f all"
        with self.assertRaisesRegex(RequestError, "container_name"):
            parse_request(values)

        values = self.valid_payload()
        values["reason"] = "token=super-secret"
        with self.assertRaisesRegex(RequestError, "reason"):
            parse_request(values)

    def test_loads_only_a_json_object_from_the_allowed_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request_path = root / "request.json"
            request_path.write_text(json.dumps(self.valid_payload()), encoding="utf-8")

            self.assertEqual(
                parse_request(self.valid_payload()), load_request(request_path, root)
            )

            outside = root.parent / "outside.json"
            outside.write_text(json.dumps(self.valid_payload()), encoding="utf-8")
            try:
                with self.assertRaisesRegex(RequestError, "allowed root"):
                    load_request(outside, root)
            finally:
                outside.unlink()

    def test_cli_emits_only_the_canonical_secret_free_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request_path = root / "request.json"
            request_path.write_text(json.dumps(self.valid_payload()), encoding="utf-8")
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(
                    ["--request", str(request_path), "--root", str(root)]
                )

            self.assertEqual(0, exit_code)
            self.assertEqual(
                canonicalize_request(parse_request(self.valid_payload())),
                json.loads(output.getvalue()),
            )


if __name__ == "__main__":
    unittest.main()
