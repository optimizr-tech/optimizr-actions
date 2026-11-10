import json
import os
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import unittest


@unittest.skipUnless(
    os.environ.get("GITHUB_ACTIONS") == "true",
    "anonymous GitHub asset smoke test runs only on hosted Actions",
)
class SemanticReleasePublicAssetAccessTests(unittest.TestCase):
    repository = "optimizr-tech/optimizr-actions"
    ref = "v1"
    assets = (
        "templates/.releaserc.json",
        "scripts/release/prepare_protected_releaserc.py",
    )

    def test_canonical_assets_are_readable_without_authentication(self):
        for path in self.assets:
            with self.subTest(path=path):
                url = (
                    f"https://api.github.com/repos/{self.repository}/contents/{path}?"
                    f"{urlencode({'ref': self.ref})}"
                )
                request = Request(
                    url,
                    headers={
                        "Accept": "application/vnd.github.raw+json",
                        "User-Agent": "optimizr-actions-contract-test",
                    },
                )
                self.assertIsNone(request.get_header("Authorization"))

                try:
                    with urlopen(request, timeout=15) as response:
                        content = response.read()
                except HTTPError as error:
                    error_body = ""
                    try:
                        error_body = error.read().decode("utf-8", errors="ignore").lower()
                    except Exception:
                        pass
                    if error.code == 403 and (
                        error.headers.get("X-RateLimit-Remaining") == "0"
                        or "rate limit" in error_body
                        or "rate limit" in str(getattr(error, "reason", "")).lower()
                    ):
                        self.skipTest(
                            f"anonymous read of {path}@{self.ref} hit GitHub API rate limit (403)"
                        )
                    self.fail(
                        f"anonymous read of {path}@{self.ref} failed with HTTP "
                        f"{error.code}; no authorization header was sent"
                    )

                self.assertTrue(content, f"{path}@{self.ref} returned an empty file")
                if path.endswith(".json"):
                    self.assertIsInstance(json.loads(content), dict)
                else:
                    self.assertIn(b"class ProtectedReleaseError", content)


if __name__ == "__main__":
    unittest.main()
