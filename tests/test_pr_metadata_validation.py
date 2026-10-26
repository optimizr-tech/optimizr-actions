from __future__ import annotations

import errno
import importlib.util
import io
from pathlib import Path
import socket
import ssl
import sys
import time
import unittest
import urllib.error
import urllib.parse
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / ".github/actions/pr-metadata-validation/validate.py"
spec = importlib.util.spec_from_file_location("pr_metadata_validation", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def verified_dependabot_group_case(subject: str | None = None) -> tuple[dict, dict, str]:
    subject = subject or (
        ":arrow_up: chore(deps): bump the github-actions-minor-and-patch group with 2 updates"
    )
    pr = {
        "user": {"login": "dependabot[bot]", "id": 49699333, "type": "Bot"},
        "head": {"ref": "dependabot/github_actions/group-update"},
    }
    item = {
        "author": {"login": "dependabot[bot]", "id": 49699333, "type": "Bot"},
        "committer": {"login": "web-flow", "id": 19864447, "type": "User"},
        "commit": {
            "author": {
                "email": "49699333+dependabot[bot]@users.noreply.github.com",
            },
            "committer": {"email": "noreply@github.com"},
            "message": (
                f"{subject}\n\n"
                "Bumps the github-actions-minor-and-patch group with 2 updates: actions.\n\n"
                "updated-dependencies:\n"
                "- dependency-name: actions/upload-artifact\n"
                "  dependency-version: 7.0.2\n"
                "  dependency-group: github-actions-minor-and-patch"
            ),
            "verification": {"verified": True, "reason": "valid"},
        },
    }
    return pr, item, subject


def verified_dependabot_npm_group_case() -> tuple[dict, dict, str]:
    subject = (
        ":arrow_up: chore(deps): bump the admin-minor-and-patch group across "
        "1 directory with 27 updates"
    )
    pr, item, _ = verified_dependabot_group_case(subject)
    pr["head"]["ref"] = (
        "dependabot/npm_and_yarn/frontend/apps/admin/"
        "admin-minor-and-patch-699e44dd5a"
    )
    item["commit"]["message"] = (
        f"{subject}\n\n"
        "Bumps the admin-minor-and-patch group with 27 updates in the "
        "/frontend/apps/admin directory:\n\n"
        "updated-dependencies:\n"
        "- dependency-name: vite\n"
        "  dependency-version: 8.3.4\n"
        "  dependency-group: admin-minor-and-patch"
    )
    return pr, item, subject


class PRMetadataValidationTests(unittest.TestCase):
    def test_valid_org_subject_passes(self):
        self.assertEqual([], module.validate_subject(":shield: security(ci): isolate metadata", "title"))

    def test_verified_dependabot_group_commit_can_exceed_72_characters(self):
        pr, item, subject = verified_dependabot_group_case()

        self.assertGreater(len(subject), 72)
        self.assertEqual([], module.validate_commit_metadata(pr, item, "commit 1"))

    def test_verified_dependabot_npm_group_commit_with_directory_summary_passes(self):
        pr, item, subject = verified_dependabot_npm_group_case()

        self.assertGreater(len(subject), 72)
        self.assertTrue(module.is_verified_dependabot_group_commit(pr, item))
        self.assertEqual([], module.validate_commit_metadata(pr, item, "commit 1"))
        self.assertEqual(subject, module.resolve_effective_pr_title(subject, pr, [item]))
        self.assertTrue(
            any(
                "at most 72 characters" in failure.message
                for failure in module.validate_subject(subject, "PR title")
            )
        )

    def test_human_authored_signed_group_commit_cannot_use_length_exception(self):
        pr, item, subject = verified_dependabot_group_case()
        pr["user"] = {"login": "human-maintainer", "type": "User"}
        item["author"] = {"login": "human-maintainer", "type": "User"}
        item["committer"] = {"login": "human-maintainer", "type": "User"}
        item["commit"]["author"]["email"] = "human@example.com"

        failures = module.validate_commit_metadata(pr, item, "commit 1")

        self.assertGreater(len(subject), 72)
        self.assertTrue(any("at most 72 characters" in failure.message for failure in failures))

    def test_unverified_dependabot_group_commit_cannot_use_length_exception(self):
        pr, item, subject = verified_dependabot_group_case()
        item["commit"]["verification"] = {"verified": False, "reason": "unsigned"}

        failures = module.validate_commit_metadata(pr, item, "commit 1")

        self.assertGreater(len(subject), 72)
        self.assertTrue(any("at most 72 characters" in failure.message for failure in failures))

    def test_verified_dependabot_commit_without_group_marker_cannot_use_exception(self):
        pr, item, subject = verified_dependabot_group_case()
        item["commit"]["message"] = subject

        failures = module.validate_commit_metadata(pr, item, "commit 1")

        self.assertGreater(len(subject), 72)
        self.assertTrue(any("at most 72 characters" in failure.message for failure in failures))

    def test_dependabot_group_exception_requires_both_group_markers(self):
        for message in (
            "Bumps the github-actions-minor-and-patch group with 2 updates:\n"
            "- dependency-name: actions/upload-artifact",
            "updated-dependencies:\n"
            "- dependency-name: actions/upload-artifact\n"
            "  dependency-group: github-actions-minor-and-patch",
        ):
            with self.subTest(message=message):
                pr, item, subject = verified_dependabot_group_case()
                item["commit"]["message"] = f"{subject}\n\n{message}"

                failures = module.validate_commit_metadata(pr, item, "commit 1")

                self.assertGreater(len(subject), 72)
                self.assertTrue(
                    any("at most 72 characters" in failure.message for failure in failures)
                )

    def test_dependabot_group_exception_binds_signed_author_email_to_bot_id(self):
        pr, item, subject = verified_dependabot_group_case()
        item["commit"]["author"]["email"] = (
            "12345+dependabot[bot]@users.noreply.github.com"
        )

        failures = module.validate_commit_metadata(pr, item, "commit 1")

        self.assertGreater(len(subject), 72)
        self.assertTrue(any("at most 72 characters" in failure.message for failure in failures))

    def test_verified_dependabot_group_subject_has_an_absolute_sanity_limit(self):
        subject = (
            ":arrow_up: chore(deps): bump the github-actions-minor-and-patch group with 2 updates "
            + "x" * 160
        )
        pr, item, subject = verified_dependabot_group_case(subject)

        failures = module.validate_commit_metadata(pr, item, "commit 1")

        self.assertGreater(len(subject), 200)
        self.assertTrue(any("at most 200 characters" in failure.message for failure in failures))

    def test_dependabot_pull_request_title_keeps_72_character_limit(self):
        long_title = (
            ":arrow_up: chore(deps): bump python from 3.14.7-slim-trixie to "
            "3.15.0rc3-slim-trixie in the docker-minor-and-patch group"
        )

        failures = module.validate_subject(long_title, "PR title")

        self.assertTrue(any("at most 72 characters" in failure.message for failure in failures))

    def test_portuguese_or_trailing_period_fails(self):
        failures = module.validate_subject(":bug: fix(ci): corrigir validacao.", "title")
        messages = " ".join(item.message for item in failures)
        self.assertIn("trailing period", messages)
        self.assertIn("English", messages)

    def test_invalid_gitmoji_fails(self):
        failures = module.validate_subject(":unknown: fix(ci): repair metadata", "title")
        self.assertTrue(any("not allowed" in item.message for item in failures))

    def test_body_rejects_empty_controls_and_mojibake(self):
        self.assertTrue(module.validate_body("   "))
        self.assertTrue(module.validate_body("hello\x07world"))
        self.assertTrue(module.validate_body("ðŸ broken"))
        self.assertTrue(module.validate_body("## Summary\nCafÃ© in a copied title"))
        self.assertEqual([], module.validate_body("## Summary\nMetadata only."))

    def test_body_allows_valid_uppercase_portuguese_diacritics(self):
        self.assertEqual([], module.validate_body("## Context\nNÃO alterar this contract."))

    def test_ai_coauthorship_trailer_fails(self):
        message = ":bug: fix(ci): protect commit authorship\n\nCo-authored-by: Codex <codex@openai.com>"
        failures = module.validate_commit_message(message, "commit 1")
        self.assertTrue(any("AI co-authorship" in item.message for item in failures))

    def test_human_coauthorship_trailer_is_not_misclassified(self):
        message = ":bug: fix(ci): protect commit authorship\n\nCo-authored-by: Human Reviewer <reviewer@example.com>"
        self.assertEqual([], module.validate_commit_message(message, "commit 1"))

    def test_fetch_is_bounded_and_paginates(self):
        calls = []
        original = module._request_json
        try:
            def fake(url, token):
                calls.append(url)
                if url.endswith("/pulls/7"):
                    return {"base": {"sha": "a" * 40}, "head": {"sha": "b" * 40}}
                if url.endswith("page=1"):
                    return [{"commit": {"message": ":bug: fix(ci): repair metadata"}}] * 100
                return [{"commit": {"message": ":memo: docs(ci): explain metadata"}}]
            module._request_json = fake
            pr, commits = module.fetch_pr_metadata("https://api.github.test", "owner/repo", 7, "token")
        finally:
            module._request_json = original
        self.assertEqual("a" * 40, pr["base"]["sha"])
        self.assertEqual(101, len(commits))
        self.assertEqual(3, len(calls))

    def test_branch_history_is_bounded_and_encodes_exact_head(self):
        calls = []
        original = module._request_json
        try:
            def fake(url, token):
                calls.append(url)
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
                if query.get("page") == ["1"]:
                    return [{"number": 4, "merged_at": None}] * 100
                return [{"number": 5, "merged_at": "2026-08-04T12:00:00Z"}]
            module._request_json = fake
            history = module.fetch_branch_history(
                "https://api.github.test",
                "owner/repo",
                "owner",
                "fix/issue-1",
                "token",
            )
        finally:
            module._request_json = original
        self.assertEqual(101, len(history))
        self.assertEqual(2, len(calls))
        self.assertIn("state=closed", calls[0])
        self.assertIn("head=owner%3Afix%2Fissue-1", calls[0])


class MetadataApiClientTests(unittest.TestCase):
    def test_first_attempt_success_does_not_retry_or_sleep(self):
        response = io.BytesIO(b'{"ok": true}')
        with (
            patch.object(module.urllib.request, "urlopen", return_value=response) as urlopen,
            patch.object(time, "sleep") as sleep,
        ):
            client = module.MetadataApiClient()
            payload = client.request_json("https://api.github.test/repos/o/r", "secret-token")

        self.assertEqual({"ok": True}, payload)
        self.assertEqual(1, urlopen.call_count)
        self.assertEqual("GET", urlopen.call_args.args[0].get_method())
        self.assertEqual(30, urlopen.call_args.kwargs["timeout"])
        sleep.assert_not_called()

    def test_transient_transport_failure_retries_with_two_then_four_seconds(self):
        response = io.BytesIO(b'{"ok": true}')
        with (
            patch.object(
                module.urllib.request,
                "urlopen",
                side_effect=[
                    urllib.error.URLError(ConnectionResetError("private connection detail")),
                    urllib.error.URLError(TimeoutError("private timeout detail")),
                    response,
                ],
            ) as urlopen,
            patch.object(time, "sleep") as sleep,
        ):
            payload = module.MetadataApiClient().request_json(
                "https://api.github.test/repos/o/r?private=query",
                "secret-token",
            )

        self.assertEqual({"ok": True}, payload)
        self.assertEqual(3, urlopen.call_count)
        self.assertEqual([call(2), call(4)], sleep.call_args_list)

    def test_persistent_transient_failure_is_bounded_and_sanitized(self):
        private_detail = "secret-token=do-not-print private query"
        with (
            patch.object(
                module.urllib.request,
                "urlopen",
                side_effect=urllib.error.URLError(ConnectionResetError(private_detail)),
            ) as urlopen,
            patch.object(time, "sleep") as sleep,
        ):
            with self.assertRaises(module.MetadataRequestError) as caught:
                module.MetadataApiClient().request_json(
                    "https://api.github.test/repos/o/r?private=query",
                    "secret-token",
                )

        self.assertEqual(3, urlopen.call_count)
        self.assertEqual([call(2), call(4)], sleep.call_args_list)
        self.assertEqual(3, caught.exception.attempts)
        self.assertEqual("connection_reset", caught.exception.category)
        self.assertNotIn(private_detail, str(caught.exception))
        self.assertNotIn("secret-token", str(caught.exception))
        self.assertNotIn("private=query", str(caught.exception))

    def test_http_statuses_are_not_retried(self):
        for status in (403, 404, 429, 500, 503):
            with self.subTest(status=status):
                error = urllib.error.HTTPError(
                    "https://api.github.test/private?token=secret",
                    status,
                    "private response reason",
                    {},
                    None,
                )
                with (
                    patch.object(module.urllib.request, "urlopen", side_effect=error) as urlopen,
                    patch.object(time, "sleep") as sleep,
                ):
                    with self.assertRaises(module.MetadataRequestError) as caught:
                        module.MetadataApiClient().request_json(
                            "https://api.github.test/private?token=secret",
                            "secret-token",
                        )

                self.assertEqual(1, urlopen.call_count)
                sleep.assert_not_called()
                self.assertEqual(status, caught.exception.status_code)
                self.assertNotIn("secret", str(caught.exception))

    def test_tls_and_unknown_url_errors_fail_immediately(self):
        failures = (
            urllib.error.URLError(ssl.SSLCertVerificationError("private certificate detail")),
            urllib.error.URLError("private transport detail"),
        )
        expected_categories = ("tls_error", "transport_error")
        for failure, expected_category in zip(failures, expected_categories, strict=True):
            with self.subTest(failure_type=type(failure.reason).__name__):
                with (
                    patch.object(module.urllib.request, "urlopen", side_effect=failure) as urlopen,
                    patch.object(time, "sleep") as sleep,
                ):
                    with self.assertRaises(module.MetadataRequestError) as caught:
                        module.MetadataApiClient().request_json(
                            "https://api.github.test/private",
                            "secret-token",
                        )

                self.assertEqual(1, urlopen.call_count)
                self.assertEqual(expected_category, caught.exception.category)
                sleep.assert_not_called()

    def test_only_temporary_dns_failure_is_retryable(self):
        response = io.BytesIO(b'{"ok": true}')
        temporary = urllib.error.URLError(
            socket.gaierror(socket.EAI_AGAIN, "private DNS detail")
        )
        with (
            patch.object(module.urllib.request, "urlopen", side_effect=[temporary, response]) as urlopen,
            patch.object(time, "sleep") as sleep,
        ):
            self.assertEqual(
                {"ok": True},
                module.MetadataApiClient().request_json("https://api.github.test/repo", "token"),
            )
        self.assertEqual(2, urlopen.call_count)
        sleep.assert_called_once_with(2)

        permanent = urllib.error.URLError(
            socket.gaierror(socket.EAI_NONAME, "private DNS detail")
        )
        with (
            patch.object(module.urllib.request, "urlopen", side_effect=permanent) as urlopen,
            patch.object(time, "sleep") as sleep,
        ):
            with self.assertRaises(module.MetadataRequestError) as caught:
                module.MetadataApiClient().request_json("https://api.github.test/repo", "token")
        self.assertEqual(1, urlopen.call_count)
        self.assertEqual("dns_resolution", caught.exception.category)
        sleep.assert_not_called()

    def test_recognized_connection_failures_are_retryable(self):
        failures = (
            (urllib.error.URLError(ConnectionAbortedError("private detail")), "connection_aborted"),
            (urllib.error.URLError(ConnectionRefusedError("private detail")), "connection_refused"),
            (
                urllib.error.URLError(OSError(errno.EHOSTUNREACH, "private detail")),
                "network_unreachable",
            ),
            (
                urllib.error.URLError(OSError(errno.ENETUNREACH, "private detail")),
                "network_unreachable",
            ),
        )
        for failure, expected_category in failures:
            with self.subTest(category=expected_category, reason=type(failure.reason).__name__):
                self.assertEqual(
                    (expected_category, True),
                    module._classify_transport_error(failure),
                )

    def test_invalid_json_is_not_retried(self):
        for invalid_body, error_type in (
            (b"not json", module.json.JSONDecodeError),
            (b"\xff", UnicodeDecodeError),
        ):
            with self.subTest(error_type=error_type.__name__):
                with (
                    patch.object(
                        module.urllib.request,
                        "urlopen",
                        return_value=io.BytesIO(invalid_body),
                    ) as urlopen,
                    patch.object(time, "sleep") as sleep,
                ):
                    with self.assertRaises(error_type):
                        module.MetadataApiClient().request_json(
                            "https://api.github.test/repo",
                            "token",
                        )
                self.assertEqual(1, urlopen.call_count)
                sleep.assert_not_called()

    def test_retry_budget_is_shared_across_gets_and_caps_retry_timeout(self):
        now = [0.0]
        timeouts = []
        calls = []

        def clock():
            return now[0]

        def sleep(seconds):
            now[0] += seconds

        def urlopen(request, *, timeout):
            calls.append(request.full_url)
            timeouts.append(timeout)
            if request.full_url.endswith("/first"):
                if len([url for url in calls if url.endswith("/first")]) == 1:
                    raise urllib.error.URLError(ConnectionResetError("reset"))
                return io.BytesIO(b'{"ok": true}')
            raise urllib.error.URLError(ConnectionResetError("reset"))

        with patch.object(module.urllib.request, "urlopen", side_effect=urlopen):
            client = module.MetadataApiClient(
                retry_budget_seconds=5,
                clock=clock,
                sleep=sleep,
            )
            self.assertEqual(
                {"ok": True},
                client.request_json("https://api.github.test/first", "token"),
            )
            with self.assertRaises(module.MetadataRequestError) as caught:
                client.request_json("https://api.github.test/second", "token")

        self.assertEqual(
            [
                "https://api.github.test/first",
                "https://api.github.test/first",
                "https://api.github.test/second",
                "https://api.github.test/second",
            ],
            calls,
        )
        self.assertEqual([30, 3, 30, 1], timeouts)
        self.assertEqual(2, caught.exception.attempts)
        self.assertTrue(caught.exception.budget_exhausted)
        self.assertEqual(1, client.retry_budget_remaining)

    def test_retry_budget_must_fit_backoff_and_a_retry_attempt(self):
        with (
            patch.object(
                module.urllib.request,
                "urlopen",
                side_effect=urllib.error.URLError(ConnectionResetError("reset")),
            ) as urlopen,
            patch.object(time, "sleep") as sleep,
        ):
            with self.assertRaises(module.MetadataRequestError) as caught:
                module.MetadataApiClient(retry_budget_seconds=2).request_json(
                    "https://api.github.test/repo",
                    "token",
                )
        self.assertEqual(1, urlopen.call_count)
        self.assertEqual(1, caught.exception.attempts)
        self.assertTrue(caught.exception.budget_exhausted)
        sleep.assert_not_called()

class PRMetadataValidationExtraTests(unittest.TestCase):
    def test_reused_merged_branch_fails(self):
        pr = {"state": "open", "merged": False, "merged_at": None}
        prior = [
            {"number": 194, "merged_at": "2026-08-04T12:43:18Z"},
            {"number": 193, "merged_at": None},
        ]
        failures = module.validate_pr_lifecycle(pr, 195, prior)
        messages = " ".join(item.message for item in failures)
        self.assertIn("merged PR #194", messages)

    def test_closed_unmerged_branch_history_is_allowed(self):
        pr = {"state": "open", "merged": False, "merged_at": None}
        prior = [{"number": 198, "merged_at": None}]
        self.assertEqual([], module.validate_pr_lifecycle(pr, 199, prior))

    def test_closed_or_merged_current_pr_fails(self):
        closed = module.validate_pr_lifecycle(
            {"state": "closed", "merged": False, "merged_at": None},
            7,
            [],
        )
        merged = module.validate_pr_lifecycle(
            {"state": "closed", "merged": True, "merged_at": "2026-08-04T12:00:00Z"},
            7,
            [],
        )
        self.assertTrue(any("not open" in item.message for item in closed))
        self.assertTrue(any("already merged" in item.message for item in merged))

    def test_changed_files_rejects_added_mojibake(self):
        corrupted = "per\u00c3\u00ado"
        files = [{"filename": "ui/app.tsx", "patch": f"@@ -1 +1 @@\n-ok\n+{corrupted}"}]
        failures = module.validate_changed_files(files)
        self.assertTrue(any("ui/app.tsx" in item.message for item in failures))
        self.assertTrue(any("mojibake" in item.message for item in failures))

    def test_changed_files_allow_removed_corruption_and_markdown(self):
        corrupted = "per\u00c3\u00ado"
        files = [
            {"filename": "ui/app.tsx", "patch": f"@@ -1 +1 @@\n-{corrupted}\n+per\u00edodo"},
            {"filename": "docs/CONTRIBUTING.md", "patch": f"@@ -1 +1 @@\n+{corrupted}"},
        ]
        self.assertEqual([], module.validate_changed_files(files))

    def test_changed_files_skips_lockfiles_binaries_and_clean_patches(self):
        corrupted = "per\u00c3\u00ado"
        files = [
            {"filename": "package-lock.json", "patch": f"@@ -1 +1 @@\n+{corrupted}"},
            {"filename": "assets/logo.png"},
            {"filename": "src/clean.ts", "patch": "@@ -1 +1 @@\n+const x = 1"},
        ]
        self.assertEqual([], module.validate_changed_files(files))

    def test_fetch_pr_files_is_bounded_and_paginates(self):
        calls = []
        original = module._request_json
        try:
            def fake(url, token):
                calls.append(url)
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
                if query.get("page") == ["1"]:
                    return [{"filename": f"f{i}.ts"} for i in range(100)]
                return [{"filename": "last.ts"}]
            module._request_json = fake
            files = module.fetch_pr_files("https://api.github.test", "owner/repo", 7, "token")
        finally:
            module._request_json = original
        self.assertEqual(101, len(files))
        self.assertEqual(2, len(calls))


GENERATED_GROUP_SUBJECT = ":arrow_up: chore(deps): bump actions/create-github-app-token"
GENERATED_GROUP_TITLE = (
    f"{GENERATED_GROUP_SUBJECT} from 3.2.0 to 3.3.0 in the gha-minor-patch group"
)


class DependabotTitleCompactionTests(unittest.TestCase):
    def case(self):
        pr, item, subject = verified_dependabot_group_case(GENERATED_GROUP_SUBJECT)
        item["commit"]["message"] = item["commit"]["message"].replace(
            "dependency-group: github-actions-minor-and-patch",
            "dependency-group: gha-minor-patch",
        )
        return pr, [item], subject

    def test_generated_group_title_compacts_to_verified_commit_subject(self):
        pr, commits, subject = self.case()

        self.assertEqual(109, len(GENERATED_GROUP_TITLE))
        effective = module.resolve_effective_pr_title(GENERATED_GROUP_TITLE, pr, commits)

        self.assertEqual(subject, effective)
        self.assertLessEqual(len(effective), 72)
        self.assertEqual([], module.validate_subject(effective, "PR title"))

    def test_short_titles_are_never_rewritten(self):
        pr, commits, _ = self.case()
        title = ":shield: security(ci): isolate metadata"

        self.assertEqual(title, module.resolve_effective_pr_title(title, pr, commits))

    def test_human_pr_with_long_title_is_not_compacted(self):
        pr, commits, _ = self.case()
        pr["user"] = {"login": "human-maintainer", "type": "User", "id": 1}
        pr["head"] = {"ref": "feature/x"}

        effective = module.resolve_effective_pr_title(GENERATED_GROUP_TITLE, pr, commits)

        self.assertEqual(GENERATED_GROUP_TITLE, effective)
        self.assertTrue(module.validate_subject(effective, "PR title"))

    def test_unverified_commit_does_not_enable_compaction(self):
        pr, commits, _ = self.case()
        commits[0]["commit"]["verification"] = {"verified": False, "reason": "unsigned"}

        effective = module.resolve_effective_pr_title(GENERATED_GROUP_TITLE, pr, commits)

        self.assertEqual(GENERATED_GROUP_TITLE, effective)

    def test_title_not_matching_verified_commit_subject_is_not_compacted(self):
        pr, commits, _ = self.case()
        title = GENERATED_GROUP_TITLE.replace("create-github-app-token", "other-action")

        self.assertEqual(title, module.resolve_effective_pr_title(title, pr, commits))

    def test_arbitrary_suffix_after_verified_subject_is_not_compacted(self):
        pr, commits, _ = self.case()
        title = f"{GENERATED_GROUP_SUBJECT} plus a hand written and much longer explanation here"

        self.assertEqual(title, module.resolve_effective_pr_title(title, pr, commits))

    def test_main_accepts_generated_group_title_and_still_rejects_long_human_title(self):
        pr, commits, _ = self.case()
        pr.update(
            {
                "state": "open",
                "base": {"sha": "a" * 40},
                "head": {**pr["head"], "sha": "b" * 40,
                         "repo": {"full_name": "o/r"}},
            }
        )

        def run(title, pr_value):
            env = {
                "INPUT_REPOSITORY": "o/r",
                "INPUT_TOKEN": "t",
                "INPUT_PR_TITLE": title,
                "INPUT_PR_BODY": "Body text",
                "INPUT_PR_NUMBER": "7",
                "INPUT_BASE_SHA": "a" * 40,
                "INPUT_HEAD_SHA": "b" * 40,
            }
            with patch.dict(module.os.environ, env, clear=True), patch.object(
                module, "fetch_pr_metadata", return_value=(pr_value, commits)
            ), patch.object(module, "fetch_branch_history", return_value=[]), patch.object(
                module, "emit_failure"
            ) as emitted:
                return module.main(), emitted

        code, emitted = run(GENERATED_GROUP_TITLE, pr)
        self.assertEqual(0, code, emitted.call_args_list)

        human = {**pr, "user": {"login": "human", "type": "User", "id": 1},
                 "head": {**pr["head"], "ref": "feature/x"}}
        code, emitted = run(GENERATED_GROUP_TITLE, human)
        self.assertEqual(1, code)
        self.assertTrue(
            any("at most 72" in c.args[0].message for c in emitted.call_args_list)
        )


if __name__ == "__main__":
    unittest.main()
