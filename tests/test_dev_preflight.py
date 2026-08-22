from __future__ import annotations

import unittest

from scripts.dev import preflight


class GitStateValidationTests(unittest.TestCase):
    def test_feature_branch_based_on_origin_main_passes(self):
        state = preflight.GitState(
            branch="codex/dev-preflight-validation",
            base_ref="origin/main",
            ahead=2,
            behind=0,
            dirty=True,
        )

        result = preflight.validate_git_state(state)

        self.assertTrue(result.ok)
        self.assertIn("codex/dev-preflight-validation", result.detail)

    def test_stale_branch_fails_with_recovery_command(self):
        state = preflight.GitState(
            branch="codex/stale-work",
            base_ref="origin/main",
            ahead=1,
            behind=3,
            dirty=False,
        )

        result = preflight.validate_git_state(state)

        self.assertFalse(result.ok)
        self.assertIn("git fetch origin main", result.detail)
        self.assertIn("rebase", result.detail)

    def test_protected_branch_fails(self):
        state = preflight.GitState(
            branch="main",
            base_ref="origin/main",
            ahead=0,
            behind=0,
            dirty=False,
        )

        result = preflight.validate_git_state(state)

        self.assertFalse(result.ok)
        self.assertIn("protected", result.detail)

    def test_detached_head_fails(self):
        state = preflight.GitState(
            branch="",
            base_ref="origin/main",
            ahead=0,
            behind=0,
            dirty=False,
        )

        result = preflight.validate_git_state(state)

        self.assertFalse(result.ok)
        self.assertIn("detached", result.detail)


class ToolValidationTests(unittest.TestCase):
    def test_required_tools_must_be_available(self):
        result = preflight.validate_tools(
            {"python": True, "git": True, "docker": False},
            required=("python", "git", "docker"),
        )

        self.assertFalse(result.ok)
        self.assertIn("docker", result.detail)

    def test_all_required_tools_pass(self):
        result = preflight.validate_tools(
            {"python": True, "git": True, "docker": True},
            required=("python", "git", "docker"),
        )

        self.assertTrue(result.ok)


class ValidationCommandTests(unittest.TestCase):
    def test_canonical_validation_runs_suite_compileall_and_all_diff_checks(self):
        commands = preflight.validation_commands(
            python_executable="python3",
            base_ref="origin/main",
        )

        self.assertEqual(
            ["python3", "-m", "unittest", "discover", "-v"],
            commands[0],
        )
        self.assertEqual(
            ["python3", "-m", "compileall", "-q", "scripts", "tests"],
            commands[1],
        )
        self.assertEqual(
            ["git", "diff", "--check"],
            commands[2],
        )
        self.assertEqual(
            ["git", "diff", "--cached", "--check"],
            commands[3],
        )
        self.assertEqual(
            ["git", "diff", "--check", "origin/main", "HEAD"],
            commands[4],
        )


if __name__ == "__main__":
    unittest.main()
