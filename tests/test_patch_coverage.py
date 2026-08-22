import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.parsers.coverage import CoverageReport, FileCoverage
from cli.patch_coverage import (
    REASON_CODE_NO_COVERABLE_LINES,
    UnsafeGitRefError,
    _validate_git_ref,
    compute_patch_coverage,
    compute_patch_modified_lines,
)


def _git(args, cwd):
    subprocess.run(["git"] + args, cwd=cwd, check=True, capture_output=True, text=True)


class _TempGitRepo:
    """A minimal real git repo (compute_patch_coverage shells out to `git
    diff`, so a real repo is simpler and more trustworthy here than
    mocking subprocess.run) with a base commit containing a Python source
    file, for tests to layer additional commits on top of."""

    def __enter__(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.path = self._tmpdir.name
        _git(["init", "-q"], self.path)
        _git(["config", "user.email", "test@example.com"], self.path)
        _git(["config", "user.name", "Test"], self.path)

        with open(os.path.join(self.path, "app.py"), "w") as f:
            f.write("def foo():\n    return 1\n")
        _git(["add", "."], self.path)
        _git(["commit", "-q", "-m", "base"], self.path)
        self.base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.path, capture_output=True, text=True, check=True
        ).stdout.strip()
        return self

    def __exit__(self, *exc):
        self._tmpdir.cleanup()

    def commit_docs_only_change(self) -> str:
        with open(os.path.join(self.path, "README.md"), "w") as f:
            f.write("# hello\n")
        _git(["add", "."], self.path)
        _git(["commit", "-q", "-m", "docs"], self.path)
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.path, capture_output=True, text=True, check=True
        ).stdout.strip()

    def commit_code_change(self) -> str:
        with open(os.path.join(self.path, "app.py"), "a") as f:
            f.write("def bar():\n    return 2\n")
        _git(["add", "."], self.path)
        _git(["commit", "-q", "-m", "code"], self.path)
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.path, capture_output=True, text=True, check=True
        ).stdout.strip()


_EMPTY_COVERAGE = CoverageReport(overall_line_rate=0.9, overall_branch_rate=0.8, files={})


class ComputePatchCoverageReasonCodeTests(unittest.TestCase):
    def test_docs_only_diff_sets_no_coverable_lines_reason_code(self):
        with _TempGitRepo() as repo:
            head_sha = repo.commit_docs_only_change()
            result = compute_patch_coverage(repo.base_sha, head_sha, repo.path, _EMPTY_COVERAGE)

        self.assertFalse(result.available)
        self.assertEqual(result.reason_code, REASON_CODE_NO_COVERABLE_LINES)
        self.assertIn("docs/config-only change", result.reason)

    def test_missing_base_sha_has_no_reason_code(self):
        # A genuinely unverifiable case (no base SHA at all) must not be
        # mistaken for the benign docs-only case -- reason_code stays None.
        result = compute_patch_coverage(None, "deadbeef", "/tmp", _EMPTY_COVERAGE)

        self.assertFalse(result.available)
        self.assertIsNone(result.reason_code)

    def test_failed_git_diff_has_no_reason_code(self):
        with _TempGitRepo() as repo:
            result = compute_patch_coverage("not-a-real-sha", repo.base_sha, repo.path, _EMPTY_COVERAGE)

        self.assertFalse(result.available)
        self.assertIsNone(result.reason_code)

    def test_covered_code_change_has_no_reason_code(self):
        coverage = CoverageReport(
            overall_line_rate=0.9,
            overall_branch_rate=0.8,
            files={"app.py": FileCoverage(line_hits={3: 1, 4: 1})},
        )
        with _TempGitRepo() as repo:
            head_sha = repo.commit_code_change()
            result = compute_patch_coverage(repo.base_sha, head_sha, repo.path, coverage)

        self.assertTrue(result.available)
        self.assertIsNone(result.reason_code)


class ValidateGitRefTests(unittest.TestCase):
    """_validate_git_ref: the allowlist regex guard in front of every git
    CLI argument, on top of (not instead of) --end-of-options and
    shell=False."""

    def test_accepts_a_real_commit_sha(self):
        self.assertEqual(_validate_git_ref("a" * 40, "head_sha"), "a" * 40)

    def test_accepts_branch_names_with_slashes_and_hyphens(self):
        self.assertEqual(_validate_git_ref("feat/my-branch_v2", "head_sha"), "feat/my-branch_v2")

    def test_rejects_shell_metacharacters(self):
        for bad in ["$(whoami)", "; rm -rf /", "`id`", "a && b", "a|b", "a;b"]:
            with self.subTest(bad=bad):
                with self.assertRaises(UnsafeGitRefError):
                    _validate_git_ref(bad, "head_sha")

    def test_rejects_whitespace(self):
        with self.assertRaises(UnsafeGitRefError):
            _validate_git_ref("sha with spaces", "head_sha")

    def test_rejects_empty_string(self):
        with self.assertRaises(UnsafeGitRefError):
            _validate_git_ref("", "head_sha")

    def test_rejects_non_string(self):
        with self.assertRaises(UnsafeGitRefError):
            _validate_git_ref(None, "head_sha")  # type: ignore[arg-type]

    def test_error_message_includes_the_label(self):
        with self.assertRaises(UnsafeGitRefError) as cm:
            _validate_git_ref("bad ref", "base_sha")
        self.assertIn("base_sha", str(cm.exception))


class GitRefValidationEndToEndTests(unittest.TestCase):
    """A malicious base_sha/head_sha is refused before ever reaching
    subprocess.run(), and both public entry points degrade the same way
    they already do for a failed git diff (fail closed, never raise)."""

    def test_compute_patch_coverage_degrades_on_unsafe_base_sha(self):
        with _TempGitRepo() as repo:
            result = compute_patch_coverage("$(touch /tmp/pwned)", repo.base_sha, repo.path, _EMPTY_COVERAGE)

        self.assertFalse(result.available)
        self.assertIn("git diff refused", result.reason)

    def test_compute_patch_coverage_degrades_on_unsafe_head_sha(self):
        with _TempGitRepo() as repo:
            result = compute_patch_coverage(repo.base_sha, "; rm -rf /", repo.path, _EMPTY_COVERAGE)

        self.assertFalse(result.available)
        self.assertIn("git diff refused", result.reason)

    def test_compute_patch_modified_lines_degrades_to_empty_on_unsafe_ref(self):
        with _TempGitRepo() as repo:
            result = compute_patch_modified_lines("$(touch /tmp/pwned)", repo.base_sha, repo.path)

        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
