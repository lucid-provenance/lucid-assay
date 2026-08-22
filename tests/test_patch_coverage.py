import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.parsers.coverage import CoverageReport, FileCoverage
from cli.patch_coverage import REASON_CODE_NO_COVERABLE_LINES, compute_patch_coverage


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


if __name__ == "__main__":
    unittest.main()
