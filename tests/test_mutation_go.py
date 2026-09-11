import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.mutation.common import LANGUAGE_GO, REASON_CODE_NO_COVERABLE_LINES
from cli.mutation.go_runner import _go_mod_present, run

# Real report shape confirmed empirically against a live gremlins
# install this session (go install .../gremlins@latest, real scratch Go
# module, real `--diff <base_sha>` run). "SKIPPED" = outside --diff's
# scope; "NOT COVERED" = in scope, genuinely reached but insufficiently
# asserted (confirmed via a real `go test -coverprofile` showing partial
# coverage on the same line, not a gremlins quirk).
_REAL_REPORT = {
    "go_module": "mathy",
    "files": [
        {
            "file_name": "mathy/mathy.go",
            "mutations": [
                {"type": "CONDITIONALS_NEGATION", "status": "SKIPPED", "line": 8, "column": 13},
                {"type": "ARITHMETIC_BASE", "status": "KILLED", "line": 20, "column": 11},
                {"type": "CONDITIONALS_BOUNDARY", "status": "NOT COVERED", "line": 24, "column": 7},
                {"type": "INVERT_NEGATIVES", "status": "LIVED", "line": 20, "column": 11},
            ],
        }
    ],
    "test_efficacy": 50.0,
    "mutations_coverage": 75.0,
    "mutants_total": 3,
    "mutants_killed": 1,
    "mutants_lived": 1,
    "mutants_not_viable": 0,
    "mutants_not_covered": 1,
    "elapsed_time": 0.05,
}


def _ok(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=["gremlins"], returncode=returncode, stdout=stdout, stderr=stderr)


class GoModDetectionTests(unittest.TestCase):

    def test_no_go_mod_is_not_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(_go_mod_present(Path(tmp)))

    def test_go_mod_present_is_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "go.mod").write_text("module mathy\n", encoding="utf-8")
            self.assertTrue(_go_mod_present(Path(tmp)))


class RunTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self._tmp.name)
        (self.repo_dir / "go.mod").write_text("module mathy\n", encoding="utf-8")
        (self.repo_dir / "mathy").mkdir()
        (self.repo_dir / "mathy" / "mathy.go").write_text("package mathy\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _diff_files(self):
        return ["mathy/mathy.go"]

    def test_no_go_mod_reports_not_configured_without_invoking_gremlins(self):
        (self.repo_dir / "go.mod").unlink()
        with patch("cli.mutation.go_runner._run_gremlins") as run_mock:
            result = run(
                self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5,
                base_sha="a" * 40,
            )
        run_mock.assert_not_called()
        self.assertEqual(result.status, "not_configured")

    def test_missing_base_sha_is_unavailable_not_a_crash(self):
        # Should be unreachable in practice (see go_runner's own module
        # docstring) -- still must not crash if it somehow happens.
        result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5, base_sha=None)
        self.assertEqual(result.status, "unavailable")

    def test_unsafe_base_sha_is_refused(self):
        result = run(
            self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5,
            base_sha="; rm -rf /",
        )
        self.assertEqual(result.status, "unavailable")

    def test_real_report_is_parsed_skipping_out_of_scope_mutants(self):
        def side_effect(base_sha, report_path, *, cwd, timeout_seconds):
            report_path.write_text(json.dumps(_REAL_REPORT), encoding="utf-8")
            return _ok()

        with patch("cli.mutation.go_runner._run_gremlins", side_effect=side_effect):
            result = run(
                self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5,
                base_sha="a" * 40,
            )
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.killed, 1)
        # LIVED + NOT COVERED both fold into "survived" -- both are real
        # "this mutant escaped detection" signals.
        self.assertEqual(result.survived, 2)
        self.assertEqual(result.timeout, 0)
        # SKIPPED (out of --diff scope) never counts.
        self.assertEqual(result.total_generated, 3)
        self.assertEqual(len(result.surviving_mutants), 2)
        for m in result.surviving_mutants:
            self.assertEqual(m.language, LANGUAGE_GO)
            self.assertEqual(m.status, "survived")

    def test_base_sha_is_passed_through_to_the_diff_flag(self):
        captured = {}

        def side_effect(base_sha, report_path, *, cwd, timeout_seconds):
            captured["base_sha"] = base_sha
            report_path.write_text(json.dumps(_REAL_REPORT), encoding="utf-8")
            return _ok()

        with patch("cli.mutation.go_runner._run_gremlins", side_effect=side_effect):
            run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5, base_sha="deadbeef")
        self.assertEqual(captured["base_sha"], "deadbeef")

    def test_all_skipped_is_the_zero_mutant_exemption(self):
        report = {
            "go_module": "mathy",
            "files": [{"file_name": "mathy/mathy.go", "mutations": [
                {"type": "ARITHMETIC_BASE", "status": "SKIPPED", "line": 4, "column": 11},
            ]}],
        }

        def side_effect(base_sha, report_path, *, cwd, timeout_seconds):
            report_path.write_text(json.dumps(report), encoding="utf-8")
            return _ok()

        with patch("cli.mutation.go_runner._run_gremlins", side_effect=side_effect):
            result = run(
                self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5,
                base_sha="a" * 40,
            )
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)

    def test_missing_report_after_clean_exit_is_the_exemption_not_a_failure(self):
        with patch("cli.mutation.go_runner._run_gremlins", return_value=_ok(returncode=0)):
            result = run(
                self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5,
                base_sha="a" * 40,
            )
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)

    def test_nonzero_exit_with_no_report_is_unavailable(self):
        with patch("cli.mutation.go_runner._run_gremlins", return_value=_ok(returncode=1, stderr="boom")):
            result = run(
                self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5,
                base_sha="a" * 40,
            )
        self.assertEqual(result.status, "unavailable")

    def test_timeout_is_unavailable_never_full_credit(self):
        with patch(
            "cli.mutation.go_runner._run_gremlins",
            side_effect=subprocess.TimeoutExpired(cmd=[], timeout=1),
        ):
            result = run(
                self.repo_dir, self._diff_files(), timeout_seconds=1, max_surviving_detail=5,
                base_sha="a" * 40,
            )
        self.assertEqual(result.status, "unavailable")

    def test_missing_gremlins_binary_is_unavailable(self):
        with patch(
            "cli.mutation.go_runner._run_gremlins", side_effect=FileNotFoundError("gremlins not found")
        ):
            result = run(
                self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5,
                base_sha="a" * 40,
            )
        self.assertEqual(result.status, "unavailable")


if __name__ == "__main__":
    unittest.main()
