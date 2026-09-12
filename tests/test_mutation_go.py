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
from cli.mutation.go_runner import _collect_from_report, _go_mod_present, run

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
        self.assertEqual(result.language, LANGUAGE_GO)

    def test_no_existing_diff_files_reports_not_configured_without_invoking_gremlins(self):
        # Distinct call site from the "no go.mod" case above -- run()
        # short-circuits here *before* even checking for go.mod, whenever
        # none of the diff's own files exist on disk.
        with patch("cli.mutation.go_runner._run_gremlins") as run_mock:
            result = run(
                self.repo_dir, ["does/not/exist.go"], timeout_seconds=90, max_surviving_detail=5,
                base_sha="a" * 40,
            )
        run_mock.assert_not_called()
        self.assertEqual(result.status, "not_configured")
        self.assertEqual(result.language, LANGUAGE_GO)

    def test_missing_base_sha_is_unavailable_not_a_crash(self):
        # Should be unreachable in practice (see go_runner's own module
        # docstring) -- still must not crash if it somehow happens.
        result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5, base_sha=None)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.language, LANGUAGE_GO)
        self.assertEqual(result.reason, "no base_sha available to diff against")

    def test_unsafe_base_sha_is_refused(self):
        result = run(
            self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5,
            base_sha="; rm -rf /",
        )
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.language, LANGUAGE_GO)
        self.assertTrue(result.reason.startswith("gremlins refused: "))
        # The underlying UnsafeGitRefError's own message embeds the label
        # _validate_git_ref() was called with -- pins that it's "base_sha",
        # not some other/garbled field name.
        self.assertIn("base_sha is not a safe git ref", result.reason)

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
            captured["report_path"] = report_path
            captured["cwd"] = cwd
            captured["timeout_seconds"] = timeout_seconds
            report_path.write_text(json.dumps(_REAL_REPORT), encoding="utf-8")
            return _ok()

        with patch("cli.mutation.go_runner._run_gremlins", side_effect=side_effect):
            run(self.repo_dir, self._diff_files(), timeout_seconds=123, max_surviving_detail=5, base_sha="deadbeef")
        self.assertEqual(captured["base_sha"], "deadbeef")
        # Exact report filename -- not just "some file got written somewhere".
        self.assertEqual(captured["report_path"].name, "gremlins-report.json")
        self.assertEqual(captured["cwd"], self.repo_dir)
        self.assertEqual(captured["timeout_seconds"], 123)

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
        self.assertEqual(result.language, LANGUAGE_GO)
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)

    def test_nonzero_exit_with_no_report_is_unavailable(self):
        with patch("cli.mutation.go_runner._run_gremlins", return_value=_ok(returncode=1, stderr="boom")):
            result = run(
                self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5,
                base_sha="a" * 40,
            )
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.language, LANGUAGE_GO)
        self.assertEqual(result.reason, "gremlins run failed (exit 1): boom")

    def test_nonzero_exit_with_empty_stderr_has_no_placeholder_text(self):
        with patch("cli.mutation.go_runner._run_gremlins", return_value=_ok(returncode=1, stderr="")):
            result = run(
                self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5,
                base_sha="a" * 40,
            )
        self.assertEqual(result.reason, "gremlins run failed (exit 1): ")

    def test_stderr_is_truncated_to_exactly_300_chars(self):
        long_stderr = "x" * 350
        with patch("cli.mutation.go_runner._run_gremlins", return_value=_ok(returncode=1, stderr=long_stderr)):
            result = run(
                self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5,
                base_sha="a" * 40,
            )
        self.assertEqual(result.reason, f"gremlins run failed (exit 1): {'x' * 300}")

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
        self.assertEqual(result.language, LANGUAGE_GO)
        self.assertEqual(result.reason, "gremlins exceeded the 1s time budget")

    def test_missing_gremlins_binary_is_unavailable(self):
        with patch(
            "cli.mutation.go_runner._run_gremlins", side_effect=FileNotFoundError("gremlins not found")
        ):
            result = run(
                self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5,
                base_sha="a" * 40,
            )
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.language, LANGUAGE_GO)
        self.assertIn("gremlins could not be invoked", result.reason)


class CollectFromReportTests(unittest.TestCase):
    """Direct, no-subprocess unit tests against _collect_from_report itself
    -- real gremlins JSON report shapes written straight to disk, no
    run()/mocked-subprocess wrapping."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.report_path = Path(self._tmp.name) / "gremlins-report.json"

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, report) -> Path:
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        return self.report_path

    def test_missing_report_file_is_unavailable_with_exact_reason(self):
        result = _collect_from_report(self.report_path, 5)  # never written
        self.assertEqual(result.language, LANGUAGE_GO)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.reason, "gremlins ran but its results could not be read")

    def test_malformed_json_is_unavailable_with_exact_reason(self):
        self.report_path.write_text("{not valid json", encoding="utf-8")
        result = _collect_from_report(self.report_path, 5)
        self.assertEqual(result.language, LANGUAGE_GO)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.reason, "gremlins ran but its results could not be read")

    def test_full_status_taxonomy_pins_exact_counts_and_fields(self):
        report = {
            "files": [
                {
                    "file_name": "mathy/mathy.go",
                    "mutations": [
                        {"type": "CONDITIONALS_NEGATION", "status": "SKIPPED", "line": 1, "column": 1},
                        {"type": "NOT_VIABLE_ONE", "status": "NOT VIABLE", "line": 2, "column": 1},
                        # Two KILLED, two TIMED OUT -- `+= 1` and `= 1` are
                        # indistinguishable from a single occurrence.
                        {"type": "ARITHMETIC_BASE", "status": "KILLED", "line": 20, "column": 11},
                        {"type": "ARITHMETIC_BASE_2", "status": "KILLED", "line": 21, "column": 11},
                        {"type": "INVERT_NEGATIVES", "status": "LIVED", "line": 24, "column": 7},
                        {"type": "CONDITIONALS_BOUNDARY", "status": "NOT COVERED", "line": 30, "column": 3},
                        {"type": "REMOVE_CALL", "status": "TIMED OUT", "line": 40, "column": 5},
                        {"type": "REMOVE_CALL_2", "status": "TIMED OUT", "line": 41, "column": 5},
                        {"type": "MYSTERY_OP", "status": "SOME_FUTURE_STATUS", "line": 50, "column": 9},
                    ],
                }
            ],
        }
        result = _collect_from_report(self._write(report), 5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.language, LANGUAGE_GO)
        self.assertEqual(result.killed, 2)
        self.assertEqual(result.survived, 2)  # LIVED + NOT COVERED
        self.assertEqual(result.timeout, 2)
        # SKIPPED/NOT VIABLE never count; an unrecognized status still
        # counts toward total_generated (it was in scope) but lands in no
        # bucket and produces no surviving-mutant detail.
        self.assertEqual(result.total_generated, 7)
        self.assertEqual(result.scoped_files, ["mathy/mathy.go"])
        self.assertEqual(len(result.surviving_mutants), 4)

        lived, not_covered, timed_out_1, timed_out_2 = result.surviving_mutants
        expected = [
            (lived, "INVERT_NEGATIVES", "survived", "INVERT_NEGATIVES at mathy/mathy.go:24:7", 24),
            (not_covered, "CONDITIONALS_BOUNDARY", "survived", "CONDITIONALS_BOUNDARY at mathy/mathy.go:30:3", 30),
            (timed_out_1, "REMOVE_CALL", "timeout", "REMOVE_CALL at mathy/mathy.go:40:5", 40),
            (timed_out_2, "REMOVE_CALL_2", "timeout", "REMOVE_CALL_2 at mathy/mathy.go:41:5", 41),
        ]
        for detail, function, status, diff, line in expected:
            self.assertEqual(detail.language, LANGUAGE_GO)
            self.assertEqual(detail.file, "mathy/mathy.go")
            self.assertEqual(detail.function, function)
            self.assertEqual(detail.status, status)
            self.assertEqual(detail.diff, diff)
            self.assertEqual(detail.line, line)

    def test_missing_status_key_is_uncounted_but_still_in_scope(self):
        report = {"files": [{"file_name": "mathy/mathy.go", "mutations": [
            {"type": "X", "line": 1, "column": 1},  # no "status" key at all
        ]}]}
        result = _collect_from_report(self._write(report), 5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)
        self.assertEqual(result.scoped_files, ["mathy/mathy.go"])

    def test_timeout_branch_missing_type_defaults_function_to_unknown(self):
        # The TIMED OUT branch builds its own separate SurvivingMutant --
        # a distinct code path from the LIVED/NOT COVERED one above, with
        # its own independent field defaults to pin.
        report = {"files": [{"file_name": "mathy/mathy.go", "mutations": [
            {"status": "TIMED OUT", "line": 5, "column": 1},
        ]}]}
        result = _collect_from_report(self._write(report), 5)
        detail = result.surviving_mutants[0]
        self.assertEqual(detail.language, LANGUAGE_GO)
        self.assertEqual(detail.file, "mathy/mathy.go")
        self.assertEqual(detail.function, "unknown")
        self.assertEqual(detail.diff, " at mathy/mathy.go:5:1")

    def test_missing_type_key_defaults_function_to_unknown(self):
        report = {"files": [{"file_name": "mathy/mathy.go", "mutations": [
            {"status": "LIVED", "line": 5, "column": 1},
        ]}]}
        result = _collect_from_report(self._write(report), 5)
        detail = result.surviving_mutants[0]
        self.assertEqual(detail.function, "unknown")
        # The diff string's own type lookup has no fallback default ("")
        # -- distinct from `function`'s "unknown" default just above.
        self.assertEqual(detail.diff, " at mathy/mathy.go:5:1")

    def test_missing_line_and_column_render_as_none_in_diff(self):
        report = {"files": [{"file_name": "mathy/mathy.go", "mutations": [
            {"type": "ARITHMETIC_BASE", "status": "LIVED"},
        ]}]}
        result = _collect_from_report(self._write(report), 5)
        detail = result.surviving_mutants[0]
        self.assertIsNone(detail.line)
        self.assertEqual(detail.diff, "ARITHMETIC_BASE at mathy/mathy.go:None:None")

    def test_missing_file_name_key_defaults_to_empty_string(self):
        report = {"files": [{"mutations": [
            {"type": "ARITHMETIC_BASE", "status": "KILLED", "line": 1, "column": 1},
        ]}]}
        result = _collect_from_report(self._write(report), 5)
        self.assertEqual(result.scoped_files, [""])

    def test_non_dict_file_entry_is_skipped_not_fatal(self):
        report = {"files": [
            "not-a-dict-at-all",
            {"file_name": "mathy/mathy.go", "mutations": [
                {"type": "ARITHMETIC_BASE", "status": "KILLED", "line": 1, "column": 1},
            ]},
        ]}
        result = _collect_from_report(self._write(report), 5)
        self.assertEqual(result.killed, 1)
        self.assertEqual(result.scoped_files, ["mathy/mathy.go"])

    def test_non_dict_mutation_entry_is_skipped_not_fatal(self):
        report = {"files": [{"file_name": "mathy/mathy.go", "mutations": [
            "not-a-dict-at-all",
            {"type": "ARITHMETIC_BASE", "status": "KILLED", "line": 1, "column": 1},
        ]}]}
        result = _collect_from_report(self._write(report), 5)
        self.assertEqual(result.killed, 1)
        self.assertEqual(result.total_generated, 1)

    def test_file_with_only_ignored_statuses_is_excluded_from_scoped_files(self):
        report = {"files": [
            {"file_name": "untouched/only_skipped.go", "mutations": [
                {"type": "X", "status": "SKIPPED", "line": 1, "column": 1},
                {"type": "Y", "status": "NOT VIABLE", "line": 2, "column": 1},
            ]},
            {"file_name": "mathy/mathy.go", "mutations": [
                {"type": "ARITHMETIC_BASE", "status": "KILLED", "line": 1, "column": 1},
            ]},
        ]}
        result = _collect_from_report(self._write(report), 5)
        self.assertEqual(result.scoped_files, ["mathy/mathy.go"])
        self.assertEqual(result.killed, 1)

    def test_mutations_key_missing_on_file_entry_does_not_crash(self):
        report = {"files": [{"file_name": "mathy/mathy.go"}]}
        result = _collect_from_report(self._write(report), 5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)
        self.assertEqual(result.scoped_files, [])

    def test_files_key_missing_yields_empty_scope(self):
        result = _collect_from_report(self._write({}), 5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.language, LANGUAGE_GO)
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)
        self.assertEqual(result.scoped_files, [])

    def test_files_key_not_a_list_yields_empty_scope(self):
        result = _collect_from_report(self._write({"files": "not-a-list"}), 5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)

    def test_max_detail_boundary_is_strict_less_than(self):
        report = {"files": [{"file_name": "mathy/mathy.go", "mutations": [
            {"type": "A", "status": "LIVED", "line": 10, "column": 1},
            {"type": "B", "status": "LIVED", "line": 20, "column": 1},
            {"type": "C", "status": "LIVED", "line": 30, "column": 1},
        ]}]}
        result = _collect_from_report(self._write(report), 2)
        self.assertEqual(result.survived, 3)  # all three still counted...
        self.assertEqual(len(result.surviving_mutants), 2)  # ...but detail caps at 2
        self.assertEqual([m.line for m in result.surviving_mutants], [10, 20])

    def test_max_detail_boundary_is_strict_less_than_for_timeouts_too(self):
        # The TIMED OUT branch has its own independent `< max_detail`
        # check -- a distinct mutant target from the one above.
        report = {"files": [{"file_name": "mathy/mathy.go", "mutations": [
            {"type": "A", "status": "TIMED OUT", "line": 10, "column": 1},
            {"type": "B", "status": "TIMED OUT", "line": 20, "column": 1},
            {"type": "C", "status": "TIMED OUT", "line": 30, "column": 1},
        ]}]}
        result = _collect_from_report(self._write(report), 2)
        self.assertEqual(result.timeout, 3)
        self.assertEqual(len(result.surviving_mutants), 2)
        self.assertEqual([m.line for m in result.surviving_mutants], [10, 20])

    def test_killed_and_timeout_present_is_not_the_zero_mutant_exemption(self):
        # Pins the `+` in `killed + survived + timeout_ct == 0` -- a sign
        # flip to `killed + survived - timeout_ct` would read this exact
        # case (1 killed, 0 survived, 1 timeout) as zero and wrongly
        # trigger the exemption.
        report = {"files": [{"file_name": "mathy/mathy.go", "mutations": [
            {"type": "A", "status": "KILLED", "line": 1, "column": 1},
            {"type": "B", "status": "TIMED OUT", "line": 2, "column": 1},
        ]}]}
        result = _collect_from_report(self._write(report), 5)
        self.assertEqual(result.status, "ran")
        self.assertIsNone(result.reason)
        self.assertEqual(result.killed, 1)
        self.assertEqual(result.timeout, 1)

    def test_killed_equals_survived_is_not_the_zero_mutant_exemption(self):
        # Pins the other `+` in the same expression -- `killed - survived +
        # timeout_ct` would read this exact case (1 killed, 1 survived, 0
        # timeout) as zero and wrongly trigger the exemption.
        report = {"files": [{"file_name": "mathy/mathy.go", "mutations": [
            {"type": "A", "status": "KILLED", "line": 1, "column": 1},
            {"type": "B", "status": "LIVED", "line": 2, "column": 1},
        ]}]}
        result = _collect_from_report(self._write(report), 5)
        self.assertEqual(result.status, "ran")
        self.assertIsNone(result.reason)
        self.assertEqual(result.killed, 1)
        self.assertEqual(result.survived, 1)


if __name__ == "__main__":
    unittest.main()
