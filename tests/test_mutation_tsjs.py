import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.mutation.common import LANGUAGE_TSJS, REASON_CODE_NO_COVERABLE_LINES
from cli.mutation.tsjs_runner import _collect_from_report, _stryker_configured, run


def _ok(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=["npx"], returncode=returncode, stdout=stdout, stderr=stderr)


def _write_report(repo_dir: Path, files: dict) -> None:
    out = repo_dir / "reports" / "mutation" / "mutation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"schemaVersion": "1.0", "files": files}), encoding="utf-8")


class StrykerConfigDetectionTests(unittest.TestCase):

    def test_no_config_at_all_is_not_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(_stryker_configured(Path(tmp)))

    def test_stryker_conf_json_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "stryker.conf.json").write_text("{}", encoding="utf-8")
            self.assertTrue(_stryker_configured(Path(tmp)))

    def test_package_json_stryker_key_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text(json.dumps({"stryker": {}}), encoding="utf-8")
            self.assertTrue(_stryker_configured(Path(tmp)))

    def test_package_json_without_stryker_key_is_not_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text(json.dumps({"name": "x"}), encoding="utf-8")
            self.assertFalse(_stryker_configured(Path(tmp)))

    def test_malformed_package_json_is_not_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text("{not valid json", encoding="utf-8")
            self.assertFalse(_stryker_configured(Path(tmp)))


class RunTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self._tmp.name)
        (self.repo_dir / "src").mkdir()
        (self.repo_dir / "src" / "mathy.js").write_text("function f() { return 1; }\n", encoding="utf-8")
        (self.repo_dir / "stryker.conf.json").write_text("{}", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _diff_files(self):
        return ["src/mathy.js"]

    def test_no_config_reports_not_configured_without_invoking_npx(self):
        (self.repo_dir / "stryker.conf.json").unlink()
        with patch("cli.mutation.tsjs_runner._run_stryker") as run_mock:
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        run_mock.assert_not_called()
        self.assertEqual(result.status, "not_configured")
        self.assertEqual(result.language, LANGUAGE_TSJS)

    def test_no_matching_files_reports_not_configured(self):
        result = run(self.repo_dir, ["src/other.ts"], timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "not_configured")
        self.assertEqual(result.language, LANGUAGE_TSJS)

    def test_real_report_is_parsed_into_killed_survived(self):
        # Real shape confirmed empirically against a live Stryker
        # 10.0.0 run this session -- status/location.start.line/
        # mutatorName per mutant.
        def side_effect(files, *, cwd, timeout_seconds):
            _write_report(self.repo_dir, {
                "src/mathy.js": {
                    "language": "javascript",
                    "mutants": [
                        {"id": "0", "mutatorName": "ConditionalExpression", "status": "Killed",
                         "location": {"start": {"line": 1, "column": 1}, "end": {"line": 1, "column": 2}}},
                        {"id": "1", "mutatorName": "EqualityOperator", "status": "Survived",
                         "location": {"start": {"line": 1, "column": 3}, "end": {"line": 1, "column": 4}},
                         "replacement": ">="},
                    ],
                },
            })
            return _ok()

        with patch("cli.mutation.tsjs_runner._run_stryker", side_effect=side_effect):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.killed, 1)
        self.assertEqual(result.survived, 1)
        self.assertEqual(len(result.surviving_mutants), 1)
        detail = result.surviving_mutants[0]
        self.assertEqual(detail.language, LANGUAGE_TSJS)
        self.assertEqual(detail.line, 1)
        self.assertEqual(detail.status, "survived")

    def test_zero_mutants_in_report_is_the_exemption(self):
        def side_effect(files, *, cwd, timeout_seconds):
            _write_report(self.repo_dir, {"src/mathy.js": {"language": "javascript", "mutants": []}})
            return _ok()

        with patch("cli.mutation.tsjs_runner._run_stryker", side_effect=side_effect):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.language, LANGUAGE_TSJS)
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)

    def test_missing_report_after_a_clean_exit_is_the_exemption_not_a_failure(self):
        with patch("cli.mutation.tsjs_runner._run_stryker", return_value=_ok(returncode=0)):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.language, LANGUAGE_TSJS)
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)
        self.assertEqual(result.scoped_files, self._diff_files())

    def test_nonzero_exit_with_no_report_is_unavailable(self):
        with patch("cli.mutation.tsjs_runner._run_stryker", return_value=_ok(returncode=1, stderr="boom")):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.language, LANGUAGE_TSJS)
        self.assertEqual(result.reason, "stryker run failed (exit 1): boom")

    def test_nonzero_exit_with_empty_stderr_has_no_placeholder_text(self):
        with patch("cli.mutation.tsjs_runner._run_stryker", return_value=_ok(returncode=1, stderr="")):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.reason, "stryker run failed (exit 1): ")

    def test_stderr_is_truncated_to_exactly_300_chars(self):
        with patch("cli.mutation.tsjs_runner._run_stryker", return_value=_ok(returncode=1, stderr="x" * 350)):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.reason, f"stryker run failed (exit 1): {'x' * 300}")

    def test_timeout_is_unavailable_never_full_credit(self):
        with patch("cli.mutation.tsjs_runner._run_stryker", side_effect=subprocess.TimeoutExpired(cmd=[], timeout=1)):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=1, max_surviving_detail=5)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.language, LANGUAGE_TSJS)
        self.assertEqual(result.reason, "stryker exceeded the 1s time budget")

    def test_missing_npx_binary_is_unavailable(self):
        with patch("cli.mutation.tsjs_runner._run_stryker", side_effect=FileNotFoundError("npx not found")):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.language, LANGUAGE_TSJS)
        self.assertIn("stryker could not be invoked", result.reason)

    def test_timeout_seconds_is_passed_through_to_run_stryker(self):
        captured = {}

        def side_effect(files, *, cwd, timeout_seconds):
            captured["files"] = files
            captured["cwd"] = cwd
            captured["timeout_seconds"] = timeout_seconds
            _write_report(self.repo_dir, {"src/mathy.js": {"mutants": []}})
            return _ok()

        with patch("cli.mutation.tsjs_runner._run_stryker", side_effect=side_effect):
            run(self.repo_dir, self._diff_files(), timeout_seconds=123, max_surviving_detail=5)
        self.assertEqual(captured["files"], self._diff_files())
        self.assertEqual(captured["cwd"], self.repo_dir)
        self.assertEqual(captured["timeout_seconds"], 123)

    def test_sandbox_dir_is_reset_before_running(self):
        stale = self.repo_dir / ".stryker-tmp" / "leftover.txt"
        stale.parent.mkdir(parents=True)
        stale.write_text("stale", encoding="utf-8")

        def side_effect(files, *, cwd, timeout_seconds):
            self.assertFalse((self.repo_dir / ".stryker-tmp").exists())
            return _ok(returncode=1, stderr="boom")

        with patch("cli.mutation.tsjs_runner._run_stryker", side_effect=side_effect):
            run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        # And cleaned up again afterward, even on a failure path.
        self.assertFalse((self.repo_dir / ".stryker-tmp").exists())


class CollectFromReportTests(unittest.TestCase):
    """Direct, no-subprocess unit tests against _collect_from_report itself
    -- real Stryker JSON report shapes handed straight in as a dict, no
    run()/mocked-subprocess wrapping."""

    def test_full_status_taxonomy_pins_exact_counts_and_fields(self):
        report = {
            "files": {
                "src/mathy.js": {
                    "mutants": [
                        {"mutatorName": "A", "status": "Killed", "location": {"start": {"line": 1}}},
                        {"mutatorName": "A2", "status": "Killed", "location": {"start": {"line": 2}}},
                        {"mutatorName": "B", "status": "Survived", "location": {"start": {"line": 3}}, "replacement": ">="},
                        {"mutatorName": "C", "status": "Timeout", "location": {"start": {"line": 4}}},
                        {"mutatorName": "C2", "status": "Timeout", "location": {"start": {"line": 5}}},
                        {"mutatorName": "D", "status": "NoCoverage", "location": {"start": {"line": 6}}},
                        {"mutatorName": "E", "status": "CompileError", "location": {"start": {"line": 7}}},
                    ],
                },
            },
        }
        # Two Killed, two Timeout -- `+= 1` and `= 1` are indistinguishable
        # from a single occurrence.
        result = _collect_from_report(report, ["src/mathy.js"], 5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.language, LANGUAGE_TSJS)
        self.assertEqual(result.killed, 2)
        self.assertEqual(result.survived, 1)
        self.assertEqual(result.timeout, 2)
        # NoCoverage/CompileError count toward total_generated (they were
        # in the scoped file) but land in no bucket and produce no detail.
        self.assertEqual(result.total_generated, 7)
        self.assertEqual(result.scoped_files, ["src/mathy.js"])
        self.assertEqual(len(result.surviving_mutants), 3)

        survived, timeout_1, timeout_2 = result.surviving_mutants
        expected = [
            (survived, "B", "survived", "B: replaced with `>=`", 3),
            (timeout_1, "C", "timeout", "C: replaced with ``", 4),
            (timeout_2, "C2", "timeout", "C2: replaced with ``", 5),
        ]
        for detail, function, status, diff, line in expected:
            self.assertEqual(detail.language, LANGUAGE_TSJS)
            self.assertEqual(detail.file, "src/mathy.js")
            self.assertEqual(detail.function, function)
            self.assertEqual(detail.status, status)
            self.assertEqual(detail.diff, diff)
            self.assertEqual(detail.line, line)

    def test_files_outside_scoped_files_are_ignored(self):
        report = {
            "files": {
                "src/untouched.js": {"mutants": [{"mutatorName": "A", "status": "Killed", "location": {}}]},
                "src/mathy.js": {"mutants": [{"mutatorName": "B", "status": "Killed", "location": {}}]},
            },
        }
        result = _collect_from_report(report, ["src/mathy.js"], 5)
        self.assertEqual(result.killed, 1)
        self.assertEqual(result.total_generated, 1)

    def test_missing_type_key_defaults_function_to_unknown(self):
        report = {"files": {"src/mathy.js": {"mutants": [
            {"status": "Survived", "location": {"start": {"line": 5}}},
        ]}}}
        result = _collect_from_report(report, ["src/mathy.js"], 5)
        detail = result.surviving_mutants[0]
        self.assertEqual(detail.function, "unknown")
        self.assertEqual(detail.diff, ": replaced with ``")

    def test_missing_location_and_replacement_render_as_none_and_empty(self):
        report = {"files": {"src/mathy.js": {"mutants": [
            {"mutatorName": "A", "status": "Survived"},
        ]}}}
        result = _collect_from_report(report, ["src/mathy.js"], 5)
        detail = result.surviving_mutants[0]
        self.assertIsNone(detail.line)
        self.assertEqual(detail.diff, "A: replaced with ``")

    def test_non_dict_files_map_yields_empty_scope(self):
        result = _collect_from_report({"files": "not-a-dict"}, ["src/mathy.js"], 5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)
        self.assertEqual(result.scoped_files, ["src/mathy.js"])

    def test_missing_files_key_yields_empty_scope(self):
        result = _collect_from_report({}, ["src/mathy.js"], 5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)
        self.assertEqual(result.scoped_files, ["src/mathy.js"])

    def test_non_dict_file_data_yields_no_mutants_for_that_file(self):
        report = {"files": {"src/mathy.js": "not-a-dict"}}
        result = _collect_from_report(report, ["src/mathy.js"], 5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)

    def test_max_detail_boundary_is_strict_less_than(self):
        report = {"files": {"src/mathy.js": {"mutants": [
            {"mutatorName": "A", "status": "Survived", "location": {"start": {"line": 10}}},
            {"mutatorName": "B", "status": "Survived", "location": {"start": {"line": 20}}},
            {"mutatorName": "C", "status": "Survived", "location": {"start": {"line": 30}}},
        ]}}}
        result = _collect_from_report(report, ["src/mathy.js"], 2)
        self.assertEqual(result.survived, 3)
        self.assertEqual(len(result.surviving_mutants), 2)
        self.assertEqual([m.line for m in result.surviving_mutants], [10, 20])

    def test_killed_and_timeout_present_is_not_the_zero_mutant_exemption(self):
        report = {"files": {"src/mathy.js": {"mutants": [
            {"mutatorName": "A", "status": "Killed", "location": {}},
            {"mutatorName": "B", "status": "Timeout", "location": {}},
        ]}}}
        result = _collect_from_report(report, ["src/mathy.js"], 5)
        self.assertEqual(result.status, "ran")
        self.assertIsNone(result.reason)
        self.assertEqual(result.killed, 1)
        self.assertEqual(result.timeout, 1)

    def test_killed_equals_survived_is_not_the_zero_mutant_exemption(self):
        report = {"files": {"src/mathy.js": {"mutants": [
            {"mutatorName": "A", "status": "Killed", "location": {}},
            {"mutatorName": "B", "status": "Survived", "location": {}},
        ]}}}
        result = _collect_from_report(report, ["src/mathy.js"], 5)
        self.assertEqual(result.status, "ran")
        self.assertIsNone(result.reason)
        self.assertEqual(result.killed, 1)
        self.assertEqual(result.survived, 1)


if __name__ == "__main__":
    unittest.main()
