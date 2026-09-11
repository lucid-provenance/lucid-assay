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
from cli.mutation.tsjs_runner import _stryker_configured, run


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

    def test_no_matching_files_reports_not_configured(self):
        result = run(self.repo_dir, ["src/other.ts"], timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "not_configured")

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
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)

    def test_missing_report_after_a_clean_exit_is_the_exemption_not_a_failure(self):
        with patch("cli.mutation.tsjs_runner._run_stryker", return_value=_ok(returncode=0)):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)

    def test_nonzero_exit_with_no_report_is_unavailable(self):
        with patch("cli.mutation.tsjs_runner._run_stryker", return_value=_ok(returncode=1, stderr="boom")):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "unavailable")

    def test_timeout_is_unavailable_never_full_credit(self):
        with patch("cli.mutation.tsjs_runner._run_stryker", side_effect=subprocess.TimeoutExpired(cmd=[], timeout=1)):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=1, max_surviving_detail=5)
        self.assertEqual(result.status, "unavailable")

    def test_missing_npx_binary_is_unavailable(self):
        with patch("cli.mutation.tsjs_runner._run_stryker", side_effect=FileNotFoundError("npx not found")):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "unavailable")

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


if __name__ == "__main__":
    unittest.main()
