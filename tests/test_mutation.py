import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.common import UnsafePathError
from cli.mutation import (
    MUTATION_MIN_SAMPLE_SIZE_DEFAULT,
    MULTIPLIER_FAILED,
    MULTIPLIER_NOT_APPLICABLE,
    MULTIPLIER_PASSED,
    MULTIPLIER_UNAVAILABLE,
    REASON_CODE_INSUFFICIENT_SAMPLE,
    REASON_CODE_NO_CLI_CHANGES,
    REASON_CODE_NO_COVERABLE_LINES,
    REASON_CODE_SKIPPED,
    _NO_MATCH_MARKER,
    _dotted_module,
    _parse_mutant_key,
    _wildcard_for,
    run_mutation_testing,
    select_changed_python_files,
    skipped_report,
)


def _write_stats(repo_dir: Path, **counts) -> None:
    stats = dict(killed=0, survived=0, total=0, no_tests=0, skipped=0, suspicious=0, timeout=0)
    stats.update(counts)
    out = repo_dir / "mutants" / "mutmut-cicd-stats.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(stats), encoding="utf-8")


def _ok(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=["mutmut"], returncode=returncode, stdout=stdout, stderr=stderr)


class SelectChangedPythonFilesTests(unittest.TestCase):

    def test_filters_to_cli_py_files_only(self):
        changed = {
            "cli/scorer.py": {1, 2},
            "tests/test_scorer.py": {1},
            "README.md": {1},
            "cli/parsers/sarif.py": {5},
            "schema/lucid-attestation-v1.schema.json": {1},
        }
        self.assertEqual(select_changed_python_files(changed), ["cli/parsers/sarif.py", "cli/scorer.py"])

    def test_empty_diff_yields_empty_list(self):
        self.assertEqual(select_changed_python_files({}), [])


class DottedModuleAndWildcardTests(unittest.TestCase):

    def test_dotted_module_matches_mutmut_own_namespacing(self):
        # Confirmed empirically against a real mutmut 3.7.0 run: a mutant
        # in pkg/mathy.py surfaces as "pkg.mathy.x_<func>__mutmut_<n>".
        self.assertEqual(_dotted_module("cli/parsers/sarif.py"), "cli.parsers.sarif")
        self.assertEqual(_wildcard_for("cli/scorer.py"), "cli.scorer.*")

    def test_parse_mutant_key_resolves_back_to_scoped_file_and_function(self):
        scoped = ["cli/parsers/sarif.py", "cli/scorer.py"]
        resolved = _parse_mutant_key("cli.scorer.x_score_test_health__mutmut_3", scoped)
        self.assertEqual(resolved, ("cli/scorer.py", "score_test_health"))

    def test_parse_mutant_key_returns_none_for_unscoped_file(self):
        self.assertIsNone(_parse_mutant_key("cli.verify.x_something__mutmut_1", ["cli/scorer.py"]))


class SkippedReportTests(unittest.TestCase):

    def test_skipped_report_never_defaults_to_full_credit(self):
        report = skipped_report()
        self.assertFalse(report.available)
        self.assertEqual(report.multiplier, MULTIPLIER_UNAVAILABLE)
        self.assertLess(report.multiplier, MULTIPLIER_PASSED)
        self.assertEqual(report.reason_code, REASON_CODE_SKIPPED)


class RunMutationTestingTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self._tmp.name)
        (self.repo_dir / "cli").mkdir()
        (self.repo_dir / "cli" / "scorer.py").write_text(
            "def score_test_health(totals):\n    return 1\n\n\ndef other():\n    return 2\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self._tmp.cleanup()

    def _diff(self):
        return {"cli/scorer.py": {1, 2}}

    def test_no_cli_py_changes_short_circuits_without_invoking_mutmut(self):
        with patch("cli.mutation._run_mutmut") as run_mock:
            report = run_mutation_testing(str(self.repo_dir), {"README.md": {1}})
        run_mock.assert_not_called()
        self.assertFalse(report.available)
        self.assertEqual(report.grade, "not_applicable")
        self.assertEqual(report.multiplier, MULTIPLIER_NOT_APPLICABLE)
        self.assertEqual(report.reason_code, REASON_CODE_NO_CLI_CHANGES)

    def test_unsafe_repo_dir_is_refused_and_reported_unavailable(self):
        with patch("cli.mutation.safe_resolve_path", side_effect=UnsafePathError("bad path")):
            report = run_mutation_testing("cli/scorer.py\x00", self._diff())
        self.assertFalse(report.available)
        self.assertIn("unsafe repo_dir", report.reason)

    def test_high_kill_rate_grades_passed_with_no_discount(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                _write_stats(self.repo_dir, killed=9, survived=1, total=10)
                return _ok()
            if args[0] == "export-cicd-stats":
                return _ok()
            return _ok()

        with patch("cli.mutation._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertEqual(report.grade, "passed")
        self.assertEqual(report.multiplier, MULTIPLIER_PASSED)
        self.assertAlmostEqual(report.mutation_score, 90.0)

    def test_weak_kill_rate_grades_degraded(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                _write_stats(self.repo_dir, killed=7, survived=3, total=10)
                return _ok()
            return _ok()

        with patch("cli.mutation._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertEqual(report.grade, "degraded")
        self.assertEqual(report.reason_code, "weak_assertion_coverage")
        self.assertIn("discounted by", report.reason)

    def test_decorative_kill_rate_grades_failed(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                _write_stats(self.repo_dir, killed=2, survived=8, total=10)
                return _ok()
            return _ok()

        with patch("cli.mutation._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertEqual(report.grade, "failed")
        self.assertEqual(report.multiplier, MULTIPLIER_FAILED)
        self.assertEqual(report.reason_code, "decorative_coverage")

    def test_small_sample_does_not_apply_a_discount(self):
        # A single surviving mutant out of one generated mutant is a 0%
        # kill rate on a coin flip, not a real signal.
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                _write_stats(self.repo_dir, killed=0, survived=1, total=1)
                return _ok()
            return _ok()

        with patch("cli.mutation._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(
                str(self.repo_dir), self._diff(), min_sample_size=MUTATION_MIN_SAMPLE_SIZE_DEFAULT
            )
        self.assertEqual(report.grade, "insufficient_sample")
        self.assertEqual(report.multiplier, MULTIPLIER_NOT_APPLICABLE)
        self.assertEqual(report.reason_code, REASON_CODE_INSUFFICIENT_SAMPLE)

    def test_zero_mutants_generated_is_the_exemption_not_a_crash(self):
        # mutmut's own `run <wildcard>` raises an uncaught AssertionError
        # when every wildcard matches nothing (confirmed empirically) --
        # this must translate into the zero-mutant exemption, never
        # propagate or get treated as a genuine tool failure.
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                return _ok(returncode=1, stderr=f"AssertionError: {_NO_MATCH_MARKER}\n\nFilter: ('cli.scorer.*',)")
            return _ok()

        with patch("cli.mutation._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertEqual(report.grade, "not_applicable")
        self.assertEqual(report.reason_code, REASON_CODE_NO_COVERABLE_LINES)
        self.assertFalse(report.available)

    def test_zero_tested_mutants_after_a_clean_run_is_also_the_exemption(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                _write_stats(self.repo_dir, killed=0, survived=0, timeout=0, total=3)
                return _ok()
            return _ok()

        with patch("cli.mutation._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertEqual(report.reason_code, REASON_CODE_NO_COVERABLE_LINES)
        self.assertEqual(report.multiplier, MULTIPLIER_NOT_APPLICABLE)

    def test_timeout_is_reported_unavailable_never_full_credit(self):
        def side_effect(args, *, cwd, timeout_seconds):
            raise subprocess.TimeoutExpired(cmd=args, timeout=timeout_seconds)

        with patch("cli.mutation._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff(), timeout_seconds=1)
        self.assertFalse(report.available)
        self.assertEqual(report.multiplier, MULTIPLIER_UNAVAILABLE)
        self.assertLess(report.multiplier, MULTIPLIER_PASSED)

    def test_a_genuine_mutmut_crash_is_unavailable_not_the_exemption(self):
        # Distinct from the zero-mutant AssertionError case above -- any
        # other non-zero exit must fail closed (penalized), not be read
        # as "nothing to mutate".
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                return _ok(returncode=1, stderr="Traceback: something else entirely broke")
            return _ok()

        with patch("cli.mutation._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertFalse(report.available)
        self.assertEqual(report.multiplier, MULTIPLIER_UNAVAILABLE)
        self.assertNotEqual(report.reason_code, REASON_CODE_NO_COVERABLE_LINES)

    def test_surviving_mutant_detail_is_collected_and_capped(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                _write_stats(self.repo_dir, killed=2, survived=8, total=10)
                return _ok()
            if args[0] == "export-cicd-stats":
                return _ok()
            if args[0] == "results":
                return _ok(stdout="    cli.scorer.x_score_test_health__mutmut_1: survived\n")
            if args[0] == "show":
                return _ok(stdout="--- cli/scorer.py\n+++ cli/scorer.py\n@@ -1,2 +1,2 @@\n-return 1\n+return 2\n")
            return _ok()

        with patch("cli.mutation._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertEqual(len(report.surviving_mutants), 1)
        detail = report.surviving_mutants[0]
        self.assertEqual(detail.file, "cli/scorer.py")
        self.assertEqual(detail.function, "score_test_health")
        self.assertEqual(detail.line, 1)  # AST lineno of score_test_health in the fixture file
        self.assertIn("+return 2", detail.diff)

    def test_report_is_written_to_the_requested_path(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                _write_stats(self.repo_dir, killed=9, survived=1, total=10)
                return _ok()
            return _ok()

        out_path = self.repo_dir / "reports" / "mutation" / "mutation-report.json"
        with patch("cli.mutation._run_mutmut", side_effect=side_effect):
            run_mutation_testing(str(self.repo_dir), self._diff(), report_out=str(out_path))
        self.assertTrue(out_path.exists())
        written = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(written["grade"], "passed")

    def test_stale_cache_is_reset_before_each_run(self):
        # See the module docstring's "Stats leaking across unrelated
        # files" hardening note -- a leftover mutants/ dir from a prior,
        # differently-scoped invocation must never survive into this run.
        stale = self.repo_dir / "mutants" / "mutmut-cicd-stats.json"
        stale.parent.mkdir(parents=True)
        stale.write_text(json.dumps({"killed": 0, "survived": 99, "total": 99}), encoding="utf-8")

        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                self.assertFalse((self.repo_dir / "mutants").exists())
                _write_stats(self.repo_dir, killed=9, survived=1, total=10)
                return _ok()
            return _ok()

        with patch("cli.mutation._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertEqual(report.survived, 1)


if __name__ == "__main__":
    unittest.main()
