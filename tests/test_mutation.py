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
    _classify_changed_files,
    run_mutation_testing,
    select_changed_python_files,
    skipped_report,
)
from cli.mutation.common import (
    MUTATION_MIN_SAMPLE_SIZE_DEFAULT,
    MULTIPLIER_FAILED,
    MULTIPLIER_NOT_APPLICABLE,
    MULTIPLIER_PASSED,
    MULTIPLIER_UNAVAILABLE,
    LANGUAGE_JAVA,
    LANGUAGE_PYTHON,
    LANGUAGE_TSJS,
    LanguageRunResult,
    REASON_CODE_INSUFFICIENT_SAMPLE,
    REASON_CODE_NO_COVERABLE_LINES,
    REASON_CODE_NO_SOURCE_CHANGES,
    REASON_CODE_SKIPPED,
)
from cli.mutation.python_runner import (
    _NO_MATCH_MARKER,
    _dotted_module,
    _parse_mutant_key,
    _wildcard_for,
)


def _write_stats(repo_dir: Path, **counts) -> None:
    stats = dict(killed=0, survived=0, total=0, no_tests=0, skipped=0, suspicious=0, timeout=0)
    stats.update(counts)
    out = repo_dir / "mutants" / "mutmut-cicd-stats.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(stats), encoding="utf-8")


def _ok(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=["mutmut"], returncode=returncode, stdout=stdout, stderr=stderr)


class ClassifyChangedFilesTests(unittest.TestCase):

    def test_splits_by_language_and_excludes_tests(self):
        changed = {
            "cli/scorer.py": {1, 2},
            "tests/test_scorer.py": {1},
            "src/app/handlers.ts": {1},
            "src/app/handlers.spec.ts": {1},
            "mathy/Mathy.java": {1},
            "mathy/MathyTest.java": {1},
            "README.md": {1},
        }
        result = _classify_changed_files(changed)
        self.assertEqual(result[LANGUAGE_PYTHON], ["cli/scorer.py"])
        self.assertEqual(result[LANGUAGE_TSJS], ["src/app/handlers.ts"])
        self.assertEqual(result[LANGUAGE_JAVA], ["mathy/Mathy.java"])

    def test_empty_diff_yields_empty_dict(self):
        self.assertEqual(_classify_changed_files({}), {})

    def test_select_changed_python_files_is_the_python_slice(self):
        changed = {"cli/scorer.py": {1}, "src/app/handlers.ts": {1}}
        self.assertEqual(select_changed_python_files(changed), ["cli/scorer.py"])


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


class RunMutationTestingPythonTests(unittest.TestCase):
    """End-to-end through run_mutation_testing() -- single-language
    (Python-only) diffs, exercising the dispatcher + python_runner
    together the same way the pre-multi-language test suite did."""

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

    def test_no_source_changes_short_circuits_without_invoking_any_tool(self):
        with patch("cli.mutation.python_runner._run_mutmut") as run_mock:
            report = run_mutation_testing(str(self.repo_dir), {"README.md": {1}})
        run_mock.assert_not_called()
        self.assertFalse(report.available)
        self.assertEqual(report.grade, "not_applicable")
        self.assertEqual(report.multiplier, MULTIPLIER_NOT_APPLICABLE)
        self.assertEqual(report.reason_code, REASON_CODE_NO_SOURCE_CHANGES)

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
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertEqual(report.grade, "passed")
        self.assertEqual(report.multiplier, MULTIPLIER_PASSED)
        self.assertAlmostEqual(report.mutation_score, 90.0)
        self.assertIn(LANGUAGE_PYTHON, report.by_language)

    def test_weak_kill_rate_grades_degraded(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                _write_stats(self.repo_dir, killed=7, survived=3, total=10)
                return _ok()
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
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

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertEqual(report.grade, "failed")
        self.assertEqual(report.multiplier, MULTIPLIER_FAILED)
        self.assertEqual(report.reason_code, "decorative_coverage")

    def test_small_sample_does_not_apply_a_discount(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                _write_stats(self.repo_dir, killed=0, survived=1, total=1)
                return _ok()
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(
                str(self.repo_dir), self._diff(), min_sample_size=MUTATION_MIN_SAMPLE_SIZE_DEFAULT
            )
        self.assertEqual(report.grade, "insufficient_sample")
        self.assertEqual(report.multiplier, MULTIPLIER_NOT_APPLICABLE)
        self.assertEqual(report.reason_code, REASON_CODE_INSUFFICIENT_SAMPLE)

    def test_zero_mutants_generated_is_the_exemption_not_a_crash(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                return _ok(returncode=1, stderr=f"AssertionError: {_NO_MATCH_MARKER}\n\nFilter: ('cli.scorer.*',)")
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertEqual(report.grade, "not_applicable")
        self.assertEqual(report.reason_code, REASON_CODE_NO_COVERABLE_LINES)
        self.assertFalse(report.available)

    def test_timeout_is_reported_unavailable_never_full_credit(self):
        def side_effect(args, *, cwd, timeout_seconds):
            raise subprocess.TimeoutExpired(cmd=args, timeout=timeout_seconds)

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff(), timeout_seconds=1)
        self.assertFalse(report.available)
        self.assertEqual(report.multiplier, MULTIPLIER_UNAVAILABLE)
        self.assertLess(report.multiplier, MULTIPLIER_PASSED)

    def test_a_genuine_mutmut_crash_is_unavailable_not_the_exemption(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                return _ok(returncode=1, stderr="Traceback: something else entirely broke")
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
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

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertEqual(len(report.surviving_mutants), 1)
        detail = report.surviving_mutants[0]
        self.assertEqual(detail.file, "cli/scorer.py")
        self.assertEqual(detail.function, "score_test_health")
        self.assertEqual(detail.language, LANGUAGE_PYTHON)
        self.assertEqual(detail.line, 1)  # AST lineno of score_test_health in the fixture file
        self.assertIn("+return 2", detail.diff)

    def test_report_is_written_to_the_requested_path(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                _write_stats(self.repo_dir, killed=9, survived=1, total=10)
                return _ok()
            return _ok()

        out_path = self.repo_dir / "reports" / "mutation" / "mutation-report.json"
        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            run_mutation_testing(str(self.repo_dir), self._diff(), report_out=str(out_path))
        self.assertTrue(out_path.exists())
        written = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(written["grade"], "passed")

    def test_stale_cache_is_reset_before_each_run(self):
        # See python_runner.py's own hardening note -- a leftover
        # mutants/ dir from a prior, differently-scoped invocation must
        # never survive into this run.
        stale = self.repo_dir / "mutants" / "mutmut-cicd-stats.json"
        stale.parent.mkdir(parents=True)
        stale.write_text(json.dumps({"killed": 0, "survived": 99, "total": 99}), encoding="utf-8")

        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                self.assertFalse((self.repo_dir / "mutants").exists())
                _write_stats(self.repo_dir, killed=9, survived=1, total=10)
                return _ok()
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertEqual(report.survived, 1)


class CombineResultsMultiLanguageTests(unittest.TestCase):
    """Aggregation logic: a diff can touch more than one language at
    once, and the dispatcher combines their raw mutant counts into one
    score before grading -- see cli.mutation.__init__'s own docstring."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self._tmp.name)
        (self.repo_dir / "cli").mkdir()
        (self.repo_dir / "cli" / "scorer.py").write_text("def f():\n    return 1\n", encoding="utf-8")
        (self.repo_dir / "app.ts").write_text("export function f() { return 1; }\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _diff(self):
        return {"cli/scorer.py": {1}, "app.ts": {1}}

    def test_combined_totals_sum_raw_mutant_counts_not_percentages(self):
        # 80 killed/20 survived in Python (80%) + 2 killed/2 survived in
        # TS (50%) should combine to 82/104 = ~78.8%, not an average of
        # the two percentages (which would misleadingly read as 65%).
        python_result = LanguageRunResult(
            language=LANGUAGE_PYTHON, status="ran", killed=80, survived=20,
            total_generated=100, scoped_files=["cli/scorer.py"],
        )
        tsjs_result = LanguageRunResult(
            language=LANGUAGE_TSJS, status="ran", killed=2, survived=2,
            total_generated=4, scoped_files=["app.ts"],
        )
        from cli.mutation import _combine_results
        report = _combine_results([python_result, tsjs_result], min_sample_size=3, max_surviving_detail=5)
        self.assertEqual(report.killed, 82)
        self.assertEqual(report.survived, 22)
        self.assertAlmostEqual(report.mutation_score, 82 / 104 * 100, places=3)
        self.assertIn(LANGUAGE_PYTHON, report.by_language)
        self.assertIn(LANGUAGE_TSJS, report.by_language)
        self.assertEqual(report.by_language[LANGUAGE_PYTHON]["killed"], 80)
        self.assertEqual(report.by_language[LANGUAGE_TSJS]["killed"], 2)

    def test_not_configured_language_contributes_nothing(self):
        python_result = LanguageRunResult(
            language=LANGUAGE_PYTHON, status="ran", killed=9, survived=1,
            total_generated=10, scoped_files=["cli/scorer.py"],
        )
        tsjs_result = LanguageRunResult(language=LANGUAGE_TSJS, status="not_configured")
        from cli.mutation import _combine_results
        report = _combine_results([python_result, tsjs_result], min_sample_size=3, max_surviving_detail=5)
        self.assertEqual(report.killed, 9)
        self.assertEqual(report.survived, 1)
        self.assertNotIn(LANGUAGE_TSJS, report.by_language)

    def test_every_touched_language_not_configured_is_not_applicable(self):
        from cli.mutation import _combine_results
        report = _combine_results(
            [
                LanguageRunResult(language=LANGUAGE_PYTHON, status="not_configured"),
                LanguageRunResult(language=LANGUAGE_TSJS, status="not_configured"),
            ],
            min_sample_size=3, max_surviving_detail=5,
        )
        self.assertEqual(report.grade, "not_applicable")
        self.assertEqual(report.multiplier, MULTIPLIER_NOT_APPLICABLE)

    def test_a_real_failure_in_one_language_is_not_masked_by_another_not_configured(self):
        # Fail-closed: if a language's tool genuinely failed, that must
        # not be silently treated the same as "nothing to evaluate"
        # just because a *different* touched language had no config.
        from cli.mutation import _combine_results
        report = _combine_results(
            [
                LanguageRunResult(language=LANGUAGE_JAVA, status="unavailable", reason="mvn could not be invoked"),
                LanguageRunResult(language=LANGUAGE_TSJS, status="not_configured"),
            ],
            min_sample_size=3, max_surviving_detail=5,
        )
        self.assertFalse(report.available)
        self.assertEqual(report.multiplier, MULTIPLIER_UNAVAILABLE)
        self.assertIn("mvn could not be invoked", report.reason)

    def test_surviving_mutants_list_is_capped_across_languages_combined(self):
        many_survivors = [
            __import__("cli.mutation.common", fromlist=["SurvivingMutant"]).SurvivingMutant(
                language=LANGUAGE_PYTHON, file="cli/scorer.py", function=f"f{i}", status="survived", diff="", line=i
            )
            for i in range(10)
        ]
        python_result = LanguageRunResult(
            language=LANGUAGE_PYTHON, status="ran", killed=1, survived=10,
            total_generated=11, scoped_files=["cli/scorer.py"], surviving_mutants=many_survivors,
        )
        from cli.mutation import _combine_results
        report = _combine_results([python_result], min_sample_size=3, max_surviving_detail=5)
        self.assertEqual(len(report.surviving_mutants), 5)


if __name__ == "__main__":
    unittest.main()
