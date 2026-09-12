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
    LANGUAGE_GO,
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
    _build_scoped_pyproject_text,
    _dotted_module,
    _parse_mutant_key,
    _scoped_only_mutate,
    _touched_functions,
    _wildcard_for,
    _wildcards_for_file,
    run as python_runner_run,
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
            "mathy/mathy.go": {1},
            "mathy/mathy_test.go": {1},
            "README.md": {1},
        }
        result = _classify_changed_files(changed)
        self.assertEqual(result[LANGUAGE_PYTHON], ["cli/scorer.py"])
        self.assertEqual(result[LANGUAGE_TSJS], ["src/app/handlers.ts"])
        self.assertEqual(result[LANGUAGE_JAVA], ["mathy/Mathy.java"])
        self.assertEqual(result[LANGUAGE_GO], ["mathy/mathy.go"])

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


class TouchedFunctionsAndWildcardsTests(unittest.TestCase):
    """_touched_functions()/_wildcards_for_file() -- see python_runner.py's
    own docstrings for why this exists: mutmut mutates a whole touched
    *file* regardless of how few of its lines actually changed, which is
    what drove this repo's own real diff's kill rate down (verify.py,
    3,663 lines, only 151 changed, still mutated in full). Narrowing to
    just the touched *functions* is confirmed safe against a real
    mutmut 3.7.0 install: mutmut never mutates module-level code at all
    (only inside function bodies, via its trampoline mechanism)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self._tmp.name)
        (self.repo_dir / "cli").mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, rel_path: str, source: str) -> None:
        path = self.repo_dir / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    def test_finds_the_function_whose_body_overlaps_a_changed_line(self):
        self._write(
            "cli/scorer.py",
            "def _clamp(x):\n"
            "    return x\n"
            "\n\n"
            "def _score_test_health(totals):\n"
            "    return 1\n",
        )
        # Line 5 is inside _score_test_health's body only.
        touched = _touched_functions(self.repo_dir, "cli/scorer.py", {5})
        self.assertEqual(touched, {"_score_test_health"})

    def test_returns_empty_set_for_module_level_only_changes(self):
        self._write("cli/scorer.py", "WEIGHTS = {}\n\n\ndef f():\n    return 1\n")
        # Line 1 is the module-level WEIGHTS assignment, outside any def.
        touched = _touched_functions(self.repo_dir, "cli/scorer.py", {1})
        self.assertEqual(touched, set())

    def test_returns_none_when_file_cannot_be_parsed(self):
        self._write("cli/scorer.py", "def f(:\n    broken\n")
        self.assertIsNone(_touched_functions(self.repo_dir, "cli/scorer.py", {1}))

    def test_visits_nested_and_class_methods_by_bare_name(self):
        self._write(
            "cli/scorer.py",
            "class C:\n"
            "    def method(self):\n"
            "        return 1\n",
        )
        touched = _touched_functions(self.repo_dir, "cli/scorer.py", {3})
        self.assertEqual(touched, {"method"})

    def test_wildcards_for_file_builds_one_per_touched_function(self):
        self._write(
            "cli/scorer.py",
            "def _clamp(x):\n"
            "    return x\n"
            "\n\n"
            "def _score_test_health(totals):\n"
            "    return 1\n",
        )
        wildcards = _wildcards_for_file(self.repo_dir, "cli/scorer.py", {5})
        self.assertEqual(wildcards, ["cli.scorer.x__score_test_health__mutmut_*"])

    def test_wildcards_for_file_falls_back_to_whole_file_when_lines_unknown(self):
        self._write("cli/scorer.py", "def f():\n    return 1\n")
        self.assertEqual(_wildcards_for_file(self.repo_dir, "cli/scorer.py", None), ["cli.scorer.*"])
        self.assertEqual(_wildcards_for_file(self.repo_dir, "cli/scorer.py", set()), ["cli.scorer.*"])

    def test_wildcards_for_file_returns_none_needed_for_module_level_only_changes(self):
        self._write("cli/scorer.py", "WEIGHTS = {}\n")
        self.assertEqual(_wildcards_for_file(self.repo_dir, "cli/scorer.py", {1}), [])

    def test_wildcards_for_file_falls_back_to_whole_file_when_unparseable(self):
        self._write("cli/scorer.py", "def f(:\n    broken\n")
        self.assertEqual(_wildcards_for_file(self.repo_dir, "cli/scorer.py", {1}), ["cli.scorer.*"])


class SkippedReportTests(unittest.TestCase):

    def test_skipped_report_never_defaults_to_full_credit(self):
        report = skipped_report()
        self.assertFalse(report.available)
        self.assertEqual(report.multiplier, MULTIPLIER_UNAVAILABLE)
        self.assertLess(report.multiplier, MULTIPLIER_PASSED)
        self.assertEqual(report.reason_code, REASON_CODE_SKIPPED)


class RunMutmutSubprocessInvocationTests(unittest.TestCase):
    """Locks in the real subprocess argv _run_mutmut() constructs -- see
    python_runner.py's own "Hardened against" docstring (the
    `sys.executable` bullet) for why this is `uv run --with
    mutmut==<pinned version> --no-sync python -m mutmut <args>`, not a
    direct `[sys.executable, "-m", "mutmut", *args]` invocation: the
    latter can never see a *target* repo's own runtime/test dependencies
    (confirmed empirically, 2026-09-12, lucid-dsse-collector's own real
    CI run -- a ModuleNotFoundError on the target's own fastapi)."""

    def test_invokes_uv_run_with_the_pinned_mutmut_version_and_no_sync(self):
        from cli.mutation.python_runner import _MUTMUT_VERSION, _run_mutmut

        with patch("cli.mutation.python_runner.subprocess.run") as run_mock:
            run_mock.return_value = _ok()
            _run_mutmut(["run", "cli.scorer.*"], cwd=Path("/tmp/some-repo"), timeout_seconds=30)

        run_mock.assert_called_once()
        argv, kwargs = run_mock.call_args.args[0], run_mock.call_args.kwargs
        self.assertEqual(
            argv,
            ["uv", "run", "--with", f"mutmut=={_MUTMUT_VERSION}", "--no-sync", "python", "-m", "mutmut", "run", "cli.scorer.*"],
        )
        # cwd is what makes uv's own project discovery (and mutmut's own
        # relative-path pyproject.toml lookup) resolve against the target
        # repo, not an explicit --project flag -- see the docstring.
        self.assertEqual(kwargs["cwd"], Path("/tmp/some-repo"))
        self.assertEqual(kwargs["timeout"], 30)
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])
        # assertIs, not assertFalse -- subprocess.run itself treats
        # check=None identically to check=False (both falsy), so a plain
        # truthiness assertion can't tell them apart; assertIs pins the
        # literal value actually written in source.
        self.assertIs(kwargs["check"], False)

    def test_mutmut_version_is_read_dynamically_not_hardcoded_a_second_time(self):
        import importlib.metadata

        from cli.mutation.python_runner import _MUTMUT_VERSION

        self.assertEqual(_MUTMUT_VERSION, importlib.metadata.version("mutmut"))


def _recording_side_effect(calls, responses):
    """A `_run_mutmut` side_effect that records every call's (args, cwd,
    timeout_seconds) into `calls` and returns/raises whatever `responses`
    maps that call's subcommand (args[0]) to -- a subprocess.CompletedProcess
    to return, or an Exception instance to raise. Any subcommand not in
    `responses` gets a bare `_ok()`."""

    def side_effect(args, *, cwd, timeout_seconds):
        calls.append((tuple(args), cwd, timeout_seconds))
        resp = responses.get(args[0])
        if isinstance(resp, Exception):
            raise resp
        return resp if resp is not None else _ok()

    return side_effect


class PythonRunnerRunDirectFieldTests(unittest.TestCase):
    """Calls cli.mutation.python_runner.run() directly (not through
    run_mutation_testing()'s combining/grading layer) and asserts on the
    exact LanguageRunResult fields it returns -- the combining layer
    (cli.mutation.__init__._combine_results) lossily projects most of
    these into a single free-text `reason` string, which makes several
    real field-level mutations (a None value, a wrong dict key, a missing
    kwarg silently defaulting) invisible to a test that only inspects the
    combined MutationTestReport. Real survivors found via a genuine
    mutmut run against this module (2026-09-12, lucid-dsse-collector PR
    #59's own CI first exercised _run_scoped at this granularity) --
    every test below targets one specific surviving mutant's exact shape,
    not a guess at what might matter."""

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

    def _run(self, *, timeout_seconds=30, max_surviving_detail=5):
        return python_runner_run(
            self.repo_dir, ["cli/scorer.py"],
            timeout_seconds=timeout_seconds, max_surviving_detail=max_surviving_detail,
            changed_lines={"cli/scorer.py": {1, 2}},
        )

    def test_run_and_export_cicd_stats_calls_receive_the_real_cwd_and_timeout(self):
        calls: List[tuple] = []
        _write_stats(self.repo_dir, killed=1, total=1)
        with patch("cli.mutation.python_runner._run_mutmut", side_effect=_recording_side_effect(calls, {})):
            self._run(timeout_seconds=42)
        run_call = next(c for c in calls if c[0][0] == "run")
        stats_call = next(c for c in calls if c[0][0] == "export-cicd-stats")
        self.assertEqual(run_call[1], self.repo_dir)
        self.assertEqual(run_call[2], 42)
        self.assertEqual(stats_call[1], self.repo_dir)
        self.assertEqual(stats_call[2], 42)

    def test_timeout_expired_reports_exact_language_status_and_reason(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                raise subprocess.TimeoutExpired(cmd=args, timeout=timeout_seconds)
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            result = self._run(timeout_seconds=17)
        self.assertEqual(result.language, LANGUAGE_PYTHON)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.reason, "mutmut exceeded the 17s time budget")

    def test_oserror_reports_exact_language_status_and_reason(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                raise OSError("no such file: mutmut")
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            result = self._run()
        self.assertEqual(result.language, LANGUAGE_PYTHON)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.reason, "mutmut could not be invoked: no such file: mutmut")

    def test_no_match_marker_exemption_reports_exact_language_status_scoped_files_and_reason(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                return _ok(returncode=1, stderr=f"AssertionError: {_NO_MATCH_MARKER}")
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            result = self._run()
        self.assertEqual(result.language, LANGUAGE_PYTHON)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.scoped_files, ["cli/scorer.py"])
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)

    def test_general_run_failure_prefers_stderr_verbatim(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                return _ok(returncode=1, stdout="ignored stdout", stderr="the real stderr reason")
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            result = self._run()
        self.assertEqual(result.language, LANGUAGE_PYTHON)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.reason, "mutmut run failed (exit 1): the real stderr reason")

    def test_general_run_failure_falls_back_to_stdout_verbatim_when_stderr_empty(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                return _ok(returncode=1, stdout="the real stdout reason", stderr="")
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            result = self._run()
        self.assertEqual(result.reason, "mutmut run failed (exit 1): the real stdout reason")

    def test_general_run_failure_with_both_streams_empty_yields_no_fabricated_placeholder(self):
        # Pins the literal fallback ("") for both `or` defaults -- a
        # mutated fallback constant (e.g. "XXXX") would leak into this
        # exact reason text, since neither stream has real content to
        # short-circuit to.
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                return _ok(returncode=1, stdout="", stderr="")
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            result = self._run()
        self.assertEqual(result.reason, "mutmut run failed (exit 1): ")

    def test_general_run_failure_truncates_error_detail_at_exactly_300_chars(self):
        long_stderr = "x" * 305

        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                return _ok(returncode=1, stderr=long_stderr)
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            result = self._run()
        self.assertEqual(result.reason, f"mutmut run failed (exit 1): {'x' * 300}")

    def test_stats_read_failure_reports_exact_language_status_and_reason(self):
        # "run" succeeds but never actually writes mutmut-cicd-stats.json
        # (the mocked "export-cicd-stats" call is a no-op) -- the
        # subsequent read genuinely fails (FileNotFoundError, an OSError).
        with patch("cli.mutation.python_runner._run_mutmut", side_effect=lambda args, **kw: _ok()):
            result = self._run()
        self.assertEqual(result.language, LANGUAGE_PYTHON)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.reason, "mutmut ran but its results could not be read")

    def test_stats_dict_reads_the_real_distinct_value_for_every_key(self):
        # Four distinct, nonzero values -- a key-name typo (wrong dict
        # key) falls back to each field's own 0 default instead of the
        # real value, which this would catch immediately. Written inside
        # the mocked "run" call, not before it -- run() itself deletes
        # any pre-existing mutants/ dir (_reset_mutmut_cache) before ever
        # reaching _run_scoped, so a stats file written beforehand would
        # just be wiped before this code gets to read it.
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                _write_stats(self.repo_dir, killed=3, survived=5, timeout=7, total=99)
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            result = self._run()
        self.assertEqual(result.killed, 3)
        self.assertEqual(result.survived, 5)
        self.assertEqual(result.timeout, 7)
        self.assertEqual(result.total_generated, 99)

    def test_stats_dict_missing_every_key_defaults_to_zero_not_none_or_one(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                stats_path = self.repo_dir / "mutants" / "mutmut-cicd-stats.json"
                stats_path.parent.mkdir(parents=True, exist_ok=True)
                stats_path.write_text("{}", encoding="utf-8")
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            result = self._run()
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.killed, 0)
        self.assertEqual(result.survived, 0)
        self.assertEqual(result.timeout, 0)
        self.assertEqual(result.total_generated, 0)

    def test_surviving_detail_is_capped_to_the_real_max_detail_not_unbounded(self):
        results_lines = "\n".join(
            f"    cli.scorer.x_score_test_health__mutmut_{i}: survived" for i in range(3)
        )
        calls: List[tuple] = []

        def side_effect(args, *, cwd, timeout_seconds):
            calls.append((tuple(args), timeout_seconds))
            if args[0] == "run":
                _write_stats(self.repo_dir, killed=1, survived=3, total=4)
            elif args[0] == "results":
                return _ok(stdout=results_lines)
            elif args[0] == "show":
                return _ok(stdout="--- a\n+++ b\n")
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            result = self._run(timeout_seconds=64, max_surviving_detail=2)
        # 3 real survivors found, capped to the real max_surviving_detail
        # (2) -- max_detail=None (list[:None]) would silently return all
        # 3 uncapped instead.
        self.assertEqual(len(result.surviving_mutants), 2)
        # _collect_surviving_detail's own "results"/"show" calls must get
        # the real timeout_seconds threaded through, not a mutated None.
        results_call = next(c for c in calls if c[0][0] == "results")
        show_call = next(c for c in calls if c[0][0] == "show")
        self.assertEqual(results_call[1], 64)
        self.assertEqual(show_call[1], 64)

    def test_final_result_carries_the_real_timeout_total_generated_and_scoped_files(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                _write_stats(self.repo_dir, killed=2, survived=0, timeout=9, total=11)
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            result = self._run()
        self.assertEqual(result.timeout, 9)
        self.assertEqual(result.total_generated, 11)
        self.assertEqual(result.scoped_files, ["cli/scorer.py"])


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

    def test_a_failed_run_with_empty_stderr_falls_back_to_stdout_in_the_reason(self):
        # A pytest collection error (e.g. the target repo's own runtime
        # dependency isn't importable) prints to stdout, not stderr -- the
        # reason string must not go blank just because stderr is empty.
        # Confirmed empirically, 2026-09-12: lucid-dsse-collector's own
        # real CI run hit exactly this shape.
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                return _ok(returncode=1, stdout="ModuleNotFoundError: No module named 'fastapi'", stderr="")
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertFalse(report.available)
        self.assertIn("ModuleNotFoundError: No module named 'fastapi'", report.reason)

    def test_a_failed_run_prefers_stderr_over_stdout_when_both_are_present(self):
        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                return _ok(returncode=1, stdout="some incidental progress output", stderr="the real crash reason")
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            report = run_mutation_testing(str(self.repo_dir), self._diff())
        self.assertIn("the real crash reason", report.reason)
        self.assertNotIn("some incidental progress output", report.reason)

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

    def test_pyproject_only_mutate_is_scoped_during_the_run_and_restored_after(self):
        # See python_runner.py's own "Hardened against" docstring: mutmut
        # has no per-invocation generation-scoping flag, so this repo's
        # own real pyproject.toml is temporarily narrowed for the whole
        # generate/run/read-results sequence, then restored.
        (self.repo_dir / "pyproject.toml").write_text(
            '[tool.mutmut]\nsource_paths = ["cli"]\nonly_mutate = ["cli/*"]\n',
            encoding="utf-8",
        )
        seen_during_run = []

        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                seen_during_run.append((self.repo_dir / "pyproject.toml").read_text(encoding="utf-8"))
                _write_stats(self.repo_dir, killed=1, survived=0, total=1)
                return _ok()
            # export-cicd-stats/results/show, if any -- also see the
            # narrowed config, not the original.
            seen_during_run.append((self.repo_dir / "pyproject.toml").read_text(encoding="utf-8"))
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            run_mutation_testing(str(self.repo_dir), self._diff())

        self.assertTrue(seen_during_run, "expected at least one mutmut invocation")
        for text in seen_during_run:
            self.assertIn('only_mutate = ["cli/scorer.py"]', text)
        restored = (self.repo_dir / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('only_mutate = ["cli/*"]', restored)

    def test_changed_lines_narrows_the_wildcard_to_just_the_touched_function(self):
        # End-to-end through the real dispatcher (run_mutation_testing),
        # not just _wildcards_for_file in isolation: setUp's cli/scorer.py
        # has two functions, score_test_health (lines 1-2) and other
        # (lines 5-6); self._diff() only touches lines 1-2. Confirms the
        # real regression this closes -- before this, mutmut would mutate
        # and test *all* of cli/scorer.py (both functions) for a diff
        # that only touched one of them.
        seen_run_args = []

        def side_effect(args, *, cwd, timeout_seconds):
            if args[0] == "run":
                seen_run_args.append(args)
                _write_stats(self.repo_dir, killed=1, survived=0, total=1)
                return _ok()
            return _ok()

        with patch("cli.mutation.python_runner._run_mutmut", side_effect=side_effect):
            run_mutation_testing(str(self.repo_dir), self._diff())

        self.assertEqual(len(seen_run_args), 1)
        self.assertEqual(seen_run_args[0][1:], ["cli.scorer.x_score_test_health__mutmut_*"])

    def test_module_level_only_diff_reports_no_coverable_lines_without_invoking_mutmut(self):
        # A diff whose only changed line is module-level (outside any
        # function) has nothing for mutmut to mutate at all (confirmed
        # empirically -- see _touched_functions's own docstring). Must
        # never fall through to an *unfiltered* `mutmut run` (mutmut's
        # own "run" with zero mutant_names means "run everything").
        (self.repo_dir / "cli" / "scorer.py").write_text("WEIGHTS = {}\n", encoding="utf-8")
        with patch("cli.mutation.python_runner._run_mutmut") as run_mock:
            report = run_mutation_testing(str(self.repo_dir), {"cli/scorer.py": {1}})
        run_mock.assert_not_called()
        self.assertEqual(report.reason_code, REASON_CODE_NO_COVERABLE_LINES)


class ScopedOnlyMutateTests(unittest.TestCase):
    """_scoped_only_mutate()/_build_scoped_pyproject_text() in isolation --
    see python_runner.py's own "Hardened against" docstring for why this
    exists: mutmut's own CLI has no per-invocation generation-scoping
    flag, only the target repo's static pyproject.toml only_mutate list,
    confirmed empirically against a real mutmut 3.7.0 install."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write_pyproject(self, text: str) -> str:
        (self.repo_dir / "pyproject.toml").write_text(text, encoding="utf-8")
        return text

    def test_rewrites_only_the_tool_mutmut_only_mutate_line(self):
        original = self._write_pyproject(
            '[tool.other]\n'
            'only_mutate = ["should-not-touch/*"]\n'
            '\n'
            '[tool.mutmut]\n'
            'source_paths = ["cli", "scripts"]\n'
            'only_mutate = ["cli/*"]\n'
            'pytest_add_cli_args_test_selection = ["tests"]\n'
            '\n'
            '[tool.another]\n'
            'key = 1\n'
        )
        with _scoped_only_mutate(self.repo_dir, ["cli/foo.py", "cli/bar.py"]):
            rewritten = (self.repo_dir / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('only_mutate = ["cli/foo.py", "cli/bar.py"]', rewritten)
        # The unrelated [tool.other] table's own only_mutate-shaped key
        # must never be touched -- confirms section-anchoring, not a
        # blind first-match-anywhere-in-the-file replace.
        self.assertIn('[tool.other]\nonly_mutate = ["should-not-touch/*"]', rewritten)
        self.assertIn('source_paths = ["cli", "scripts"]', rewritten)
        self.assertIn('[tool.another]\nkey = 1', rewritten)
        self.assertNotIn('"cli/*"', rewritten)

    def test_restores_original_text_on_success(self):
        original = self._write_pyproject(
            '[tool.mutmut]\nonly_mutate = ["cli/*"]\n'
        )
        with _scoped_only_mutate(self.repo_dir, ["cli/foo.py"]):
            pass
        self.assertEqual((self.repo_dir / "pyproject.toml").read_text(encoding="utf-8"), original)

    def test_restores_original_text_even_on_exception(self):
        original = self._write_pyproject(
            '[tool.mutmut]\nonly_mutate = ["cli/*"]\n'
        )
        with self.assertRaises(RuntimeError):
            with _scoped_only_mutate(self.repo_dir, ["cli/foo.py"]):
                raise RuntimeError("boom")
        self.assertEqual((self.repo_dir / "pyproject.toml").read_text(encoding="utf-8"), original)

    def test_missing_pyproject_is_a_silent_noop(self):
        # No pyproject.toml written at all in this test.
        with _scoped_only_mutate(self.repo_dir, ["cli/foo.py"]):
            self.assertFalse((self.repo_dir / "pyproject.toml").exists())

    def test_no_tool_mutmut_table_is_a_noop_not_a_guess(self):
        original = self._write_pyproject("[tool.other]\nkey = 1\n")
        with _scoped_only_mutate(self.repo_dir, ["cli/foo.py"]):
            unchanged = (self.repo_dir / "pyproject.toml").read_text(encoding="utf-8")
        self.assertEqual(unchanged, original)

    def test_ambiguous_multiple_only_mutate_lines_is_a_noop_not_a_guess(self):
        # Two only_mutate assignments in the same table is invalid TOML in
        # spirit and not something this module should ever guess how to
        # resolve -- fall back to the unscoped-but-correct original.
        original = self._write_pyproject(
            '[tool.mutmut]\n'
            'only_mutate = ["cli/*"]\n'
            'only_mutate = ["cli/other/*"]\n'
        )
        with _scoped_only_mutate(self.repo_dir, ["cli/foo.py"]):
            unchanged = (self.repo_dir / "pyproject.toml").read_text(encoding="utf-8")
        self.assertEqual(unchanged, original)

    def test_build_scoped_text_returns_none_when_no_confident_match(self):
        self.assertIsNone(_build_scoped_pyproject_text("[tool.other]\nkey = 1\n", ["cli/foo.py"]))


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
