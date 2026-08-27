"""
Direct unit tests for cli.real_coverage.compute_real_coverage(): the
vanity-test-aware "real" coverage cross-reference between
cli.parsers.coverage_contexts (per-test line attribution) and
cli.parsers.ast (which tests are vanity).

Builds every input directly (TestSuiteMetrics/FileInspectionResult/
TestFunctionMetrics, CoverageReport/FileCoverage, CoverageContextReport)
rather than shelling out to a real pytest/coverage.py run, for fast,
deterministic coverage of the cross-referencing logic itself. The
mechanism was additionally validated end-to-end against a real pytest
--cov-context=test run (both against this repo's own suite and a
synthetic demo package) during development; these tests pin that same
behavior at the unit level.
"""
import unittest

from cli.parsers.ast.common import FileInspectionResult, TestFunctionMetrics, TestSuiteMetrics
from cli.parsers.coverage import CoverageReport, FileCoverage
from cli.parsers.coverage_contexts import CoverageContextReport
from cli.real_coverage import compute_real_coverage


def _fn(name, file="tests/test_mod.py", assertion_count=1, tautological_count=0, class_name=None, is_skipped=False, language="python"):
    return TestFunctionMetrics(
        name=name,
        file=file,
        lineno=1,
        language=language,
        assertion_count=assertion_count,
        tautological_count=tautological_count,
        is_empty_body=False,
        is_skipped=is_skipped,
        class_name=class_name,
    )


def _metrics(*functions, file="tests/test_mod.py"):
    return TestSuiteMetrics(files=[FileInspectionResult(path=file, language="python", test_functions=list(functions))])


def _coverage(files):
    return CoverageReport(overall_line_rate=0.0, overall_branch_rate=None, files=files)


def _contexts(files):
    return CoverageContextReport(available=True, files=files)


class ComputeRealCoverageOverallTests(unittest.TestCase):
    def test_line_covered_only_by_vanity_test_is_discounted(self):
        metrics = _metrics(_fn("test_vanity", assertion_count=0, tautological_count=1))
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1, 2: 1})})
        contexts = _contexts({"pkg/mod.py": {1: frozenset({"tests/test_mod.py::test_vanity"}), 2: frozenset()}})

        result = compute_real_coverage(test_suite_metrics=metrics, coverage=coverage, context_report=contexts)

        self.assertTrue(result.overall.available)
        self.assertEqual(result.overall.measured_line_rate, 1.0)
        self.assertEqual(result.overall.real_line_rate, 0.5)
        self.assertEqual(result.overall.vanity_only_lines, 1)
        self.assertEqual(result.overall.total_lines, 2)

    def test_line_covered_by_both_real_and_vanity_test_is_not_discounted(self):
        metrics = _metrics(
            _fn("test_real", assertion_count=1, tautological_count=0),
            _fn("test_vanity", assertion_count=0, tautological_count=1),
        )
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1})})
        contexts = _contexts(
            {"pkg/mod.py": {1: frozenset({"tests/test_mod.py::test_real", "tests/test_mod.py::test_vanity"})}}
        )

        result = compute_real_coverage(test_suite_metrics=metrics, coverage=coverage, context_report=contexts)

        self.assertEqual(result.overall.vanity_only_lines, 0)
        self.assertEqual(result.overall.real_line_rate, 1.0)

    def test_line_with_no_context_at_all_is_not_discounted(self):
        # No evidence it's vanity-only -- fail-safe toward "real".
        metrics = _metrics(_fn("test_vanity", assertion_count=0, tautological_count=1))
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1})})
        contexts = _contexts({"pkg/mod.py": {}})  # line 1 never mentioned

        result = compute_real_coverage(test_suite_metrics=metrics, coverage=coverage, context_report=contexts)

        self.assertEqual(result.overall.vanity_only_lines, 0)
        self.assertEqual(result.overall.real_line_rate, 1.0)

    def test_unhit_line_is_neither_measured_nor_vanity_covered(self):
        metrics = _metrics(_fn("test_real"))
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1, 2: 0})})
        contexts = _contexts({"pkg/mod.py": {1: frozenset({"tests/test_mod.py::test_real"})}})

        result = compute_real_coverage(test_suite_metrics=metrics, coverage=coverage, context_report=contexts)

        self.assertEqual(result.overall.total_lines, 2)
        self.assertEqual(result.overall.measured_covered_lines, 1)
        self.assertEqual(result.overall.measured_line_rate, 0.5)

    def test_class_name_distinguishes_vanity_method_from_same_named_real_one(self):
        # Two classes, each with a method named "test_it" -- only one is
        # vanity. Without class_name these would be indistinguishable.
        metrics = _metrics(
            _fn("test_it", class_name="RealTests", assertion_count=1, tautological_count=0),
            _fn("test_it", class_name="VanityTests", assertion_count=0, tautological_count=1),
        )
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1, 2: 1})})
        contexts = _contexts(
            {
                "pkg/mod.py": {
                    1: frozenset({"tests/test_mod.py::RealTests::test_it"}),
                    2: frozenset({"tests/test_mod.py::VanityTests::test_it"}),
                }
            }
        )

        result = compute_real_coverage(test_suite_metrics=metrics, coverage=coverage, context_report=contexts)

        self.assertEqual(result.overall.vanity_only_lines, 1)
        self.assertEqual(result.overall.real_line_rate, 0.5)

    def test_no_coverable_lines_is_unavailable(self):
        metrics = _metrics(_fn("test_real"))
        coverage = _coverage({})
        contexts = _contexts({})

        result = compute_real_coverage(test_suite_metrics=metrics, coverage=coverage, context_report=contexts)

        self.assertFalse(result.overall.available)

    def test_context_report_unavailable_makes_both_tracks_unavailable(self):
        metrics = _metrics(_fn("test_real"))
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1})})
        contexts = CoverageContextReport(available=False, reason="no --show-contexts")

        result = compute_real_coverage(test_suite_metrics=metrics, coverage=coverage, context_report=contexts)

        self.assertFalse(result.overall.available)
        self.assertFalse(result.patch.available)
        self.assertEqual(result.overall.reason, "no --show-contexts")

    def test_non_python_vanity_test_never_discounts_a_line(self):
        # A Go/Java/JS/TS vanity test can never appear in coverage.py's
        # context data -- this must be harmless, not misattributed.
        metrics = _metrics(_fn("TestVanity", file="mod_test.go", assertion_count=0, tautological_count=1, language="go"))
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1})})
        contexts = _contexts({"pkg/mod.py": {1: frozenset({"tests/test_mod.py::test_something_else"})}})

        result = compute_real_coverage(test_suite_metrics=metrics, coverage=coverage, context_report=contexts)

        self.assertEqual(result.overall.vanity_only_lines, 0)

    def test_suffix_matching_resolves_source_root_relative_context_path(self):
        # Coverage-context file key ("mod.py") vs the Cobertura report's
        # repo-root-relative key ("pkg/mod.py") -- same mismatch
        # cli.patch_coverage._lookup_file_coverage already handles.
        metrics = _metrics(_fn("test_vanity", assertion_count=0, tautological_count=1))
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1})})
        contexts = _contexts({"mod.py": {1: frozenset({"tests/test_mod.py::test_vanity"})}})

        result = compute_real_coverage(test_suite_metrics=metrics, coverage=coverage, context_report=contexts)

        self.assertEqual(result.overall.vanity_only_lines, 1)

    def test_skipped_test_function_never_counts_as_vanity_source(self):
        # A skipped test has assertion_count == 0 by construction but
        # must not be treated as "vanity" -- it never ran at all.
        metrics = _metrics(_fn("test_skipped", assertion_count=0, tautological_count=0, is_skipped=True))
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1})})
        contexts = _contexts({"pkg/mod.py": {1: frozenset({"tests/test_mod.py::test_skipped"})}})

        result = compute_real_coverage(test_suite_metrics=metrics, coverage=coverage, context_report=contexts)

        # test_skipped isn't in the vanity set at all, so this context
        # can't be resolved to a known vanity remainder -- not discounted.
        self.assertEqual(result.overall.vanity_only_lines, 0)


class ComputeRealCoveragePatchTests(unittest.TestCase):
    def test_patch_track_discounts_vanity_only_changed_line(self):
        metrics = _metrics(_fn("test_vanity", assertion_count=0, tautological_count=1))
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1, 2: 1, 3: 1})})
        contexts = _contexts(
            {"pkg/mod.py": {1: frozenset({"tests/test_mod.py::test_vanity"}), 2: frozenset(), 3: frozenset()}}
        )
        patch_modified_lines = {"pkg/mod.py": {1, 2}}  # line 3 changed-but-not-in-diff... actually not changed

        result = compute_real_coverage(
            test_suite_metrics=metrics,
            coverage=coverage,
            context_report=contexts,
            patch_modified_lines=patch_modified_lines,
        )

        self.assertTrue(result.patch.available)
        self.assertEqual(result.patch.total_lines, 2)
        self.assertEqual(result.patch.measured_line_rate, 1.0)
        self.assertEqual(result.patch.real_line_rate, 0.5)
        self.assertEqual(result.patch.vanity_only_lines, 1)
        # Overall (all 3 lines) is unaffected by the patch narrowing.
        self.assertEqual(result.overall.total_lines, 3)

    def test_patch_track_excludes_lines_outside_the_diff(self):
        metrics = _metrics(_fn("test_vanity", assertion_count=0, tautological_count=1))
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1, 2: 1})})
        contexts = _contexts({"pkg/mod.py": {1: frozenset(), 2: frozenset({"tests/test_mod.py::test_vanity"})}})
        # Only line 1 (the non-vanity-covered one) was actually changed.
        patch_modified_lines = {"pkg/mod.py": {1}}

        result = compute_real_coverage(
            test_suite_metrics=metrics,
            coverage=coverage,
            context_report=contexts,
            patch_modified_lines=patch_modified_lines,
        )

        self.assertEqual(result.patch.total_lines, 1)
        self.assertEqual(result.patch.vanity_only_lines, 0)
        self.assertEqual(result.patch.real_line_rate, 1.0)

    def test_no_patch_modified_lines_is_unavailable_but_overall_still_computed(self):
        metrics = _metrics(_fn("test_real"))
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1})})
        contexts = _contexts({"pkg/mod.py": {1: frozenset({"tests/test_mod.py::test_real"})}})

        result = compute_real_coverage(
            test_suite_metrics=metrics, coverage=coverage, context_report=contexts, patch_modified_lines=None
        )

        self.assertFalse(result.patch.available)
        self.assertTrue(result.overall.available)

    def test_empty_patch_modified_lines_dict_is_unavailable(self):
        metrics = _metrics(_fn("test_real"))
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1})})
        contexts = _contexts({"pkg/mod.py": {1: frozenset({"tests/test_mod.py::test_real"})}})

        result = compute_real_coverage(
            test_suite_metrics=metrics, coverage=coverage, context_report=contexts, patch_modified_lines={}
        )

        self.assertFalse(result.patch.available)

    def test_changed_line_not_registered_coverable_is_skipped(self):
        metrics = _metrics(_fn("test_real"))
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1})})
        contexts = _contexts({"pkg/mod.py": {1: frozenset({"tests/test_mod.py::test_real"})}})
        # Line 99 was changed but the coverage tool never registered it
        # as coverable (e.g. a comment/blank line) -- mirrors
        # cli.patch_coverage.compute_patch_coverage's own filtering.
        patch_modified_lines = {"pkg/mod.py": {1, 99}}

        result = compute_real_coverage(
            test_suite_metrics=metrics,
            coverage=coverage,
            context_report=contexts,
            patch_modified_lines=patch_modified_lines,
        )

        self.assertEqual(result.patch.total_lines, 1)


class AsDictTests(unittest.TestCase):
    def test_as_dict_shape(self):
        metrics = _metrics(_fn("test_real"))
        coverage = _coverage({"pkg/mod.py": FileCoverage(line_hits={1: 1})})
        contexts = _contexts({"pkg/mod.py": {1: frozenset({"tests/test_mod.py::test_real"})}})

        result = compute_real_coverage(test_suite_metrics=metrics, coverage=coverage, context_report=contexts)
        d = result.as_dict()

        self.assertIn("overall", d)
        self.assertIn("patch", d)
        for track in (d["overall"], d["patch"]):
            for key in (
                "available", "reason", "measured_line_rate", "real_line_rate",
                "total_lines", "measured_covered_lines", "vanity_only_lines",
            ):
                self.assertIn(key, track)


if __name__ == "__main__":
    unittest.main()
