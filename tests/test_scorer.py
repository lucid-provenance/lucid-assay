import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.parsers.junit import TestTotals
from cli.patch_coverage import PatchCoverageResult
from cli.scorer import score_pipeline, WEIGHTS


def _base_kwargs(**overrides):
    kwargs = dict(
        test_totals=TestTotals(tests=100, passed=100, failed=0, errored=0, skipped=0, duration_ms=1000, flaky_retries=0),
        patch_coverage=PatchCoverageResult(available=True, line_rate=0.95, lines_changed=40, lines_covered=38, reason="ok"),
        overall_line_rate=0.85,
        total_assertions=200,
        total_test_functions=100,
        pr_present=True,
        approvers_count=2,
        required_approvals=2,
        review_state="approved",
    )
    kwargs.update(overrides)
    return kwargs


class RCSScorerTests(unittest.TestCase):

    def test_weights_sum_to_one(self):
        self.assertAlmostEqual(sum(WEIGHTS.values()), 1.0, places=9)

    def test_perfect_run_scores_high(self):
        result = score_pipeline(**_base_kwargs())
        self.assertGreaterEqual(result.value, 90)
        self.assertFalse(result.degraded)

    def test_zero_tests_executed_floors_test_health(self):
        result = score_pipeline(**_base_kwargs(
            test_totals=TestTotals(tests=0, passed=0, failed=0, errored=0, skipped=0, duration_ms=0),
        ))
        self.assertEqual(result.components["test_health"].raw_score, 0.0)
        self.assertIn("zero tests executed", result.components["test_health"].reason)
        # Zero tests should meaningfully drag the overall score down, not
        # just quietly zero one component while everything else compensates.
        self.assertLess(result.value, 70)

    def test_missing_patch_coverage_falls_back_and_flags_degraded(self):
        result = score_pipeline(**_base_kwargs(
            patch_coverage=PatchCoverageResult(available=False, line_rate=None, lines_changed=0, lines_covered=0,
                                                 reason="no base_commit_sha available"),
        ))
        self.assertTrue(result.degraded)
        self.assertIn("fell back to overall_coverage", result.components["patch_coverage"].reason)
        # Fallback proxy must never outscore an equivalent *real* patch measurement.
        real = score_pipeline(**_base_kwargs())
        self.assertLess(result.components["patch_coverage"].raw_score, real.components["patch_coverage"].raw_score)

    def test_docs_only_change_no_coverable_lines_does_not_zero_the_run(self):
        result = score_pipeline(**_base_kwargs(
            patch_coverage=PatchCoverageResult(available=False, line_rate=None, lines_changed=0, lines_covered=0,
                                                 reason="diff contained no coverable changed lines"),
        ))
        self.assertGreater(result.value, 0)
        self.assertTrue(result.degraded)

    def test_flaky_retries_penalize_but_do_not_dominate(self):
        clean = score_pipeline(**_base_kwargs())
        flaky = score_pipeline(**_base_kwargs(
            test_totals=TestTotals(tests=100, passed=100, failed=0, errored=0, skipped=0, duration_ms=1000, flaky_retries=5),
        ))
        self.assertLess(flaky.components["test_health"].raw_score, clean.components["test_health"].raw_score)
        self.assertGreaterEqual(flaky.components["test_health"].raw_score, 100 - 30)  # capped penalty

    def test_changes_requested_zeroes_governance(self):
        result = score_pipeline(**_base_kwargs(review_state="changes_requested", approvers_count=0))
        self.assertEqual(result.components["governance"].raw_score, 0.0)

    def test_no_pr_context_is_neutral_not_full_credit(self):
        result = score_pipeline(**_base_kwargs(pr_present=False, approvers_count=0, required_approvals=0, review_state="not_applicable"))
        self.assertEqual(result.components["governance"].raw_score, 50.0)
        self.assertTrue(result.degraded)

    def test_zero_test_functions_floors_assertion_integrity(self):
        result = score_pipeline(**_base_kwargs(total_assertions=0, total_test_functions=0))
        self.assertEqual(result.components["assertion_integrity"].raw_score, 0.0)

    def test_score_is_deterministic_and_bounded(self):
        r1 = score_pipeline(**_base_kwargs())
        r2 = score_pipeline(**_base_kwargs())
        self.assertEqual(r1.value, r2.value)
        self.assertGreaterEqual(r1.value, 0)
        self.assertLessEqual(r1.value, 100)

    def test_failing_tests_and_low_coverage_score_low(self):
        result = score_pipeline(**_base_kwargs(
            test_totals=TestTotals(tests=100, passed=40, failed=60, errored=0, skipped=0, duration_ms=1000),
            patch_coverage=PatchCoverageResult(available=True, line_rate=0.10, lines_changed=40, lines_covered=4, reason="ok"),
            overall_line_rate=0.20,
            review_state="pending",
            approvers_count=0,
        ))
        self.assertLess(result.value, 35)


if __name__ == "__main__":
    unittest.main()
