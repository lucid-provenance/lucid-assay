import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.parsers.github_rules import BranchGovernanceReport
from cli.parsers.junit import TestTotals
from cli.patch_coverage import PatchCoverageResult
from cli.scorer import score_pipeline, WEIGHTS, BRANCH_GOVERNANCE_BYPASS_PENALTY, BRANCH_GOVERNANCE_UNVERIFIED_PENALTY


def _clean_branch_governance(**overrides) -> BranchGovernanceReport:
    kwargs = dict(
        available=True,
        branch="main",
        pull_request_required=True,
        approvals_required=2,
        direct_push_prevented=True,
        bypass_actors_count=0,
        admin_enforced=True,
        warnings=[],
        reason="queried GitHub rules for example/app@main: 1 applicable rule(s), 0 bypass actor(s)",
    )
    kwargs.update(overrides)
    return BranchGovernanceReport(**kwargs)


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
        branch_governance=_clean_branch_governance(),
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

    def test_clean_branch_governance_does_not_penalize(self):
        result = score_pipeline(**_base_kwargs())
        self.assertNotIn("branch governance penalty", result.components["governance"].reason)
        self.assertFalse(result.degraded)

    def test_missing_branch_governance_flags_degraded_and_penalizes_score(self):
        # Fail closed: omitting branch_governance entirely (never fetched)
        # must cost real points, the same as a confirmed bypass would --
        # otherwise omitting GITHUB_TOKEN is a free way to dodge the penalty.
        with_bg = score_pipeline(**_base_kwargs())
        without_bg = score_pipeline(**_base_kwargs(branch_governance=None))
        self.assertTrue(without_bg.degraded)
        self.assertLess(
            without_bg.components["governance"].raw_score, with_bg.components["governance"].raw_score
        )
        self.assertIn("unverified branch governance penalty", without_bg.components["governance"].reason)

    def test_branch_governance_unavailable_flags_degraded_and_penalizes_score(self):
        clean = score_pipeline(**_base_kwargs())
        result = score_pipeline(**_base_kwargs(
            branch_governance=BranchGovernanceReport(
                available=False, branch="main", pull_request_required=False, approvals_required=0,
                direct_push_prevented=False, bypass_actors_count=0, admin_enforced=False,
                warnings=[], reason="no GITHUB_TOKEN available",
            ),
        ))
        self.assertTrue(result.degraded)
        self.assertIn("unverified branch governance penalty", result.components["governance"].reason)
        # Omitting/breaking GITHUB_TOKEN must not score any better than a
        # confirmed bypass -- both penalties are equal by design.
        self.assertAlmostEqual(
            result.components["governance"].raw_score,
            clean.components["governance"].raw_score - BRANCH_GOVERNANCE_UNVERIFIED_PENALTY,
            places=6,
        )

    def test_branch_governance_bypass_penalizes_governance_and_flags_degraded(self):
        clean = score_pipeline(**_base_kwargs())
        bypassable = score_pipeline(**_base_kwargs(
            branch_governance=_clean_branch_governance(
                bypass_actors_count=1,
                admin_enforced=False,
                warnings=["1 bypass actor(s) can bypass branch rules entirely (bypass_mode=always)"],
            ),
        ))
        self.assertTrue(bypassable.degraded)
        self.assertIn("branch governance penalty", bypassable.components["governance"].reason)
        self.assertAlmostEqual(
            bypassable.components["governance"].raw_score,
            clean.components["governance"].raw_score - BRANCH_GOVERNANCE_BYPASS_PENALTY,
            places=6,
        )

    def test_branch_governance_no_pr_required_penalizes_governance(self):
        result = score_pipeline(**_base_kwargs(
            branch_governance=_clean_branch_governance(
                pull_request_required=False, approvals_required=0, direct_push_prevented=False,
                warnings=["branch 'main' does not require a pull request"],
            ),
        ))
        self.assertTrue(result.degraded)
        self.assertIn("branch governance penalty", result.components["governance"].reason)


if __name__ == "__main__":
    unittest.main()
