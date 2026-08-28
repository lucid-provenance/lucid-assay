import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.parsers.github_rules import BranchGovernanceReport, REASON_CODE_PLATFORM_UNSUPPORTED_TIER
from cli.parsers.junit import TestTotals
from cli.parsers.sarif import SarifSummaryReport
from cli.patch_coverage import PatchCoverageResult, REASON_CODE_NO_COVERABLE_LINES
from cli.scorer import (
    score_pipeline,
    WEIGHTS,
    BRANCH_GOVERNANCE_BYPASS_PENALTY,
    BRANCH_GOVERNANCE_UNVERIFIED_PENALTY,
    DEGRADED_REASON_BRANCH_GOVERNANCE_BYPASS,
    DEGRADED_REASON_BRANCH_GOVERNANCE_UNVERIFIED,
    DEGRADED_REASON_NO_PR_CONTEXT,
    DEGRADED_REASON_PATCH_COVERAGE_UNAVAILABLE,
    DEGRADED_REASON_SARIF_UNAVAILABLE,
)


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


class DegradedReasonsTests(unittest.TestCase):
    """Coverage for RCSResult.degraded_reasons: cli.verify's
    --disallow-degraded gate relies on this being an accurate, complete
    list of *why* a run is degraded (not just that it is), so each
    independent trigger must append its own distinct reason -- and only
    that reason, not a generic catch-all."""

    def test_clean_run_has_no_degraded_reasons(self):
        result = score_pipeline(**_base_kwargs())
        self.assertFalse(result.degraded)
        self.assertEqual(result.degraded_reasons, [])

    def test_missing_patch_coverage_reason(self):
        result = score_pipeline(**_base_kwargs(
            patch_coverage=PatchCoverageResult(
                available=False, line_rate=None, lines_changed=0, lines_covered=0, reason="no base_commit_sha"
            ),
        ))
        self.assertEqual(result.degraded_reasons, [DEGRADED_REASON_PATCH_COVERAGE_UNAVAILABLE])

    def test_docs_only_diff_reason_code_is_namespaced(self):
        # This is the exact string cli.verify's --disallow-degraded gate
        # allowlists -- if this namespacing ever changes, that gate's
        # allowed-reasons set must be updated to match.
        result = score_pipeline(**_base_kwargs(
            patch_coverage=PatchCoverageResult(
                available=False, line_rate=None, lines_changed=0, lines_covered=0,
                reason="diff contained no coverable changed lines (docs/config-only change)",
                reason_code=REASON_CODE_NO_COVERABLE_LINES,
            ),
        ))
        self.assertEqual(result.degraded_reasons, ["patch_coverage:no_coverable_lines"])

    def test_no_pr_context_reason(self):
        result = score_pipeline(**_base_kwargs(pr_present=False, branch_governance=_clean_branch_governance()))
        self.assertEqual(result.degraded_reasons, [DEGRADED_REASON_NO_PR_CONTEXT])

    def test_sarif_unavailable_reason(self):
        result = score_pipeline(**_base_kwargs(
            sarif_report=SarifSummaryReport(available=False, reasons=["SARIF file not found: x.json"]),
        ))
        self.assertEqual(result.degraded_reasons, [DEGRADED_REASON_SARIF_UNAVAILABLE])

    def test_static_analysis_not_available_when_sarif_never_configured(self):
        # sarif_report defaults to None in _base_kwargs -- no --sarif flags
        # at all, distinct from "configured but broken" below. raw_score
        # still carries the scoring policy's no-penalty baseline, but
        # available=False so a consumer never reads that 100 as a real,
        # clean scan result.
        result = score_pipeline(**_base_kwargs())
        component = result.components["static_analysis"]
        self.assertFalse(component.available)
        self.assertEqual(component.raw_score, 100.0)

    def test_static_analysis_not_available_when_sarif_configured_but_broken(self):
        result = score_pipeline(**_base_kwargs(
            sarif_report=SarifSummaryReport(available=False, reasons=["SARIF file not found: x.json"]),
        ))
        self.assertFalse(result.components["static_analysis"].available)

    def test_static_analysis_available_on_a_genuine_clean_scan(self):
        result = score_pipeline(**_base_kwargs(
            sarif_report=SarifSummaryReport(available=True, total_findings=0, tools_scanned=["semgrep"]),
        ))
        self.assertTrue(result.components["static_analysis"].available)

    def test_missing_branch_governance_reason(self):
        result = score_pipeline(**_base_kwargs(branch_governance=None))
        self.assertEqual(result.degraded_reasons, [DEGRADED_REASON_BRANCH_GOVERNANCE_UNVERIFIED])

    def test_branch_governance_unavailable_without_reason_code_uses_generic_reason(self):
        result = score_pipeline(**_base_kwargs(
            branch_governance=BranchGovernanceReport(
                available=False, branch="main", pull_request_required=False, approvals_required=0,
                direct_push_prevented=False, bypass_actors_count=0, admin_enforced=False,
                warnings=[], reason="no GITHUB_TOKEN available", reason_code=None,
            ),
        ))
        self.assertEqual(result.degraded_reasons, [DEGRADED_REASON_BRANCH_GOVERNANCE_UNVERIFIED])

    def test_branch_governance_unavailable_with_platform_reason_code_is_namespaced(self):
        # This is the exact string cli.verify's --disallow-degraded gate
        # matches against -- if this namespacing ever changes, that gate's
        # allowlisted constant must be updated to match (see its comment).
        result = score_pipeline(**_base_kwargs(
            branch_governance=BranchGovernanceReport(
                available=False, branch="main", pull_request_required=False, approvals_required=0,
                direct_push_prevented=False, bypass_actors_count=0, admin_enforced=False,
                warnings=[], reason="Upgrade to GitHub Pro or make this repository public to enable this feature.",
                reason_code=REASON_CODE_PLATFORM_UNSUPPORTED_TIER,
            ),
        ))
        self.assertEqual(result.degraded_reasons, ["branch_governance:platform_unsupported_tier"])

    def test_branch_governance_bypass_reason(self):
        result = score_pipeline(**_base_kwargs(
            branch_governance=_clean_branch_governance(
                bypass_actors_count=1, admin_enforced=False,
                warnings=["1 bypass actor(s) can bypass branch rules entirely (bypass_mode=always)"],
            ),
        ))
        self.assertEqual(result.degraded_reasons, [DEGRADED_REASON_BRANCH_GOVERNANCE_BYPASS])

    def test_multiple_simultaneous_causes_all_appear(self):
        result = score_pipeline(**_base_kwargs(
            pr_present=False,
            patch_coverage=PatchCoverageResult(
                available=False, line_rate=None, lines_changed=0, lines_covered=0, reason="no base_commit_sha"
            ),
            branch_governance=None,
        ))
        self.assertEqual(
            set(result.degraded_reasons),
            {
                DEGRADED_REASON_PATCH_COVERAGE_UNAVAILABLE,
                DEGRADED_REASON_NO_PR_CONTEXT,
                DEGRADED_REASON_BRANCH_GOVERNANCE_UNVERIFIED,
            },
        )


if __name__ == "__main__":
    unittest.main()
