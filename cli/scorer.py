"""
Deterministic Release Confidence Score (RCS) algorithm, v0.1.

Hardened against:
  - NaN/Inf arithmetic propagation
  - Skipped test denominator skew in test health calculation
  - Governance review state ambiguity
  - Unbounded coverage input rates
  - Gaming the score by omitting/breaking GITHUB_TOKEN: a branch_governance
    report that is missing or unavailable docks the *same* governance
    points as a confirmed unreviewed-bypass finding, so there is no score
    incentive to suppress branch governance data (only `degraded` differed
    before -- unverified governance now costs real points too)
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .parsers.github_rules import BranchGovernanceReport, bypass_permits_unreviewed_change
from .parsers.junit import TestTotals
from .parsers.sarif import SarifSummaryReport
from .patch_coverage import PatchCoverageResult

ALGORITHM_VERSION = "rcs-v0.1"

# Machine-readable causes of `RCSResult.degraded`, one entry per independent
# trigger that fired (a run can be degraded for more than one reason at
# once). `--disallow-degraded` (cli.verify) uses these to distinguish "the
# only reason this run is degraded is a known, unavoidable platform
# limitation" (branch_governance:<REASON_CODE_PLATFORM_UNSUPPORTED_TIER>,
# from cli.parsers.github_rules) from every other cause, which still blocks.
DEGRADED_REASON_PATCH_COVERAGE_UNAVAILABLE = "patch_coverage_unavailable"
DEGRADED_REASON_NO_PR_CONTEXT = "no_pr_context"
DEGRADED_REASON_SARIF_UNAVAILABLE = "sarif_unavailable"
DEGRADED_REASON_BRANCH_GOVERNANCE_UNVERIFIED = "branch_governance_unverified"
DEGRADED_REASON_BRANCH_GOVERNANCE_BYPASS = "branch_governance_bypass_permitted"

WEIGHTS = {
    "test_health": 0.35,
    "patch_coverage": 0.20,
    "overall_coverage": 0.15,
    "assertion_integrity": 0.10,
    "governance": 0.15,
    "static_analysis": 0.05,
}
assert math.isclose(sum(WEIGHTS.values()), 1.0, abs_tol=1e-9), "RCS weights must sum to 1.0"

PATCH_COVERAGE_MIN_DEFAULT = 0.80
OVERALL_COVERAGE_MIN_DEFAULT = 0.60
PATCH_COVERAGE_FALLBACK_MULTIPLIER = 0.70
FLAKY_RETRY_PENALTY_PER_CASE = 4.0
FLAKY_RETRY_PENALTY_CAP = 30.0
ASSERTION_DENSITY_TARGET = 1.5
BRANCH_GOVERNANCE_BYPASS_PENALTY = 35.0
# Applied when branch_governance couldn't be verified at all (missing/invalid
# token, API failure, ...). Kept >= BRANCH_GOVERNANCE_BYPASS_PENALTY so that
# omitting GITHUB_TOKEN is never a cheaper way to avoid the bypass penalty.
BRANCH_GOVERNANCE_UNVERIFIED_PENALTY = 35.0

# Differential static-analysis (SARIF) penalties. A finding "new in patch"
# (introduced or touched by this change) costs far more than a pre-existing
# baseline one -- the goal is to block *newly introduced* problems without
# making a legacy-heavy repo un-shippable on day one.
STATIC_ANALYSIS_PATCH_ERROR_PENALTY = 25.0
STATIC_ANALYSIS_PATCH_WARNING_PENALTY = 5.0
STATIC_ANALYSIS_LEGACY_ERROR_PENALTY = 2.0
STATIC_ANALYSIS_LEGACY_ERROR_PENALTY_CAP = 15.0
# Applied when --sarif was configured but the report came back unavailable
# (missing/corrupt file). Fails closed like BRANCH_GOVERNANCE_UNVERIFIED_PENALTY:
# a broken scanner input must never score better than a real, clean scan.
STATIC_ANALYSIS_UNAVAILABLE_PENALTY = 25.0


@dataclass
class ScoreComponent:
    __test__ = False
    weight: float
    raw_score: float
    weighted_score: float
    reason: str

    def as_dict(self) -> Dict:
        return {
            "weight": round(self.weight, 4),
            "raw_score": round(self.raw_score, 2),
            "weighted_score": round(self.weighted_score, 2),
            "reason": self.reason,
        }


@dataclass
class RCSResult:
    __test__ = False
    value: int
    algorithm_version: str
    components: Dict[str, ScoreComponent]
    degraded: bool
    # One entry per independent trigger that set `degraded=True` -- see the
    # DEGRADED_REASON_* / "branch_governance:<reason_code>" constants above.
    # Empty whenever degraded is False. Deliberately a flat list, not a
    # bool-per-cause mapping: order doesn't matter and duplicates can't
    # occur (each trigger appends at most once), so a list is the simplest
    # shape that round-trips cleanly through JSON.
    degraded_reasons: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict:
        return {
            "value": self.value,
            "algorithm_version": self.algorithm_version,
            "components": {k: v.as_dict() for k, v in self.components.items()},
            "degraded": self.degraded,
            "degraded_reasons": self.degraded_reasons,
        }


def _clamp(x: float, lo: float = 0.0, hi: float = 100.0) -> float:
    if math.isnan(x) or math.isinf(x):
        return lo
    return max(lo, min(hi, x))


def _score_test_health(totals: TestTotals) -> ScoreComponent:
    w = WEIGHTS["test_health"]

    executed_tests = totals.passed + totals.failed + totals.errored
    if executed_tests == 0:
        if totals.skipped > 0:
            return ScoreComponent(w, 0.0, 0.0, f"all {totals.skipped} test(s) were skipped (no executed tests)")
        return ScoreComponent(w, 0.0, 0.0, "zero tests executed (broken harness or bypassed gate)")

    pass_rate = totals.passed / executed_tests
    raw = pass_rate * 100.0

    flaky_penalty = min(totals.flaky_retries * FLAKY_RETRY_PENALTY_PER_CASE, FLAKY_RETRY_PENALTY_CAP)
    raw = _clamp(raw - flaky_penalty)

    reason = f"pass_rate={pass_rate:.3f} ({totals.passed}/{executed_tests} executed)"
    if totals.flaky_retries:
        reason += f", -{flaky_penalty:.1f}pts flaky-retry penalty ({totals.flaky_retries} case(s) retried)"
    if totals.skipped:
        reason += f", {totals.skipped} skipped"
    if totals.errored:
        reason += f", {totals.errored} errored"

    return ScoreComponent(w, raw, raw * w, reason)


def _score_patch_coverage(patch: PatchCoverageResult, patch_min: float) -> ScoreComponent:
    w = WEIGHTS["patch_coverage"]

    if not patch.available or patch.line_rate is None:
        return ScoreComponent(w, 0.0, 0.0, f"patch coverage unavailable: {patch.reason}")

    rate = _clamp(patch.line_rate, 0.0, 1.0)
    raw = rate * 100.0
    met = rate >= patch_min
    reason = (
        f"patch_line_rate={rate:.3f} "
        f"({patch.lines_covered}/{patch.lines_changed} changed lines), "
        f"threshold={patch_min:.2f} {'MET' if met else 'NOT MET'}"
    )
    return ScoreComponent(w, raw, raw * w, reason)


def _score_overall_coverage(overall_line_rate: float, overall_min: float) -> ScoreComponent:
    w = WEIGHTS["overall_coverage"]
    rate = _clamp(overall_line_rate, 0.0, 1.0)
    raw = rate * 100.0
    met = rate >= overall_min
    reason = f"overall_line_rate={rate:.3f}, threshold={overall_min:.2f} {'MET' if met else 'NOT MET'}"
    return ScoreComponent(w, raw, raw * w, reason)


def _score_assertion_integrity(
    total_assertions: int, total_test_functions: int, ast_skipped_test_functions: int = 0
) -> ScoreComponent:
    w = WEIGHTS["assertion_integrity"]

    if total_test_functions <= 0 or total_assertions < 0:
        if total_test_functions <= 0 and ast_skipped_test_functions > 0:
            # Distinct from "genuinely no tests": the suite has
            # ast_skipped_test_functions test(s), all of them
            # skipped/disabled -- an auditor reading the signed reason
            # string should see that, not a claim that no tests exist.
            reason = (
                f"no non-skipped test functions to compute assertion density from "
                f"({ast_skipped_test_functions} skipped/disabled)"
            )
        else:
            reason = "no test functions to compute assertion density from"
        return ScoreComponent(w, 0.0, 0.0, reason)

    density = total_assertions / total_test_functions
    raw = _clamp((density / ASSERTION_DENSITY_TARGET) * 100.0)
    reason = f"density={density:.2f} assertions/test (target={ASSERTION_DENSITY_TARGET})"
    return ScoreComponent(w, raw, raw * w, reason)


def _score_governance(
    pr_present: bool,
    approvers_count: int,
    required_approvals: int,
    review_state: str,
    branch_governance: Optional[BranchGovernanceReport] = None,
) -> ScoreComponent:
    w = WEIGHTS["governance"]

    if not pr_present:
        raw, reason = 50.0, "no pull/merge request context on this run (governance not evaluated)"
    elif review_state == "changes_requested":
        raw, reason = 0.0, "changes requested and not re-approved"
    elif required_approvals == 0:
        raw = 60.0
        reason = "branch protection requires 0 approvals (weak governance control)"
    else:
        if review_state != "approved" and approvers_count > 0:
            ratio = min(approvers_count / required_approvals, 1.0) * 0.5  # Penalize non-approved PR state
            reason = f"{approvers_count}/{required_approvals} approvals present, but PR review state is '{review_state}'"
        else:
            ratio = min(approvers_count / required_approvals, 1.0)
            reason = f"{approvers_count}/{required_approvals} required approvals ({review_state})"
        raw = ratio * 100.0

    # A clean PR review record on *this* run doesn't matter if the target
    # branch's rules would have let the same change land unreviewed (no PR
    # required, direct pushes not blocked, or a bypass actor/role exists) --
    # dock the governance score whenever that's independently confirmed.
    # Equally, an *unverified* branch_governance report (missing/invalid
    # token, API failure) must dock the same points -- fail closed, so
    # there's no way to score higher by simply not providing GITHUB_TOKEN
    # than by having a confirmed bypass.
    if branch_governance is None or not branch_governance.available:
        raw = _clamp(raw - BRANCH_GOVERNANCE_UNVERIFIED_PENALTY)
        detail = branch_governance.reason if branch_governance is not None else "branch governance was not evaluated for this run"
        reason += f"; -{BRANCH_GOVERNANCE_UNVERIFIED_PENALTY:.0f}pts unverified branch governance penalty: {detail}"
    elif bypass_permits_unreviewed_change(branch_governance):
        raw = _clamp(raw - BRANCH_GOVERNANCE_BYPASS_PENALTY)
        bg_detail = "; ".join(branch_governance.warnings) or f"unreviewed bypass permitted on '{branch_governance.branch}'"
        reason += f"; -{BRANCH_GOVERNANCE_BYPASS_PENALTY:.0f}pts branch governance penalty: {bg_detail}"

    return ScoreComponent(w, raw, raw * w, reason)


def _score_sarif_findings(sarif_report: Optional[SarifSummaryReport]) -> ScoreComponent:
    w = WEIGHTS["static_analysis"]

    if sarif_report is None:
        # Static analysis was never wired into this run at all (no --sarif
        # flags configured) -- score the full baseline with nothing to
        # dock, the same way branch_governance's pr_present=False "not
        # evaluated" case doesn't get penalized for a control that was
        # never asked to run. This is intentionally indistinguishable from
        # an explicit, genuinely clean SarifSummaryReport(available=True,
        # findings=[]) below.
        return ScoreComponent(w, 100.0, 100.0 * w, "no --sarif reports configured for this run")

    if not sarif_report.available:
        # Configured but the report came back broken (missing/corrupt
        # file(s)) -- fail closed, dock real points. score_pipeline flags
        # the whole run degraded for this case (see below).
        detail = "; ".join(sarif_report.reasons) or "SARIF report unavailable"
        raw = _clamp(100.0 - STATIC_ANALYSIS_UNAVAILABLE_PENALTY)
        reason = (
            f"static analysis (SARIF) unavailable: {detail}; "
            f"-{STATIC_ANALYSIS_UNAVAILABLE_PENALTY:.0f}pts unavailable-scan penalty"
        )
        return ScoreComponent(w, raw, raw * w, reason)

    patch_errors = sarif_report.patch_errors_count
    patch_warnings = sarif_report.patch_warnings_count
    legacy_errors = max(sarif_report.errors_count - sarif_report.patch_errors_count, 0)

    penalty = patch_errors * STATIC_ANALYSIS_PATCH_ERROR_PENALTY
    penalty += patch_warnings * STATIC_ANALYSIS_PATCH_WARNING_PENALTY
    penalty += min(legacy_errors * STATIC_ANALYSIS_LEGACY_ERROR_PENALTY, STATIC_ANALYSIS_LEGACY_ERROR_PENALTY_CAP)

    raw = _clamp(100.0 - penalty)
    reason = (
        f"{sarif_report.total_findings} finding(s) across {len(sarif_report.tools_scanned)} tool(s) "
        f"({patch_errors} new patch error(s), {patch_warnings} new patch warning(s), "
        f"{legacy_errors} legacy error(s)); -{penalty:.1f}pts"
    )
    return ScoreComponent(w, raw, raw * w, reason)


def score_pipeline(
    *,
    test_totals: TestTotals,
    patch_coverage: PatchCoverageResult,
    overall_line_rate: float,
    total_assertions: int,
    total_test_functions: int,
    pr_present: bool,
    approvers_count: int = 0,
    required_approvals: int = 0,
    review_state: str = "not_applicable",
    patch_coverage_min: float = PATCH_COVERAGE_MIN_DEFAULT,
    overall_coverage_min: float = OVERALL_COVERAGE_MIN_DEFAULT,
    branch_governance: Optional[BranchGovernanceReport] = None,
    sarif_report: Optional[SarifSummaryReport] = None,
    ast_skipped_test_functions: int = 0,
) -> RCSResult:
    degraded = False
    degraded_reasons: List[str] = []

    test_health = _score_test_health(test_totals)

    patch_component = _score_patch_coverage(patch_coverage, patch_coverage_min)
    if not patch_coverage.available or patch_coverage.line_rate is None:
        clean_overall = _clamp(overall_line_rate, 0.0, 1.0)
        proxy_raw = _clamp(clean_overall * 100.0 * PATCH_COVERAGE_FALLBACK_MULTIPLIER)
        patch_component = ScoreComponent(
            WEIGHTS["patch_coverage"],
            proxy_raw,
            proxy_raw * WEIGHTS["patch_coverage"],
            f"{patch_component.reason}; fell back to overall_coverage*{PATCH_COVERAGE_FALLBACK_MULTIPLIER} proxy",
        )
        degraded = True
        # Namespaced with the specific reason_code when known (e.g.
        # REASON_CODE_NO_COVERABLE_LINES for a docs/config-only diff --
        # see cli.patch_coverage), mirroring how branch_governance's
        # reason_code is namespaced below; falls back to the generic
        # reason for a genuinely unverifiable patch coverage (missing
        # base SHA, failed git diff).
        if patch_coverage.reason_code:
            degraded_reasons.append(f"patch_coverage:{patch_coverage.reason_code}")
        else:
            degraded_reasons.append(DEGRADED_REASON_PATCH_COVERAGE_UNAVAILABLE)

    overall_component = _score_overall_coverage(overall_line_rate, overall_coverage_min)
    assertion_component = _score_assertion_integrity(
        total_assertions, total_test_functions, ast_skipped_test_functions
    )
    governance_component = _score_governance(
        pr_present, approvers_count, required_approvals, review_state, branch_governance
    )
    static_analysis_component = _score_sarif_findings(sarif_report)

    if not pr_present:
        degraded = True
        degraded_reasons.append(DEGRADED_REASON_NO_PR_CONTEXT)

    if sarif_report is not None and not sarif_report.available:
        degraded = True
        degraded_reasons.append(DEGRADED_REASON_SARIF_UNAVAILABLE)

    # branch_governance is a distinct, independently-fetched signal (repo
    # ruleset/API state) from the per-PR approvals above -- either it
    # couldn't be verified at all, or it was verified and shows unreviewed
    # bypasses are permitted. Both are reasons to flag the run degraded,
    # not just to dock the governance component's raw score.
    if branch_governance is None or not branch_governance.available:
        degraded = True
        # A specific, known reason_code (see cli.parsers.github_rules,
        # e.g. REASON_CODE_PLATFORM_UNSUPPORTED_TIER) is namespaced so
        # --disallow-degraded can recognize *why* branch governance is
        # unverified, not just that it is; anything else (missing token,
        # network failure, a merely under-scoped token, ...) falls back to
        # the generic "unverified" reason, which still blocks the gate.
        if branch_governance is not None and branch_governance.reason_code:
            degraded_reasons.append(f"branch_governance:{branch_governance.reason_code}")
        else:
            degraded_reasons.append(DEGRADED_REASON_BRANCH_GOVERNANCE_UNVERIFIED)
    elif bypass_permits_unreviewed_change(branch_governance):
        degraded = True
        degraded_reasons.append(DEGRADED_REASON_BRANCH_GOVERNANCE_BYPASS)

    components = {
        "test_health": test_health,
        "patch_coverage": patch_component,
        "overall_coverage": overall_component,
        "assertion_integrity": assertion_component,
        "governance": governance_component,
        "static_analysis": static_analysis_component,
    }

    total_weighted = sum(c.weighted_score for c in components.values())
    value = int(round(_clamp(total_weighted)))

    return RCSResult(
        value=value,
        algorithm_version=ALGORITHM_VERSION,
        components=components,
        degraded=degraded,
        degraded_reasons=degraded_reasons,
    )
