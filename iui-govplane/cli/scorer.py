"""
Deterministic Release Confidence Score (RCS) algorithm, v0.1.

Hardened against:
  - NaN/Inf arithmetic propagation
  - Skipped test denominator skew in test health calculation
  - Governance review state ambiguity
  - Unbounded coverage input rates
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Optional

from .parsers.junit import TestTotals
from .patch_coverage import PatchCoverageResult

ALGORITHM_VERSION = "rcs-v0.1"

WEIGHTS = {
    "test_health": 0.35,
    "patch_coverage": 0.25,
    "overall_coverage": 0.15,
    "assertion_integrity": 0.10,
    "governance": 0.15,
}
assert math.isclose(sum(WEIGHTS.values()), 1.0, abs_tol=1e-9), "RCS weights must sum to 1.0"

PATCH_COVERAGE_MIN_DEFAULT = 0.80
OVERALL_COVERAGE_MIN_DEFAULT = 0.60
PATCH_COVERAGE_FALLBACK_MULTIPLIER = 0.70
FLAKY_RETRY_PENALTY_PER_CASE = 4.0
FLAKY_RETRY_PENALTY_CAP = 30.0
ASSERTION_DENSITY_TARGET = 1.5


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

    def as_dict(self) -> Dict:
        return {
            "value": self.value,
            "algorithm_version": self.algorithm_version,
            "components": {k: v.as_dict() for k, v in self.components.items()},
            "degraded": self.degraded,
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


def _score_assertion_integrity(total_assertions: int, total_test_functions: int) -> ScoreComponent:
    w = WEIGHTS["assertion_integrity"]

    if total_test_functions <= 0 or total_assertions < 0:
        return ScoreComponent(w, 0.0, 0.0, "no test functions to compute assertion density from")

    density = total_assertions / total_test_functions
    raw = _clamp((density / ASSERTION_DENSITY_TARGET) * 100.0)
    reason = f"density={density:.2f} assertions/test (target={ASSERTION_DENSITY_TARGET})"
    return ScoreComponent(w, raw, raw * w, reason)


def _score_governance(
    pr_present: bool,
    approvers_count: int,
    required_approvals: int,
    review_state: str,
) -> ScoreComponent:
    w = WEIGHTS["governance"]

    if not pr_present:
        return ScoreComponent(w, 50.0, 50.0 * w, "no pull/merge request context on this run (governance not evaluated)")

    if review_state == "changes_requested":
        return ScoreComponent(w, 0.0, 0.0, "changes requested and not re-approved")

    if required_approvals == 0:
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
) -> RCSResult:
    degraded = False

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

    overall_component = _score_overall_coverage(overall_line_rate, overall_coverage_min)
    assertion_component = _score_assertion_integrity(total_assertions, total_test_functions)
    governance_component = _score_governance(pr_present, approvers_count, required_approvals, review_state)

    if not pr_present:
        degraded = True

    components = {
        "test_health": test_health,
        "patch_coverage": patch_component,
        "overall_coverage": overall_component,
        "assertion_integrity": assertion_component,
        "governance": governance_component,
    }

    total_weighted = sum(c.weighted_score for c in components.values())
    value = int(round(_clamp(total_weighted)))

    return RCSResult(value=value, algorithm_version=ALGORITHM_VERSION, components=components, degraded=degraded)
