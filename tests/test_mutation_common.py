"""Direct unit tests for cli/mutation/common.py's shared factory
functions and tier-grading logic -- previously only exercised
incidentally (test_mutation.py's SkippedReportTests checks a handful of
fields on skipped_report() alone). Every field on every report factory,
and every branch/boundary of grade_from_score()/discount_reason(), is
pinned exactly here."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.mutation.common import (
    MULTIPLIER_DEGRADED,
    MULTIPLIER_FAILED,
    MULTIPLIER_NOT_APPLICABLE,
    MULTIPLIER_PASSED,
    MULTIPLIER_UNAVAILABLE,
    MUTATION_SCORE_DEGRADED_THRESHOLD,
    MUTATION_SCORE_PASS_THRESHOLD,
    REASON_CODE_DECORATIVE,
    REASON_CODE_NO_SOURCE_CHANGES,
    REASON_CODE_SKIPPED,
    REASON_CODE_UNAVAILABLE,
    REASON_CODE_WEAK,
    discount_reason,
    grade_from_score,
    not_applicable_report,
    skipped_report,
    unavailable_report,
)


class NotApplicableReportTests(unittest.TestCase):

    def test_default_fields_are_exact(self):
        report = not_applicable_report("no source changed")
        self.assertIs(report.available, False)
        self.assertEqual(report.grade, "not_applicable")
        self.assertEqual(report.multiplier, MULTIPLIER_NOT_APPLICABLE)
        self.assertEqual(report.multiplier, 1.0)
        self.assertIsNone(report.mutation_score)
        self.assertEqual(report.killed, 0)
        self.assertEqual(report.survived, 0)
        self.assertEqual(report.timeout, 0)
        self.assertEqual(report.total_generated, 0)
        self.assertEqual(report.reason, "no source changed")
        self.assertEqual(report.reason_code, REASON_CODE_NO_SOURCE_CHANGES)

    def test_reason_code_override_is_honored(self):
        report = not_applicable_report("no coverable lines", reason_code="custom_code")
        self.assertEqual(report.reason_code, "custom_code")


class UnavailableReportTests(unittest.TestCase):

    def test_default_fields_are_exact(self):
        report = unavailable_report("tool crashed")
        self.assertIs(report.available, False)
        self.assertEqual(report.grade, "degraded")
        self.assertEqual(report.multiplier, MULTIPLIER_UNAVAILABLE)
        self.assertEqual(report.multiplier, 0.85)
        self.assertIsNone(report.mutation_score)
        self.assertEqual(report.killed, 0)
        self.assertEqual(report.survived, 0)
        self.assertEqual(report.timeout, 0)
        self.assertEqual(report.total_generated, 0)
        self.assertEqual(report.reason, "tool crashed")
        self.assertEqual(report.reason_code, REASON_CODE_UNAVAILABLE)

    def test_reason_code_override_is_honored(self):
        report = unavailable_report("skipped", reason_code="custom_code")
        self.assertEqual(report.reason_code, "custom_code")

    def test_unavailable_multiplier_is_never_full_credit(self):
        self.assertLess(unavailable_report("x").multiplier, MULTIPLIER_PASSED)


class SkippedReportTests(unittest.TestCase):

    def test_default_reason_text_is_exact(self):
        report = skipped_report()
        self.assertEqual(report.reason, "mutation testing skipped via --skip-mutation-testing")

    def test_custom_reason_is_passed_through(self):
        report = skipped_report("custom skip reason")
        self.assertEqual(report.reason, "custom skip reason")

    def test_delegates_to_unavailable_report_with_the_skipped_reason_code(self):
        report = skipped_report()
        self.assertEqual(report.reason_code, REASON_CODE_SKIPPED)
        self.assertEqual(report.grade, "degraded")
        self.assertEqual(report.multiplier, MULTIPLIER_UNAVAILABLE)
        self.assertFalse(report.available)


class GradeFromScoreTests(unittest.TestCase):

    def test_exactly_at_pass_threshold_is_passed(self):
        # Pins `>=` (not `>`) at the pass boundary.
        grade, multiplier, reason_code = grade_from_score(MUTATION_SCORE_PASS_THRESHOLD)
        self.assertEqual((grade, multiplier, reason_code), ("passed", MULTIPLIER_PASSED, None))

    def test_just_below_pass_threshold_is_degraded(self):
        grade, multiplier, reason_code = grade_from_score(MUTATION_SCORE_PASS_THRESHOLD - 0.1)
        self.assertEqual((grade, multiplier, reason_code), ("degraded", MULTIPLIER_DEGRADED, REASON_CODE_WEAK))

    def test_exactly_at_degraded_threshold_is_degraded(self):
        # Pins `>=` (not `>`) at the degraded boundary.
        grade, multiplier, reason_code = grade_from_score(MUTATION_SCORE_DEGRADED_THRESHOLD)
        self.assertEqual((grade, multiplier, reason_code), ("degraded", MULTIPLIER_DEGRADED, REASON_CODE_WEAK))

    def test_just_below_degraded_threshold_is_failed(self):
        grade, multiplier, reason_code = grade_from_score(MUTATION_SCORE_DEGRADED_THRESHOLD - 0.1)
        self.assertEqual((grade, multiplier, reason_code), ("failed", MULTIPLIER_FAILED, REASON_CODE_DECORATIVE))

    def test_perfect_score_is_passed(self):
        self.assertEqual(grade_from_score(100.0)[0], "passed")

    def test_zero_score_is_failed(self):
        self.assertEqual(grade_from_score(0.0)[0], "failed")


class DiscountReasonTests(unittest.TestCase):

    def test_passed_reason_is_exact(self):
        text = discount_reason("passed", MULTIPLIER_PASSED, 92.4, survived=1, tested=13)
        self.assertEqual(text, "no discount -- 92% mutation kill rate (13 mutant(s) tested)")

    def test_degraded_reason_pins_the_exact_percent_and_wording(self):
        # multiplier=0.85 -> (1.0 - 0.85) * 100 = 15 (rounded)
        text = discount_reason("degraded", MULTIPLIER_DEGRADED, 68.0, survived=5, tested=16)
        self.assertEqual(
            text,
            "Test & Coverage score discounted by 15% due to 68% Mutation Kill Rate (5 surviving mutant(s))",
        )

    def test_failed_reason_pins_a_different_percent(self):
        # multiplier=0.50 -> (1.0 - 0.50) * 100 = 50
        text = discount_reason("failed", MULTIPLIER_FAILED, 40.0, survived=6, tested=10)
        self.assertEqual(
            text,
            "Test & Coverage score discounted by 50% due to 40% Mutation Kill Rate (6 surviving mutant(s))",
        )

    def test_pct_uses_100_not_101_as_the_percent_multiplier(self):
        # multiplier=0.0 -> real: round(1.0 * 100) = 100; a `* 101` mutant
        # would instead compute 101 -- a difference small deltas (like the
        # real 0.85/0.5 tiers) can round away, so use the extreme to force
        # a real, unrounded-away divergence.
        text = discount_reason("failed", 0.0, 10.0, survived=9, tested=10)
        self.assertIn("discounted by 100%", text)

    def test_pct_is_rounded_not_truncated(self):
        # (1.0 - 0.835) * 100 = 16.5 -> rounds to 16 (banker's rounding:
        # round(16.5) == 16 in Python 3) -- pin the real value, not an
        # assumption about which way .5 rounds.
        text = discount_reason("degraded", 0.835, 75.0, survived=2, tested=8)
        self.assertIn(f"discounted by {round((1.0 - 0.835) * 100)}%", text)

    def test_other_grades_return_empty_string(self):
        self.assertEqual(discount_reason("not_applicable", MULTIPLIER_NOT_APPLICABLE, None, 0, 0), "")
        self.assertEqual(discount_reason("insufficient_sample", MULTIPLIER_PASSED, None, 0, 2), "")


if __name__ == "__main__":
    unittest.main()
