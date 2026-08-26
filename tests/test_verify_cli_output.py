"""
Direct unit tests for cli/verify.py's _print_verify_result_human(), the
human-readable (non --json) stderr renderer extracted from main() during
the SonarCloud complexity sweep.
"""
from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr

from cli.verify import VerificationResult, _print_verify_result_human


class PrintVerifyResultHumanTests(unittest.TestCase):
    def _render(self, result: VerificationResult) -> str:
        buf = io.StringIO()
        with redirect_stderr(buf):
            _print_verify_result_human(result)
        return buf.getvalue()

    def test_degraded_run_prints_reasons(self):
        result = VerificationResult(
            passed=True,
            rcs_value=72,
            degraded=True,
            degraded_reasons=["patch_coverage:no_coverable_lines"],
        )
        out = self._render(result)
        self.assertIn("RCS=72 degraded=True", out)
        self.assertIn("degraded_reasons=['patch_coverage:no_coverable_lines']", out)

    def test_subject_digests_printed_when_present(self):
        result = VerificationResult(passed=True, subject_digests=["sha256:" + "a" * 64])
        out = self._render(result)
        self.assertIn("subject_digests=", out)

    def test_static_analysis_table_rendered_when_present(self):
        result = VerificationResult(
            passed=True,
            static_analysis_tools=[{"name": "semgrep", "summary": {"errors": 1, "warnings": 0}, "extensions": {}}],
        )
        out = self._render(result)
        self.assertIn("static analysis:", out)
        self.assertIn("semgrep", out)

    def test_violations_and_warnings_printed(self):
        result = VerificationResult(passed=False, violations=["RCS too low"], warnings=["something minor"])
        out = self._render(result)
        self.assertIn("VIOLATION: RCS too low", out)
        self.assertIn("warning: something minor", out)

    def test_minimal_result_has_no_optional_sections(self):
        result = VerificationResult(passed=True)
        out = self._render(result)
        self.assertNotIn("subject_digests", out)
        self.assertNotIn("static analysis:", out)
        self.assertNotIn("RCS=", out)

    def test_heading_uses_verdict_word_not_a_separate_pass_fail_binary(self):
        # See _verdict_word's docstring: the heading must show the same
        # word FINAL VERDICT does, not its own PASS/FAIL binary.
        result = VerificationResult(passed=True, verdict_word="GATED")
        out = self._render(result)
        self.assertIn("tenax-assay verify: GATED", out)
        self.assertNotIn("tenax-assay verify: PASS", out)

    def test_heading_falls_back_to_failed_when_verdict_word_unset(self):
        # e.g. a VerificationResult built directly by a test/caller without
        # going through verify_dsse_attestation() -- never render a blank
        # heading.
        result = VerificationResult(passed=True)
        out = self._render(result)
        self.assertIn("tenax-assay verify: FAILED", out)


if __name__ == "__main__":
    unittest.main()
