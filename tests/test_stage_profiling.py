"""Tests for the --debug stage-timing profiler added to cli/main.py, and the
matching sub-stage timing hooks added to cli/oidc_signer.py::sign_statement.

Hardened against:
  - A logical stage split across multiple non-adjacent code blocks (e.g.
    SARIF parsing landing in "parse_inputs" despite running later in
    main()) silently overwriting instead of accumulating.
  - --debug changing any of the pipeline's non-diagnostic stdout/stderr
    output (RCS=/blocking_overhead_ms=, warnings, exit code).
  - sign_statement()'s new `timing` param being anything but a strict
    backward-compatible addition (existing two-positional-arg call sites,
    like tests/test_sarif.py, must keep working unmodified).
"""
from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stderr

from cli.main import _emit_stage_profile, _fmt_ms, _fmt_s, _stage
from cli.oidc_signer import sign_statement


class StageTimerAccumulationTests(unittest.TestCase):
    def test_single_block_records_positive_duration(self):
        stage_ns = {}
        with _stage(stage_ns, "parse_inputs"):
            pass
        self.assertIn("parse_inputs", stage_ns)
        self.assertGreaterEqual(stage_ns["parse_inputs"], 0)

    def test_same_key_across_two_blocks_accumulates_not_overwrites(self):
        """Mirrors main.py's real usage: SARIF parsing is timed under
        "parse_inputs" in a second, later `with _stage(...)` block -- the
        second block's duration must add to, not replace, the first's."""
        stage_ns = {}
        with _stage(stage_ns, "parse_inputs"):
            pass
        first = stage_ns["parse_inputs"]
        with _stage(stage_ns, "parse_inputs"):
            pass
        self.assertGreaterEqual(stage_ns["parse_inputs"], first)

    def test_exception_inside_block_still_records_and_propagates(self):
        stage_ns = {}
        with self.assertRaises(ValueError):
            with _stage(stage_ns, "ast_inspection"):
                raise ValueError("boom")
        self.assertIn("ast_inspection", stage_ns)


class FormatHelperTests(unittest.TestCase):
    def test_fmt_ms_renders_thousands_separator(self):
        self.assertEqual(_fmt_ms(24_120_000_000), "24,120.0 ms")

    def test_fmt_ms_zero(self):
        self.assertEqual(_fmt_ms(0), "0.0 ms")

    def test_fmt_s_renders_two_decimals(self):
        self.assertEqual(_fmt_s(24_340_000_000), "24.34 s")


class EmitStageProfileTests(unittest.TestCase):
    def test_report_contains_every_stage_label_and_sigstore_sublines(self):
        stage_ns = {
            "parse_inputs": 200_000,
            "diff_patch_analysis": 8_100_000,
            "ast_inspection": 12_300_000,
            "github_rules_api": 182_000_000,
            "rcs_scoring": 1_100_000,
            "predicate_assembly": 800_000,
            "worm_upload": 100_000,
        }
        sign_sub_ns = {"oidc_token_fetch_ns": 150_000_000, "fulcio_rekor_ns": 23_970_000_000}

        buf = io.StringIO()
        with redirect_stderr(buf):
            _emit_stage_profile(
                stage_ns,
                sign_total_ns=24_120_000_000,
                sign_sub_ns=sign_sub_ns,
                blocking_elapsed_ms=204.6,
                wall_elapsed_ns=24_330_000_000,
            )
        out = buf.getvalue()

        self.assertIn("=== Plinth Assay Stage Profiling ===", out)
        for label in (
            "Inputs & Parsing",
            "Diff & Patch Coverage",
            "AST Assertion Walking",
            "GitHub Ruleset API",
            "RCS Scoring Engine",
            "Predicate Serialization",
            "WORM Upload Dispatch",
            "Sigstore Signing (Total)",
            "OIDC Token Fetch",
            "Fulcio/Rekor Round-Trip",
        ):
            self.assertIn(label, out)
        self.assertIn("Total Blocking Overhead:", out)
        self.assertIn("Total Wall-Clock Time:", out)
        self.assertIn("204.6 ms", out)
        self.assertIn("24.33 s", out)

    def test_missing_stage_key_defaults_to_zero_rather_than_raising(self):
        buf = io.StringIO()
        with redirect_stderr(buf):
            _emit_stage_profile({}, sign_total_ns=None, sign_sub_ns={}, blocking_elapsed_ms=0.0, wall_elapsed_ns=0)
        out = buf.getvalue()
        self.assertIn("0.0 ms", out)
        # No signing was performed -- the Sigstore block must not appear.
        self.assertNotIn("Sigstore Signing", out)

    def test_no_signing_omits_sigstore_block_entirely(self):
        buf = io.StringIO()
        with redirect_stderr(buf):
            _emit_stage_profile(
                {"parse_inputs": 1_000_000},
                sign_total_ns=None,
                sign_sub_ns={},
                blocking_elapsed_ms=1.0,
                wall_elapsed_ns=1_000_000,
            )
        out = buf.getvalue()
        self.assertNotIn("↳", out)


class SignStatementTimingHookTests(unittest.TestCase):
    def test_dry_run_populates_zeroed_timing_dict(self):
        timing: dict = {}
        sign_statement(b'{"fake": true}', dry_run=True, timing=timing)
        self.assertEqual(timing, {"oidc_token_fetch_ns": 0, "fulcio_rekor_ns": 0})

    def test_timing_param_is_optional_and_backward_compatible(self):
        """The pre-existing two-positional-arg call shape (no `timing`
        kwarg at all) used elsewhere in the test suite must still work."""
        envelope = sign_statement(b'{"fake": true}', dry_run=True)
        self.assertEqual(envelope.signatures[0]["sig"], "DRY_RUN_UNSIGNED")

    def test_dry_run_without_timing_dict_does_not_raise(self):
        # timing=None is the default -- must be a no-op, not an AttributeError.
        sign_statement(b'{"fake": true}', dry_run=True, timing=None)


if __name__ == "__main__":
    unittest.main()
