"""
Tests for the SLSA Source Track (Levels 1-4), SLSA Build Level 3, the
unified track report (Source + Build + Assay Health, FINAL VERDICT
banner), and the $GITHUB_STEP_SUMMARY markdown writer -- see
cli/verify.py's "SLSA Build Level 3" / Source-check section and the
project plan "SLSA Source/Build Track Reporting + Fail-Closed Build L3".
"""
from __future__ import annotations

import base64
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.verify import (
    EXIT_PASS,
    EXIT_POLICY_VIOLATION,
    SLSA_PROVENANCE_PREDICATE_TYPE,
    TRUSTED_CONTROL_PLANE_BUILDER_IDS,
    main,
    verify_dsse_attestation,
    _build_verify_json_payload,
    _evaluate_slsa_l3,
    _evaluate_source_l1,
    _evaluate_source_l2,
    _evaluate_source_l3,
    _evaluate_source_l4,
    _format_verdict_banner,
    _print_verify_result_human,
    _render_step_summary_markdown,
    _slsa_check_control_plane_builder_identity,
    _slsa_check_isolated_provenance_generation,
    _slsa_check_materialized_dependencies,
    _verdict_word,
)

SUBJECT_DIGEST = "a" * 64
TRUSTED_CONTROL_PLANE_ID = next(iter(TRUSTED_CONTROL_PLANE_BUILDER_IDS))


def _rcs_statement(*, vcs=None, branch_governance=None, rcs_value=85) -> Dict[str, Any]:
    predicate: Dict[str, Any] = {
        "release_confidence_score": {
            "value": rcs_value,
            "algorithm_version": "rcs-v0.1",
            "components": {"governance": {"weight": 0.15, "raw_score": 100.0, "weighted_score": 15.0, "reason": "ok"}},
            "degraded": False,
        },
    }
    if vcs is not None:
        predicate["vcs"] = vcs
    if branch_governance is not None:
        predicate["branch_governance"] = branch_governance
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "registry.example.com/org/svc", "digest": {"sha256": SUBJECT_DIGEST}}],
        "predicateType": "https://tenax.io/attestations/assay/v1",
        "predicate": predicate,
    }


def _envelope(statement: Dict[str, Any]) -> Dict[str, Any]:
    payload_b64 = base64.b64encode(json.dumps(statement).encode("utf-8")).decode("ascii")
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": payload_b64,
        "signatures": [{"sig": "DRY_RUN_UNSIGNED", "certificate": "DRY_RUN_NO_CERT"}],
    }


def _full_vcs() -> Dict[str, Any]:
    return {
        "provider": "github",
        "repository": "acme/widgets",
        "branch": "main",
        "commit_sha": "b" * 40,
        "base_commit_sha": "c" * 40,
        "pull_request": {"number": 7, "target_branch": "main"},
    }


class SourceLevel1Tests(unittest.TestCase):
    def test_full_vcs_passes(self):
        self.assertTrue(_evaluate_source_l1(_full_vcs())["passed"])

    def test_missing_fields_fail_with_reason(self):
        result = _evaluate_source_l1({})
        self.assertFalse(result["passed"])
        detail = result["items"][0]["detail"]
        self.assertIn("vcs.provider", detail)
        self.assertIn("vcs.repository", detail)
        self.assertIn("vcs.branch", detail)


class SourceLevel2Tests(unittest.TestCase):
    def test_full_lineage_passes(self):
        self.assertTrue(_evaluate_source_l2(_full_vcs())["passed"])

    def test_missing_base_sha_fails(self):
        vcs = _full_vcs()
        del vcs["base_commit_sha"]
        result = _evaluate_source_l2(vcs)
        self.assertFalse(result["passed"])
        self.assertIn("vcs.base_commit_sha", result["items"][0]["detail"])

    def test_pr_without_target_branch_fails(self):
        vcs = _full_vcs()
        vcs["pull_request"] = {"number": 7}
        result = _evaluate_source_l2(vcs)
        self.assertFalse(result["passed"])
        self.assertIn("vcs.pull_request.target_branch", result["items"][0]["detail"])


class SourceLevel3Tests(unittest.TestCase):
    def test_missing_commit_author_fails(self):
        """No vcs.commit_author field at all (an attestation predating
        this field, or a caller that didn't supply one) -- an honest [✗],
        never treated as "not applicable"."""
        result = _evaluate_source_l3(_full_vcs())
        self.assertFalse(result["passed"])
        self.assertIn("not captured", result["items"][0]["detail"])

    def test_unavailable_data_collection_fails_with_reason(self):
        """The GitHub API check itself failed (no token, transport error,
        ...) -- reports that specific reason, not a generic message."""
        vcs = _full_vcs()
        vcs["commit_author"] = {
            "available": False,
            "commit_sha": "b" * 40,
            "verified_github_account": False,
            "reason": "no GITHUB_TOKEN available",
        }
        result = _evaluate_source_l3(vcs)
        self.assertFalse(result["passed"])
        self.assertIn("no GITHUB_TOKEN available", result["items"][0]["detail"])

    def test_unverified_author_email_fails(self):
        """The check ran, but the commit author's email doesn't resolve to
        a linked GitHub account -- a legitimate, common [✗]."""
        vcs = _full_vcs()
        vcs["commit_author"] = {
            "available": True,
            "commit_sha": "b" * 40,
            "name": "Some Author",
            "email": "someone@example.com",
            "github_login": None,
            "verified_github_account": False,
            "reason": "commit author email does not resolve to a linked, verified GitHub account",
        }
        result = _evaluate_source_l3(vcs)
        self.assertFalse(result["passed"])
        self.assertIn("someone@example.com", result["items"][0]["detail"])

    def test_verified_github_account_passes(self):
        vcs = _full_vcs()
        vcs["commit_author"] = {
            "available": True,
            "commit_sha": "b" * 40,
            "name": "Bill Wonch",
            "email": "bill.wonch@gmail.com",
            "github_login": "billwonch",
            "verified_github_account": True,
            "reason": "commit author email resolved to verified GitHub account 'billwonch'",
        }
        result = _evaluate_source_l3(vcs)
        self.assertTrue(result["passed"])
        self.assertIn("@billwonch", result["items"][0]["label"])


class SourceLevel4Tests(unittest.TestCase):
    def test_two_or_more_approvals_required_passes(self):
        result = _evaluate_source_l4({"approvals_required": 2})
        self.assertTrue(result["passed"])
        self.assertIn("2 approval(s) required", result["items"][0]["label"])

    def test_zero_approvals_required_fails(self):
        result = _evaluate_source_l4({"approvals_required": 0})
        self.assertFalse(result["passed"])
        self.assertIn("requires >= 1", result["items"][0]["detail"])

    def test_missing_branch_governance_fails(self):
        result = _evaluate_source_l4(None)
        self.assertFalse(result["passed"])
        self.assertIn("missing", result["items"][0]["detail"])

    def test_platform_unsupported_tier_fails_with_specific_reason(self):
        result = _evaluate_source_l4({"reason_code": "platform_unsupported_tier", "reason": "GitHub Free plan"})
        self.assertFalse(result["passed"])
        self.assertIn("unsupported platform tier", result["items"][0]["detail"])


class BuildLevel3ChecksTests(unittest.TestCase):
    def test_control_plane_builder_identity_passes_only_for_trusted_id(self):
        predicate = {"runDetails": {"builder": {"id": TRUSTED_CONTROL_PLANE_ID}}}
        self.assertTrue(_slsa_check_control_plane_builder_identity(predicate)["passed"])

    def test_control_plane_builder_identity_fails_for_generic_hosted_runner(self):
        predicate = {"runDetails": {"builder": {"id": "https://github.com/actions/runner"}}}
        result = _slsa_check_control_plane_builder_identity(predicate)
        self.assertFalse(result["passed"])
        self.assertIn("isolated-control-plane allowlist", result["detail"])

    def test_isolated_provenance_generation_requires_verified_identity(self):
        predicate = {"runDetails": {"builder": {"id": TRUSTED_CONTROL_PLANE_ID}}}
        result = _slsa_check_isolated_provenance_generation(predicate, identity_status="skipped", cert_identity=TRUSTED_CONTROL_PLANE_ID)
        self.assertFalse(result["passed"])
        self.assertIn("not cryptographically confirmed", result["detail"])

    def test_isolated_provenance_generation_passes_when_signer_matches_builder(self):
        predicate = {"runDetails": {"builder": {"id": TRUSTED_CONTROL_PLANE_ID}}}
        result = _slsa_check_isolated_provenance_generation(
            predicate, identity_status="verified", cert_identity=f"{TRUSTED_CONTROL_PLANE_ID}@{'d' * 40}"
        )
        self.assertTrue(result["passed"])

    def test_isolated_provenance_generation_fails_when_signer_differs_from_builder(self):
        predicate = {"runDetails": {"builder": {"id": TRUSTED_CONTROL_PLANE_ID}}}
        result = _slsa_check_isolated_provenance_generation(
            predicate, identity_status="verified", cert_identity="https://github.com/some/other/.github/workflows/x.yml@" + "d" * 40
        )
        self.assertFalse(result["passed"])
        self.assertIn("does not match", result["detail"])

    def test_materialized_dependencies_requires_pkg_purl_with_sha256(self):
        predicate = {"buildDefinition": {"resolvedDependencies": [{"uri": "git+https://github.com/acme/widgets", "digest": {"gitCommit": "e" * 40}}]}}
        result = _slsa_check_materialized_dependencies(predicate)
        self.assertFalse(result["passed"])
        self.assertIn("no 'pkg:' PURL entries", result["detail"])

    def test_materialized_dependencies_passes_with_package_entry(self):
        predicate = {
            "buildDefinition": {
                "resolvedDependencies": [
                    {"uri": "git+https://github.com/acme/widgets", "digest": {"gitCommit": "e" * 40}},
                    {"uri": "pkg:pypi/requests@2.31.0", "digest": {"sha256": "f" * 64}},
                ]
            }
        }
        result = _slsa_check_materialized_dependencies(predicate)
        self.assertTrue(result["passed"])
        self.assertIn("1 packages recorded", result["items"][0]["label"] if "items" in result else result["label"])

    def test_l3_origin_reflects_statement_invocation_id(self):
        """_evaluate_slsa_l3 threads _slsa_invocation_origin(predicate)
        through the same way _evaluate_slsa_l1/_l2 do, so a failed Level 3
        block (the common case -- see test_build_level3_fails_by_default_
        for_every_caller_today below) can still be traced back to the run
        that produced it."""
        statement = {
            "predicate": {
                "runDetails": {
                    "builder": {"id": "https://github.com/actions/runner"},
                    "metadata": {"invocationId": "https://github.com/acme/widgets/actions/runs/42/attempts/1"},
                },
            },
        }

        assessment = _evaluate_slsa_l3(statement, identity_status="skipped", cert_identity=None)

        self.assertFalse(assessment["passed"])  # fails closed, same as every other caller today
        self.assertEqual(assessment["origin"], "https://github.com/acme/widgets/actions/runs/42/attempts/1")

    def test_build_level3_fails_by_default_for_every_caller_today(self):
        """The whole point of the fail-closed requirement: a fully-populated,
        real SLSA v1.0 statement (matching what tenax-assay's own build job
        emits today) must still legitimately fail Build Level 3, since the
        architecture that would make it pass doesn't exist until Phase 2."""
        rcs_envelope = _envelope(_rcs_statement(vcs=_full_vcs(), branch_governance={"approvals_required": 2}))
        slsa_statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "x", "digest": {"sha256": SUBJECT_DIGEST}}],
            "predicateType": SLSA_PROVENANCE_PREDICATE_TYPE,
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
                    "externalParameters": {"workflow": {"repository": "https://github.com/acme/widgets"}},
                    "resolvedDependencies": [{"uri": "pkg:pypi/requests@2.31.0", "digest": {"sha256": "f" * 64}}],
                },
                "runDetails": {
                    "builder": {"id": "https://github.com/actions/runner"},
                    "metadata": {"invocationId": "run-1"},
                },
            },
        }

        result = verify_dsse_attestation(json.loads(json.dumps(rcs_envelope)), dry_run=True, slsa_statement=slsa_statement)

        self.assertFalse(result.slsa_level3["passed"])
        # Purely informational: the hard gate still passes.
        self.assertTrue(result.passed, result.violations)


class RequireSlsaBuildL3Tests(unittest.TestCase):
    def test_require_flag_fails_the_gate_when_l3_incomplete(self):
        envelope = _envelope(_rcs_statement())

        result = verify_dsse_attestation(envelope, dry_run=True, require_slsa_build_l3=True)

        self.assertFalse(result.passed)
        self.assertTrue(any("--require-slsa-build-l3" in v for v in result.violations), result.violations)

    def test_flag_off_by_default_does_not_affect_gate(self):
        envelope = _envelope(_rcs_statement())

        result = verify_dsse_attestation(envelope, dry_run=True)

        self.assertTrue(result.passed, result.violations)


class UnifiedTwoEnvelopeInvocationTests(unittest.TestCase):
    def test_slsa_envelope_arg_feeds_build_track_and_primary_feeds_source_track(self):
        rcs_envelope = _envelope(_rcs_statement(vcs=_full_vcs(), branch_governance={"approvals_required": 2}))
        slsa_statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "x", "digest": {"sha256": SUBJECT_DIGEST}}],
            "predicateType": SLSA_PROVENANCE_PREDICATE_TYPE,
            "predicate": {
                "buildDefinition": {"buildType": "t", "resolvedDependencies": []},
                "runDetails": {"metadata": {"invocationId": "run-1"}},
            },
        }

        result = verify_dsse_attestation(rcs_envelope, dry_run=True, slsa_statement=slsa_statement)

        self.assertTrue(result.source_level1["passed"])
        self.assertTrue(result.source_level4["passed"])
        self.assertTrue(result.slsa_level1["passed"])  # evaluated against slsa_statement, not the RCS one

    def test_verdict_reflects_highest_cumulative_level_each_track(self):
        rcs_envelope = _envelope(_rcs_statement(vcs=_full_vcs(), branch_governance={"approvals_required": 2}))

        result = verify_dsse_attestation(rcs_envelope, dry_run=True)

        self.assertIn("Source L2", result.verdict)  # L3 always fails today, so cumulative source stalls at 2
        self.assertIn("FINAL VERDICT", result.verdict)

    def test_json_payload_includes_source_and_verdict(self):
        envelope = _envelope(_rcs_statement(vcs=_full_vcs(), branch_governance={"approvals_required": 2}))
        result = verify_dsse_attestation(envelope, dry_run=True)

        payload = _build_verify_json_payload(result)

        self.assertIn("source", payload)
        self.assertEqual(payload["source"]["level_1"]["level"], 1)
        self.assertEqual(payload["source"]["level_4"]["level"], 4)
        self.assertIn("level_3", payload["slsa"])
        self.assertIsInstance(payload["verdict"], str)
        self.assertIn("FINAL VERDICT", payload["verdict"])


class VerdictBannerTests(unittest.TestCase):
    def _result(self, passed: bool):
        from cli.verify import VerificationResult

        return VerificationResult(passed=passed)

    def test_failed_when_hard_gate_rejects(self):
        lines = _format_verdict_banner(self._result(False), source_highest=0, build_highest=0)
        self.assertIn("FAILED", lines[1])

    def test_gated_when_gate_passes_but_not_fully_compliant(self):
        lines = _format_verdict_banner(self._result(True), source_highest=2, build_highest=1)
        self.assertIn("GATED", lines[1])
        self.assertIn("SLSA Build L2 Incomplete", lines[1])

    def test_passed_when_gate_passes_and_fully_compliant(self):
        lines = _format_verdict_banner(self._result(True), source_highest=4, build_highest=3)
        self.assertIn("PASSED", lines[1])
        self.assertNotIn("Incomplete", lines[1])

    def test_verdict_word_agrees_with_format_verdict_banner_failed(self):
        self.assertEqual(_verdict_word(self._result(False), source_highest=0, build_highest=0), "FAILED")

    def test_verdict_word_agrees_with_format_verdict_banner_gated(self):
        self.assertEqual(_verdict_word(self._result(True), source_highest=2, build_highest=1), "GATED")

    def test_verdict_word_agrees_with_format_verdict_banner_passed(self):
        self.assertEqual(_verdict_word(self._result(True), source_highest=4, build_highest=3), "PASSED")

    def test_verdict_word_ignores_track_levels_when_gate_failed(self):
        # A rejected hard gate is FAILED regardless of how SLSA-compliant
        # the tracks otherwise look -- mirrors _format_verdict_banner's own
        # `if not result.passed` short-circuit.
        self.assertEqual(_verdict_word(self._result(False), source_highest=4, build_highest=3), "FAILED")


class VerdictHeadingConsistencyTests(unittest.TestCase):
    """Regression coverage for the PASS-heading-vs-GATED-verdict confusion:
    _print_verify_result_human's and _render_step_summary_markdown's
    top-of-report headings must always show the exact same word as FINAL
    VERDICT below them, never a separately-computed PASS/FAIL binary (see
    _verdict_word's docstring)."""

    def test_gated_run_shows_gated_in_heading_not_pass(self):
        # The exact real-world case that motivated this: a --dry-run with
        # no --slsa-envelope is admissible (RCS clears --min-rcs) but the
        # SLSA tracks are all incomplete -- GATED, not the old "✅ PASS".
        envelope = _envelope(_rcs_statement())

        result = verify_dsse_attestation(envelope, dry_run=True)

        self.assertTrue(result.passed)
        self.assertEqual(result.verdict_word, "GATED")
        self.assertIn("FINAL VERDICT: GATED", result.verdict)

        markdown = _render_step_summary_markdown(result)
        self.assertIn("## tenax-assay verify: ⚠️ GATED", markdown)
        self.assertNotIn("PASS", markdown.split("\n")[0])

        buf = io.StringIO()
        with redirect_stderr(buf):
            _print_verify_result_human(result)
        self.assertIn("tenax-assay verify: GATED", buf.getvalue())

    def test_fully_compliant_result_shows_passed_in_heading(self):
        # Constructed directly (rather than driven through
        # verify_dsse_attestation(), which would need a real, cryptographically
        # verified Sigstore signature to ever reach identity_status=="verified")
        # so this exercises exactly the heading code path in isolation --
        # VerdictBannerTests above already covers _verdict_word's own PASSED
        # decision from source_highest/build_highest.
        from cli.verify import VerificationResult

        result = VerificationResult(passed=True, verdict_word="PASSED")

        markdown = _render_step_summary_markdown(result)
        self.assertIn("## tenax-assay verify: ✅ PASSED", markdown)

        buf = io.StringIO()
        with redirect_stderr(buf):
            _print_verify_result_human(result)
        self.assertIn("tenax-assay verify: PASSED", buf.getvalue())

    def test_malformed_envelope_reports_failed_not_blank(self):
        result = verify_dsse_attestation("not-a-dict", dry_run=True)  # type: ignore[arg-type]

        self.assertEqual(result.verdict_word, "FAILED")
        markdown = _render_step_summary_markdown(result)
        self.assertIn("## tenax-assay verify: ❌ FAILED", markdown)


class StaticAnalysisInStepSummaryTests(unittest.TestCase):
    """Regression coverage for the SARIF/static-analysis table being
    stderr-only: it used to be printed directly by
    _print_verify_result_human and was silently absent from every
    $GITHUB_STEP_SUMMARY, since _render_step_summary_markdown never
    rendered it. Both renderers now go through the same
    _render_track_sections block, so they can't drift apart on this
    again."""

    def test_static_analysis_table_appears_in_step_summary_markdown(self):
        from cli.verify import VerificationResult

        result = VerificationResult(
            passed=True,
            verdict_word="PASSED",
            static_analysis_tools=[
                {"name": "semgrep", "summary": {"errors": 1, "warnings": 0}, "extensions": {}}
            ],
        )

        markdown = _render_step_summary_markdown(result)
        self.assertIn("static analysis:", markdown)
        self.assertIn("semgrep", markdown)

    def test_no_static_analysis_section_when_no_tools_ran(self):
        from cli.verify import VerificationResult

        result = VerificationResult(passed=True, verdict_word="PASSED")

        markdown = _render_step_summary_markdown(result)
        self.assertNotIn("static analysis:", markdown)


class StepSummaryWriterTests(unittest.TestCase):
    def test_writes_markdown_to_github_step_summary_env_var(self):
        envelope = _envelope(_rcs_statement())

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            path = f.name
        try:
            argv = [
                _write_temp_envelope(envelope),
                "--dry-run",
            ]
            env_backup = os.environ.get("GITHUB_STEP_SUMMARY")
            os.environ["GITHUB_STEP_SUMMARY"] = path
            try:
                main(argv)
            finally:
                if env_backup is None:
                    os.environ.pop("GITHUB_STEP_SUMMARY", None)
                else:
                    os.environ["GITHUB_STEP_SUMMARY"] = env_backup

            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("tenax-assay verify:", content)
            self.assertIn("SLSA Source Track", content)
            self.assertIn("FINAL VERDICT", content)
        finally:
            os.remove(path)

    def test_no_op_when_env_var_absent(self):
        envelope = _envelope(_rcs_statement())
        result = verify_dsse_attestation(envelope, dry_run=True)

        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        from cli.verify import _write_github_step_summary

        _write_github_step_summary(result)  # must not raise

    def test_never_raises_on_unwritable_path(self):
        envelope = _envelope(_rcs_statement())
        result = verify_dsse_attestation(envelope, dry_run=True)

        from cli.verify import _write_github_step_summary

        env_backup = os.environ.get("GITHUB_STEP_SUMMARY")
        os.environ["GITHUB_STEP_SUMMARY"] = "/nonexistent-dir/does-not-exist/summary.md"
        try:
            _write_github_step_summary(result)  # must not raise
        finally:
            if env_backup is None:
                os.environ.pop("GITHUB_STEP_SUMMARY", None)
            else:
                os.environ["GITHUB_STEP_SUMMARY"] = env_backup

    def test_render_function_is_pure_and_json_free(self):
        envelope = _envelope(_rcs_statement())
        result = verify_dsse_attestation(envelope, dry_run=True)

        markdown = _render_step_summary_markdown(result)

        self.assertIn("## tenax-assay verify:", markdown)
        self.assertIn("```text", markdown)


def _write_temp_envelope(envelope: Dict[str, Any]) -> str:
    fd, path = tempfile.mkstemp(suffix=".dsse.json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(envelope, f)
    return path


if __name__ == "__main__":
    unittest.main()
