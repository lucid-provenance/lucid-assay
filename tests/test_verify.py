import base64
import datetime
import json
import os
import sys
import tempfile
import unittest
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests._fulcio_cert_helpers import _der_utf8_string, _make_fulcio_style_cert

from cli.verify import (
    EXIT_FILE_ERROR,
    EXIT_PASS,
    EXIT_POLICY_VIOLATION,
    GITHUB_ACTIONS_OIDC_ISSUER,
    SLSA_PROVENANCE_PREDICATE_TYPE,
    TRUSTED_HOSTED_BUILDER_IDS,
    VerificationResult,
    main,
    parse_args,
    verify_dsse_attestation,
    _build_identity_policy,
    _build_verify_json_payload,
    _describe_actual_cert_claims,
    _envelope_to_bundle_json,
    _evaluate_slsa_l1,
    _evaluate_slsa_l2,
    _extract_cert_ref,
    _format_assay_health_report,
    _format_coverage_line,
    _format_pct,
    _format_slsa_level_block,
    _format_test_coverage_summary,
    _format_test_validity_line,
    _format_track_report,
    _slsa_invocation_origin,
    _slsa_level_result,
    _static_analysis_tools_by_name,
    _verify_sigstore_identity,
)

SUBJECT_DIGEST = "a" * 64


def _format_slsa_report(l1: Dict[str, Any], l2: Dict[str, Any]):
    """Test-local shim: cli.verify's old two-level-specific
    _format_slsa_report(l1, l2) was generalized into
    _format_track_report(levels) -> (lines, cumulative_status) to also
    render the SLSA Source Track's four levels. Existing call sites below
    only ever asserted on the rendered lines, so this shim keeps them
    unchanged."""
    return _format_track_report([l1, l2])[0]


_DEGRADED_REASONS_OMITTED = object()  # sentinel: distinct from None/[] -- key left out of the predicate entirely


def _statement(
    *,
    rcs_value=85,
    degraded=False,
    degraded_reasons=_DEGRADED_REASONS_OMITTED,
    omit_degraded_field=False,
    subject_sha256=SUBJECT_DIGEST,
):
    rcs_block = {
        "value": rcs_value,
        "algorithm_version": "rcs-v0.1",
        "components": {},
        "computed_at": "2026-08-20T02:18:40Z",
    }
    if not omit_degraded_field:
        rcs_block["degraded"] = degraded
    if degraded_reasons is not _DEGRADED_REASONS_OMITTED:
        rcs_block["degraded_reasons"] = degraded_reasons
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "registry.example.com/org/svc",
                "digest": {"sha256": subject_sha256},
            }
        ],
        "predicateType": "https://tenax.io/attestations/assay/v1",
        "predicate": {
            "predicate_version": "0.1.0",
            "release_confidence_score": rcs_block,
            "test_verification": {
                "totals": {"tests": 4, "passed": 4, "failed": 0, "errored": 0, "skipped": 0},
            },
            "coverage": {"overall": {"line_rate": 0.9, "branch_rate": 0.8}},
        },
    }


def _envelope(statement, *, payload_type="application/vnd.in-toto+json", signatures=None):
    payload_b64 = base64.b64encode(json.dumps(statement).encode("utf-8")).decode("ascii")
    if signatures is None:
        signatures = [{"sig": "DRY_RUN_UNSIGNED", "certificate": "DRY_RUN_NO_CERT"}]
    return {
        "payloadType": payload_type,
        "payload": payload_b64,
        "signatures": signatures,
        "_rekor": {"logIndex": None, "logId": None},
    }


class VerifyDsseAttestationTests(unittest.TestCase):
    def test_valid_envelope_passes_rcs_threshold(self):
        envelope = _envelope(_statement(rcs_value=85, degraded=False))

        result = verify_dsse_attestation(envelope, min_rcs=70, dry_run=True)

        self.assertTrue(result.passed, result.violations)
        self.assertEqual(result.violations, [])
        self.assertEqual(result.rcs_value, 85)
        self.assertFalse(result.degraded)
        self.assertEqual(result.subject_digests, [f"sha256:{SUBJECT_DIGEST}"])
        self.assertEqual(result.identity_status, "skipped")

    def test_dry_run_placeholder_signature_is_skipped_not_failed_without_dry_run_flag(self):
        # Even when --dry-run isn't passed, an envelope produced by
        # --dry-run-sign carries a placeholder signature that must never be
        # mistaken for a verified one, and must never attempt network I/O.
        envelope = _envelope(_statement())

        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=False)

        self.assertTrue(result.passed, result.violations)
        self.assertEqual(result.identity_status, "skipped")

    def test_rcs_below_min_rcs_fails(self):
        envelope = _envelope(_statement(rcs_value=60))

        result = verify_dsse_attestation(envelope, min_rcs=80, dry_run=True)

        self.assertFalse(result.passed)
        self.assertTrue(any("RCS score 60" in v for v in result.violations), result.violations)

    def test_subject_digest_mismatch_fails(self):
        envelope = _envelope(_statement(subject_sha256=SUBJECT_DIGEST))

        result = verify_dsse_attestation(
            envelope, min_rcs=0, require_digest="sha256:" + "b" * 64, dry_run=True
        )

        self.assertFalse(result.passed)
        self.assertTrue(any("required subject digest" in v for v in result.violations), result.violations)

    def test_subject_digest_match_passes(self):
        envelope = _envelope(_statement(subject_sha256=SUBJECT_DIGEST))

        result = verify_dsse_attestation(
            envelope, min_rcs=0, require_digest=SUBJECT_DIGEST, dry_run=True
        )

        self.assertTrue(result.passed, result.violations)

    def test_disallow_degraded_fails_when_degraded(self):
        envelope = _envelope(_statement(degraded=True))

        result = verify_dsse_attestation(envelope, min_rcs=0, disallow_degraded=True, dry_run=True)

        self.assertFalse(result.passed)
        self.assertTrue(any("disallow-degraded" in v for v in result.violations), result.violations)

    def test_disallow_degraded_allows_sole_platform_unsupported_tier_cause(self):
        # The one case --disallow-degraded is meant to let through: the run
        # is degraded *solely* because of GitHub's Free-plan rulesets
        # limitation, not a real governance gap.
        envelope = _envelope(_statement(
            degraded=True, degraded_reasons=["branch_governance:platform_unsupported_tier"]
        ))

        result = verify_dsse_attestation(envelope, min_rcs=0, disallow_degraded=True, dry_run=True)

        self.assertTrue(result.passed, result.violations)
        self.assertFalse(any("disallow-degraded" in v for v in result.violations))
        self.assertTrue(any("platform_unsupported_tier" in w for w in result.warnings), result.warnings)

    def test_disallow_degraded_still_blocks_when_platform_tier_is_not_the_only_cause(self):
        # A second, unrelated degradation cause alongside the platform-tier
        # one must still block -- the exemption is only for "this is the
        # *sole* reason", never "this is present among others".
        envelope = _envelope(_statement(
            degraded=True,
            degraded_reasons=["branch_governance:platform_unsupported_tier", "no_pr_context"],
        ))

        result = verify_dsse_attestation(envelope, min_rcs=0, disallow_degraded=True, dry_run=True)

        self.assertFalse(result.passed)
        self.assertTrue(any("disallow-degraded" in v for v in result.violations), result.violations)

    def test_disallow_degraded_allows_sole_docs_only_patch_coverage_cause(self):
        # A docs/config-only diff has no code for patch coverage to be
        # missing over -- the same kind of unavoidable, benign state as
        # the platform-tier branch-governance case.
        envelope = _envelope(_statement(
            degraded=True, degraded_reasons=["patch_coverage:no_coverable_lines"]
        ))

        result = verify_dsse_attestation(envelope, min_rcs=0, disallow_degraded=True, dry_run=True)

        self.assertTrue(result.passed, result.violations)
        self.assertFalse(any("disallow-degraded" in v for v in result.violations))

    def test_disallow_degraded_allows_both_exempted_causes_together(self):
        # The exact real-world scenario this test guards: a docs-only PR
        # against a private GitHub Free-plan repo triggers *both* exempted
        # causes at once (no coverable lines AND branch governance can't
        # be verified on this plan tier) -- neither is a real gap, so
        # neither should block, together or separately.
        envelope = _envelope(_statement(
            degraded=True,
            degraded_reasons=[
                "patch_coverage:no_coverable_lines",
                "branch_governance:platform_unsupported_tier",
            ],
        ))

        result = verify_dsse_attestation(envelope, min_rcs=0, disallow_degraded=True, dry_run=True)

        self.assertTrue(result.passed, result.violations)
        self.assertFalse(any("disallow-degraded" in v for v in result.violations))

    def test_disallow_degraded_blocks_generic_branch_governance_unverified(self):
        # A generic "couldn't verify branch governance at all" (missing
        # token, network failure, an under-scoped-but-not-platform-limited
        # token, ...) is NOT the exempted case and must still block.
        envelope = _envelope(_statement(
            degraded=True, degraded_reasons=["branch_governance_unverified"]
        ))

        result = verify_dsse_attestation(envelope, min_rcs=0, disallow_degraded=True, dry_run=True)

        self.assertFalse(result.passed)
        self.assertTrue(any("disallow-degraded" in v for v in result.violations), result.violations)

    def test_disallow_degraded_blocks_when_degraded_reasons_missing(self):
        # Fail closed: degraded=True with no degraded_reasons at all (an
        # older attestation predating this field, or a malformed one)
        # can't prove the sole cause is the exempted one, so it must not
        # be silently waved through.
        envelope = _envelope(_statement(degraded=True))  # degraded_reasons omitted entirely
        decoded_payload = json.loads(base64.b64decode(envelope["payload"]))
        self.assertNotIn("degraded_reasons", decoded_payload["predicate"]["release_confidence_score"])

        result = verify_dsse_attestation(envelope, min_rcs=0, disallow_degraded=True, dry_run=True)

        self.assertFalse(result.passed)
        self.assertTrue(any("disallow-degraded" in v for v in result.violations), result.violations)

    def test_disallow_degraded_blocks_when_degraded_reasons_is_empty_list(self):
        # Same fail-closed principle, but the field is present and
        # explicitly empty rather than absent -- also can't prove the
        # exempted cause, also must block.
        envelope = _envelope(_statement(degraded=True, degraded_reasons=[]))

        result = verify_dsse_attestation(envelope, min_rcs=0, disallow_degraded=True, dry_run=True)

        self.assertFalse(result.passed)
        self.assertTrue(any("disallow-degraded" in v for v in result.violations), result.violations)

    def test_disallow_degraded_permissive_when_flag_not_set(self):
        # Sanity check: without --disallow-degraded, none of the above
        # matters -- a degraded run always passes regardless of cause.
        envelope = _envelope(_statement(degraded=True, degraded_reasons=["no_pr_context"]))

        result = verify_dsse_attestation(envelope, min_rcs=0, disallow_degraded=False, dry_run=True)

        self.assertTrue(result.passed, result.violations)

    def test_disallow_degraded_blocks_when_degraded_field_itself_is_missing(self):
        # Fail closed on an unknown state, not just a known-True one: a
        # predicate that omits release_confidence_score.degraded entirely
        # (schema declares it optional with a display default of False)
        # must not be silently trusted as "confirmed not degraded" when
        # --disallow-degraded is set -- the whole point of the flag is to
        # never let an unconfirmed state slip through as if it were a pass.
        envelope = _envelope(_statement(omit_degraded_field=True))
        decoded_payload = json.loads(base64.b64decode(envelope["payload"]))
        self.assertNotIn("degraded", decoded_payload["predicate"]["release_confidence_score"])

        result = verify_dsse_attestation(envelope, min_rcs=0, disallow_degraded=True, dry_run=True)

        self.assertFalse(result.passed)
        self.assertTrue(any("disallow-degraded" in v for v in result.violations), result.violations)
        self.assertFalse(result.degraded_field_present)
        self.assertFalse(result.degraded)  # display default, not itself a compliance claim

    def test_missing_degraded_field_is_permissive_when_flag_not_set(self):
        # Without --disallow-degraded, the missing field is display-only
        # and defaults to False (this field's own schema-declared default)
        # -- it must not itself become a blocking violation.
        envelope = _envelope(_statement(omit_degraded_field=True))

        result = verify_dsse_attestation(envelope, min_rcs=0, disallow_degraded=False, dry_run=True)

        self.assertTrue(result.passed, result.violations)
        self.assertFalse(result.degraded_field_present)
        self.assertFalse(result.degraded)

    def test_degraded_field_present_true_when_explicitly_asserted(self):
        envelope = _envelope(_statement(degraded=False))

        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        self.assertTrue(result.degraded_field_present)
        self.assertFalse(result.degraded)

    def test_malformed_degraded_type_is_treated_as_not_present(self):
        # A non-bool degraded value is both its own violation (existing
        # behavior) and, per the fail-closed fix, degraded_field_present
        # goes False too -- a malformed assertion is exactly as untrusted
        # as a missing one, not silently coerced into "confirmed False".
        envelope = _envelope(_statement(degraded="not-a-bool"))

        result = verify_dsse_attestation(envelope, min_rcs=0, disallow_degraded=True, dry_run=True)

        self.assertFalse(result.passed)
        self.assertFalse(result.degraded_field_present)
        self.assertTrue(any("invalid release_confidence_score.degraded type" in v for v in result.violations), result.violations)

    def test_invalid_degraded_reasons_type_is_a_violation_and_still_blocks(self):
        envelope = _envelope(_statement(degraded=True, degraded_reasons="not-a-list"))

        result = verify_dsse_attestation(envelope, min_rcs=0, disallow_degraded=True, dry_run=True)

        self.assertFalse(result.passed)
        self.assertTrue(any("invalid" in v and "degraded_reasons" in v for v in result.violations), result.violations)
        self.assertTrue(any("disallow-degraded" in v for v in result.violations), result.violations)

    def test_invalid_payload_type_rejected(self):
        envelope = _envelope(_statement(), payload_type="application/json")

        result = verify_dsse_attestation(envelope, dry_run=True)

        self.assertFalse(result.passed)
        self.assertTrue(any("payloadType" in v for v in result.violations), result.violations)

    def test_empty_signatures_rejected(self):
        envelope = _envelope(_statement(), signatures=[])

        result = verify_dsse_attestation(envelope, dry_run=True)

        self.assertFalse(result.passed)
        self.assertTrue(any("no signatures" in v for v in result.violations), result.violations)

    def test_missing_signatures_field_rejected(self):
        envelope = _envelope(_statement())
        del envelope["signatures"]

        result = verify_dsse_attestation(envelope, dry_run=True)

        self.assertFalse(result.passed)
        self.assertTrue(any("signatures" in v for v in result.violations), result.violations)

    def test_malformed_base64_payload_rejected(self):
        envelope = _envelope(_statement())
        envelope["payload"] = "not-valid-base64!!"

        result = verify_dsse_attestation(envelope, dry_run=True)

        self.assertFalse(result.passed)
        self.assertIsNone(result.statement)

    def test_non_dict_envelope_rejected(self):
        result = verify_dsse_attestation(["not", "a", "dict"], dry_run=True)

        self.assertFalse(result.passed)


class VerifyCliMainTests(unittest.TestCase):
    def _write_envelope(self, envelope):
        fd, path = tempfile.mkstemp(suffix=".dsse.json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(envelope, f)
        self.addCleanup(os.remove, path)
        return path

    def test_main_exit_0_on_pass(self):
        path = self._write_envelope(_envelope(_statement(rcs_value=90)))

        rc = main([path, "--min-rcs", "80", "--dry-run"])

        self.assertEqual(rc, EXIT_PASS)

    def test_main_exit_2_on_policy_violation(self):
        path = self._write_envelope(_envelope(_statement(rcs_value=50)))

        rc = main([path, "--min-rcs", "80", "--dry-run"])

        self.assertEqual(rc, EXIT_POLICY_VIOLATION)

    def test_main_exit_1_on_missing_file(self):
        rc = main(["/nonexistent/path/does-not-exist.dsse.json", "--dry-run"])

        self.assertEqual(rc, EXIT_FILE_ERROR)

    def test_main_exit_1_on_invalid_json(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("{not valid json")
        self.addCleanup(os.remove, path)

        rc = main([path, "--dry-run"])

        self.assertEqual(rc, EXIT_FILE_ERROR)

    def test_format_json_emits_only_valid_json_on_stdout_and_preserves_exit_code(self):
        import contextlib
        import io

        path = self._write_envelope(_envelope(_statement(rcs_value=90)))
        captured_stdout = io.StringIO()

        with contextlib.redirect_stdout(captured_stdout):
            rc = main([path, "--min-rcs", "80", "--dry-run", "--format", "json"])

        self.assertEqual(rc, EXIT_PASS)
        payload = json.loads(captured_stdout.getvalue())  # raises if stdout wasn't pure JSON
        self.assertEqual(payload["version"], "1.0.0")
        self.assertTrue(payload["verified"])
        self.assertEqual(payload["release_confidence_score"]["score"], 90)
        self.assertIn("slsa", payload)
        self.assertIn("level_1", payload["slsa"])
        self.assertIn("level_2", payload["slsa"])
        self.assertEqual(
            payload["envelope"]["predicate_type"], "https://tenax.io/attestations/assay/v1"
        )

    def test_format_json_reflects_nonzero_exit_on_policy_violation(self):
        import contextlib
        import io

        path = self._write_envelope(_envelope(_statement(rcs_value=50)))
        captured_stdout = io.StringIO()

        with contextlib.redirect_stdout(captured_stdout):
            rc = main([path, "--min-rcs", "80", "--dry-run", "--format", "json"])

        self.assertEqual(rc, EXIT_POLICY_VIOLATION)
        payload = json.loads(captured_stdout.getvalue())
        self.assertFalse(payload["verified"])

    def test_format_defaults_to_text_on_stderr_not_stdout(self):
        import contextlib
        import io

        path = self._write_envelope(_envelope(_statement(rcs_value=90)))
        captured_stdout = io.StringIO()

        with contextlib.redirect_stdout(captured_stdout):
            rc = main([path, "--min-rcs", "80", "--dry-run"])

        self.assertEqual(rc, EXIT_PASS)
        self.assertEqual(captured_stdout.getvalue(), "")

    def test_deprecated_json_flag_still_emits_json_and_warns_on_stderr(self):
        import contextlib
        import io

        path = self._write_envelope(_envelope(_statement(rcs_value=90)))
        captured_stdout = io.StringIO()
        captured_stderr = io.StringIO()

        with contextlib.redirect_stdout(captured_stdout), contextlib.redirect_stderr(captured_stderr):
            rc = main([path, "--min-rcs", "80", "--dry-run", "--json"])

        self.assertEqual(rc, EXIT_PASS)
        payload = json.loads(captured_stdout.getvalue())
        self.assertTrue(payload["verified"])
        self.assertIn("deprecated", captured_stderr.getvalue())


class VerifyJsonPayloadTests(unittest.TestCase):
    # Dedicated SLSA-assessment coverage (well-formed predicate, malformed
    # predicateType, fails-closed identity/dependency states, etc.) lives in
    # EvaluateSlsaL1Tests/EvaluateSlsaL2Tests/FormatSlsaReportTests below --
    # this class only needs to confirm _build_verify_json_payload plumbs
    # that already-computed result through faithfully.

    def test_static_analysis_tools_by_name_merges_summary_and_quality_gate(self):
        tools = [
            {"name": "codeql", "summary": {"errors": 0, "warnings": 2}},
            {
                "name": "sonarcloud",
                "extensions": {"sonarqube": {"quality_gate": "PASSED"}},
            },
            {"name": "", "summary": {"errors": 1}},  # no usable name -- skipped
        ]

        out = _static_analysis_tools_by_name(tools)

        self.assertEqual(out["codeql"], {"errors": 0, "warnings": 2})
        self.assertEqual(out["sonarcloud"], {"quality_gate": "PASSED"})
        self.assertNotIn("", out)

    def test_build_verify_json_payload_includes_all_top_level_sections(self):
        envelope = _envelope(_statement(rcs_value=85))
        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        payload = _build_verify_json_payload(result)

        for key in (
            "version",
            "verified",
            "verdict",
            "verdict_word",
            "envelope",
            "slsa",
            "release_confidence_score",
            "static_analysis",
            "identity",
            "violations",
            "warnings",
        ):
            self.assertIn(key, payload)
        self.assertIn(payload["verdict_word"], ("FAILED", "GATED", "PASSED"))
        json.dumps(payload)  # must be JSON-serializable end to end

    def test_json_payload_degraded_never_null(self):
        envelope = _envelope(_statement(omit_degraded_field=True))
        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        payload = _build_verify_json_payload(result)

        self.assertIs(payload["release_confidence_score"]["degraded"], False)
        self.assertIs(payload["release_confidence_score"]["degraded_field_present"], False)

    def test_json_payload_slsa_matches_text_output_checklist(self):
        """Regression guard for the exact bug this merge fixes: --format
        json's "slsa" block and the text formatter's SLSA checklist
        (_format_slsa_report) must be the same underlying assessment
        (result.slsa_level1/slsa_level2), never two independently computed
        (and potentially disagreeing) SLSA verdicts for the same run."""
        envelope = _envelope(_statement(rcs_value=85))
        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        payload = _build_verify_json_payload(result)

        self.assertIs(payload["slsa"]["level_1"], result.slsa_level1)
        self.assertIs(payload["slsa"]["level_2"], result.slsa_level2)
        self.assertEqual(payload["slsa"]["level_1"]["passed"], result.slsa_level1["passed"])
        self.assertEqual(
            [line for line in _format_slsa_report(result.slsa_level1, result.slsa_level2)],
            _format_slsa_report(payload["slsa"]["level_1"], payload["slsa"]["level_2"]),
        )


class CertificateIdentityClaimsTests(unittest.TestCase):
    """Unit tests for cli.verify's certificate SAN / GitHub OIDC extension
    claims matching, exercised directly against synthetic Fulcio-shaped
    certificates (see _make_fulcio_style_cert) rather than through a full
    network Sigstore verification round-trip."""

    def _cert(self, **overrides):
        defaults = dict(
            san_uri="https://github.com/acme/widgets/.github/workflows/assay.yml@refs/heads/main",
            issuer=GITHUB_ACTIONS_OIDC_ISSUER,
            repository="acme/widgets",
            workflow_name="Tenax Assay",
            ref="refs/heads/main",
        )
        defaults.update(overrides)
        return _make_fulcio_style_cert(**defaults)

    def test_matching_repository_workflow_and_ref_passes(self):
        cert = self._cert()
        policy, unsafe, _ = _build_identity_policy(
            cert_identity=None,
            cert_oidc_issuer=None,
            expected_issuer=None,
            expected_repository="acme/widgets",
            expected_workflow="Tenax Assay",
            expected_ref="refs/heads/main",
        )
        self.assertFalse(unsafe)
        policy.verify(cert)  # must not raise

    def test_mismatched_repository_fails(self):
        cert = self._cert(repository="acme/widgets")
        policy, _, _ = _build_identity_policy(
            cert_identity=None, cert_oidc_issuer=None, expected_issuer=None,
            expected_repository="attacker/evil-fork", expected_workflow=None, expected_ref=None,
        )
        from sigstore.errors import VerificationError

        with self.assertRaises(VerificationError):
            policy.verify(cert)

    def test_mismatched_issuer_fails(self):
        cert = self._cert(issuer="https://gitlab.com")
        policy, _, _ = _build_identity_policy(
            cert_identity=None, cert_oidc_issuer=None,
            expected_issuer=GITHUB_ACTIONS_OIDC_ISSUER,
            expected_repository=None, expected_workflow=None, expected_ref=None,
        )
        from sigstore.errors import VerificationError

        with self.assertRaises(VerificationError):
            policy.verify(cert)

    def test_mismatched_workflow_name_fails(self):
        cert = self._cert(workflow_name="Some Other Workflow")
        policy, _, _ = _build_identity_policy(
            cert_identity=None, cert_oidc_issuer=None, expected_issuer=None,
            expected_repository=None, expected_workflow="Tenax Assay", expected_ref=None,
        )
        from sigstore.errors import VerificationError

        with self.assertRaises(VerificationError):
            policy.verify(cert)

    def test_repository_matches_via_v2_source_repository_uri_when_v1_absent(self):
        cert = self._cert(repository=None, source_repository_uri="https://github.com/acme/widgets")
        policy, _, _ = _build_identity_policy(
            cert_identity=None, cert_oidc_issuer=None, expected_issuer=None,
            expected_repository="acme/widgets", expected_workflow=None, expected_ref=None,
        )
        # AnyOf(v1, v2) accepts the v2-only cert -- policy.verify() returns
        # None on success (raises on failure), so assertIsNone both proves
        # it didn't raise and pins the documented return contract.
        self.assertIsNone(policy.verify(cert))

    def test_ref_glob_pattern_matches(self):
        cert = self._cert(ref="refs/heads/release/1.0")
        policy, _, _ = _build_identity_policy(
            cert_identity=None, cert_oidc_issuer=None, expected_issuer=None,
            expected_repository=None, expected_workflow=None, expected_ref="refs/heads/release/*",
        )
        self.assertIsNone(policy.verify(cert))

    def test_ref_glob_pattern_mismatch_fails(self):
        cert = self._cert(ref="refs/heads/feature/x")
        policy, _, _ = _build_identity_policy(
            cert_identity=None, cert_oidc_issuer=None, expected_issuer=None,
            expected_repository=None, expected_workflow=None, expected_ref="refs/heads/main",
        )
        from sigstore.errors import VerificationError

        with self.assertRaises(VerificationError):
            policy.verify(cert)

    def test_ref_matches_via_v2_extension_when_v1_absent(self):
        cert = self._cert(ref="refs/tags/v1.2.3", ref_is_v2=True)
        self.assertEqual(_extract_cert_ref(cert), "refs/tags/v1.2.3")
        policy, _, _ = _build_identity_policy(
            cert_identity=None, cert_oidc_issuer=None, expected_issuer=None,
            expected_repository=None, expected_workflow=None, expected_ref="refs/tags/v*",
        )
        policy.verify(cert)

    def test_missing_ref_extension_fails_closed(self):
        cert = self._cert(ref=None)
        self.assertIsNone(_extract_cert_ref(cert))
        policy, _, _ = _build_identity_policy(
            cert_identity=None, cert_oidc_issuer=None, expected_issuer=None,
            expected_repository=None, expected_workflow=None, expected_ref="refs/heads/main",
        )
        from sigstore.errors import VerificationError

        with self.assertRaises(VerificationError):
            policy.verify(cert)

    def test_no_identity_assertions_yields_unsafe_noop(self):
        policy, unsafe, detail = _build_identity_policy(
            cert_identity=None, cert_oidc_issuer=None, expected_issuer=None,
            expected_repository=None, expected_workflow=None, expected_ref=None,
        )
        self.assertTrue(unsafe)
        self.assertIn("identity", detail.lower())
        # UnsafeNoOp() genuinely never raises, by design -- confirm the
        # "unsafe" flag is how callers are meant to detect this, not an
        # exception from .verify().
        policy.verify(self._cert(repository="literally-anything/at-all"))

    def test_expected_repository_alone_defaults_issuer_to_github_actions(self):
        cert = self._cert(issuer=GITHUB_ACTIONS_OIDC_ISSUER)
        policy, unsafe, detail = _build_identity_policy(
            cert_identity=None, cert_oidc_issuer=None, expected_issuer=None,
            expected_repository="acme/widgets", expected_workflow=None, expected_ref=None,
        )
        self.assertFalse(unsafe)
        self.assertIn(GITHUB_ACTIONS_OIDC_ISSUER, detail)
        policy.verify(cert)  # passes: cert's issuer really is GitHub Actions'

        wrong_issuer_cert = self._cert(issuer="https://gitlab.com")
        from sigstore.errors import VerificationError

        with self.assertRaises(VerificationError):
            policy.verify(wrong_issuer_cert)  # same policy object, different cert

    def test_explicit_expected_issuer_overrides_default(self):
        cert = self._cert(issuer="https://token.actions.githubusercontent.com/enterprise-slug")
        policy, _, detail = _build_identity_policy(
            cert_identity=None, cert_oidc_issuer=None,
            expected_issuer="https://token.actions.githubusercontent.com/enterprise-slug",
            expected_repository="acme/widgets", expected_workflow=None, expected_ref=None,
        )
        # explicit issuer wins over the GH Actions default
        self.assertIsNone(policy.verify(cert))

    def test_cert_identity_and_issuer_combination_still_supported(self):
        cert = self._cert(
            san_uri="https://github.com/acme/widgets/.github/workflows/assay.yml@refs/heads/main",
            issuer=GITHUB_ACTIONS_OIDC_ISSUER,
        )
        policy, unsafe, _ = _build_identity_policy(
            cert_identity="https://github.com/acme/widgets/.github/workflows/assay.yml@refs/heads/main",
            cert_oidc_issuer=GITHUB_ACTIONS_OIDC_ISSUER,
            expected_issuer=None, expected_repository=None, expected_workflow=None, expected_ref=None,
        )
        self.assertFalse(unsafe)
        policy.verify(cert)

    def test_mismatched_cert_identity_fails(self):
        """A cert signed by a different workflow entirely (different repo,
        different workflow file) must be rejected outright -- this is the
        exact bypass --cert-identity exists to close: some other workflow
        that ever acquired id-token: write must not be able to impersonate
        the quarantined signer."""
        cert = self._cert(
            san_uri="https://github.com/tenax-io/tenax-assay/.github/workflows/assay.yml@refs/heads/main",
            issuer=GITHUB_ACTIONS_OIDC_ISSUER,
        )
        policy, unsafe, _ = _build_identity_policy(
            cert_identity="https://github.com/tenax-io/tenax-attest/.github/workflows/sign.yml@11086bc4004f0e0e061a3c3e30223535f696e1f0",
            cert_oidc_issuer=GITHUB_ACTIONS_OIDC_ISSUER,
            expected_issuer=None, expected_repository=None, expected_workflow=None, expected_ref=None,
        )
        self.assertFalse(unsafe)
        from sigstore.errors import VerificationError

        with self.assertRaises(VerificationError):
            policy.verify(cert)

    def test_cert_identity_rejects_prefix_match(self):
        """A SAN that merely starts with (or extends) the expected identity
        string must not verify -- sp.Identity matches via Python `in` against
        a *set* of exact SAN strings (see sigstore.verify.policy.Identity),
        never a prefix/substring test, so an attacker-controlled workflow
        path that happens to share a prefix (e.g. a same-named workflow file
        one path segment deeper, or an extra trailing ref segment) must still
        be rejected."""
        expected = "https://github.com/tenax-io/tenax-attest/.github/workflows/sign.yml@11086bc4004f0e0e061a3c3e30223535f696e1f0"
        cert = self._cert(
            san_uri=expected + "-evil",  # expected is a strict prefix of the actual SAN
            issuer=GITHUB_ACTIONS_OIDC_ISSUER,
        )
        policy, _, _ = _build_identity_policy(
            cert_identity=expected,
            cert_oidc_issuer=GITHUB_ACTIONS_OIDC_ISSUER,
            expected_issuer=None, expected_repository=None, expected_workflow=None, expected_ref=None,
        )
        from sigstore.errors import VerificationError

        with self.assertRaises(VerificationError):
            policy.verify(cert)

    def test_cert_oidc_issuer_alone_matches(self):
        cert = self._cert(issuer=GITHUB_ACTIONS_OIDC_ISSUER)
        policy, unsafe, _ = _build_identity_policy(
            cert_identity=None,
            cert_oidc_issuer=GITHUB_ACTIONS_OIDC_ISSUER,
            expected_issuer=None, expected_repository=None, expected_workflow=None, expected_ref=None,
        )
        self.assertFalse(unsafe)
        policy.verify(cert)  # must not raise

    def test_cert_oidc_issuer_alone_mismatch_fails(self):
        cert = self._cert(issuer="https://gitlab.com")
        policy, _, _ = _build_identity_policy(
            cert_identity=None,
            cert_oidc_issuer=GITHUB_ACTIONS_OIDC_ISSUER,
            expected_issuer=None, expected_repository=None, expected_workflow=None, expected_ref=None,
        )
        from sigstore.errors import VerificationError

        with self.assertRaises(VerificationError):
            policy.verify(cert)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _fake_cert_pem() -> str:
    """A syntactically valid (but not Fulcio-issued) self-signed PEM
    certificate, for tests that only need `_pem_to_der_b64` to succeed --
    not a real Sigstore identity/trust-chain check."""
    from cryptography.hazmat.primitives import serialization

    return _make_fulcio_style_cert().public_bytes(serialization.Encoding.PEM).decode("ascii")


def _schema_valid_sigstore_bundle() -> dict:
    """A full, schema-shaped Sigstore bundle dict -- i.e. exactly what
    `sigstore sign --bundle` writes to disk and cli.oidc_signer now embeds
    verbatim under `_sigstore_bundle`. The signature/log-entry material is
    placeholder (not cryptographically valid -- this doesn't exercise
    signature/inclusion-proof *verification*), but every field
    sigstore.models.Bundle requires to construct -- a real DER certificate,
    plus tlogEntries' kindVersion/inclusionProof (with checkpoint)/
    inclusionPromise/canonicalizedBody -- is present and correctly typed,
    so Bundle.from_json() must accept it structurally."""
    from cryptography.hazmat.primitives import serialization

    cert_der = _make_fulcio_style_cert().public_bytes(serialization.Encoding.DER)

    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": _b64(cert_der)},
            "tlogEntries": [
                {
                    "logIndex": "0",
                    "logId": {"keyId": _b64(b"fake-log-id")},
                    "kindVersion": {"kind": "dsse", "version": "0.0.2"},
                    "integratedTime": "1700000000",
                    "inclusionPromise": {"signedEntryTimestamp": _b64(b"fake-set")},
                    "inclusionProof": {
                        "logIndex": "0",
                        "rootHash": _b64(b"fake-root-hash"),
                        "treeSize": "1",
                        "hashes": [_b64(b"fake-hash")],
                        "checkpoint": {"envelope": "fake-checkpoint-envelope"},
                    },
                    "canonicalizedBody": _b64(b"fake-canonicalized-body"),
                }
            ],
        },
        "dsseEnvelope": {
            "payload": _b64(b'{"fake": "statement"}'),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": _b64(b"fake-signature")}],
        },
    }


class EnvelopeToBundleJsonTests(unittest.TestCase):
    """Regression coverage for the Sigstore bundle round-trip: cli.verify
    must hand a full, previously-embedded bundle straight to
    sigstore.models.Bundle.from_json() rather than hand-reconstructing a
    partial one from a handful of extracted fields (which can never satisfy
    Bundle's schema, since tlogEntries' kindVersion/inclusionProof/
    canonicalizedBody are required, not optional)."""

    def test_embedded_full_bundle_round_trips_verbatim(self):
        full_bundle = _schema_valid_sigstore_bundle()
        envelope = _envelope(_statement(), signatures=[{"sig": "s", "certificate": "c"}])
        envelope["_sigstore_bundle"] = full_bundle

        raw_json = _envelope_to_bundle_json(envelope)

        self.assertEqual(json.loads(raw_json), full_bundle)

    def test_embedded_full_bundle_satisfies_sigstore_bundle_schema(self):
        from sigstore.models import Bundle

        full_bundle = _schema_valid_sigstore_bundle()
        envelope = _envelope(_statement(), signatures=[{"sig": "s", "certificate": "c"}])
        envelope["_sigstore_bundle"] = full_bundle

        # Every field Bundle's pydantic schema requires (including the
        # tlogEntries fields the old hand-reconstruction dropped) is
        # present in the embedded bundle, so parsing succeeds and returns
        # a real Bundle rather than raising.
        bundle = Bundle.from_json(_envelope_to_bundle_json(envelope))
        self.assertIsInstance(bundle, Bundle)

    def test_missing_embedded_bundle_falls_back_to_legacy_reconstruction(self):
        # Envelopes minted before `_sigstore_bundle` existed (no key at
        # all) must still produce *some* bundle JSON via the legacy
        # sig/certificate/_rekor reconstruction, not raise a KeyError.
        envelope = _envelope(
            _statement(),
            signatures=[{"sig": "s", "certificate": _fake_cert_pem()}],
        )
        self.assertNotIn("_sigstore_bundle", envelope)

        raw_json = _envelope_to_bundle_json(envelope)

        reconstructed = json.loads(raw_json)
        self.assertEqual(
            reconstructed["mediaType"], "application/vnd.dev.sigstore.bundle.v0.3+json"
        )

    def test_null_embedded_bundle_falls_back_to_legacy_reconstruction(self):
        # cli.oidc_signer always writes the `_sigstore_bundle` key, but it's
        # null for --dry-run-sign envelopes; null must be treated the same
        # as "absent", not handed to Bundle.from_json() as-is.
        envelope = _envelope(
            _statement(),
            signatures=[{"sig": "s", "certificate": _fake_cert_pem()}],
        )
        envelope["_sigstore_bundle"] = None

        raw_json = _envelope_to_bundle_json(envelope)

        reconstructed = json.loads(raw_json)
        self.assertEqual(
            reconstructed["mediaType"], "application/vnd.dev.sigstore.bundle.v0.3+json"
        )


class DescribeActualCertClaimsTests(unittest.TestCase):
    """Coverage for the human-readable actual-claims summary printed to
    stderr when identity verification fails (see
    VerifySigstoreIdentityDiagnosticsTests below)."""

    def test_reports_all_present_claims(self):
        cert = _make_fulcio_style_cert(
            san_uri="https://github.com/acme/widgets/.github/workflows/assay.yml@refs/heads/main",
            issuer=GITHUB_ACTIONS_OIDC_ISSUER,
            repository="acme/widgets",
            workflow_name="Tenax Assay",
            ref="refs/heads/main",
        )

        summary = _describe_actual_cert_claims(cert)

        self.assertIn("acme/widgets", summary)
        self.assertIn(GITHUB_ACTIONS_OIDC_ISSUER, summary)
        self.assertIn("Tenax Assay", summary)
        self.assertIn("refs/heads/main", summary)
        self.assertIn(
            "https://github.com/acme/widgets/.github/workflows/assay.yml@refs/heads/main", summary
        )

    def test_v2_only_repository_and_ref_still_reported(self):
        cert = _make_fulcio_style_cert(
            repository=None,
            source_repository_uri="https://github.com/acme/widgets",
            ref="refs/tags/v1.2.3",
            ref_is_v2=True,
        )

        summary = _describe_actual_cert_claims(cert)

        self.assertIn("https://github.com/acme/widgets", summary)
        self.assertIn("refs/tags/v1.2.3", summary)

    def test_missing_claims_reported_as_none_not_raised(self):
        cert = _make_fulcio_style_cert()  # no SAN, no GitHub OIDC extensions at all

        summary = _describe_actual_cert_claims(cert)  # must not raise

        self.assertIn("SAN=None", summary)
        self.assertIn("issuer=None", summary)
        self.assertIn("repository=None", summary)
        self.assertIn("workflow=None", summary)
        self.assertIn("ref=None", summary)


class VerifySigstoreIdentityDiagnosticsTests(unittest.TestCase):
    """Regression coverage: on a genuine Sigstore identity-policy mismatch,
    cli.verify must log the expected vs. actual certificate claims to
    stderr, so the mismatch is immediately diagnoseable straight from CI
    logs rather than just a bare exception message."""

    def test_failed_verification_logs_expected_vs_actual_claims_to_stderr(self):
        import contextlib
        import io
        from unittest import mock

        from sigstore.errors import VerificationError

        actual_cert = _make_fulcio_style_cert(
            san_uri="https://github.com/acme/widgets/.github/workflows/assay.yml@refs/heads/main",
            issuer=GITHUB_ACTIONS_OIDC_ISSUER,
            repository="acme/widgets",
            workflow_name="Tenax Assay",
            ref="refs/heads/main",
        )
        fake_bundle = mock.Mock()
        fake_bundle.signing_certificate = actual_cert

        envelope = _envelope(
            _statement(),
            signatures=[{"sig": "c2ln", "certificate": _fake_cert_pem()}],
        )

        with mock.patch("sigstore.models.Bundle.from_json", return_value=fake_bundle), mock.patch(
            "sigstore.verify.Verifier.production"
        ) as mock_production:
            mock_verifier = mock.Mock()
            mock_verifier.verify_dsse.side_effect = VerificationError(
                "certificate repository mismatch"
            )
            mock_production.return_value = mock_verifier

            captured_stderr = io.StringIO()
            with contextlib.redirect_stderr(captured_stderr):
                status, detail = _verify_sigstore_identity(
                    envelope,
                    dry_run=False,
                    cert_identity=None,
                    cert_oidc_issuer=None,
                    expected_repository="attacker/evil-fork",
                )

        self.assertEqual(status, "failed")
        stderr_output = captured_stderr.getvalue()
        self.assertIn("expected:", stderr_output)
        self.assertIn("attacker/evil-fork", stderr_output)
        self.assertIn("actual:", stderr_output)
        self.assertIn("acme/widgets", stderr_output)
        self.assertIn("certificate repository mismatch", stderr_output)


def _slsa_provenance_statement(
    *,
    statement_type="https://in-toto.io/Statement/v1",
    predicate_type=SLSA_PROVENANCE_PREDICATE_TYPE,
    subject_digests=None,
    build_type="https://actions.github.io/buildtypes/workflow/v1",
    invocation_id="run-12345",
    started_on="2026-08-23T00:00:00Z",
    finished_on="2026-08-23T00:05:00Z",
    builder_id="https://github.com/actions/runner",
    repository="https://github.com/acme/widgets",
    resolved_dependencies=None,
):
    """Builds a fully SLSA v1.0 Build Level 1+2-shaped in-toto Statement
    (buildDefinition/runDetails/externalParameters), with every field
    individually overridable so tests can knock out exactly one checklist
    item at a time. Passing None for a field omits it (or, for
    subject_digests/resolved_dependencies, an explicit [] empties it)."""
    predicate: Dict[str, Any] = {}

    build_definition: Dict[str, Any] = {}
    if build_type is not None:
        build_definition["buildType"] = build_type
    if repository is not None:
        build_definition["externalParameters"] = {"workflow": {"repository": repository}}
    if resolved_dependencies is not None:
        build_definition["resolvedDependencies"] = resolved_dependencies
    predicate["buildDefinition"] = build_definition

    run_details: Dict[str, Any] = {}
    if builder_id is not None:
        run_details["builder"] = {"id": builder_id}
    metadata = {}
    if invocation_id is not None:
        metadata["invocationId"] = invocation_id
    if started_on is not None:
        metadata["startedOn"] = started_on
    if finished_on is not None:
        metadata["finishedOn"] = finished_on
    run_details["metadata"] = metadata
    predicate["runDetails"] = run_details

    subject = (
        [{"name": "pkg:generic/widget", "digest": {"sha256": SUBJECT_DIGEST}}]
        if subject_digests is None
        else subject_digests
    )

    return {
        "_type": statement_type,
        "subject": subject,
        "predicateType": predicate_type,
        "predicate": predicate,
    }


DEFAULT_RESOLVED_DEPENDENCIES = [
    {"uri": f"pkg:pypi/pkg{i}@1.0.0", "digest": {"sha256": "b" * 64}} for i in range(142)
]


class EvaluateSlsaL1Tests(unittest.TestCase):
    def test_fully_compliant_statement_passes_all_items(self):
        statement = _slsa_provenance_statement(resolved_dependencies=DEFAULT_RESOLVED_DEPENDENCIES)

        assessment = _evaluate_slsa_l1(statement)

        self.assertEqual(assessment["level"], 1)
        self.assertTrue(assessment["passed"])
        self.assertTrue(all(item["passed"] for item in assessment["items"]))
        self.assertEqual(len(assessment["items"]), 4)

    def test_wrong_statement_type_fails_that_item_only(self):
        statement = _slsa_provenance_statement(statement_type="https://example.com/not-in-toto")

        assessment = _evaluate_slsa_l1(statement)

        self.assertFalse(assessment["passed"])
        by_label = {i["label"]: i for i in assessment["items"]}
        self.assertFalse(by_label["in-toto v1 Statement Envelope"]["passed"])
        self.assertIn("https://example.com/not-in-toto", by_label["in-toto v1 Statement Envelope"]["detail"])
        # Every other item is still independently evaluated and passes.
        self.assertTrue(by_label["SLSA v1.0 Provenance Predicate"]["passed"])
        self.assertTrue(by_label["Subject Artifact Digest Verification"]["passed"])

    def test_wrong_predicate_type_fails(self):
        statement = _slsa_provenance_statement(predicate_type="https://tenax.io/attestations/assay/v1")

        assessment = _evaluate_slsa_l1(statement)

        self.assertFalse(assessment["passed"])
        by_label = {i["label"]: i for i in assessment["items"]}
        self.assertFalse(by_label["SLSA v1.0 Provenance Predicate"]["passed"])

    def test_missing_build_type_fails_combined_item(self):
        statement = _slsa_provenance_statement(build_type=None)

        assessment = _evaluate_slsa_l1(statement)

        by_label = {i["label"]: i for i in assessment["items"]}
        item = by_label["Build Definition & Invocation Metadata"]
        self.assertFalse(item["passed"])
        self.assertIn("buildDefinition.buildType", item["detail"])

    def test_missing_invocation_metadata_fails_combined_item(self):
        statement = _slsa_provenance_statement(invocation_id=None, started_on=None, finished_on=None)

        assessment = _evaluate_slsa_l1(statement)

        by_label = {i["label"]: i for i in assessment["items"]}
        item = by_label["Build Definition & Invocation Metadata"]
        self.assertFalse(item["passed"])
        self.assertIn("invocationId", item["detail"])

    def test_started_and_finished_on_satisfy_metadata_without_invocation_id(self):
        statement = _slsa_provenance_statement(invocation_id=None, started_on="a", finished_on="b")

        assessment = _evaluate_slsa_l1(statement)

        by_label = {i["label"]: i for i in assessment["items"]}
        self.assertTrue(by_label["Build Definition & Invocation Metadata"]["passed"])

    def test_only_started_on_without_finished_on_is_insufficient(self):
        statement = _slsa_provenance_statement(invocation_id=None, started_on="a", finished_on=None)

        assessment = _evaluate_slsa_l1(statement)

        by_label = {i["label"]: i for i in assessment["items"]}
        self.assertFalse(by_label["Build Definition & Invocation Metadata"]["passed"])

    def test_missing_subject_digest_fails(self):
        statement = _slsa_provenance_statement(subject_digests=[])

        assessment = _evaluate_slsa_l1(statement)

        by_label = {i["label"]: i for i in assessment["items"]}
        self.assertFalse(by_label["Subject Artifact Digest Verification"]["passed"])

    def test_non_dict_predicate_fails_closed_without_raising(self):
        statement = {"_type": "https://in-toto.io/Statement/v1", "predicateType": "x", "predicate": "not-a-dict"}

        assessment = _evaluate_slsa_l1(statement)

        self.assertFalse(assessment["passed"])

    def test_empty_statement_fails_every_item_without_raising(self):
        assessment = _evaluate_slsa_l1({})

        self.assertFalse(assessment["passed"])
        self.assertTrue(all(not i["passed"] for i in assessment["items"]))


class EvaluateSlsaL2Tests(unittest.TestCase):
    def _l2(self, statement, *, identity_status="verified", identity_detail="ok", expected_repository=None):
        return _evaluate_slsa_l2(
            statement,
            identity_status=identity_status,
            identity_detail=identity_detail,
            expected_repository=expected_repository,
        )

    def test_fully_compliant_statement_passes_all_items(self):
        statement = _slsa_provenance_statement(resolved_dependencies=DEFAULT_RESOLVED_DEPENDENCIES)

        assessment = self._l2(statement, expected_repository="acme/widgets")

        self.assertEqual(assessment["level"], 2)
        self.assertTrue(assessment["passed"])
        self.assertEqual(len(assessment["items"]), 4)
        by_label = {i["label"]: i for i in assessment["items"]}
        self.assertIn("Hosted Builder Identity (https://github.com/actions/runner)", by_label)
        self.assertIn("Materialized Resolved Dependencies (142 packages recorded)", by_label)

    def test_untrusted_builder_id_fails(self):
        statement = _slsa_provenance_statement(builder_id="https://evil.example.com/self-hosted")

        assessment = self._l2(statement)

        item = next(i for i in assessment["items"] if i["label"].startswith("Hosted Builder Identity"))
        self.assertFalse(item["passed"])
        self.assertIn("not in the trusted hosted-builder allowlist", item["detail"])

    def test_missing_builder_id_fails(self):
        statement = _slsa_provenance_statement(builder_id=None)

        assessment = self._l2(statement)

        item = next(i for i in assessment["items"] if i["label"] == "Hosted Builder Identity")
        self.assertFalse(item["passed"])

    def test_trusted_builder_id_is_the_documented_constant(self):
        # Sanity check that the allowlist actually contains the builder id
        # used throughout this test file's fixtures/examples.
        self.assertIn("https://github.com/actions/runner", TRUSTED_HOSTED_BUILDER_IDS)

    def test_unverified_signature_fails_that_item(self):
        statement = _slsa_provenance_statement()

        assessment = self._l2(statement, identity_status="unavailable", identity_detail="offline")

        by_label = {i["label"]: i for i in assessment["items"]}
        item = by_label["Cryptographic Envelope Signature (Sigstore Keyless OIDC)"]
        self.assertFalse(item["passed"])
        self.assertIn("unavailable", item["detail"])
        self.assertIn("offline", item["detail"])

    def test_verified_signature_passes(self):
        statement = _slsa_provenance_statement()

        assessment = self._l2(statement, identity_status="verified", identity_detail="ok")

        by_label = {i["label"]: i for i in assessment["items"]}
        self.assertTrue(by_label["Cryptographic Envelope Signature (Sigstore Keyless OIDC)"]["passed"])

    def test_missing_source_repository_fails(self):
        statement = _slsa_provenance_statement(repository=None)

        assessment = self._l2(statement)

        by_label = {i["label"]: i for i in assessment["items"]}
        self.assertFalse(by_label["Authenticated Source Repository Binding"]["passed"])

    def test_source_repository_mismatch_fails_when_expected_repository_given(self):
        statement = _slsa_provenance_statement(repository="https://github.com/acme/widgets")

        assessment = self._l2(statement, expected_repository="someone-else/other-repo")

        by_label = {i["label"]: i for i in assessment["items"]}
        item = by_label["Authenticated Source Repository Binding"]
        self.assertFalse(item["passed"])
        self.assertIn("someone-else/other-repo", item["detail"])

    def test_source_repository_present_passes_without_expected_repository(self):
        statement = _slsa_provenance_statement(repository="https://github.com/acme/widgets")

        assessment = self._l2(statement, expected_repository=None)

        by_label = {i["label"]: i for i in assessment["items"]}
        self.assertTrue(by_label["Authenticated Source Repository Binding"]["passed"])

    def test_missing_resolved_dependencies_fails(self):
        statement = _slsa_provenance_statement(resolved_dependencies=None)
        # buildDefinition.resolvedDependencies was never set at all in this case.

        assessment = self._l2(statement)

        by_label = {i["label"]: i for i in assessment["items"]}
        self.assertFalse(by_label["Materialized Resolved Dependencies"]["passed"])

    def test_empty_resolved_dependencies_list_fails(self):
        statement = _slsa_provenance_statement(resolved_dependencies=[])

        assessment = self._l2(statement)

        by_label = {i["label"]: i for i in assessment["items"]}
        self.assertFalse(by_label["Materialized Resolved Dependencies"]["passed"])

    def test_resolved_dependencies_with_missing_uris_are_not_counted(self):
        statement = _slsa_provenance_statement(
            resolved_dependencies=[{"uri": "pkg:pypi/good@1.0"}, {"digest": {"sha256": "a" * 64}}, {"uri": ""}]
        )

        assessment = self._l2(statement)

        by_label = {i["label"]: i for i in assessment["items"]}
        # Only the one entry with a non-empty 'uri' should be counted.
        self.assertIn("Materialized Resolved Dependencies (1 packages recorded)", by_label)
        self.assertTrue(by_label["Materialized Resolved Dependencies (1 packages recorded)"]["passed"])

    def test_non_dict_predicate_fails_closed_without_raising(self):
        statement = {"predicate": ["not", "a", "dict"]}

        assessment = self._l2(statement)

        self.assertFalse(assessment["passed"])


class FormatSlsaReportTests(unittest.TestCase):
    def test_both_levels_passed_renders_passed_status_for_both(self):
        statement = _slsa_provenance_statement(resolved_dependencies=DEFAULT_RESOLVED_DEPENDENCIES)
        l1 = _evaluate_slsa_l1(statement)
        l2 = _evaluate_slsa_l2(
            statement, identity_status="verified", identity_detail="ok", expected_repository="acme/widgets"
        )

        lines = _format_slsa_report(l1, l2)
        text = "\n".join(lines)

        self.assertIn("=== SLSA Build Level 1 Assessment ===", text)
        self.assertIn("=== SLSA Build Level 2 Assessment ===", text)
        self.assertIn("Status: PASSED (SLSA Build Level 1)", text)
        self.assertIn("Status: PASSED (SLSA Build Level 2)", text)
        self.assertIn("[✓] in-toto v1 Statement Envelope", text)
        self.assertIn("[✓] Materialized Resolved Dependencies (142 packages recorded)", text)
        self.assertTrue(text.rstrip("\n").endswith("====================================="))

    def test_failing_item_renders_cross_mark_and_detail(self):
        statement = _slsa_provenance_statement(statement_type="https://example.com/wrong")
        l1 = _evaluate_slsa_l1(statement)
        l2 = _evaluate_slsa_l2(statement, identity_status="skipped", identity_detail="--dry-run")

        lines = _format_slsa_report(l1, l2)
        text = "\n".join(lines)

        self.assertIn("[✗] in-toto v1 Statement Envelope -- unexpected _type:", text)
        self.assertIn("Status: FAILED (SLSA Build Level 1)", text)

    def test_level2_status_fails_when_level1_fails_even_if_all_level2_items_pass(self):
        # SLSA leveling is cumulative: Level 2 can't PASS on its own merits
        # if the statement doesn't even satisfy Level 1.
        statement = _slsa_provenance_statement(
            predicate_type="https://tenax.io/attestations/assay/v1",  # breaks L1's predicateType check
            resolved_dependencies=DEFAULT_RESOLVED_DEPENDENCIES,
        )
        l1 = _evaluate_slsa_l1(statement)
        l2 = _evaluate_slsa_l2(
            statement, identity_status="verified", identity_detail="ok", expected_repository="acme/widgets"
        )
        self.assertFalse(l1["passed"])
        self.assertTrue(l2["passed"])  # every L2-specific item, evaluated independently, does pass

        lines = _format_slsa_report(l1, l2)
        text = "\n".join(lines)

        self.assertIn("Status: FAILED (SLSA Build Level 1)", text)
        self.assertIn("Status: FAILED (SLSA Build Level 2)", text)
        # But the individual Level 2 items are still shown as passing --
        # only the combined Status line reflects the Level 1 gating.
        self.assertIn("[✓] Hosted Builder Identity", text)

    def test_partially_passing_level_shows_mixed_marks(self):
        statement = _slsa_provenance_statement(builder_id=None, resolved_dependencies=DEFAULT_RESOLVED_DEPENDENCIES)
        l1 = _evaluate_slsa_l1(statement)
        l2 = _evaluate_slsa_l2(
            statement, identity_status="verified", identity_detail="ok", expected_repository="acme/widgets"
        )

        lines = _format_slsa_report(l1, l2)
        text = "\n".join(lines)

        self.assertIn("[✗] Hosted Builder Identity -- missing runDetails.builder.id", text)
        self.assertIn("[✓] Cryptographic Envelope Signature (Sigstore Keyless OIDC)", text)
        self.assertIn("Status: FAILED (SLSA Build Level 2)", text)


class SlsaInvocationOriginTests(unittest.TestCase):
    """_slsa_invocation_origin() extracts runDetails.metadata.invocationId
    -- the CI run URL slsa_provenance.py's _invocation_metadata() already
    populates -- defensively, the same fail-closed-to-None contract as the
    rest of this module's predicate parsing."""

    def test_extracts_invocation_id_when_present(self):
        predicate = {"runDetails": {"metadata": {"invocationId": "https://github.com/acme/widgets/actions/runs/1/attempts/1"}}}
        self.assertEqual(
            _slsa_invocation_origin(predicate), "https://github.com/acme/widgets/actions/runs/1/attempts/1"
        )

    def test_missing_run_details_returns_none(self):
        self.assertIsNone(_slsa_invocation_origin({}))

    def test_non_dict_run_details_returns_none(self):
        self.assertIsNone(_slsa_invocation_origin({"runDetails": "not-a-dict"}))

    def test_missing_metadata_returns_none(self):
        self.assertIsNone(_slsa_invocation_origin({"runDetails": {}}))

    def test_non_dict_metadata_returns_none(self):
        self.assertIsNone(_slsa_invocation_origin({"runDetails": {"metadata": "not-a-dict"}}))

    def test_missing_invocation_id_returns_none(self):
        self.assertIsNone(_slsa_invocation_origin({"runDetails": {"metadata": {"startedOn": "x"}}}))

    def test_non_string_invocation_id_returns_none(self):
        self.assertIsNone(_slsa_invocation_origin({"runDetails": {"metadata": {"invocationId": 12345}}}))

    def test_blank_invocation_id_returns_none(self):
        self.assertIsNone(_slsa_invocation_origin({"runDetails": {"metadata": {"invocationId": "   "}}}))


class SlsaLevelResultOriginTests(unittest.TestCase):
    def test_origin_defaults_to_none(self):
        self.assertIsNone(_slsa_level_result("Build", 1, "SLSA Build Level 1", [])["origin"])

    def test_origin_is_carried_through_when_given(self):
        result = _slsa_level_result("Build", 1, "SLSA Build Level 1", [], origin="https://example.com/run/1")
        self.assertEqual(result["origin"], "https://example.com/run/1")


class EvaluateSlsaOriginIntegrationTests(unittest.TestCase):
    """_evaluate_slsa_l1/_l2 thread _slsa_invocation_origin(predicate)
    through to the level's own "origin" field -- see
    FormatSlsaLevelBlockOriginTests for how that's rendered."""

    def test_l1_origin_reflects_statement_invocation_id(self):
        statement = _slsa_provenance_statement(invocation_id="https://github.com/acme/widgets/actions/runs/42/attempts/1")
        self.assertEqual(
            _evaluate_slsa_l1(statement)["origin"], "https://github.com/acme/widgets/actions/runs/42/attempts/1"
        )

    def test_l2_origin_reflects_statement_invocation_id(self):
        statement = _slsa_provenance_statement(invocation_id="https://github.com/acme/widgets/actions/runs/42/attempts/1")
        assessment = _evaluate_slsa_l2(statement, identity_status="verified", identity_detail="ok")
        self.assertEqual(assessment["origin"], "https://github.com/acme/widgets/actions/runs/42/attempts/1")

    def test_origin_is_none_when_statement_has_no_invocation_id(self):
        statement = _slsa_provenance_statement(invocation_id=None, started_on=None, finished_on=None)
        self.assertIsNone(_evaluate_slsa_l1(statement)["origin"])


class FormatSlsaLevelBlockOriginTests(unittest.TestCase):
    """The "Origin CI Run:" line _format_slsa_level_block renders only
    belongs inside a *failed* level's own block -- a passing level, or a
    failed level whose statement carried no invocationId, renders exactly
    as before this line existed."""

    def _level(self, *, item_passed: bool, origin):
        items = [{"label": "X", "passed": item_passed, "detail": "" if item_passed else "boom"}]
        return _slsa_level_result("Build", 1, "SLSA Build Level 1", items, origin=origin)

    def test_origin_line_shown_when_level_failed_and_origin_present(self):
        assessment = self._level(item_passed=False, origin="https://github.com/acme/widgets/actions/runs/1/attempts/1")

        lines = _format_slsa_level_block(assessment, overall_passed=False)

        self.assertIn("Origin CI Run:  https://github.com/acme/widgets/actions/runs/1/attempts/1", lines)

    def test_origin_line_omitted_when_level_passed_even_if_origin_present(self):
        assessment = self._level(item_passed=True, origin="https://github.com/acme/widgets/actions/runs/1/attempts/1")

        lines = _format_slsa_level_block(assessment, overall_passed=True)

        self.assertFalse(any(line.startswith("Origin CI Run:") for line in lines))

    def test_origin_line_omitted_when_no_origin_available(self):
        assessment = self._level(item_passed=False, origin=None)

        lines = _format_slsa_level_block(assessment, overall_passed=False)

        self.assertFalse(any(line.startswith("Origin CI Run:") for line in lines))

    def test_origin_line_rendered_immediately_before_status_line(self):
        assessment = self._level(item_passed=False, origin="https://example.com/run/1")

        lines = _format_slsa_level_block(assessment, overall_passed=False)

        origin_idx = next(i for i, line in enumerate(lines) if line.startswith("Origin CI Run:"))
        status_idx = next(i for i, line in enumerate(lines) if line.startswith("Status:"))
        self.assertEqual(origin_idx, status_idx - 1)


class VerifyDsseAttestationSlsaIntegrationTests(unittest.TestCase):
    """SLSA checklist wiring through verify_dsse_attestation(): purely
    informational, must never affect `passed`/violations regardless of
    whether the statement happens to be tenax-assay's own RCS predicate
    (which is not SLSA-provenance-shaped) or a real SLSA provenance one."""

    def test_tenax_predicate_gets_slsa_assessment_without_affecting_rcs_gate(self):
        envelope = _envelope(_statement(rcs_value=85, degraded=False))

        result = verify_dsse_attestation(envelope, min_rcs=70, dry_run=True)

        self.assertTrue(result.passed)
        self.assertIsNotNone(result.slsa_level1)
        self.assertIsNotNone(result.slsa_level2)
        # tenax-assay's own predicate isn't SLSA-provenance-shaped, so most
        # items legitimately fail -- but that must never leak into violations.
        self.assertFalse(result.slsa_level1["passed"])
        self.assertEqual(result.violations, [])

    def test_slsa_fields_present_in_as_dict(self):
        envelope = _envelope(_statement())

        result = verify_dsse_attestation(envelope, dry_run=True)
        d = result.as_dict()

        self.assertIn("slsa_level1", d)
        self.assertIn("slsa_level2", d)
        self.assertEqual(d["slsa_level1"]["level"], 1)
        self.assertEqual(d["slsa_level2"]["level"], 2)
        self.assertIn("verdict_word", d)
        self.assertIn(d["verdict_word"], ("FAILED", "GATED", "PASSED"))

    def test_malformed_envelope_still_yields_no_slsa_assessment(self):
        # verify_dsse_attestation()'s top-level malformed-envelope guard
        # returns before any SLSA evaluation is even attempted.
        result = verify_dsse_attestation("not a dict")

        self.assertIsNone(result.slsa_level1)
        self.assertIsNone(result.slsa_level2)


class FormatPctTests(unittest.TestCase):
    def test_formats_one_decimal_percentage(self):
        self.assertEqual(_format_pct(0.871), "87.1%")

    def test_zero_and_one_are_valid_rates(self):
        self.assertEqual(_format_pct(0.0), "0.0%")
        self.assertEqual(_format_pct(1.0), "100.0%")

    def test_non_numeric_is_not_available(self):
        self.assertEqual(_format_pct(None), "n/a")
        self.assertEqual(_format_pct("87%"), "n/a")

    def test_bool_is_not_treated_as_numeric(self):
        # bool is a subclass of int -- must not silently format True/False
        # as "100.0%"/"0.0%".
        self.assertEqual(_format_pct(True), "n/a")

    def test_nan_and_inf_are_not_available(self):
        self.assertEqual(_format_pct(float("nan")), "n/a")
        self.assertEqual(_format_pct(float("inf")), "n/a")


class FormatCoverageLineTests(unittest.TestCase):
    def test_total_and_patch_coverage_both_present(self):
        line = _format_coverage_line(
            {
                "coverage_overall": {"line_rate": 0.871},
                "coverage_patch": {"available": True, "line_rate": 0.925},
            }
        )
        self.assertIn("87.1%", line)
        self.assertIn("92.5%", line)
        self.assertIn("total code covered", line)
        self.assertIn("new/patch code covered", line)

    def test_patch_unavailable_shows_reason_not_a_percentage(self):
        line = _format_coverage_line(
            {
                "coverage_overall": {"line_rate": 0.50},
                "coverage_patch": {"available": False, "reason": "no PR base ref"},
            }
        )
        self.assertIn("50.0%", line)
        self.assertIn("n/a (no PR base ref)", line)

    def test_missing_metrics_degrades_to_na_without_raising(self):
        line = _format_coverage_line({})
        self.assertIn("n/a", line)


class FormatTestValidityLineTests(unittest.TestCase):
    def test_renders_valid_ratio_and_counts(self):
        line = _format_test_validity_line(
            {"assertion_density": {"total_test_functions": 156, "valid_test_functions": 142}}
        )
        self.assertIsNotNone(line)
        self.assertIn("91.0%", line)
        self.assertIn("142/156", line)
        self.assertIn("14 vanity", line)

    def test_none_when_fields_absent(self):
        # An older attestation predating valid_test_functions, or a
        # hand-built fixture that never populated assertion_density --
        # silence, not a fabricated "0% valid" claim.
        self.assertIsNone(_format_test_validity_line({}))
        self.assertIsNone(_format_test_validity_line({"assertion_density": {"total_test_functions": 10}}))

    def test_none_when_zero_test_functions(self):
        self.assertIsNone(
            _format_test_validity_line({"assertion_density": {"total_test_functions": 0, "valid_test_functions": 0}})
        )

    def test_all_valid_shows_zero_vanity(self):
        line = _format_test_validity_line(
            {"assertion_density": {"total_test_functions": 10, "valid_test_functions": 10}}
        )
        self.assertIn("100.0%", line)
        self.assertIn("0 vanity", line)


class FormatTestCoverageSummaryTests(unittest.TestCase):
    def test_empty_metrics_yields_no_lines(self):
        self.assertEqual(_format_test_coverage_summary(VerificationResult(passed=True, metrics={})), [])

    def test_coverage_line_always_present_when_metrics_nonempty(self):
        result = VerificationResult(passed=True, metrics={"coverage_overall": {"line_rate": 0.5}})
        lines = _format_test_coverage_summary(result)
        self.assertEqual(len(lines), 1)
        self.assertIn("Coverage:", lines[0])

    def test_validity_line_appended_when_available(self):
        result = VerificationResult(
            passed=True,
            metrics={
                "coverage_overall": {"line_rate": 0.5},
                "assertion_density": {"total_test_functions": 10, "valid_test_functions": 8},
            }
        )
        lines = _format_test_coverage_summary(result)
        self.assertEqual(len(lines), 2)
        self.assertIn("Test Validity:", lines[1])


class FormatAssayHealthReportTests(unittest.TestCase):
    def test_coverage_and_validity_lines_appear_before_component_breakdown(self):
        result = VerificationResult(
            passed=True,
            rcs_value=82,
            degraded=False,
            rcs_components={},
            metrics={
                "coverage_overall": {"line_rate": 0.871},
                "coverage_patch": {"available": True, "line_rate": 0.925},
                "assertion_density": {"total_test_functions": 156, "valid_test_functions": 142},
            },
        )
        lines = _format_assay_health_report(result)
        text = "\n".join(lines)

        self.assertIn("Coverage:       87.1% of total code covered, 92.5% of new/patch code covered", text)
        self.assertIn("Test Validity:  91.0% valid (142/156 test functions; 14 vanity)", text)
        rcs_idx = next(i for i, l in enumerate(lines) if l.startswith("Release Confidence Score"))
        coverage_idx = next(i for i, l in enumerate(lines) if l.startswith("Coverage:"))
        self.assertLess(rcs_idx, coverage_idx)

    def test_no_rcs_still_shows_coverage_summary(self):
        result = VerificationResult(
            passed=True,
            rcs_value=None,
            metrics={"coverage_overall": {"line_rate": 0.5}},
        )
        lines = _format_assay_health_report(result)
        text = "\n".join(lines)

        self.assertIn("Release Confidence Score: unavailable", text)
        self.assertIn("Coverage:", text)

    def test_no_metrics_at_all_omits_coverage_lines(self):
        result = VerificationResult(passed=True, rcs_value=70, metrics={})
        lines = _format_assay_health_report(result)
        self.assertFalse(any(l.startswith("Coverage:") for l in lines))
        self.assertFalse(any(l.startswith("Test Validity:") for l in lines))


class VerifyDsseAttestationTestCoverageIntegrationTests(unittest.TestCase):
    """End-to-end: coverage.patch + assertion_density fields on a real
    decoded statement flow all the way through _extract_metrics into
    result.metrics, and from there into both the text report and the
    --format json payload."""

    def _statement_with_test_coverage_data(self):
        statement = _statement(rcs_value=82)
        statement["predicate"]["coverage"]["patch"] = {"available": True, "line_rate": 0.925}
        statement["predicate"]["assertion_density"] = {
            "total_assertions": 200,
            "total_test_functions": 156,
            "density_ratio": 1.282,
            "valid_test_functions": 142,
            "valid_test_ratio": 0.910,
        }
        return statement

    def test_metrics_populated_on_result(self):
        envelope = _envelope(self._statement_with_test_coverage_data())

        result = verify_dsse_attestation(envelope, dry_run=True)

        self.assertEqual(result.metrics["coverage_patch"]["line_rate"], 0.925)
        self.assertEqual(result.metrics["assertion_density"]["valid_test_functions"], 142)

    def test_lines_appear_in_full_track_sections_report(self):
        from cli.verify import _render_track_sections

        envelope = _envelope(self._statement_with_test_coverage_data())
        result = verify_dsse_attestation(envelope, dry_run=True)

        text = "\n".join(_render_track_sections(result))
        self.assertIn("Coverage:", text)
        self.assertIn("Test Validity:", text)
        self.assertIn("91.0%", text)

    def test_test_coverage_block_present_in_json_payload(self):
        envelope = _envelope(self._statement_with_test_coverage_data())
        result = verify_dsse_attestation(envelope, dry_run=True)

        payload = _build_verify_json_payload(result)

        self.assertIn("test_coverage", payload)
        self.assertEqual(payload["test_coverage"]["assertion_density"]["valid_test_functions"], 142)
        json.dumps(payload)  # must stay JSON-serializable end to end


if __name__ == "__main__":
    unittest.main()

# Verified PR gate trigger test

def test_pr_patch_marker():
    from cli.verify import pr_patch_marker
    assert pr_patch_marker() == "patch-verified"
