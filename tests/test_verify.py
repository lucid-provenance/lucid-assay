import base64
import datetime
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.verify import (
    EXIT_FILE_ERROR,
    EXIT_PASS,
    EXIT_POLICY_VIOLATION,
    GITHUB_ACTIONS_OIDC_ISSUER,
    main,
    verify_dsse_attestation,
    _build_identity_policy,
    _describe_actual_cert_claims,
    _envelope_to_bundle_json,
    _extract_cert_ref,
    _verify_sigstore_identity,
)

SUBJECT_DIGEST = "a" * 64


def _statement(*, rcs_value=85, degraded=False, subject_sha256=SUBJECT_DIGEST):
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "registry.example.com/org/svc",
                "digest": {"sha256": subject_sha256},
            }
        ],
        "predicateType": "https://plinth.dev/attestation/v1",
        "predicate": {
            "predicate_version": "0.1.0",
            "release_confidence_score": {
                "value": rcs_value,
                "algorithm_version": "rcs-v0.1",
                "components": {},
                "degraded": degraded,
                "computed_at": "2026-08-20T02:18:40Z",
            },
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


def _der_utf8_string(value: str) -> bytes:
    """DER-encodes `value` as a primitive ASN.1 UTF8String with a short-form
    length, matching how Fulcio v2 certificate extensions are encoded (and
    how cli.verify._der_decode_short_utf8_string expects to read them)."""
    encoded = value.encode("utf-8")
    assert len(encoded) < 128, "test helper only supports short-form DER lengths"
    return bytes([0x0C, len(encoded)]) + encoded


def _make_fulcio_style_cert(
    *,
    san_uri=None,
    issuer=None,
    repository=None,
    source_repository_uri=None,
    workflow_name=None,
    ref=None,
    ref_is_v2=False,
):
    """Builds a self-signed X.509 certificate carrying the same GitHub
    Actions OIDC extensions (and SAN) that a real Fulcio-issued certificate
    would carry, so cli.verify's policy-composition logic can be unit
    tested directly against `.verify(cert)` without a live Sigstore/Fulcio
    round-trip (which needs network access and a trusted root)."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "plinth-assay-test")])
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(minutes=10))
    )

    if san_uri:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san_uri)]), critical=False
        )

    def _v1(oid: str, value: str) -> x509.UnrecognizedExtension:
        return x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value.encode("utf-8"))

    if issuer:
        builder = builder.add_extension(_v1("1.3.6.1.4.1.57264.1.1", issuer), critical=False)
    if repository:
        builder = builder.add_extension(_v1("1.3.6.1.4.1.57264.1.5", repository), critical=False)
    if workflow_name:
        builder = builder.add_extension(_v1("1.3.6.1.4.1.57264.1.4", workflow_name), critical=False)
    if source_repository_uri:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.12"), _der_utf8_string(source_repository_uri)
            ),
            critical=False,
        )
    if ref:
        if ref_is_v2:
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.14"), _der_utf8_string(ref)
                ),
                critical=False,
            )
        else:
            builder = builder.add_extension(_v1("1.3.6.1.4.1.57264.1.6", ref), critical=False)

    return builder.sign(key, None)


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
            workflow_name="Plinth Assay",
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
            expected_workflow="Plinth Assay",
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
            expected_repository=None, expected_workflow="Plinth Assay", expected_ref=None,
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
        policy.verify(cert)  # must not raise -- AnyOf(v1, v2) accepts the v2-only cert

    def test_ref_glob_pattern_matches(self):
        cert = self._cert(ref="refs/heads/release/1.0")
        policy, _, _ = _build_identity_policy(
            cert_identity=None, cert_oidc_issuer=None, expected_issuer=None,
            expected_repository=None, expected_workflow=None, expected_ref="refs/heads/release/*",
        )
        policy.verify(cert)

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
        policy.verify(cert)  # must not raise: explicit issuer wins over the GH Actions default

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

        # Must not raise: every field Bundle's pydantic schema requires
        # (including the tlogEntries fields the old hand-reconstruction
        # dropped) is present in the embedded bundle.
        Bundle.from_json(_envelope_to_bundle_json(envelope))

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
            workflow_name="Plinth Assay",
            ref="refs/heads/main",
        )

        summary = _describe_actual_cert_claims(cert)

        self.assertIn("acme/widgets", summary)
        self.assertIn(GITHUB_ACTIONS_OIDC_ISSUER, summary)
        self.assertIn("Plinth Assay", summary)
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
            workflow_name="Plinth Assay",
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


if __name__ == "__main__":
    unittest.main()

# Verified PR gate trigger test

def test_pr_patch_marker():
    from cli.verify import pr_patch_marker
    assert pr_patch_marker() == "patch-verified"
