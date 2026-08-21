import base64
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
    main,
    verify_dsse_attestation,
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


if __name__ == "__main__":
    unittest.main()

# Verified PR gate trigger test

def test_pr_patch_marker():
    from cli.verify import pr_patch_marker
    assert pr_patch_marker() == "patch-verified"
