"""
Post-audit defensive hardening tests:
  - Attestation envelope size guard (cli.verify.load_envelope/main)
  - Formal JSON Schema validation guard (cli.verify.verify_dsse_attestation)
  - Ambient OIDC token fetch retry/timeout bounding (cli.oidc_signer)
"""
import base64
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.verify import (
    EXIT_FILE_ERROR,
    EXIT_PASS,
    MAX_ENVELOPE_SIZE,
    EnvelopeTooLargeError,
    load_envelope,
    main,
    verify_dsse_attestation,
)

SUBJECT_DIGEST = "a" * 64


def _statement(*, predicate_overrides=None):
    """A minimal, deliberately partial predicate -- same style as
    tests/test_verify.py's _statement() helper: only the fields relevant
    to whatever's under test, not a full schema-compliant document. This
    is itself the fixture that motivates schema validation staying
    diagnostic (warnings) rather than a blocking gate -- see
    verify_dsse_attestation()'s comment at the schema-validation call
    site."""
    predicate = {
        "predicate_version": "0.1.0",
        "release_confidence_score": {
            "value": 85,
            "algorithm_version": "rcs-v0.1",
            "components": {},
            "degraded": False,
            "computed_at": "2026-08-20T02:18:40Z",
        },
        "test_verification": {
            "totals": {"tests": 4, "passed": 4, "failed": 0, "errored": 0, "skipped": 0},
        },
        "coverage": {"overall": {"line_rate": 0.9, "branch_rate": 0.8}},
    }
    if predicate_overrides is not None:
        predicate = predicate_overrides
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "registry.example.com/org/svc", "digest": {"sha256": SUBJECT_DIGEST}}],
        "predicateType": "https://tenax.io/attestations/assay/v1",
        "predicate": predicate,
    }


def _envelope(statement, *, signatures=None):
    payload_b64 = base64.b64encode(json.dumps(statement).encode("utf-8")).decode("ascii")
    if signatures is None:
        signatures = [{"sig": "DRY_RUN_UNSIGNED", "certificate": "DRY_RUN_NO_CERT"}]
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": payload_b64,
        "signatures": signatures,
        "_rekor": {"logIndex": None, "logId": None},
    }


def _write_json(doc) -> str:
    fd, path = tempfile.mkstemp(suffix=".dsse.json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    return path


class _TempFileMixin:
    def setUp(self):
        self._paths = []
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for p in self._paths:
            try:
                os.remove(p)
            except OSError:
                pass

    def _write(self, doc) -> str:
        path = _write_json(doc)
        self._paths.append(path)
        return path


class EnvelopeSizeGuardTests(_TempFileMixin, unittest.TestCase):
    """MAX_ENVELOPE_SIZE is enforced via a stat() check before any bytes
    are read -- these tests fake the reported size via os.path.getsize
    rather than actually writing multi-megabyte fixture files, so they
    stay fast while still exercising the real guard code path."""

    def test_load_envelope_rejects_oversized_file(self):
        path = self._write(_envelope(_statement()))
        with mock.patch("cli.verify.os.path.getsize", return_value=MAX_ENVELOPE_SIZE + 1):
            with self.assertRaises(EnvelopeTooLargeError) as cm:
                load_envelope(path)
        self.assertIn(str(MAX_ENVELOPE_SIZE + 1), str(cm.exception))

    def test_load_envelope_accepts_file_at_exact_limit(self):
        path = self._write(_envelope(_statement()))
        with mock.patch("cli.verify.os.path.getsize", return_value=MAX_ENVELOPE_SIZE):
            envelope = load_envelope(path)  # should not raise
        self.assertIsInstance(envelope, dict)

    def test_load_envelope_accepts_small_file_without_mocking(self):
        path = self._write(_envelope(_statement()))
        envelope = load_envelope(path)  # real file, real (small) size
        self.assertIsInstance(envelope, dict)

    def test_main_rejects_oversized_envelope_with_clear_message_and_exit_code(self):
        path = self._write(_envelope(_statement()))
        with mock.patch("cli.verify.os.path.getsize", return_value=MAX_ENVELOPE_SIZE + 1):
            with mock.patch("sys.stderr", new_callable=__import__("io").StringIO) as fake_stderr:
                exit_code = main([path])

        self.assertEqual(exit_code, EXIT_FILE_ERROR)
        self.assertIn("Attestation file exceeds maximum allowed size (10MB)", fake_stderr.getvalue())

    def test_main_does_not_exhaust_memory_reading_oversized_file_first(self):
        """The size check must happen before open()/json.load() -- patch
        open() to blow up if it's ever called on an oversized path, proving
        the guard short-circuits before any read is attempted."""
        path = self._write(_envelope(_statement()))
        real_open = open

        def _open_that_fails_if_called(*args, **kwargs):
            raise AssertionError("open() must not be called once the size guard has rejected the file")

        with mock.patch("cli.verify.os.path.getsize", return_value=MAX_ENVELOPE_SIZE + 1):
            with mock.patch("builtins.open", side_effect=_open_that_fails_if_called):
                with self.assertRaises(EnvelopeTooLargeError):
                    load_envelope(path)


class SchemaValidationGuardTests(_TempFileMixin, unittest.TestCase):
    """Formal jsonschema validation against schema/tenax-attestation-v1.schema.json.

    Deliberately diagnostic (a `warnings` entry), not a blocking gate: this
    predicate schema evolves over time (branch_governance/degraded_reasons/
    static_analysis were all added after real, already-signed attestations
    existed without them), and hand-built partial predicates -- like this
    file's own _statement() helper, and test_verify.py's -- are a
    legitimate, deliberate testing pattern elsewhere in this codebase.
    Making a schema mismatch alone block --min-rcs would fail every older
    real attestation and most of the existing test suite's fixtures.
    """

    def test_schema_noncompliant_predicate_is_flagged_not_rejected(self):
        # Missing almost every required top-level section (pipeline, vcs,
        # branch_governance, artifact, assertion_density) -- a real schema
        # mismatch, but not something that should fail an otherwise-passing
        # RCS/policy evaluation on its own.
        envelope = _envelope(_statement())
        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        self.assertEqual(result.schema_validation_status, "failed")
        self.assertTrue(any("predicate schema violation" in w for w in result.warnings))
        self.assertTrue(result.passed, result.violations)  # not blocked by schema alone

    def test_schema_compliant_predicate_passes_validation(self):
        # A fully populated, schema-conformant predicate (mirrors what
        # cli.builder.build_statement actually produces).
        predicate = {
            "predicate_version": "0.1.0",
            "pipeline": {
                "ci_provider": "github-actions", "run_id": "1", "run_attempt": 1,
                "workflow_ref": "org/repo/.github/workflows/ci.yml@refs/heads/main",
                "started_at": "2026-08-20T00:00:00Z", "finished_at": "2026-08-20T00:01:00Z",
            },
            "vcs": {"provider": "github", "repository": "org/repo", "branch": "main", "commit_sha": "b" * 40},
            "branch_governance": {
                "available": True, "branch": "main", "pull_request_required": True,
                "approvals_required": 2, "direct_push_prevented": True, "bypass_actors_count": 0,
                "admin_enforced": True, "warnings": [], "reason": "clean",
            },
            "artifact": {"subject": {"name": "registry.example.com/org/svc", "digest": {"sha256": SUBJECT_DIGEST}}},
            "test_verification": {
                "framework": "pytest", "report_format": "junit-xml", "report_sha256": "d" * 64,
                "totals": {"tests": 4, "passed": 4, "failed": 0, "errored": 0, "skipped": 0},
                "met": True,
                "duration_ms": 100,
            },
            "coverage": {
                "format": "cobertura-xml", "report_sha256": "e" * 64,
                "overall": {"line_rate": 0.9, "branch_rate": 0.8},
                "patch": {"available": True, "line_rate": 0.9, "lines_changed": 10, "lines_covered": 9, "reason": "ok"},
                "thresholds": {"overall_min": 0.6, "patch_min": 0.8, "overall_met": True, "patch_met": True},
            },
            "assertion_density": {
                "total_assertions": 20, "total_test_functions": 10, "density_ratio": 2.0, "target": 1.5, "met": True,
                "heuristics": {"empty_test_bodies": 0, "assertion_only_true": 0, "skipped_or_disabled_ratio": 0.0},
            },
            "release_confidence_score": {
                "value": 85, "algorithm_version": "rcs-v0.1", "degraded": False,
                "computed_at": "2026-08-20T00:01:00Z",
                "components": {
                    name: {
                        "weight": 0.2, "raw_score": 100.0, "weighted_score": 20.0, "reason": "ok", "available": True,
                    }
                    for name in (
                        "test_health", "patch_coverage", "overall_coverage",
                        "assertion_integrity", "governance",
                    )
                },
            },
        }
        envelope = _envelope(_statement(predicate_overrides=predicate))
        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        self.assertEqual(result.schema_validation_status, "passed")
        self.assertFalse(any("predicate schema violation" in w for w in result.warnings))

    def test_jsonschema_unavailable_degrades_to_skipped_not_a_failure(self):
        envelope = _envelope(_statement())
        with mock.patch("cli.verify._JSONSCHEMA_AVAILABLE", False):
            result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        self.assertEqual(result.schema_validation_status, "skipped")
        self.assertTrue(any("schema validation skipped" in w for w in result.warnings))
        self.assertTrue(result.passed, result.violations)

    def test_missing_schema_file_degrades_to_skipped_not_a_failure(self):
        envelope = _envelope(_statement())
        with mock.patch("cli.verify._load_schema", return_value=None):
            result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        self.assertEqual(result.schema_validation_status, "skipped")
        self.assertTrue(result.passed, result.violations)

    def test_schema_validator_raising_unexpectedly_degrades_to_skipped(self):
        envelope = _envelope(_statement())
        with mock.patch("cli.verify.jsonschema.Draft202012Validator", side_effect=RuntimeError("boom")):
            result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        self.assertEqual(result.schema_validation_status, "skipped")
        self.assertTrue(result.passed, result.violations)


class StructurallyCorruptedPayloadRejectionTests(unittest.TestCase):
    """Genuinely malformed/corrupted payloads *are* rejected -- this is the
    existing, pre-schema-guard machinery (missing/invalid RCS fields,
    undecodable payloads, etc.), still exercised end to end here."""

    def test_predicate_missing_release_confidence_score_entirely_is_rejected(self):
        envelope = _envelope(_statement(predicate_overrides={"predicate_version": "0.1.0"}))
        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        self.assertFalse(result.passed)
        self.assertTrue(any("release_confidence_score.value is missing" in v for v in result.violations))

    def test_non_dict_predicate_is_rejected(self):
        statement = _statement()
        statement["predicate"] = "not-a-dict"
        envelope = _envelope(statement)
        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        self.assertFalse(result.passed)

    def test_undecodable_base64_payload_is_rejected(self):
        envelope = _envelope(_statement())
        envelope["payload"] = "!!!not-valid-base64!!!"
        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        self.assertFalse(result.passed)
        self.assertTrue(any("failed to decode DSSE payload" in v for v in result.violations))

    def test_non_object_envelope_is_rejected(self):
        result = verify_dsse_attestation([1, 2, 3], min_rcs=0, dry_run=True)
        self.assertFalse(result.passed)


class OidcFetchRetryResilienceTests(unittest.TestCase):
    """cli.oidc_signer.fetch_ambient_oidc_token: bounded retry with capped
    backoff on the GitHub Actions branch, never an unbounded/tight loop."""

    def setUp(self):
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.githubusercontent.com/token",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "fake-request-token",
            },
        )
        self._env_patch.start()
        self.addCleanup(self._env_patch.stop)
        # Never actually sleep in tests -- the retry/backoff *logic* is
        # what's under test, not real wall-clock delay.
        self._sleep_patch = mock.patch("cli.oidc_signer.time.sleep")
        self.mock_sleep = self._sleep_patch.start()
        self.addCleanup(self._sleep_patch.stop)

    def test_succeeds_immediately_without_retry_when_first_attempt_works(self):
        from cli.oidc_signer import fetch_ambient_oidc_token

        fake_resp = mock.MagicMock()
        fake_resp.__enter__.return_value.read.return_value = json.dumps({"value": "tok-123"}).encode()
        with mock.patch("cli.oidc_signer.urllib.request.urlopen", return_value=fake_resp) as mock_urlopen:
            token = fetch_ambient_oidc_token()

        self.assertEqual(token, "tok-123")
        self.assertEqual(mock_urlopen.call_count, 1)
        self.mock_sleep.assert_not_called()

    def test_retries_transient_failures_then_succeeds(self):
        from cli.oidc_signer import fetch_ambient_oidc_token

        fake_resp = mock.MagicMock()
        fake_resp.__enter__.return_value.read.return_value = json.dumps({"value": "tok-456"}).encode()

        with mock.patch(
            "cli.oidc_signer.urllib.request.urlopen",
            side_effect=[TimeoutError("slow endpoint"), fake_resp],
        ) as mock_urlopen:
            token = fetch_ambient_oidc_token()

        self.assertEqual(token, "tok-456")
        self.assertEqual(mock_urlopen.call_count, 2)
        self.mock_sleep.assert_called_once()

    def test_gives_up_after_max_attempts_with_bounded_retry_count(self):
        from cli.oidc_signer import (
            AmbientIdentityError,
            _OIDC_FETCH_MAX_ATTEMPTS,
            fetch_ambient_oidc_token,
        )

        with mock.patch(
            "cli.oidc_signer.urllib.request.urlopen",
            side_effect=TimeoutError("persistently unreachable"),
        ) as mock_urlopen:
            with self.assertRaises(AmbientIdentityError) as cm:
                fetch_ambient_oidc_token()

        # Bounded: exactly _OIDC_FETCH_MAX_ATTEMPTS attempts, not an
        # unbounded/tight retry loop.
        self.assertEqual(mock_urlopen.call_count, _OIDC_FETCH_MAX_ATTEMPTS)
        self.assertEqual(self.mock_sleep.call_count, _OIDC_FETCH_MAX_ATTEMPTS - 1)
        self.assertIn(str(_OIDC_FETCH_MAX_ATTEMPTS), str(cm.exception))

    def test_backoff_between_attempts_is_capped_not_unbounded(self):
        from cli.oidc_signer import _OIDC_FETCH_BACKOFF_CAP_SECONDS, fetch_ambient_oidc_token, AmbientIdentityError

        with mock.patch(
            "cli.oidc_signer.urllib.request.urlopen",
            side_effect=TimeoutError("persistently unreachable"),
        ):
            with self.assertRaises(AmbientIdentityError):
                fetch_ambient_oidc_token()

        for call in self.mock_sleep.call_args_list:
            (delay,) = call.args
            self.assertLessEqual(delay, _OIDC_FETCH_BACKOFF_CAP_SECONDS)

    def test_each_attempt_still_uses_a_bounded_per_call_timeout(self):
        from cli.oidc_signer import _OIDC_FETCH_TIMEOUT_SECONDS, fetch_ambient_oidc_token

        fake_resp = mock.MagicMock()
        fake_resp.__enter__.return_value.read.return_value = json.dumps({"value": "tok"}).encode()
        with mock.patch("cli.oidc_signer.urllib.request.urlopen", return_value=fake_resp) as mock_urlopen:
            fetch_ambient_oidc_token()

        _, kwargs = mock_urlopen.call_args
        self.assertEqual(kwargs.get("timeout"), _OIDC_FETCH_TIMEOUT_SECONDS)


if __name__ == "__main__":
    unittest.main()
