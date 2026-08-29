"""
CLI-level tests for `lucid-assay sign` (cli/sign.py) and its underlying
cli.oidc_signer.sign_file_to_envelope -- the standalone signing subcommand
used by an isolated CI job that only has an already-built unsigned
statement file, not this pipeline's in-process state (see cli/sign.py's
module docstring). Mirrors tests/test_verify.py's CLI-level style.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.main import derive_signed_path
from cli.main import main as cli_main
from cli.oidc_signer import MAX_INPUT_FILE_SIZE, InputFileTooLargeError, sign_file_to_envelope
from cli.sign import EXIT_FILE_ERROR, EXIT_PASS, EXIT_SIGNING_ERROR, main as sign_main

# GITHUB_*/CI_JOB_JWT_V2/SIGSTORE_ID_TOKEN ambient-identity env vars this
# module's fetch_ambient_oidc_token() checks -- cleared around the
# real-signing-failure tests below so they're deterministic whether or not
# they happen to run inside real CI (where most of these really are set).
_AMBIENT_IDENTITY_ENV_KEYS = (
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "SIGSTORE_ID_TOKEN",
    "CI_JOB_JWT_V2",
)


def _write(tmp_path: str, name: str, content: str) -> str:
    path = os.path.join(tmp_path, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


_STATEMENT = json.dumps({
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{"name": "r", "digest": {"sha256": "a" * 64}}],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {},
})


class _TempDirTestCase(unittest.TestCase):
    def _tmp(self) -> str:
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d


class SignFileToEnvelopeTests(_TempDirTestCase):
    def test_dry_run_writes_placeholder_signed_envelope(self):
        tmp = self._tmp()
        in_path = _write(tmp, "statement.unsigned.json", _STATEMENT)
        out_path = os.path.join(tmp, "statement.dsse.json")

        result = sign_file_to_envelope(in_path, out_path, dry_run=True)

        self.assertTrue(os.path.exists(result))
        with open(result, "r", encoding="utf-8") as f:
            envelope = json.load(f)
        self.assertEqual(envelope["payloadType"], "application/vnd.in-toto+json")
        self.assertEqual(envelope["signatures"][0]["sig"], "DRY_RUN_UNSIGNED")
        self.assertEqual(envelope["signatures"][0]["certificate"], "DRY_RUN_NO_CERT")
        # Payload round-trips back to the exact original statement bytes.
        import base64
        decoded = json.loads(base64.b64decode(envelope["payload"]))
        self.assertEqual(decoded, json.loads(_STATEMENT))

    def test_missing_input_file_raises_file_not_found(self):
        tmp = self._tmp()
        with self.assertRaises(FileNotFoundError):
            sign_file_to_envelope(
                os.path.join(tmp, "does-not-exist.json"), os.path.join(tmp, "out.json"), dry_run=True
            )

    def test_oversized_input_file_rejected_before_reading(self):
        tmp = self._tmp()
        in_path = os.path.join(tmp, "huge.json")
        with open(in_path, "wb") as f:
            f.seek(MAX_INPUT_FILE_SIZE)
            f.write(b"0")
        with self.assertRaises(InputFileTooLargeError):
            sign_file_to_envelope(in_path, os.path.join(tmp, "out.json"), dry_run=True)

    def test_timing_dict_populated_on_dry_run(self):
        tmp = self._tmp()
        in_path = _write(tmp, "statement.unsigned.json", _STATEMENT)
        timing: dict = {}
        sign_file_to_envelope(in_path, os.path.join(tmp, "out.json"), dry_run=True, timing=timing)
        self.assertEqual(timing, {"oidc_token_fetch_ns": 0, "fulcio_rekor_ns": 0})


class SignCliTests(_TempDirTestCase):
    def test_explicit_out_path_is_honored(self):
        tmp = self._tmp()
        in_path = _write(tmp, "statement.unsigned.json", _STATEMENT)
        out_path = os.path.join(tmp, "custom-signed.json")

        rc = sign_main([in_path, "--out", out_path, "--dry-run-sign"])

        self.assertEqual(rc, EXIT_PASS)
        self.assertTrue(os.path.exists(out_path))

    def test_out_defaults_via_derive_signed_path(self):
        tmp = self._tmp()
        in_path = _write(tmp, "statement.unsigned.json", _STATEMENT)

        rc = sign_main([in_path, "--dry-run-sign"])

        self.assertEqual(rc, EXIT_PASS)
        self.assertTrue(os.path.exists(derive_signed_path(in_path)))

    def test_missing_file_exits_with_file_error_and_diagnostic(self):
        tmp = self._tmp()
        buf_path = os.path.join(tmp, "does-not-exist.json")

        import io
        from contextlib import redirect_stderr

        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = sign_main([buf_path, "--dry-run-sign"])

        self.assertEqual(rc, EXIT_FILE_ERROR)
        self.assertIn("statement file not found", buf.getvalue())

    def test_dispatches_via_cli_main_sign_subcommand(self):
        tmp = self._tmp()
        in_path = _write(tmp, "statement.unsigned.json", _STATEMENT)
        out_path = os.path.join(tmp, "signed.json")

        rc = cli_main(["sign", in_path, "--out", out_path, "--dry-run-sign"])

        self.assertEqual(rc, EXIT_PASS)
        self.assertTrue(os.path.exists(out_path))

    def test_oversized_input_file_exits_with_file_error_and_diagnostic(self):
        tmp = self._tmp()
        in_path = os.path.join(tmp, "huge.json")
        with open(in_path, "wb") as f:
            f.seek(MAX_INPUT_FILE_SIZE)
            f.write(b"0")

        import io
        from contextlib import redirect_stderr

        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = sign_main([in_path, "--dry-run-sign"])

        self.assertEqual(rc, EXIT_FILE_ERROR)
        self.assertIn("exceeds maximum allowed size", buf.getvalue())

    def test_unsafe_path_exits_with_file_error_and_diagnostic(self):
        import io
        from contextlib import redirect_stderr

        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = sign_main(["bad\x00path.json", "--dry-run-sign"])

        self.assertEqual(rc, EXIT_FILE_ERROR)
        self.assertIn("unsafe path", buf.getvalue())

    def test_no_ambient_identity_exits_with_signing_error_and_diagnostic(self):
        """Without --dry-run-sign and with no ambient OIDC env vars present
        (real CI env cleared for this test), signing must fail closed with
        a diagnostic rather than silently producing an unsigned envelope --
        AmbientIdentityError is raised before any network call is made."""
        tmp = self._tmp()
        in_path = _write(tmp, "statement.unsigned.json", _STATEMENT)

        import io
        from contextlib import redirect_stderr

        saved = {k: os.environ.get(k) for k in _AMBIENT_IDENTITY_ENV_KEYS}
        for k in _AMBIENT_IDENTITY_ENV_KEYS:
            os.environ.pop(k, None)
        try:
            buf = io.StringIO()
            with redirect_stderr(buf):
                rc = sign_main([in_path])
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

        self.assertEqual(rc, EXIT_SIGNING_ERROR)
        self.assertIn("no ambient OIDC identity available", buf.getvalue())

    def test_unexpected_signing_failure_exits_with_signing_error(self):
        tmp = self._tmp()
        in_path = _write(tmp, "statement.unsigned.json", _STATEMENT)

        with mock.patch("cli.sign.sign_file_to_envelope", side_effect=RuntimeError("Sigstore signing failed: boom")):
            rc = sign_main([in_path, "--dry-run-sign"])

        self.assertEqual(rc, EXIT_SIGNING_ERROR)


if __name__ == "__main__":
    unittest.main()
