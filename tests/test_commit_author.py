"""
Tests for cli.parsers.commit_author.inspect_commit_author -- the GitHub
commit-author identity check backing SLSA Source Level 3 (see
cli/verify.py's _source_check_retained_history). Mirrors
tests/test_github_rules.py's mocking style for the same
urllib-request-based GitHub REST API pattern.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.parsers.commit_author import CommitAuthorReport, inspect_commit_author, _signature_type_from_blob

_REPO = "acme/widgets"
_SHA = "b" * 40


def _mock_response(payload):
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


def _commit_payload(*, author_login=None, author_name="Some Author", author_email="someone@example.com", verification=None):
    return {
        "commit": {
            "author": {"name": author_name, "email": author_email},
            "verification": verification if verification is not None else {},
        },
        "author": ({"login": author_login} if author_login else None),
    }


class InputValidationTests(unittest.TestCase):
    def test_invalid_repository_fails_closed(self):
        result = inspect_commit_author("not-a-repo", _SHA, token="tok")
        self.assertFalse(result.available)
        self.assertIn("invalid repository", result.reason)

    def test_invalid_commit_sha_fails_closed(self):
        result = inspect_commit_author(_REPO, "not-a-sha!!", token="tok")
        self.assertFalse(result.available)
        self.assertIn("invalid commit sha", result.reason)

    def test_missing_token_fails_closed(self):
        saved = os.environ.pop("GITHUB_TOKEN", None)
        try:
            result = inspect_commit_author(_REPO, _SHA, token=None)
        finally:
            if saved is not None:
                os.environ["GITHUB_TOKEN"] = saved
        self.assertFalse(result.available)
        self.assertIn("no GITHUB_TOKEN available", result.reason)

    def test_ambient_github_token_used_when_not_passed_explicitly(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ambient-tok"}, clear=False):
            with patch("cli.parsers.commit_author.urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.return_value = _mock_response(_commit_payload(author_login="octocat"))
                result = inspect_commit_author(_REPO, _SHA, token=None)
        self.assertTrue(result.available)
        headers = mock_urlopen.call_args.args[0].headers
        self.assertEqual(headers.get("Authorization"), "Bearer ambient-tok")


class VerifiedAccountResolutionTests(unittest.TestCase):
    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_linked_github_account_is_verified(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(_commit_payload(author_login="octocat"))
        result = inspect_commit_author(_REPO, _SHA, token="tok")
        self.assertTrue(result.available)
        self.assertTrue(result.verified_github_account)
        self.assertEqual(result.github_login, "octocat")
        self.assertEqual(result.name, "Some Author")
        self.assertEqual(result.email, "someone@example.com")
        self.assertIn("octocat", result.reason)

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_unmatched_author_email_is_not_verified(self, mock_urlopen):
        """GitHub's top-level `author` is null -- the free-text
        commit.author name/email alone must never be treated as
        verification, however plausible it looks."""
        mock_urlopen.return_value = _mock_response(_commit_payload(author_login=None))
        result = inspect_commit_author(_REPO, _SHA, token="tok")
        self.assertTrue(result.available)
        self.assertFalse(result.verified_github_account)
        self.assertIsNone(result.github_login)
        self.assertEqual(result.name, "Some Author")

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_unexpected_response_shape_fails_closed(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(["not", "an", "object"])
        result = inspect_commit_author(_REPO, _SHA, token="tok")
        self.assertFalse(result.available)
        self.assertIn("unexpected response shape", result.reason)


class SignatureTypeFromBlobTests(unittest.TestCase):
    def test_pgp_header_detected(self):
        self.assertEqual(_signature_type_from_blob("-----BEGIN PGP SIGNATURE-----\n\n...\n"), "gpg")

    def test_ssh_header_detected(self):
        self.assertEqual(_signature_type_from_blob("-----BEGIN SSH SIGNATURE-----\n...\n"), "ssh")

    def test_leading_whitespace_tolerated(self):
        self.assertEqual(_signature_type_from_blob("  \n-----BEGIN SSH SIGNATURE-----\n..."), "ssh")

    def test_unrecognized_header_returns_none(self):
        self.assertIsNone(_signature_type_from_blob("-----BEGIN SOMETHING ELSE-----\n"))

    def test_none_returns_none(self):
        self.assertIsNone(_signature_type_from_blob(None))

    def test_non_string_returns_none(self):
        self.assertIsNone(_signature_type_from_blob(12345))


class CommitSignatureVerificationTests(unittest.TestCase):
    # Real shapes confirmed against GitHub's actual API (repos/lucid-provenance/
    # lucid-assay/commits/<sha>) before writing this -- both a real GitHub-signed
    # merge commit (verified/valid/PGP) and a real unsigned one, not guessed.
    _REAL_VERIFIED = {
        "verified": True,
        "reason": "valid",
        "signature": "-----BEGIN PGP SIGNATURE-----\n\nwsFcBAABCAAQ...\n-----END PGP SIGNATURE-----\n",
        "payload": "tree ...",
    }
    _REAL_UNSIGNED = {"verified": False, "reason": "unsigned", "signature": None, "payload": None}

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_real_verified_gpg_commit(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(
            _commit_payload(author_login="octocat", verification=self._REAL_VERIFIED)
        )
        result = inspect_commit_author(_REPO, _SHA, token="tok")
        self.assertTrue(result.commit_signature_verified)
        self.assertEqual(result.commit_signature_reason, "valid")
        self.assertEqual(result.commit_signature_type, "gpg")

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_real_unsigned_commit(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(
            _commit_payload(author_login="octocat", verification=self._REAL_UNSIGNED)
        )
        result = inspect_commit_author(_REPO, _SHA, token="tok")
        self.assertFalse(result.commit_signature_verified)
        self.assertEqual(result.commit_signature_reason, "unsigned")
        self.assertIsNone(result.commit_signature_type)

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_ssh_signed_commit(self, mock_urlopen):
        verification = {
            "verified": True, "reason": "valid",
            "signature": "-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----\n",
        }
        mock_urlopen.return_value = _mock_response(_commit_payload(author_login="octocat", verification=verification))
        result = inspect_commit_author(_REPO, _SHA, token="tok")
        self.assertTrue(result.commit_signature_verified)
        self.assertEqual(result.commit_signature_type, "ssh")

    def test_missing_verification_block_degrades_to_none_not_false(self):
        """A response shape with no verification block at all (older API
        version, or a hand-built test fixture predating this field) must
        report None -- distinct from a confirmed-unsigned commit's False --
        so a caller can tell 'not asked' from 'asked and no'."""
        with patch("cli.parsers.commit_author.urllib.request.urlopen") as mock_urlopen:
            payload = _commit_payload(author_login="octocat")
            del payload["commit"]["verification"]
            mock_urlopen.return_value = _mock_response(payload)
            result = inspect_commit_author(_REPO, _SHA, token="tok")
        self.assertIsNone(result.commit_signature_verified)
        self.assertIsNone(result.commit_signature_reason)
        self.assertIsNone(result.commit_signature_type)

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_signature_verification_independent_of_author_verification(self, mock_urlopen):
        """A signed commit whose author email doesn't resolve to a linked
        GitHub account (verified_github_account=False) must still report
        its own, independent signature verification result -- the two
        checks answer genuinely different questions and neither should
        suppress the other."""
        mock_urlopen.return_value = _mock_response(
            _commit_payload(author_login=None, verification=self._REAL_VERIFIED)
        )
        result = inspect_commit_author(_REPO, _SHA, token="tok")
        self.assertFalse(result.verified_github_account)
        self.assertTrue(result.commit_signature_verified)


class TransportErrorTests(unittest.TestCase):
    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_404_fails_closed_with_reason(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.github.com/x", code=404, msg="Not Found", hdrs=None, fp=None
        )
        result = inspect_commit_author(_REPO, _SHA, token="tok")
        self.assertFalse(result.available)
        self.assertIn("not found", result.reason)

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_403_fails_closed_with_status_detail(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.github.com/x", code=403, msg="Forbidden", hdrs=None, fp=None
        )
        result = inspect_commit_author(_REPO, _SHA, token="tok")
        self.assertFalse(result.available)
        self.assertIn("HTTP 403", result.reason)

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_network_failure_fails_closed(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")
        result = inspect_commit_author(_REPO, _SHA, token="tok")
        self.assertFalse(result.available)
        self.assertIn("connection refused", result.reason)


class AsDictTests(unittest.TestCase):
    def test_as_dict_shape(self):
        report = CommitAuthorReport(
            available=True,
            commit_sha=_SHA,
            name="A",
            email="a@example.com",
            github_login="a",
            verified_github_account=True,
            reason="ok",
            commit_signature_verified=True,
            commit_signature_reason="valid",
            commit_signature_type="gpg",
        )
        self.assertEqual(
            report.as_dict(),
            {
                "available": True,
                "commit_sha": _SHA,
                "name": "A",
                "email": "a@example.com",
                "github_login": "a",
                "verified_github_account": True,
                "reason": "ok",
                "commit_signature_verified": True,
                "commit_signature_reason": "valid",
                "commit_signature_type": "gpg",
            },
        )


if __name__ == "__main__":
    unittest.main()
