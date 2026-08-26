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

from cli.parsers.commit_author import CommitAuthorReport, inspect_commit_author

_REPO = "acme/widgets"
_SHA = "b" * 40


def _mock_response(payload):
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


def _commit_payload(*, author_login=None, author_name="Some Author", author_email="someone@example.com"):
    return {
        "commit": {"author": {"name": author_name, "email": author_email}},
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
            },
        )


if __name__ == "__main__":
    unittest.main()
