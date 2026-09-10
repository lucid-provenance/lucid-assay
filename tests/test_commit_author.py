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

from cli.parsers.commit_author import (
    CommitAuthorReport,
    inspect_commit_author,
    _fetch_associated_pr_number,
    _fetch_pr_branch_tip_sha,
    _signature_type_from_blob,
    _web_flow_merge_second_parent,
)

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


def _mock_response_sequence(*payloads):
    return [_mock_response(p) for p in payloads]


# Real shapes confirmed against GitHub's actual API 2026-09-04: a real
# GitHub-web "Merge pull request" merge commit (lucid-console PR #38,
# commit 5f27171...) and its real second parent -- the actual PR head
# commit a maintainer pushed, genuinely unsigned. Ground truth for the
# GitHub-web-flow merge commit walk-back, not guessed/synthesized.
_MERGE_SHA = "5f27171fd5aa8efd56df41e4051d8ca73a6f71a5"
_BASE_PARENT_SHA = "a0968136d09043007599560e3e1405272e17038f"
_PR_HEAD_SHA = "a0585b697a19f7197e350a772367bd5afa5bec77"

_REAL_WEB_FLOW_MERGE_COMMIT = {
    "sha": _MERGE_SHA,
    "parents": [{"sha": _BASE_PARENT_SHA}, {"sha": _PR_HEAD_SHA}],
    "committer": {"login": "web-flow"},
    "author": {"login": "billwonch"},
    "commit": {
        "author": {"name": "billwonch", "email": "84951388+billwonch@users.noreply.github.com"},
        "committer": {"name": "GitHub", "email": "noreply@github.com"},
        "verification": {
            "verified": True,
            "reason": "valid",
            "signature": "-----BEGIN PGP SIGNATURE-----\n\nwsFcBAABCAAQ...\n-----END PGP SIGNATURE-----\n",
        },
    },
}
_REAL_PR_HEAD_COMMIT_UNSIGNED = {
    "sha": _PR_HEAD_SHA,
    "parents": [{"sha": _BASE_PARENT_SHA}],
    "committer": {"login": "billwonch"},
    "author": {"login": "billwonch"},
    "commit": {
        "author": {"name": "Bill Wonch", "email": "billwonch@outlook.com"},
        "committer": {"name": "Bill Wonch", "email": "billwonch@outlook.com"},
        "verification": {"verified": False, "reason": "unsigned", "signature": None},
    },
}


class WebFlowMergeSecondParentTests(unittest.TestCase):
    def test_real_merge_commit_yields_its_second_parent(self):
        self.assertEqual(_web_flow_merge_second_parent(_REAL_WEB_FLOW_MERGE_COMMIT), _PR_HEAD_SHA)

    def test_real_pr_head_commit_is_not_treated_as_a_merge(self):
        self.assertIsNone(_web_flow_merge_second_parent(_REAL_PR_HEAD_COMMIT_UNSIGNED))

    def test_non_web_flow_committer_with_two_parents_is_not_walked(self):
        """A real human-performed `git merge` + `git push` also has 2
        parents -- but committer.login isn't 'web-flow', so it must not
        be walked back (there's no GitHub-auto-signing false positive to
        correct for)."""
        body = dict(_REAL_WEB_FLOW_MERGE_COMMIT, committer={"login": "billwonch"})
        self.assertIsNone(_web_flow_merge_second_parent(body))

    def test_squash_merge_shape_one_parent_is_not_walked(self):
        """A squash-merged commit is also web-flow-signed but has only
        one parent -- nothing for *this* parent-graph helper to walk
        back to (see SquashOrRebaseMergeCorrectionTests below for the
        higher-level PR-lookup fallback that actually corrects for this
        shape, via a different API path)."""
        body = dict(_REAL_WEB_FLOW_MERGE_COMMIT, parents=[{"sha": _BASE_PARENT_SHA}])
        self.assertIsNone(_web_flow_merge_second_parent(body))

    def test_missing_committer_is_not_walked(self):
        body = {k: v for k, v in _REAL_WEB_FLOW_MERGE_COMMIT.items() if k != "committer"}
        self.assertIsNone(_web_flow_merge_second_parent(body))

    def test_malformed_second_parent_entry_is_not_walked(self):
        body = dict(_REAL_WEB_FLOW_MERGE_COMMIT, parents=[{"sha": _BASE_PARENT_SHA}, "not-a-dict"])
        self.assertIsNone(_web_flow_merge_second_parent(body))


class WebFlowMergeCommitWalkBackTests(unittest.TestCase):
    """inspect_commit_author()'s end-to-end walk-back behavior -- built
    directly from real GitHub API responses (see the fixtures above),
    per this repo's ground-truth discipline."""

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_walks_back_to_the_real_unsigned_pr_head_commit(self, mock_urlopen):
        mock_urlopen.side_effect = _mock_response_sequence(
            _REAL_WEB_FLOW_MERGE_COMMIT, _REAL_PR_HEAD_COMMIT_UNSIGNED
        )
        result = inspect_commit_author(_REPO, _MERGE_SHA, token="tok")

        self.assertEqual(mock_urlopen.call_count, 2)
        # The signature verdict reflects the real, unsigned PR head --
        # not GitHub's own auto-signature on the merge commit itself.
        self.assertFalse(result.commit_signature_verified)
        self.assertEqual(result.commit_signature_reason, "unsigned")
        self.assertIsNone(result.commit_signature_type)
        self.assertEqual(result.commit_signature_source_sha, _PR_HEAD_SHA)
        # Author-identity fields are untouched -- still the originally
        # requested (merge) commit's own, honestly-real author.
        self.assertEqual(result.commit_sha, _MERGE_SHA)
        self.assertTrue(result.verified_github_account)
        self.assertEqual(result.github_login, "billwonch")
        self.assertEqual(result.name, "billwonch")

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_non_merge_commit_makes_only_one_api_call(self, mock_urlopen):
        mock_urlopen.side_effect = _mock_response_sequence(_REAL_PR_HEAD_COMMIT_UNSIGNED)
        result = inspect_commit_author(_REPO, _PR_HEAD_SHA, token="tok")

        self.assertEqual(mock_urlopen.call_count, 1)
        self.assertIsNone(result.commit_signature_source_sha)
        self.assertFalse(result.commit_signature_verified)

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_walked_back_commit_that_is_itself_signed_reports_verified(self, mock_urlopen):
        pr_head_signed = dict(
            _REAL_PR_HEAD_COMMIT_UNSIGNED,
            commit={
                **_REAL_PR_HEAD_COMMIT_UNSIGNED["commit"],
                "verification": {
                    "verified": True, "reason": "valid",
                    "signature": "-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----\n",
                },
            },
        )
        mock_urlopen.side_effect = _mock_response_sequence(_REAL_WEB_FLOW_MERGE_COMMIT, pr_head_signed)
        result = inspect_commit_author(_REPO, _MERGE_SHA, token="tok")

        self.assertTrue(result.commit_signature_verified)
        self.assertEqual(result.commit_signature_type, "ssh")
        self.assertEqual(result.commit_signature_source_sha, _PR_HEAD_SHA)

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_transport_error_during_walk_back_fails_closed_not_credited(self, mock_urlopen):
        mock_urlopen.side_effect = [
            _mock_response(_REAL_WEB_FLOW_MERGE_COMMIT),
            urllib.error.URLError("connection refused"),
        ]
        result = inspect_commit_author(_REPO, _MERGE_SHA, token="tok")

        self.assertIsNone(result.commit_signature_verified)
        self.assertIn("could not walk back", result.commit_signature_reason)
        # Author-identity fields still resolve fine -- the walk-back
        # failure is scoped to the signature fields only.
        self.assertTrue(result.verified_github_account)

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_walk_back_chain_exceeding_hop_bound_fails_closed(self, mock_urlopen):
        """A pathological chain of >5 consecutive web-flow merge commits
        (shouldn't occur in practice, but must not hang or silently
        credit an unverified signature) gives up after the bounded
        number of hops -- provably terminating, never unbounded."""
        chain = []
        for i in range(7):
            sha = f"{i:040x}"
            next_sha = f"{i + 1:040x}"
            chain.append({
                "sha": sha,
                "parents": [{"sha": _BASE_PARENT_SHA}, {"sha": next_sha}],
                "committer": {"login": "web-flow"},
                "author": {"login": "billwonch"},
                "commit": {
                    "author": {"name": "billwonch", "email": "b@example.com"},
                    "committer": {"name": "GitHub", "email": "noreply@github.com"},
                    "verification": {"verified": True, "reason": "valid", "signature": None},
                },
            })
        mock_urlopen.side_effect = _mock_response_sequence(*chain)
        result = inspect_commit_author(_REPO, chain[0]["sha"], token="tok")

        self.assertIsNone(result.commit_signature_verified)
        self.assertIn("gave up walking back", result.commit_signature_reason)
        self.assertIn("5 hops", result.commit_signature_reason)


# Real shapes confirmed against GitHub's actual API 2026-09-10: a real
# GitHub-web *squash* merge (lucid-assay PR #94, commit f931d63...) --
# this repo enforces Linear History, which structurally forbids the
# true 2-parent merge commit WebFlowMergeCommitWalkBackTests above
# assumes, so every real merge here takes exactly this shape. Ground
# truth for the squash/rebase-merge correction, not guessed/synthesized:
# f931d63 itself reports `verified: true` via GitHub's own key, while
# the actual human-authored branch tip GitHub squashed, f8af55a...,
# reports `verified: false, reason: "unsigned"`.
_SQUASH_MERGE_SHA = "f931d63084ead13dd42f4606f86ac8cfc06dc207"
_SQUASH_BASE_PARENT_SHA = "fe26426a98cb1f7b5ac711d4efb7b1279a98aedf"
_SQUASH_PR_NUMBER = 94
_SQUASH_PR_EARLIER_COMMIT_SHA = "e66e5cb28796aa0424667167bc3a45b658f0c405"
_SQUASH_PR_BRANCH_TIP_SHA = "f8af55af2d8f0e01c63dc10508d375e7b6f4a372"

_REAL_SQUASH_MERGE_COMMIT = {
    "sha": _SQUASH_MERGE_SHA,
    "parents": [{"sha": _SQUASH_BASE_PARENT_SHA}],
    "committer": {"login": "web-flow"},
    "author": {"login": "billwonch"},
    "commit": {
        "author": {"name": "billwonch", "email": "84951388+billwonch@users.noreply.github.com"},
        "committer": {"name": "GitHub", "email": "noreply@github.com"},
        "verification": {
            "verified": True,
            "reason": "valid",
            "signature": "-----BEGIN PGP SIGNATURE-----\n\nwsFcBAABCAAQ...\n-----END PGP SIGNATURE-----\n",
        },
    },
}
_REAL_ASSOCIATED_PRS_RESPONSE = [{"number": _SQUASH_PR_NUMBER}]
_REAL_PR_COMMITS_RESPONSE = [{"sha": _SQUASH_PR_EARLIER_COMMIT_SHA}, {"sha": _SQUASH_PR_BRANCH_TIP_SHA}]
_REAL_SQUASH_PR_BRANCH_TIP_COMMIT_UNSIGNED = {
    "sha": _SQUASH_PR_BRANCH_TIP_SHA,
    "parents": [{"sha": _SQUASH_PR_EARLIER_COMMIT_SHA}],
    "committer": {"login": "billwonch"},
    "author": {"login": "billwonch"},
    "commit": {
        "author": {"name": "Bill Wonch", "email": "billwonch@outlook.com"},
        "committer": {"name": "Bill Wonch", "email": "billwonch@outlook.com"},
        "verification": {"verified": False, "reason": "unsigned", "signature": None},
    },
}


class SquashOrRebaseMergeCorrectionTests(unittest.TestCase):
    """inspect_commit_author()'s correction for a web-flow-signed commit
    with no second parent to walk through -- formerly a known residual
    gap (see commit_author.py's docstring), now closed via the
    associated PR's own retained commit list."""

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_walks_back_to_the_real_pr_branch_tip_via_pr_lookup(self, mock_urlopen):
        mock_urlopen.side_effect = _mock_response_sequence(
            _REAL_SQUASH_MERGE_COMMIT, _REAL_ASSOCIATED_PRS_RESPONSE, _REAL_PR_COMMITS_RESPONSE,
            _REAL_SQUASH_PR_BRANCH_TIP_COMMIT_UNSIGNED,
        )
        result = inspect_commit_author(_REPO, _SQUASH_MERGE_SHA, token="tok")

        self.assertEqual(mock_urlopen.call_count, 4)
        # The signature verdict reflects the real, unsigned PR branch tip
        # -- not GitHub's own auto-signature on the squash commit itself.
        self.assertFalse(result.commit_signature_verified)
        self.assertEqual(result.commit_signature_reason, "unsigned")
        self.assertEqual(result.commit_signature_source_sha, _SQUASH_PR_BRANCH_TIP_SHA)
        # Author-identity fields are untouched -- still the originally
        # requested (squash) commit's own, honestly-real author.
        self.assertEqual(result.commit_sha, _SQUASH_MERGE_SHA)
        self.assertTrue(result.verified_github_account)
        self.assertEqual(result.github_login, "billwonch")

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_no_associated_pr_fails_closed(self, mock_urlopen):
        mock_urlopen.side_effect = _mock_response_sequence(_REAL_SQUASH_MERGE_COMMIT, [])
        result = inspect_commit_author(_REPO, _SQUASH_MERGE_SHA, token="tok")

        self.assertIsNone(result.commit_signature_verified)
        self.assertIn("no pull request associated", result.commit_signature_reason)
        # Never falls back to crediting the squash commit's own signature.
        self.assertIsNone(result.commit_signature_source_sha)

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_transport_error_resolving_associated_pr_fails_closed(self, mock_urlopen):
        mock_urlopen.side_effect = [
            _mock_response(_REAL_SQUASH_MERGE_COMMIT),
            urllib.error.URLError("connection refused"),
        ]
        result = inspect_commit_author(_REPO, _SQUASH_MERGE_SHA, token="tok")

        self.assertIsNone(result.commit_signature_verified)
        self.assertIn("resolving the PR associated with", result.commit_signature_reason)
        self.assertTrue(result.verified_github_account)

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_pr_with_no_commits_on_record_fails_closed(self, mock_urlopen):
        mock_urlopen.side_effect = _mock_response_sequence(
            _REAL_SQUASH_MERGE_COMMIT, _REAL_ASSOCIATED_PRS_RESPONSE, []
        )
        result = inspect_commit_author(_REPO, _SQUASH_MERGE_SHA, token="tok")

        self.assertIsNone(result.commit_signature_verified)
        self.assertIn("no commits on record", result.commit_signature_reason)

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_failure_fetching_branch_tip_body_fails_closed(self, mock_urlopen):
        mock_urlopen.side_effect = [
            _mock_response(_REAL_SQUASH_MERGE_COMMIT),
            _mock_response(_REAL_ASSOCIATED_PRS_RESPONSE),
            _mock_response(_REAL_PR_COMMITS_RESPONSE),
            urllib.error.HTTPError(url="https://api.github.com/x", code=404, msg="Not Found", hdrs=None, fp=None),
        ]
        result = inspect_commit_author(_REPO, _SQUASH_MERGE_SHA, token="tok")

        self.assertIsNone(result.commit_signature_verified)
        self.assertIn("could not fetch PR #94's real branch-tip commit", result.commit_signature_reason)

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_ordinary_non_web_flow_single_parent_commit_is_not_redirected(self, mock_urlopen):
        """A single-parent commit that isn't GitHub-generated (an
        ordinary, non-merge commit) must never trigger the squash/rebase
        fallback -- there's no GitHub auto-signature to correct for."""
        mock_urlopen.side_effect = _mock_response_sequence(_REAL_SQUASH_PR_BRANCH_TIP_COMMIT_UNSIGNED)
        result = inspect_commit_author(_REPO, _SQUASH_PR_BRANCH_TIP_SHA, token="tok")

        self.assertEqual(mock_urlopen.call_count, 1)
        self.assertIsNone(result.commit_signature_source_sha)
        self.assertFalse(result.commit_signature_verified)


class AssociatedPrLookupHelperTests(unittest.TestCase):
    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_resolves_real_pr_number(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(_REAL_ASSOCIATED_PRS_RESPONSE)
        number, error = _fetch_associated_pr_number(_REPO, _SQUASH_MERGE_SHA, {}, 10)
        self.assertEqual(number, _SQUASH_PR_NUMBER)
        self.assertIsNone(error)

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_malformed_entry_fails_closed(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(["not-a-dict"])
        number, error = _fetch_associated_pr_number(_REPO, _SQUASH_MERGE_SHA, {}, 10)
        self.assertIsNone(number)
        self.assertIn("unexpected response shape", error)


class PrBranchTipHelperTests(unittest.TestCase):
    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_resolves_last_commit_as_branch_tip(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(_REAL_PR_COMMITS_RESPONSE)
        sha, error = _fetch_pr_branch_tip_sha(_REPO, _SQUASH_PR_NUMBER, {}, 10)
        self.assertEqual(sha, _SQUASH_PR_BRANCH_TIP_SHA)
        self.assertIsNone(error)

    @patch("cli.parsers.commit_author.urllib.request.urlopen")
    def test_malformed_sha_fails_closed(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response([{"sha": "not-hex!!"}])
        sha, error = _fetch_pr_branch_tip_sha(_REPO, _SQUASH_PR_NUMBER, {}, 10)
        self.assertIsNone(sha)
        self.assertIn("unexpected response shape", error)


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
            commit_signature_source_sha="c" * 40,
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
                "commit_signature_source_sha": "c" * 40,
            },
        )


if __name__ == "__main__":
    unittest.main()
