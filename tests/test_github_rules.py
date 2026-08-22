import io
import json
import os
import sys
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.parsers.github_rules import (
    BranchGovernanceReport,
    GitHubAPIError,
    REASON_CODE_PLATFORM_UNSUPPORTED_TIER,
    bypass_permits_unreviewed_change,
    inspect_branch_governance,
    _extract_http_error_detail,
    _github_api_get,
    _is_platform_tier_limitation,
    _quote_ref,
)
from cli.parsers.junit import TestTotals
from cli.patch_coverage import PatchCoverageResult
from cli.scorer import score_pipeline, BRANCH_GOVERNANCE_UNVERIFIED_PENALTY


def _pull_request_rule(required_approving_review_count=2):
    return {
        "type": "pull_request",
        "ruleset_source_type": "Repository",
        "ruleset_id": 1,
        "parameters": {"required_approving_review_count": required_approving_review_count},
    }


def _active_branch_ruleset_summary(ruleset_id=1):
    return {"id": ruleset_id, "name": "protect-main", "target": "branch", "enforcement": "active"}


def _api_get_router(routes):
    """Builds a side_effect function for mocking _github_api_get: `routes` maps
    a path (or path prefix) to either a value to return or an exception instance
    to raise. Exact matches win; otherwise the longest matching prefix wins, so
    e.g. ".../rulesets/1" isn't shadowed by a broader ".../rulesets" route."""
    def _dispatch(path, token, timeout=10):
        if path in routes:
            outcome = routes[path]
        else:
            candidates = [k for k in routes if path.startswith(k)]
            if not candidates:
                raise AssertionError(f"unexpected path queried: {path}")
            outcome = routes[max(candidates, key=len)]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
    return _dispatch


class InspectBranchGovernanceTests(unittest.TestCase):

    @patch("cli.parsers.github_rules._github_api_get")
    def test_200_active_ruleset_no_bypass_actors_is_clean(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": [_pull_request_rule(2)],
            "/repos/acme/widgets/rulesets": [_active_branch_ruleset_summary(1)],
            "/repos/acme/widgets/rulesets/1": {"id": 1, "bypass_actors": []},
        })

        report = inspect_branch_governance("acme/widgets", "main", token="tok")

        self.assertTrue(report.available)
        self.assertEqual(report.branch, "main")
        self.assertTrue(report.pull_request_required)
        self.assertEqual(report.approvals_required, 2)
        self.assertTrue(report.direct_push_prevented)
        self.assertEqual(report.bypass_actors_count, 0)
        self.assertTrue(report.admin_enforced)
        self.assertEqual(report.warnings, [])
        self.assertFalse(bypass_permits_unreviewed_change(report))

    @patch("cli.parsers.github_rules._github_api_get")
    def test_200_with_always_bypass_actor_flags_warning_and_disables_admin_enforced(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": [_pull_request_rule(2)],
            "/repos/acme/widgets/rulesets": [_active_branch_ruleset_summary(7)],
            "/repos/acme/widgets/rulesets/7": {
                "id": 7,
                "bypass_actors": [{"actor_type": "OrganizationAdmin", "bypass_mode": "always"}],
            },
        })

        report = inspect_branch_governance("acme/widgets", "main", token="tok")

        self.assertTrue(report.available)
        self.assertEqual(report.bypass_actors_count, 1)
        self.assertFalse(report.admin_enforced)
        self.assertTrue(any("bypass_mode=always" in w for w in report.warnings))
        self.assertTrue(bypass_permits_unreviewed_change(report))

    @patch("cli.parsers.github_rules._github_api_get")
    def test_200_with_pull_request_only_bypass_actor_still_warns(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": [_pull_request_rule(2)],
            "/repos/acme/widgets/rulesets": [_active_branch_ruleset_summary(9)],
            "/repos/acme/widgets/rulesets/9": {
                "id": 9,
                "bypass_actors": [{"actor_type": "Team", "bypass_mode": "pull_request"}],
            },
        })

        report = inspect_branch_governance("acme/widgets", "main", token="tok")

        self.assertTrue(report.available)
        self.assertEqual(report.bypass_actors_count, 1)
        # PR-only bypass doesn't exempt from the branch rules entirely.
        self.assertTrue(report.admin_enforced)
        self.assertTrue(any("bypass_mode=pull_request" in w for w in report.warnings))
        self.assertTrue(bypass_permits_unreviewed_change(report))

    @patch("cli.parsers.github_rules._github_api_get")
    def test_404_no_rulesets_on_existing_branch_is_available_but_warns_no_protection(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": None,
            "/repos/acme/widgets/rulesets": None,
            # The 404 on rules-for-branch is only trusted as "benign" once
            # the branch is independently confirmed to exist.
            "/repos/acme/widgets/branches/main": {"name": "main", "commit": {"sha": "deadbeef"}},
        })

        report = inspect_branch_governance("acme/widgets", "main", token="tok")

        self.assertTrue(report.available)
        self.assertFalse(report.pull_request_required)
        self.assertEqual(report.approvals_required, 0)
        self.assertFalse(report.direct_push_prevented)
        self.assertEqual(report.bypass_actors_count, 0)
        self.assertTrue(any("no branch rules found" in w for w in report.warnings))
        self.assertTrue(bypass_permits_unreviewed_change(report))

    @patch("cli.parsers.github_rules._github_api_get")
    def test_404_on_rules_with_nonexistent_branch_fails_closed(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/typo-branch": None,
            # Branch lookup also 404s: the branch genuinely doesn't exist,
            # so the earlier 404 was NOT a benign "no rules configured".
            "/repos/acme/widgets/branches/typo-branch": None,
        })

        report = inspect_branch_governance("acme/widgets", "typo-branch", token="tok")

        self.assertFalse(report.available)
        self.assertIn("does not exist", report.reason)

    @patch("cli.parsers.github_rules._github_api_get")
    def test_404_on_rules_with_unverifiable_branch_existence_fails_closed(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": None,
            # The branch-existence check itself errors out (network/API
            # failure) -- existence can't be confirmed either way, so this
            # must fail closed rather than assume "no rules configured".
            "/repos/acme/widgets/branches/main": GitHubAPIError("GET ... -> HTTP 500: Internal Server Error"),
        })

        report = inspect_branch_governance("acme/widgets", "main", token="tok")

        self.assertFalse(report.available)
        self.assertIn("failing closed", report.reason)

    @patch("cli.parsers.github_rules._github_api_get")
    def test_pull_request_rule_with_zero_required_approvals_warns(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": [_pull_request_rule(0)],
            "/repos/acme/widgets/rulesets": [],
        })

        report = inspect_branch_governance("acme/widgets", "main", token="tok")

        self.assertTrue(report.available)
        self.assertTrue(report.pull_request_required)
        self.assertEqual(report.approvals_required, 0)
        self.assertTrue(any("0 approving reviews" in w for w in report.warnings))

    def test_missing_token_is_unavailable_without_any_api_call(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch("cli.parsers.github_rules._github_api_get") as mock_get:
            report = inspect_branch_governance("acme/widgets", "main", token=None)

        mock_get.assert_not_called()
        self.assertFalse(report.available)
        self.assertIn("GITHUB_TOKEN", report.reason)
        self.assertEqual(report.warnings, [])

    def test_ambient_github_token_env_var_is_used_when_not_passed_explicitly(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "env-token"}), \
             patch("cli.parsers.github_rules._github_api_get") as mock_get:
            mock_get.side_effect = _api_get_router({
                "/repos/acme/widgets/rules/branches/main": [],
                "/repos/acme/widgets/rulesets": [],
            })
            report = inspect_branch_governance("acme/widgets", "main", token=None)

        self.assertTrue(report.available)
        used_tokens = {call.args[1] for call in mock_get.call_args_list}
        self.assertEqual(used_tokens, {"env-token"})

    @patch("cli.parsers.github_rules._github_api_get")
    def test_api_error_on_rules_endpoint_returns_unavailable(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": GitHubAPIError("GET ... -> HTTP 500: Internal Server Error"),
        })

        report = inspect_branch_governance("acme/widgets", "main", token="tok")

        self.assertFalse(report.available)
        self.assertIn("GitHub rules API request failed", report.reason)
        self.assertEqual(report.warnings, [])

    @patch("cli.parsers.github_rules._github_api_get")
    def test_403_on_rules_endpoint_gives_actionable_administration_read_diagnostic(self, mock_get):
        # The default GITHUB_TOKEN can never be granted 'Administration:
        # Read' via a workflow's `permissions:` block -- a 403 straight from
        # the primary rules-for-branch call is the single most common way
        # an under-scoped token shows up, so it must fail closed with a
        # concrete, actionable diagnostic (not just a bare "HTTP 403").
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": GitHubAPIError(
                "GET ... -> HTTP 403: Forbidden", status_code=403
            ),
        })

        report = inspect_branch_governance("acme/widgets", "main", token="under-scoped-token")

        self.assertFalse(report.available)
        self.assertIn("authentication/authorization failed", report.reason)
        self.assertIn("Administration: Read", report.reason)
        self.assertIn("querying rules for branch", report.reason)
        # A generic 403 (no plan-limitation marker in the message) must not
        # be misclassified as the platform/plan-tier condition.
        self.assertIsNone(report.reason_code)

    @patch("cli.parsers.github_rules._github_api_get")
    def test_403_free_plan_message_sets_platform_unsupported_tier_reason_code(self, mock_get):
        # GitHub returns the identical HTTP 403 whether the token is
        # under-scoped or the token is fine but rulesets simply aren't
        # supported for this repo at all (a private repo on GitHub Free).
        # reason_code must distinguish the two so downstream policy (e.g.
        # cli.verify's --disallow-degraded) can tell them apart, rather
        # than treating every unavailable governance report identically.
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": GitHubAPIError(
                "GET /repos/acme/widgets/rules/branches/main -> HTTP 403: "
                "Upgrade to GitHub Pro or make this repository public to enable this feature.",
                status_code=403,
            ),
        })

        report = inspect_branch_governance("acme/widgets", "main", token="correctly-scoped-app-token")

        self.assertFalse(report.available)
        self.assertEqual(report.reason_code, REASON_CODE_PLATFORM_UNSUPPORTED_TIER)
        self.assertIn("Upgrade to GitHub Pro", report.reason)

    @patch("cli.parsers.github_rules._github_api_get")
    def test_403_free_plan_message_during_ruleset_enumeration_sets_reason_code(self, mock_get):
        # Same condition, but hit during the secondary bypass-actor
        # enrichment call rather than the primary rules-for-branch call --
        # reason_code must be set there too, not just on the first call site.
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": [_pull_request_rule(2)],
            "/repos/acme/widgets/rulesets": GitHubAPIError(
                "GET /repos/acme/widgets/rulesets -> HTTP 403: "
                "Upgrade to GitHub Pro or make this repository public to enable this feature.",
                status_code=403,
            ),
        })

        report = inspect_branch_governance("acme/widgets", "main", token="correctly-scoped-app-token")

        self.assertFalse(report.available)
        self.assertEqual(report.reason_code, REASON_CODE_PLATFORM_UNSUPPORTED_TIER)

    @patch("cli.parsers.github_rules._github_api_get")
    def test_403_on_free_plan_private_repo_degrades_cleanly_without_raising(self, mock_get):
        # GitHub returns the identical HTTP 403 whether the token is
        # under-scoped or the token is fine but rulesets simply aren't
        # supported for this repo at all (a private repo on GitHub Free).
        # _github_api_get captures GitHub's own error-body message (see
        # _extract_http_error_detail) and _actionable_auth_failure_reason
        # leads with it -- so a real Free-plan 403 must surface that exact
        # message, not just the generic "Administration: Read" guess, and
        # must never raise: available=False plus a warning-carrying reason
        # is a normal degraded state, not an error condition.
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": GitHubAPIError(
                "GET /repos/acme/widgets/rules/branches/main -> HTTP 403: "
                "Upgrade to GitHub Pro or make this repository public to enable this feature.",
                status_code=403,
            ),
        })

        report = inspect_branch_governance("acme/widgets", "main", token="correctly-scoped-app-token")

        self.assertIsInstance(report, BranchGovernanceReport)
        self.assertFalse(report.available)
        self.assertIn("Upgrade to GitHub Pro", report.reason)
        # Still mentions the token-permission possibility as a secondary
        # hint -- the status code alone can't distinguish the two causes.
        self.assertIn("Administration: Read", report.reason)

    @patch("cli.parsers.github_rules._github_api_get")
    def test_401_on_rules_endpoint_gives_actionable_administration_read_diagnostic(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": GitHubAPIError(
                "GET ... -> HTTP 401: Unauthorized", status_code=401
            ),
        })

        report = inspect_branch_governance("acme/widgets", "main", token="bad-token")

        self.assertFalse(report.available)
        self.assertIn("Administration: Read", report.reason)

    @patch("cli.parsers.github_rules._github_api_get")
    def test_ruleset_detail_error_degrades_bypass_visibility_but_keeps_rules_result(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": [_pull_request_rule(2)],
            "/repos/acme/widgets/rulesets": [_active_branch_ruleset_summary(3)],
            "/repos/acme/widgets/rulesets/3": GitHubAPIError("GET ... -> HTTP 403: Forbidden"),
        })

        report = inspect_branch_governance("acme/widgets", "main", token="tok")

        self.assertTrue(report.available)
        self.assertTrue(report.pull_request_required)
        self.assertEqual(report.bypass_actors_count, 0)
        self.assertTrue(any("could not enumerate ruleset bypass actors" in w for w in report.warnings))

    @patch("cli.parsers.github_rules._github_api_get")
    def test_inactive_and_non_branch_rulesets_are_skipped(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": [_pull_request_rule(2)],
            "/repos/acme/widgets/rulesets": [
                {"id": 1, "target": "branch", "enforcement": "disabled"},
                {"id": 2, "target": "tag", "enforcement": "active"},
                {"id": 3, "target": "branch", "enforcement": "active"},
            ],
            "/repos/acme/widgets/rulesets/3": {"id": 3, "bypass_actors": [{"bypass_mode": "always"}]},
        })

        report = inspect_branch_governance("acme/widgets", "main", token="tok")

        # Only ruleset 3 (active + branch-targeting) should have been fetched
        # for detail, so only its bypass actor is counted.
        self.assertEqual(report.bypass_actors_count, 1)
        queried_paths = [call.args[0] for call in mock_get.call_args_list]
        self.assertNotIn("/repos/acme/widgets/rulesets/1", queried_paths)
        self.assertNotIn("/repos/acme/widgets/rulesets/2", queried_paths)
        self.assertIn("/repos/acme/widgets/rulesets/3", queried_paths)

    def test_branch_name_with_slash_is_percent_encoded_in_rules_path(self):
        with patch("cli.parsers.github_rules._github_api_get") as mock_get:
            mock_get.side_effect = _api_get_router({
                "/repos/acme/widgets/rules/branches/release%2F1.0": [],
                "/repos/acme/widgets/rulesets": [],
            })
            report = inspect_branch_governance("acme/widgets", "release/1.0", token="tok")

        self.assertTrue(report.available)
        self.assertEqual(report.branch, "release/1.0")

    def test_invalid_repository_format_is_rejected_without_any_api_call(self):
        for bad_repo in ["foo/bar?", "../../etc", "foo", "foo/bar/baz", "", "foo/", "/bar", "foo bar/baz"]:
            with self.subTest(repository=bad_repo), \
                 patch("cli.parsers.github_rules._github_api_get") as mock_get:
                report = inspect_branch_governance(bad_repo, "main", token="tok")

            mock_get.assert_not_called()
            self.assertFalse(report.available, f"{bad_repo!r} should have been rejected")
            self.assertIn("invalid repository", report.reason)

    @patch("cli.parsers.github_rules._github_api_get")
    def test_401_enumerating_rulesets_invalidates_whole_report(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": [_pull_request_rule(2)],
            "/repos/acme/widgets/rulesets": GitHubAPIError(
                "GET ... -> HTTP 401: Unauthorized", status_code=401
            ),
        })

        report = inspect_branch_governance("acme/widgets", "main", token="bad-token")

        self.assertFalse(report.available)
        self.assertIn("authentication/authorization failed", report.reason)
        self.assertIn("Administration: Read", report.reason)

    @patch("cli.parsers.github_rules._github_api_get")
    def test_403_enumerating_ruleset_detail_invalidates_whole_report(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": [_pull_request_rule(2)],
            "/repos/acme/widgets/rulesets": [_active_branch_ruleset_summary(3)],
            "/repos/acme/widgets/rulesets/3": GitHubAPIError(
                "GET ... -> HTTP 403: Forbidden", status_code=403
            ),
        })

        report = inspect_branch_governance("acme/widgets", "main", token="under-scoped-token")

        self.assertFalse(report.available)
        self.assertIn("authentication/authorization failed", report.reason)
        self.assertIn("Administration: Read", report.reason)

    @patch("cli.parsers.github_rules._github_api_get")
    def test_unrecognized_bypass_mode_fails_closed(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": [_pull_request_rule(2)],
            "/repos/acme/widgets/rulesets": [_active_branch_ruleset_summary(4)],
            "/repos/acme/widgets/rulesets/4": {
                "id": 4,
                "bypass_actors": [{"actor_type": "Team", "bypass_mode": "custom_role_override"}],
            },
        })

        report = inspect_branch_governance("acme/widgets", "main", token="tok")

        self.assertTrue(report.available)
        self.assertEqual(report.bypass_actors_count, 1)
        # Only bypass_mode="pull_request" is treated as not a full bypass;
        # an unrecognized mode must fail closed the same as "always" would.
        self.assertFalse(report.admin_enforced)
        self.assertTrue(any("unrecognized bypass_mode" in w for w in report.warnings))
        self.assertTrue(bypass_permits_unreviewed_change(report))

    @patch("cli.parsers.github_rules._github_api_get")
    def test_bypass_actor_missing_mode_field_fails_closed(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": [_pull_request_rule(2)],
            "/repos/acme/widgets/rulesets": [_active_branch_ruleset_summary(5)],
            "/repos/acme/widgets/rulesets/5": {
                "id": 5,
                "bypass_actors": [{"actor_type": "Integration"}],  # no bypass_mode at all
            },
        })

        report = inspect_branch_governance("acme/widgets", "main", token="tok")

        self.assertFalse(report.admin_enforced)
        self.assertTrue(bypass_permits_unreviewed_change(report))


class QuoteRefTests(unittest.TestCase):

    def test_plain_branch_name_is_unchanged(self):
        self.assertEqual(_quote_ref("main"), "main")

    def test_slash_is_percent_encoded(self):
        self.assertEqual(_quote_ref("release/1.0"), "release%2F1.0")


class IsPlatformTierLimitationTests(unittest.TestCase):
    """Unit coverage for the marker-matching that classifies a 403's error
    body as GitHub's plan/visibility feature gate, in isolation from the
    full inspect_branch_governance() round-trip."""

    def test_matches_real_github_wording(self):
        self.assertTrue(_is_platform_tier_limitation(
            "Upgrade to GitHub Pro or make this repository public to enable this feature."
        ))

    def test_matches_case_insensitively(self):
        self.assertTrue(_is_platform_tier_limitation("UPGRADE TO GITHUB PRO to unlock this"))

    def test_either_marker_alone_is_sufficient(self):
        self.assertTrue(_is_platform_tier_limitation("please make this repository public first"))

    def test_generic_forbidden_does_not_match(self):
        self.assertFalse(_is_platform_tier_limitation("Forbidden"))

    def test_administration_scope_message_does_not_match(self):
        self.assertFalse(_is_platform_tier_limitation(
            "Resource not accessible by integration; token needs 'Administration: Read'"
        ))

    def test_empty_or_none_does_not_raise_or_match(self):
        self.assertFalse(_is_platform_tier_limitation(""))
        self.assertFalse(_is_platform_tier_limitation(None))


class GitHubApiGetTransportTests(unittest.TestCase):
    """Exercises the low-level HTTP GET helper directly (not mocked away),
    to verify the 404-is-not-an-error contract, pagination, and error
    propagation."""

    def _mock_response(self, payload, link_header=""):
        resp = MagicMock()
        resp.read.return_value = json.dumps(payload).encode("utf-8")
        resp.headers = {"Link": link_header} if link_header else {}
        resp.__enter__.return_value = resp
        resp.__exit__.return_value = False
        return resp

    @patch("cli.parsers.github_rules.urllib.request.urlopen")
    def test_200_returns_parsed_json(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_response([{"type": "pull_request"}])
        result = _github_api_get("/repos/acme/widgets/rules/branches/main", "tok")
        self.assertEqual(result, [{"type": "pull_request"}])

    @patch("cli.parsers.github_rules.urllib.request.urlopen")
    def test_paginated_list_response_is_aggregated_across_pages(self, mock_urlopen):
        page1 = self._mock_response(
            [{"id": 1}, {"id": 2}],
            link_header='<https://api.github.com/repos/acme/widgets/rulesets?page=2>; rel="next"',
        )
        page2 = self._mock_response(
            [{"id": 3}],
            link_header='<https://api.github.com/repos/acme/widgets/rulesets?page=1>; rel="prev"',
        )
        mock_urlopen.side_effect = [page1, page2]

        result = _github_api_get("/repos/acme/widgets/rulesets", "tok")

        self.assertEqual(result, [{"id": 1}, {"id": 2}, {"id": 3}])
        self.assertEqual(mock_urlopen.call_count, 2)
        second_request = mock_urlopen.call_args_list[1].args[0]
        self.assertEqual(second_request.full_url, "https://api.github.com/repos/acme/widgets/rulesets?page=2")

    @patch("cli.parsers.github_rules.urllib.request.urlopen")
    def test_pagination_is_bounded_to_max_pages(self, mock_urlopen):
        def _infinite_page(*args, **kwargs):
            return self._mock_response(
                [{"id": 1}],
                link_header='<https://api.github.com/repos/acme/widgets/rulesets?page=next>; rel="next"',
            )
        mock_urlopen.side_effect = _infinite_page

        result = _github_api_get("/repos/acme/widgets/rulesets", "tok")

        from cli.parsers.github_rules import MAX_PAGES
        self.assertEqual(mock_urlopen.call_count, MAX_PAGES)
        self.assertEqual(result, [{"id": 1}] * MAX_PAGES)

    @patch("cli.parsers.github_rules.urllib.request.urlopen")
    def test_next_link_off_github_host_is_not_followed(self, mock_urlopen):
        page1 = self._mock_response(
            [{"id": 1}],
            link_header='<https://evil.example.com/steal>; rel="next"',
        )
        mock_urlopen.return_value = page1

        result = _github_api_get("/repos/acme/widgets/rulesets", "tok")

        self.assertEqual(result, [{"id": 1}])
        self.assertEqual(mock_urlopen.call_count, 1)

    @patch("cli.parsers.github_rules.urllib.request.urlopen")
    def test_single_resource_object_response_ignores_pagination(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_response(
            {"id": 1, "bypass_actors": []},
            link_header='<https://api.github.com/repos/acme/widgets/rulesets/1?page=2>; rel="next"',
        )
        result = _github_api_get("/repos/acme/widgets/rulesets/1", "tok")
        self.assertEqual(result, {"id": 1, "bypass_actors": []})
        self.assertEqual(mock_urlopen.call_count, 1)

    @patch("cli.parsers.github_rules.urllib.request.urlopen")
    def test_404_returns_none_not_an_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.github.com/repos/acme/widgets/rulesets",
            code=404, msg="Not Found", hdrs=None, fp=None,
        )
        result = _github_api_get("/repos/acme/widgets/rulesets", "tok")
        self.assertIsNone(result)

    @patch("cli.parsers.github_rules.urllib.request.urlopen")
    def test_500_raises_github_api_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.github.com/repos/acme/widgets/rulesets",
            code=500, msg="Internal Server Error", hdrs=None, fp=None,
        )
        with self.assertRaises(GitHubAPIError):
            _github_api_get("/repos/acme/widgets/rulesets", "tok")

    @patch("cli.parsers.github_rules.urllib.request.urlopen")
    def test_network_failure_raises_github_api_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")
        with self.assertRaises(GitHubAPIError):
            _github_api_get("/repos/acme/widgets/rulesets", "tok")

    @patch("cli.parsers.github_rules.urllib.request.urlopen")
    def test_403_error_body_message_is_surfaced_in_diagnostic(self, mock_urlopen):
        # GitHub's actual 403 response body for rulesets on a private
        # Free-plan repo carries a specific, human-readable `message` (e.g.
        # "Upgrade to GitHub Pro or make this repository public to enable
        # this feature.") that's far more useful than the bare status
        # code -- it must be pulled out of the body and included verbatim.
        body = json.dumps(
            {"message": "Upgrade to GitHub Pro or make this repository public to enable this feature."}
        ).encode("utf-8")
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.github.com/repos/acme/widgets/rules/branches/main",
            code=403, msg="Forbidden", hdrs=None, fp=io.BytesIO(body),
        )

        with self.assertRaises(GitHubAPIError) as ctx:
            _github_api_get("/repos/acme/widgets/rules/branches/main", "tok")

        self.assertIn("Upgrade to GitHub Pro", str(ctx.exception))
        self.assertEqual(ctx.exception.status_code, 403)

    @patch("cli.parsers.github_rules.urllib.request.urlopen")
    def test_error_body_that_is_not_json_falls_back_to_reason_phrase(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.github.com/repos/acme/widgets/rulesets",
            code=403, msg="Forbidden", hdrs=None, fp=io.BytesIO(b"not json"),
        )

        with self.assertRaises(GitHubAPIError) as ctx:
            _github_api_get("/repos/acme/widgets/rulesets", "tok")

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("Forbidden", str(ctx.exception))


class ExtractHttpErrorDetailTests(unittest.TestCase):
    """Unit coverage for _extract_http_error_detail in isolation, separate
    from the full _github_api_get round-trip above."""

    def test_extracts_message_field_from_json_body(self):
        body = json.dumps({"message": "Upgrade to GitHub Pro or make this repository public."}).encode()
        e = urllib.error.HTTPError(url="https://api.github.com/x", code=403, msg="Forbidden", hdrs=None, fp=io.BytesIO(body))

        self.assertEqual(_extract_http_error_detail(e), "Upgrade to GitHub Pro or make this repository public.")

    def test_falls_back_to_reason_when_body_is_not_json(self):
        e = urllib.error.HTTPError(url="https://api.github.com/x", code=403, msg="Forbidden", hdrs=None, fp=io.BytesIO(b"<html>nope</html>"))

        self.assertEqual(_extract_http_error_detail(e), "Forbidden")

    def test_falls_back_to_reason_when_body_unreadable(self):
        e = urllib.error.HTTPError(url="https://api.github.com/x", code=403, msg="Forbidden", hdrs=None, fp=None)

        self.assertEqual(_extract_http_error_detail(e), "Forbidden")

    def test_falls_back_to_reason_when_message_field_missing_or_blank(self):
        body = json.dumps({"documentation_url": "https://docs.github.com/"}).encode()
        e = urllib.error.HTTPError(url="https://api.github.com/x", code=403, msg="Forbidden", hdrs=None, fp=io.BytesIO(body))

        self.assertEqual(_extract_http_error_detail(e), "Forbidden")


class BypassPermitsUnreviewedChangeTests(unittest.TestCase):

    def _report(self, **overrides):
        from cli.parsers.github_rules import BranchGovernanceReport
        kwargs = dict(
            available=True, branch="main", pull_request_required=True, approvals_required=2,
            direct_push_prevented=True, bypass_actors_count=0, admin_enforced=True,
            warnings=[], reason="ok",
        )
        kwargs.update(overrides)
        return BranchGovernanceReport(**kwargs)

    def test_clean_report_does_not_permit_bypass(self):
        self.assertFalse(bypass_permits_unreviewed_change(self._report()))

    def test_no_pull_request_required_permits_bypass(self):
        self.assertTrue(bypass_permits_unreviewed_change(self._report(pull_request_required=False)))

    def test_direct_push_not_prevented_permits_bypass(self):
        self.assertTrue(bypass_permits_unreviewed_change(self._report(direct_push_prevented=False)))

    def test_bypass_actors_present_permits_bypass(self):
        self.assertTrue(bypass_permits_unreviewed_change(self._report(bypass_actors_count=1)))

    def test_admin_not_enforced_permits_bypass(self):
        self.assertTrue(bypass_permits_unreviewed_change(self._report(admin_enforced=False)))


class ScorerFailClosedIntegrationTests(unittest.TestCase):
    """End-to-end: reports actually produced by inspect_branch_governance
    (not hand-built fixtures) must force score_pipeline() to fail closed --
    missing/invalid GITHUB_TOKEN must not be a cheaper way to score well
    than a confirmed unreviewed-bypass finding."""

    _CLEAN_REPORT = BranchGovernanceReport(
        available=True, branch="main", pull_request_required=True, approvals_required=2,
        direct_push_prevented=True, bypass_actors_count=0, admin_enforced=True,
        warnings=[], reason="ok",
    )

    def _pipeline_kwargs(self, branch_governance):
        return dict(
            test_totals=TestTotals(tests=10, passed=10, failed=0, errored=0, skipped=0, duration_ms=100),
            patch_coverage=PatchCoverageResult(
                available=True, line_rate=0.95, lines_changed=10, lines_covered=9, reason="ok"
            ),
            overall_line_rate=0.9,
            total_assertions=20,
            total_test_functions=10,
            pr_present=True,
            approvers_count=2,
            required_approvals=2,
            review_state="approved",
            branch_governance=branch_governance,
        )

    def test_missing_token_forces_degraded_and_scorer_penalty(self):
        with patch.dict(os.environ, {}, clear=True):
            report = inspect_branch_governance("acme/widgets", "main", token=None)
        self.assertFalse(report.available)

        clean = score_pipeline(**self._pipeline_kwargs(self._CLEAN_REPORT))
        result = score_pipeline(**self._pipeline_kwargs(report))

        self.assertTrue(result.degraded)
        self.assertAlmostEqual(
            result.components["governance"].raw_score,
            clean.components["governance"].raw_score - BRANCH_GOVERNANCE_UNVERIFIED_PENALTY,
            places=6,
        )

    @patch("cli.parsers.github_rules._github_api_get")
    def test_401_response_forces_degraded_and_scorer_penalty(self, mock_get):
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": GitHubAPIError(
                "GET ... -> HTTP 401: Unauthorized", status_code=401
            ),
        })
        report = inspect_branch_governance("acme/widgets", "main", token="bad-token")
        self.assertFalse(report.available)

        clean = score_pipeline(**self._pipeline_kwargs(self._CLEAN_REPORT))
        result = score_pipeline(**self._pipeline_kwargs(report))

        self.assertTrue(result.degraded)
        self.assertAlmostEqual(
            result.components["governance"].raw_score,
            clean.components["governance"].raw_score - BRANCH_GOVERNANCE_UNVERIFIED_PENALTY,
            places=6,
        )

    @patch("cli.parsers.github_rules._github_api_get")
    def test_free_plan_403_forces_degraded_and_scorer_penalty(self, mock_get):
        # The real-world case this is guarding against: a correctly-scoped
        # token still gets a 403 because branch rulesets simply aren't a
        # supported feature for a private repo on GitHub Free. That must
        # dock the governance score exactly like any other unverifiable
        # report -- a plan limitation is not a loophole to a clean score.
        mock_get.side_effect = _api_get_router({
            "/repos/acme/widgets/rules/branches/main": GitHubAPIError(
                "GET /repos/acme/widgets/rules/branches/main -> HTTP 403: "
                "Upgrade to GitHub Pro or make this repository public to enable this feature.",
                status_code=403,
            ),
        })
        report = inspect_branch_governance("acme/widgets", "main", token="correctly-scoped-app-token")
        self.assertFalse(report.available)

        clean = score_pipeline(**self._pipeline_kwargs(self._CLEAN_REPORT))
        result = score_pipeline(**self._pipeline_kwargs(report))

        self.assertTrue(result.degraded)
        self.assertAlmostEqual(
            result.components["governance"].raw_score,
            clean.components["governance"].raw_score - BRANCH_GOVERNANCE_UNVERIFIED_PENALTY,
            places=6,
        )

    def test_omitting_token_never_scores_better_than_a_confirmed_bypass(self):
        bypass_report = BranchGovernanceReport(
            available=True, branch="main", pull_request_required=False, approvals_required=0,
            direct_push_prevented=False, bypass_actors_count=0, admin_enforced=True,
            warnings=["branch 'main' does not require a pull request"], reason="ok",
        )
        with patch.dict(os.environ, {}, clear=True):
            unverified_report = inspect_branch_governance("acme/widgets", "main", token=None)

        bypass_result = score_pipeline(**self._pipeline_kwargs(bypass_report))
        unverified_result = score_pipeline(**self._pipeline_kwargs(unverified_report))

        self.assertTrue(bypass_result.degraded)
        self.assertTrue(unverified_result.degraded)
        self.assertGreaterEqual(
            unverified_result.components["governance"].raw_score,
            bypass_result.components["governance"].raw_score,
        )


if __name__ == "__main__":
    unittest.main()
