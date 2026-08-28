"""
GitHub branch governance / ruleset inspection.

Queries GitHub's REST API for the *effective* rules on a branch (the
union of every applicable repository + organization ruleset) and cross-
references active rulesets' bypass actors, so a run can tell whether
"branch protection" actually prevents an unreviewed direct commit or
merge, as opposed to merely appearing to.

Hardened against:
  - Missing/expired GITHUB_TOKEN (degrades to available=False, never raises)
  - Path/URL injection via `repository` (strict `owner/repo` allowlist regex,
    checked before any URL is built) and via `branch`/ref values (always
    percent-encoded with urllib.parse.quote(..., safe=""))
  - 404 responses that are genuinely "no rulesets configured" vs. a
    nonexistent repository/branch masquerading as a clean report: an
    ambiguous 404 on rules-for-branch is only trusted once branch
    existence is independently confirmed; otherwise the result fails
    closed (available=False) rather than reporting a false-clean bill
    of health
  - Auth failures (401/403) anywhere in the flow -- including secondary
    ruleset/bypass-actor enrichment -- invalidate the whole report
    (available=False), since a bad/under-scoped token can't be trusted
    to have reported the rest of the data faithfully either. The default
    GITHUB_TOKEN can never be granted the 'Administration: Read'
    permission these endpoints require (it isn't an available workflow
    `permissions:` scope at all), so a 401/403 here almost always means
    that; the failure reason spells this out explicitly rather than
    surfacing a bare status code
  - Unbounded/adversarial pagination (bounded to MAX_PAGES, following
    only same-origin HTTPS `Link: rel="next"` targets)
  - Transport/timeout/malformed-JSON failures on either endpoint (degrades
    to available=False with the failure captured in `reason`), including
    pathologically deep JSON nesting in a response body: `json.loads` is
    recursive descent, so a malicious/compromised endpoint response
    crafted to exceed `sys.getrecursionlimit()` raises `RecursionError`,
    not `json.JSONDecodeError` -- caught alongside it wherever a response
    body is parsed, same fail-closed outcome as any other malformed body
  - Bypass actors with an unrecognized/unknown `bypass_mode`: only the
    explicitly-known least-dangerous mode (bypass_mode="pull_request") is
    treated as not fully bypassing the branch's rules; anything else
    (bypass_mode="always", missing, or a novel value) fails closed
  - Conflating "the token is under-scoped" with "this repo's plan/
    visibility doesn't support rulesets at all" (a private repo on
    GitHub Free): both produce an identical HTTP 403, so `reason_code`
    is set to REASON_CODE_PLATFORM_UNSUPPORTED_TIER specifically when
    GitHub's own error body says so, rather than leaving every 403
    looking like the same generic auth failure to callers (e.g.
    cli.verify's --disallow-degraded gate) that may want to treat the
    two differently
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

GITHUB_API_BASE = "https://api.github.com"
DEFAULT_TIMEOUT = 10

# Safeguard against unbounded/adversarial pagination (e.g. a compromised or
# misbehaving API response looping `Link: rel="next"` forever).
MAX_PAGES = 10

# Strict "owner/repo" allowlist -- matches GitHub's own permitted charset for
# both segments. Rejects anything that could smuggle extra path segments,
# query strings, or traversal sequences into the request URL.
_REPO_RE = re.compile(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$")

# Machine-readable `BranchGovernanceReport.reason_code` value for a 403
# caused by GitHub's own plan/visibility feature gate (rulesets aren't
# supported on this repo at all -- see _is_platform_tier_limitation),
# distinct from an actual under-scoped/invalid token. Threaded through to
# the attestation predicate (cli.builder) so downstream policy -- e.g.
# cli.verify's --disallow-degraded -- can tell the two apart instead of
# treating every unavailable governance report identically.
REASON_CODE_PLATFORM_UNSUPPORTED_TIER = "platform_unsupported_tier"

# Substrings of GitHub's own 403 error-body message (see
# _extract_http_error_detail) that identify the platform/plan-tier
# limitation specifically -- confirmed against GitHub's actual wording:
# "Upgrade to GitHub Pro or make this repository public to enable this
# feature." Matched case-insensitively; either substring alone is
# sufficient (GitHub's wording could vary slightly by context).
_PLATFORM_TIER_LIMITATION_MARKERS = ("upgrade to github pro", "make this repository public")


def _is_platform_tier_limitation(detail: str) -> bool:
    """True when a 403's error-body detail (from _extract_http_error_detail)
    identifies GitHub's plan/visibility feature gate on rulesets, rather
    than an actual auth/permission failure. Never raises on odd input."""
    lowered = (detail or "").lower()
    return any(marker in lowered for marker in _PLATFORM_TIER_LIMITATION_MARKERS)


# A bypass actor with this mode can skip the ruleset entirely, including
# outside of a pull request (i.e. a genuine unreviewed direct push).
BYPASS_MODE_ALWAYS = "always"
# A bypass actor with this mode can only skip PR-specific rules (e.g. merge
# without the required approvals) but still has to go through a pull request.
# This is the *only* mode treated as not fully bypassing branch rules --
# anything else (including modes we don't recognize) fails closed.
BYPASS_MODE_PULL_REQUEST = "pull_request"


class GitHubAPIError(RuntimeError):
    """Raised when a GitHub REST API request fails: a non-404 error status,
    a transport failure, or an unparseable response body."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


# The rules-for-branch and rulesets endpoints require 'Administration: Read'
# repository permission -- never available to the default GITHUB_TOKEN via a
# workflow's `permissions:` block, since it isn't one of the scopes
# GITHUB_TOKEN supports -- so a missing/under-scoped token is *one* common
# cause of a 401/403 here. It is NOT the only one: GitHub returns the same
# HTTP 403 when the endpoint itself isn't available to the repo at all --
# e.g. a private repo on a personal (non-Pro) account or a non-Team/
# Enterprise org, where the body reads "Upgrade to GitHub Pro or make this
# repository public to enable this feature." -- a plan/feature gate that no
# amount of token permission can fix. `_github_api_get` captures GitHub's own
# error message (see `_extract_http_error_detail`) precisely so this
# function can lead with the real cause instead of guessing at one.
_ADMINISTRATION_READ_REMEDIATION = (
    "if the message above doesn't already explain it: the token may need "
    "'Administration: Read' repository permission; the default GITHUB_TOKEN can "
    "never be granted this via a workflow's `permissions:` block (it is not one "
    "of the scopes GITHUB_TOKEN supports) -- mint a GitHub App installation "
    "token instead (e.g. via actions/create-github-app-token, with the App "
    "granted 'Administration: Read') and pass it as --github-token / GITHUB_TOKEN"
)


def _actionable_auth_failure_reason(e: GitHubAPIError, context: str) -> str:
    """Builds a diagnostic for a 401/403 GitHub API response, leading with
    GitHub's own error message (already embedded in `e` -- see
    `_extract_http_error_detail`) since it's frequently the actual cause
    (e.g. a plan/feature gate, not a missing token permission), with the
    'Administration: Read' hint kept as a secondary fallback rather than an
    assumed diagnosis."""
    return f"GitHub API authentication/authorization failed {context} (HTTP {e.status_code}): {e}. {_ADMINISTRATION_READ_REMEDIATION}."


def _extract_http_error_detail(e: "urllib.error.HTTPError") -> str:
    """Best-effort extraction of GitHub's own error message from an
    HTTPError body (e.g. `{"message": "Upgrade to GitHub Pro or make this
    repository public to enable this feature.", ...}`), which is far more
    useful than the generic HTTP reason phrase (`e.reason`, e.g. just
    "Forbidden") -- GitHub returns 401/403 on this endpoint for several
    unrelated causes (missing/invalid token, a token missing
    'Administration: Read', or a plan/feature gate no token permission can
    fix), and only the body's own message tells them apart. Falls back to
    `e.reason` if the body isn't readable or isn't the expected JSON shape;
    never raises."""
    try:
        raw = e.read()
        body = json.loads(raw.decode("utf-8"))
        msg = body.get("message") if isinstance(body, dict) else None
        if isinstance(msg, str) and msg.strip():
            return msg.strip()
    except (OSError, ValueError, UnicodeDecodeError, AttributeError, RecursionError):
        pass
    return e.reason


@dataclass
class BranchGovernanceReport:
    __test__ = False
    available: bool
    branch: str
    pull_request_required: bool
    approvals_required: int
    direct_push_prevented: bool
    bypass_actors_count: int
    admin_enforced: bool
    warnings: List[str]
    reason: str
    # Machine-readable classification of *why* available=False, when it's
    # known to be something more specific than "generic failure" -- e.g.
    # REASON_CODE_PLATFORM_UNSUPPORTED_TIER. None for every other case
    # (missing token, network error, ambiguous 404, under-scoped token,
    # ...): callers must not infer anything from an absent reason_code
    # beyond "not this specific, identified condition".
    reason_code: Optional[str] = None
    # The `context` string of every "required_status_checks" rule entry
    # applying to this branch (e.g. "ci/tenax-assay-verify") -- i.e. which
    # named CI jobs must report success before a PR can merge. Always []
    # rather than omitted when no such rule exists, or on an attestation
    # predating this field; never populated at all when available=False.
    # Consumed by cli.parsers.s2c2f's AUD-1 (Enforcing Provenance) check to
    # tell whether *some* required check plausibly enforces provenance/
    # attestation verification, without this module needing to know
    # anything about S2C2F itself.
    required_status_check_contexts: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "branch": self.branch,
            "pull_request_required": self.pull_request_required,
            "approvals_required": self.approvals_required,
            "direct_push_prevented": self.direct_push_prevented,
            "bypass_actors_count": self.bypass_actors_count,
            "admin_enforced": self.admin_enforced,
            "warnings": self.warnings,
            "reason": self.reason,
            "reason_code": self.reason_code,
            "required_status_check_contexts": self.required_status_check_contexts,
        }


def bypass_permits_unreviewed_change(report: BranchGovernanceReport) -> bool:
    """True when this report's branch can, in practice, receive an
    unreviewed change: no PR is required, direct pushes aren't blocked,
    a bypass actor exists (of *any* mode, known or unrecognized -- see
    `admin_enforced`), or bypass-capable roles aren't enforced.

    Fails closed: an unavailable/unverifiable report is not this
    function's concern (callers must check `report.available` themselves
    -- see cli.scorer, which docks points for unavailable reports too);
    given an available report, any ambiguity here resolves to "permits".
    """
    return (
        not report.pull_request_required
        or not report.direct_push_prevented
        or report.bypass_actors_count > 0
        or not report.admin_enforced
    )


def _unavailable(branch: str, reason: str, reason_code: Optional[str] = None) -> BranchGovernanceReport:
    return BranchGovernanceReport(
        available=False,
        branch=branch,
        pull_request_required=False,
        approvals_required=0,
        direct_push_prevented=False,
        bypass_actors_count=0,
        admin_enforced=False,
        warnings=[],
        reason=reason,
        reason_code=reason_code,
    )


def _parse_link_header(link_header: str) -> Dict[str, str]:
    """Parses an RFC 5988 `Link` header (as used for GitHub REST pagination)
    into {rel: url}. Malformed segments are skipped rather than raising."""
    links: Dict[str, str] = {}
    if not link_header:
        return links
    for part in link_header.split(","):
        segments = [s.strip() for s in part.split(";")]
        if len(segments) < 2 or not (segments[0].startswith("<") and segments[0].endswith(">")):
            continue
        url = segments[0][1:-1]
        rel = None
        for seg in segments[1:]:
            if seg.startswith("rel="):
                rel = seg[len("rel="):].strip('"')
        if rel:
            links[rel] = url
    return links


def _is_same_origin_as_api(url: str) -> bool:
    """SSRF guard: a paginated `next` link must stay on the GitHub API host
    over HTTPS -- a Link header is technically attacker-influenceable data
    (the response body of a request we made), so it's never followed
    off-host."""
    parsed = urllib.parse.urlparse(url)
    expected = urllib.parse.urlparse(GITHUB_API_BASE)
    return parsed.scheme == "https" and parsed.netloc == expected.netloc


class _NotFoundPage(Exception):
    """Internal signal raised by _fetch_page() for a 404 response --
    deliberately distinct from a legitimate JSON `null` body (a valid,
    if unusual, 200 response) so _github_api_get() never conflates the
    two: only a real 404 means "not found"."""


def _fetch_page(url: str, headers: Dict[str, str], timeout: int, error_path: str) -> Tuple[Any, str]:
    """Performs one GET, returning (parsed_json_body, Link_header_value).
    Raises _NotFoundPage on a 404 -- the caller (which knows whether this
    is the first page of a paginated fetch) decides what that means.
    Any other non-2xx status or transport/parse error raises
    GitHubAPIError (tagged with `.status_code` when an HTTP status is
    available, so callers can special-case auth failures); the message
    always cites `error_path` -- the original relative API path, not the
    possibly-paginated absolute `url` -- for a stable, callable-facing
    error string across pages."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            link_header = resp.headers.get("Link", "")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise _NotFoundPage() from e
        detail = _extract_http_error_detail(e)
        raise GitHubAPIError(f"GET {error_path} -> HTTP {e.code}: {detail}", status_code=e.code) from e
    except urllib.error.URLError as e:
        raise GitHubAPIError(f"GET {error_path} failed: {e.reason}") from e
    except (json.JSONDecodeError, ValueError, OSError, RecursionError) as e:
        raise GitHubAPIError(f"GET {error_path} failed: {e}") from e
    return body, link_header


def _github_api_get(path: str, token: str, timeout: int = DEFAULT_TIMEOUT) -> Any:
    """GET a GitHub REST API path and return the parsed JSON body.

    Returns None for a 404 on the *first* page -- callers treat "not found"
    as "no rules/rulesets configured", a normal state, not a transport
    failure. Any other non-2xx status or transport/parse error raises
    GitHubAPIError (tagged with `.status_code` when an HTTP status is
    available, so callers can special-case auth failures).

    List-shaped (JSON array) responses are transparently paginated by
    following the standard GitHub `Link: rel="next"` header, up to
    MAX_PAGES pages, and only when the next link stays on the GitHub API
    host. Single-resource (JSON object) responses are returned as-is from
    the first page; GitHub never paginates those.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "tenax-assay",
    }

    url: Optional[str] = f"{GITHUB_API_BASE}{path}"
    aggregated: Optional[List[Any]] = None
    page = 0

    while url and page < MAX_PAGES:
        try:
            body, link_header = _fetch_page(url, headers, timeout, path)
        except _NotFoundPage:
            if page == 0:
                return None
            break  # ran out of pages mid-pagination; return what we have so far

        page += 1

        if not isinstance(body, list):
            return body  # single-resource response: no pagination applies

        aggregated = (aggregated or []) + body

        next_url = _parse_link_header(link_header).get("next")
        url = next_url if next_url and _is_same_origin_as_api(next_url) else None

    return aggregated if aggregated is not None else []


def _quote_ref(ref: str) -> str:
    return urllib.parse.quote(ref, safe="")


def _branch_exists(repository: str, branch: str, token: str, timeout: int) -> Optional[bool]:
    """Returns True/False when branch existence could be conclusively
    determined via GET /repos/{repository}/branches/{branch}, or None when
    the check itself failed (network/auth/parse error) and existence
    could not be determined either way -- callers must fail closed on
    None, the same as on a confirmed False."""
    try:
        detail = _github_api_get(f"/repos/{repository}/branches/{_quote_ref(branch)}", token, timeout)
    except GitHubAPIError:
        return None
    return detail is not None


def _bypass_actors_for_ruleset(
    repository: str, summary: Dict[str, Any], token: str, timeout: int
) -> List[Dict[str, Any]]:
    """Returns the bypass actors for one /rulesets list entry, or [] when
    the summary doesn't qualify for a detail fetch at all (not active, not
    branch-targeting, or an id that isn't genuinely an integer -- defense
    in depth: never follow an id that could smuggle extra path segments
    into the detail-fetch URL) or the detail fetch didn't return the
    expected shape."""
    if summary.get("enforcement") != "active":
        return []
    if summary.get("target") not in (None, "branch"):
        return []
    ruleset_id = summary.get("id")
    if not isinstance(ruleset_id, int) or isinstance(ruleset_id, bool):
        return []

    detail = _github_api_get(f"/repos/{repository}/rulesets/{ruleset_id}", token, timeout)
    if not isinstance(detail, dict):
        return []
    return [actor for actor in (detail.get("bypass_actors") or []) if isinstance(actor, dict)]


def _collect_bypass_actors(repository: str, token: str, timeout: int) -> List[Dict[str, Any]]:
    """Fetch bypass actors from every *active*, branch-targeting ruleset
    defined on the repo. The list endpoint doesn't inline bypass_actors, so
    each qualifying ruleset needs one detail fetch."""
    summaries = _github_api_get(f"/repos/{repository}/rulesets", token, timeout)
    if not isinstance(summaries, list):
        return []

    actors: List[Dict[str, Any]] = []
    for summary in summaries:
        if isinstance(summary, dict):
            actors.extend(_bypass_actors_for_ruleset(repository, summary, token, timeout))
    return actors


def _fetch_rules_for_branch(
    repository: str, branch: str, token: str, timeout: int
) -> Tuple[Optional[List[Any]], Optional[BranchGovernanceReport]]:
    """Fetches the effective rules for `branch`, resolving the 404
    ambiguity (no rules configured vs. a nonexistent repo/branch) via a
    secondary branch-existence check. Returns (rules, None) on success --
    an empty list is a valid, successful result (no rules configured) --
    or (None, early_report) when the whole inspection must fail closed
    right here."""
    try:
        raw_rules = _github_api_get(f"/repos/{repository}/rules/branches/{_quote_ref(branch)}", token, timeout)
    except GitHubAPIError as e:
        if e.status_code in (401, 403):
            reason_code = REASON_CODE_PLATFORM_UNSUPPORTED_TIER if _is_platform_tier_limitation(str(e)) else None
            return None, _unavailable(
                branch, _actionable_auth_failure_reason(e, "querying rules for branch"), reason_code
            )
        return None, _unavailable(branch, f"GitHub rules API request failed: {e}")

    if raw_rules is None:
        # rules-for-branch 404'd. GitHub returns 404 both for "no rules
        # apply to this branch" (benign) and for a nonexistent repo/branch
        # (a caller typo that must not be silently reported as "clean").
        # Only trust the benign interpretation once branch existence is
        # independently confirmed; otherwise fail closed.
        exists = _branch_exists(repository, branch, token, timeout)
        if exists is False:
            return None, _unavailable(
                branch,
                f"repository '{repository}' or branch '{branch}' does not exist "
                "(branch lookup returned 404); cannot verify branch governance",
            )
        if exists is None:
            return None, _unavailable(
                branch,
                "could not confirm repository/branch existence after an empty rules-for-branch "
                "response; failing closed rather than assuming no rules apply",
            )
        return [], None

    return (raw_rules if isinstance(raw_rules, list) else []), None


def _fetch_bypass_actors_with_fallback(
    repository: str, branch: str, token: str, timeout: int
) -> Tuple[List[Dict[str, Any]], Optional[str], Optional[BranchGovernanceReport]]:
    """Fetches bypass actors across active branch rulesets. Returns
    (bypass_actors, bypass_fetch_warning, None) on success -- an auth
    failure taints the whole report closed (returns ([], None,
    early_report) instead, since the rules-for-branch call may well have
    "succeeded" only via its own 404-is-benign short-circuit), while any
    other failure degrades to "no bypass-actor visibility" (empty list +
    a warning) without discarding the rules data already in hand."""
    try:
        bypass_actors = _collect_bypass_actors(repository, token, timeout)
    except GitHubAPIError as e:
        if e.status_code in (401, 403):
            reason_code = REASON_CODE_PLATFORM_UNSUPPORTED_TIER if _is_platform_tier_limitation(str(e)) else None
            return [], None, _unavailable(
                branch, _actionable_auth_failure_reason(e, "enumerating rulesets"), reason_code
            )
        return [], f"could not enumerate ruleset bypass actors: {e}", None
    return bypass_actors, None, None


def _derive_pr_requirements(rules: List[Any]) -> Tuple[bool, int, bool]:
    """Returns (pull_request_required, approvals_required,
    direct_push_prevented) from the rules-for-branch response. A
    "pull_request" rule is what actually blocks a direct (non-PR) push to
    the branch; no other rule type in the response has that effect."""
    pr_rule = next((r for r in rules if isinstance(r, dict) and r.get("type") == "pull_request"), None)
    pull_request_required = pr_rule is not None

    approvals_required = 0
    if pr_rule is not None:
        params = pr_rule.get("parameters") or {}
        try:
            approvals_required = int(params.get("required_approving_review_count") or 0)
        except (TypeError, ValueError):
            approvals_required = 0

    direct_push_prevented = pull_request_required
    return pull_request_required, approvals_required, direct_push_prevented


def _derive_required_status_check_contexts(rules: List[Any]) -> List[str]:
    """Returns the `context` string of every entry under every
    "required_status_checks" rule applying to this branch -- see
    BranchGovernanceReport.required_status_check_contexts. A branch can
    have more than one such rule (repo-level and org-level rulesets both
    apply); this flattens all of them. Malformed/missing entries are
    skipped individually rather than discarding the whole rule."""
    contexts: List[str] = []
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") != "required_status_checks":
            continue
        params = rule.get("parameters") or {}
        for check in params.get("required_status_checks") or []:
            if isinstance(check, dict):
                context = check.get("context")
                if isinstance(context, str) and context.strip():
                    contexts.append(context)
    return contexts


def _classify_bypass_actors(
    bypass_actors: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], bool]:
    """Returns (always_bypass, pr_only_bypass, unknown_mode_bypass,
    admin_enforced). Allowlist, not blocklist: admin_enforced is True only
    when *every* bypass actor is restricted to the one known-least-
    dangerous mode (pull_request); "always" and any unrecognized/missing
    mode value both fail closed to "not enforced"."""
    always_bypass = [a for a in bypass_actors if a.get("bypass_mode") == BYPASS_MODE_ALWAYS]
    pr_only_bypass = [a for a in bypass_actors if a.get("bypass_mode") == BYPASS_MODE_PULL_REQUEST]
    unknown_mode_bypass = [
        a for a in bypass_actors if a.get("bypass_mode") not in (BYPASS_MODE_ALWAYS, BYPASS_MODE_PULL_REQUEST)
    ]
    admin_enforced = len(always_bypass) + len(unknown_mode_bypass) == 0
    return always_bypass, pr_only_bypass, unknown_mode_bypass, admin_enforced


def _build_governance_warnings(
    *,
    bypass_fetch_warning: Optional[str],
    rules: List[Any],
    branch: str,
    pull_request_required: bool,
    approvals_required: int,
    always_bypass: List[Dict[str, Any]],
    unknown_mode_bypass: List[Dict[str, Any]],
    pr_only_bypass: List[Dict[str, Any]],
) -> List[str]:
    warnings: List[str] = []
    if bypass_fetch_warning:
        warnings.append(bypass_fetch_warning)

    if not rules:
        warnings.append(
            f"no branch rules found for '{branch}'; direct unreviewed pushes are not prevented by any ruleset"
        )
    elif not pull_request_required:
        warnings.append(
            f"branch '{branch}' does not require a pull request; direct unreviewed commits are permitted"
        )
    elif approvals_required == 0:
        warnings.append(
            f"branch '{branch}' requires a pull request but 0 approving reviews; unreviewed merges are permitted"
        )

    if always_bypass:
        warnings.append(
            f"{len(always_bypass)} bypass actor(s) can bypass branch rules entirely (bypass_mode=always), "
            "permitting an unreviewed direct push"
        )
    if unknown_mode_bypass:
        warnings.append(
            f"{len(unknown_mode_bypass)} bypass actor(s) have an unrecognized bypass_mode; "
            "treated as a full bypass (fail-closed)"
        )
    if pr_only_bypass:
        warnings.append(
            f"{len(pr_only_bypass)} bypass actor(s) can bypass pull-request review requirements "
            "(bypass_mode=pull_request)"
        )
    return warnings


def inspect_branch_governance(
    repository: str,
    branch: str = "main",
    token: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> BranchGovernanceReport:
    """Inspects the effective branch protection rules for `branch` on
    `repository` (as "owner/repo") via GitHub's rules-for-branch
    (`GET /repos/{repository}/rules/branches/{branch}`) and rulesets
    (`GET /repos/{repository}/rulesets`) REST endpoints, authenticating
    with the ambient GITHUB_TOKEN when `token` isn't supplied explicitly.

    When `available` is False because GitHub's own error body identifies
    the platform/plan-tier feature gate specifically (a private repo on
    GitHub Free -- see REASON_CODE_PLATFORM_UNSUPPORTED_TIER), the
    returned report's `reason_code` is set to that value; it's None for
    every other unavailable case (missing token, network failure, an
    under-scoped-but-otherwise-valid token, ambiguous 404, ...).

    Orchestrates (see each helper's own docstring): input validation stays
    inline below; rules-for-branch fetch delegates to
    _fetch_rules_for_branch(), bypass-actor enumeration to
    _fetch_bypass_actors_with_fallback(), PR-requirement derivation to
    _derive_pr_requirements(), bypass-mode classification to
    _classify_bypass_actors(), and warning-list assembly to
    _build_governance_warnings().
    """
    if not isinstance(repository, str) or not _REPO_RE.match(repository):
        return _unavailable(
            branch,
            f"invalid repository identifier {repository!r}; expected 'owner/repo' "
            f"matching {_REPO_RE.pattern!r}",
        )

    resolved_token = token if token is not None else os.environ.get("GITHUB_TOKEN")
    if not resolved_token:
        return _unavailable(
            branch,
            "no GITHUB_TOKEN available (neither passed explicitly nor set in the environment); "
            "branch governance could not be verified",
        )

    rules, early_report = _fetch_rules_for_branch(repository, branch, resolved_token, timeout)
    if early_report is not None:
        return early_report

    bypass_actors, bypass_fetch_warning, early_report = _fetch_bypass_actors_with_fallback(
        repository, branch, resolved_token, timeout
    )
    if early_report is not None:
        return early_report

    pull_request_required, approvals_required, direct_push_prevented = _derive_pr_requirements(rules)
    required_status_check_contexts = _derive_required_status_check_contexts(rules)
    always_bypass, pr_only_bypass, unknown_mode_bypass, admin_enforced = _classify_bypass_actors(bypass_actors)
    bypass_actors_count = len(bypass_actors)

    warnings = _build_governance_warnings(
        bypass_fetch_warning=bypass_fetch_warning,
        rules=rules,
        branch=branch,
        pull_request_required=pull_request_required,
        approvals_required=approvals_required,
        always_bypass=always_bypass,
        unknown_mode_bypass=unknown_mode_bypass,
        pr_only_bypass=pr_only_bypass,
    )

    reason = (
        f"queried GitHub rules for {repository}@{branch}: {len(rules)} applicable rule(s), "
        f"{bypass_actors_count} bypass actor(s) across active branch rulesets"
    )

    return BranchGovernanceReport(
        available=True,
        branch=branch,
        pull_request_required=pull_request_required,
        approvals_required=approvals_required,
        direct_push_prevented=direct_push_prevented,
        bypass_actors_count=bypass_actors_count,
        admin_enforced=admin_enforced,
        warnings=warnings,
        reason=reason,
        required_status_check_contexts=required_status_check_contexts,
    )
