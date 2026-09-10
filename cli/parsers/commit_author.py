"""
GitHub commit-author identity verification.

Confirms whether the author of a specific commit resolves to a linked,
verified GitHub account -- exactly what SLSA v1.0 Source Track Level 3
("Retained History & Author Identity") requires. A git commit's author
name/email is self-reported by whoever authored the commit object
(trivially set via `git commit --author="Anyone <anyone@example.com>"`,
or simply because the local `git config user.*` was never set to
anything real) -- entirely unverified without something binding it to
a hosting-platform identity.

GitHub's `GET /repos/{repo}/commits/{sha}` response exposes that
binding directly: the top-level `author` field (distinct from the
nested `commit.author` free-text name/email) is populated only when
GitHub has matched the commit's author email to a *verified* email
address on a GitHub account -- an unmatched email, a typo'd address,
or a spoofed "Author:" line all leave `author` null. This module
reports `verified_github_account` from that field alone; it never
infers verification from the free-text `commit.author.name`/`email`,
and it does not require cryptographic commit signing (GPG/SSH-signed
commits would be a stronger binding still, but cli.verify's Source
Level 3 check doesn't demand it -- see that module's docstring).

The *same response* also carries `commit.verification` (GitHub's own
cryptographic-signature check: `verified`, `reason`, and the raw
`signature` blob when one exists) -- extracted here too
(commit_signature_verified/_reason/_type) since it's the same API call
already being made, not a second fetch. Deliberately not folded into
`verified_github_account`/Source Level 3 above: this is a genuinely
different, stronger claim (cryptographic proof the commit content
itself wasn't altered after signing, vs. GitHub's email-matching
account link), consumed instead by cli.verify's separate Repository &
Workstation Governance section -- see that module's own docstring for
why the two are kept apart rather than combined into one signal.
`commit_signature_type` ("gpg"/"ssh") is inferred from the raw
signature blob's own PEM-style header when `verification.signature` is
present -- GitHub's API doesn't expose a parsed key ID/fingerprint
directly, and parsing one out of the raw OpenPGP/SSH signature packet
format is deliberately out of scope here; only genuinely-available data
is reported, nothing synthesized to look more complete than it is.

**GitHub-web-flow merge commit walk-back**: GitHub auto-signs *every*
merge commit it creates through its own merge API/UI (the "Merge pull
request" button) with its own "web-flow" bot key -- unconditionally,
regardless of whether the human author has ever configured personal
commit signing. Crediting that signature as `commit_signature_verified`
would be a false positive: it proves GitHub performed the merge, not
that the author's own workstation is set up for cryptographic signing
(confirmed empirically 2026-09-04 -- a real GitHub-web merge commit
came back `verified: true` via GitHub's own PGP key while the PR's own
head commit, the actual human-authored content, came back `verified:
false, reason: "unsigned"`). So when the requested commit looks like
one of these (top-level `committer.login == "web-flow"` and >=2
parents -- a real GitHub user object, not the free-text `commit.
committer` name/email, so it can't be spoofed by an arbitrary commit
author), `_web_flow_merge_second_parent`/`_resolve_signature_source`
walk back through the merge commit's second parent (the actual PR
branch tip GitHub merged in) and evaluate *that* commit's own
`commit.verification` instead -- bounded to
`_MAX_WEB_FLOW_WALK_BACK_HOPS` hops, a provably-terminating walk, never
unbounded. Only the signature-related fields are affected;
`verified_github_account`/`name`/`email`/`github_login` still describe
the originally-requested commit (a merge commit's own `author` is
honestly the human who merged it, not GitHub -- no walk-back needed
there). `commit_signature_source_sha` records which commit the
signature verdict actually came from, None when no walk-back was
needed. A failed walk-back (transport error, or the hop bound
exhausted) reports `commit_signature_verified=None` (not determined --
never silently falls back to crediting the web-flow signature) with an
explanatory `commit_signature_reason`.

**Squash/rebase-merge correction**: a *squash*- or *rebase*-merged
commit is also web-flow-signed by GitHub but has only one parent (the
base branch tip) -- the squashed/rebased content was never pushed as
its own commit object reachable by parent-walk, so
`_web_flow_merge_second_parent` correctly returns None for it. Formerly
a known residual gap (this platform's repos were assumed to all merge
via true 2-parent "Merge pull request" commits, confirmed 2026-09-04) --
confirmed *wrong* 2026-09-10 against a real run: this platform's own
repos actually enforce Linear History (branch ruleset
`required_linear_history`), which structurally forbids a true 2-parent
merge commit, meaning every PR here lands via squash or rebase and this
"residual" case was in fact the *only* case, silently crediting GitHub's
own auto-signature on every single merge (confirmed against
lucid-assay's real PR #94: squash commit `f931d63...` reports
`verified: true` via GitHub's key, while the actual human-authored
branch tip GitHub squashed, `f8af55a...`, reports `verified: false,
reason: "unsigned"`).

Closed the same way `_resolve_signature_source` already closes the
2-parent case, just via a different API path since squash/rebase leaves
no second-parent pointer to walk: `_resolve_squash_or_rebase_source`
resolves the PR GitHub associates with the requested commit
(`GET /repos/{repo}/commits/{sha}/pulls`), then that PR's own commit
list (`GET /repos/{repo}/pulls/{number}/commits`) -- the *last* entry is
the real pre-squash/pre-rebase branch tip, since a PR's own commit
history is retained independently of what its merge did to `main` --
and evaluates that commit's `commit.verification` instead. Triggered
only on the very first hop (a genuine 2-parent merge is never redirected
here; its own second-parent walk-back already reaches the real content
directly), and only when the requested commit is itself web-flow-signed
(the ordinary non-merge case is untouched). Any failure along this path
(no associated PR -- possible right when a merge under `commits/.../
pulls` hasn't been indexed by GitHub yet, same race
`.github/workflows/assay.yml`'s own "Resolve PR Context" step already
retries around; a transport/shape error; an empty PR commit list)
reports `commit_signature_verified=None`, the same fail-closed contract
as every other walk-back failure here -- never silently falls back to
crediting the squash/rebase commit's own web-flow signature.

Hardened against (mirrors cli.parsers.github_rules -- see that
module's docstring for the shared rationale, reused here directly
rather than re-implemented):
  - Missing/expired GITHUB_TOKEN (degrades to available=False, never raises)
  - Path/URL injection via `repository` (same strict `owner/repo` allowlist)
    and via `commit_sha` (hash-shape validated before any URL is built,
    then percent-encoded regardless)
  - Auth failures (401/403) invalidate the result (available=False)
  - 404 (commit/repo not found or not accessible) degrades cleanly,
    never conflated with a genuine "author unverified" finding
  - Transport/timeout/malformed-JSON/unexpected-shape failures degrade
    to available=False with the failure captured in `reason`
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .github_rules import DEFAULT_TIMEOUT, GITHUB_API_BASE, _REPO_RE, _extract_http_error_detail

# Accepts any plausible git abbreviated-or-full SHA -- this module treats
# commit_sha as an opaque hex string, same as cli.verify does elsewhere;
# just enough to reject an empty/malformed value before it reaches a URL.
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")

# Bounds the GitHub-web-flow merge commit walk-back (see this module's
# docstring) -- a provably-terminating walk, never unbounded recursion up
# a merge graph, the same "fixed bound, not a tight/unbounded loop"
# discipline cli.oidc_signer's OIDC fetch retries already apply.
_MAX_WEB_FLOW_WALK_BACK_HOPS = 5


@dataclass
class CommitAuthorReport:
    __test__ = False
    available: bool
    commit_sha: str
    name: Optional[str] = None
    email: Optional[str] = None
    github_login: Optional[str] = None
    verified_github_account: bool = False
    reason: str = ""
    # commit.verification's own fields -- see this module's docstring for
    # why these are separate from verified_github_account/reason above.
    # None (not False/"") for both commit_signature_verified and
    # commit_signature_type when unavailable/not captured -- distinct
    # from a confirmed-unsigned commit (verified=False, a real, checked
    # answer), same "None means not asked, False means asked and no"
    # discipline this module already applies to verified_github_account
    # via `available`.
    commit_signature_verified: Optional[bool] = None
    commit_signature_reason: Optional[str] = None
    commit_signature_type: Optional[str] = None
    # The SHA the signature verdict above actually came from, when it
    # differs from commit_sha -- set only after a GitHub-web-flow merge
    # commit walk-back (see this module's docstring). None when no
    # walk-back was needed (commit_sha's own signature was evaluated
    # directly).
    commit_signature_source_sha: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "commit_sha": self.commit_sha,
            "name": self.name,
            "email": self.email,
            "github_login": self.github_login,
            "verified_github_account": self.verified_github_account,
            "reason": self.reason,
            "commit_signature_verified": self.commit_signature_verified,
            "commit_signature_reason": self.commit_signature_reason,
            "commit_signature_type": self.commit_signature_type,
            "commit_signature_source_sha": self.commit_signature_source_sha,
        }


def _unavailable(commit_sha: str, reason: str) -> CommitAuthorReport:
    return CommitAuthorReport(available=False, commit_sha=commit_sha, reason=reason)


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _resolve_token(token: Optional[str]) -> Optional[str]:
    return token if token is not None else os.environ.get("GITHUB_TOKEN")


def _fetch_commit_body(
    repository: str, commit_sha: str, headers: Dict[str, str], timeout: int
) -> Tuple[Optional[Dict[str, Any]], Optional[CommitAuthorReport]]:
    """Performs the GitHub commits API request. Returns (body, None) on
    success, or (None, error_report) for any transport/auth/parse failure
    -- isolated here purely to keep inspect_commit_author's cognitive
    complexity low; behavior is unchanged from the inline version.
    """
    url = f"{GITHUB_API_BASE}/repos/{repository}/commits/{urllib.parse.quote(commit_sha, safe='')}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        if e.code == 404:
            reason = f"commit {commit_sha} not found in {repository} (or not accessible to the provided token)"
        else:
            reason = f"GitHub API request failed (HTTP {e.code}): {_extract_http_error_detail(e)}"
        return None, _unavailable(commit_sha, reason)
    except urllib.error.URLError as e:
        return None, _unavailable(commit_sha, f"GitHub API request failed: {e.reason}")
    except (json.JSONDecodeError, ValueError, OSError, RecursionError) as e:
        return None, _unavailable(commit_sha, f"GitHub API request failed: {e}")


def _signature_type_from_blob(signature: Any) -> Optional[str]:
    """Infers "gpg" or "ssh" from the raw signature blob's own PEM-style
    header -- the only place this distinction is actually observable in
    GitHub's response (no separate, parsed "algorithm" field exists).
    None for a malformed/absent/unrecognized blob -- never guessed."""
    if not isinstance(signature, str):
        return None
    text = signature.lstrip()
    if text.startswith("-----BEGIN SSH SIGNATURE-----"):
        return "ssh"
    if text.startswith("-----BEGIN PGP SIGNATURE-----"):
        return "gpg"
    return None


def _web_flow_merge_second_parent(body: Dict[str, Any]) -> Optional[str]:
    """Returns the SHA of a GitHub-web-flow-generated merge commit's
    second parent (the actual PR branch tip GitHub merged in) -- or None
    if `body` isn't one. Detected via the top-level `committer` field (a
    real GitHub user object resolved by GitHub itself, distinct from and
    unspoofable via the free-text `commit.committer` name/email) being
    exactly `web-flow`, GitHub's own bot identity for merges performed
    through its merge API/UI, combined with a >=2-parent merge shape.
    See this module's docstring for why this signal must never be
    credited as evidence of the commit author's own signing hygiene."""
    committer = body.get("committer")
    if not isinstance(committer, dict) or committer.get("login") != "web-flow":
        return None
    parents = body.get("parents")
    if not isinstance(parents, list) or len(parents) < 2:
        return None
    second = parents[1]
    if not isinstance(second, dict):
        return None
    sha = second.get("sha")
    return sha if isinstance(sha, str) and _SHA_RE.match(sha) else None


def _is_web_flow_committer(body: Dict[str, Any]) -> bool:
    """True when `body`'s top-level `committer` is GitHub's own real,
    unspoofable bot user object (login "web-flow") -- the same signal
    _web_flow_merge_second_parent keys off, factored out here so the
    squash/rebase fallback below can check it without a 2-parent merge
    shape also being required."""
    committer = body.get("committer")
    return isinstance(committer, dict) and committer.get("login") == "web-flow"


def _fetch_associated_pr_number(
    repository: str, commit_sha: str, headers: Dict[str, str], timeout: int
) -> Tuple[Optional[int], Optional[str]]:
    """Resolves the pull request GitHub associates with `commit_sha` via
    GET /repos/{repo}/commits/{sha}/pulls -- the same endpoint
    .github/workflows/assay.yml's own "Resolve PR Context" step already
    uses to recover PR context on a push-triggered run. Returns
    (pr_number, None) on success, (None, None) when GitHub reports no
    associated PR at all (a legitimate, distinct outcome -- not a
    failure), or (None, failure_reason) on any transport/shape failure."""
    url = f"{GITHUB_API_BASE}/repos/{repository}/commits/{urllib.parse.quote(commit_sha, safe='')}/pulls"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return None, f"GitHub API request failed (HTTP {e.code}) resolving the PR associated with {commit_sha}: {_extract_http_error_detail(e)}"
    except urllib.error.URLError as e:
        return None, f"GitHub API request failed resolving the PR associated with {commit_sha}: {e.reason}"
    except (json.JSONDecodeError, ValueError, OSError, RecursionError) as e:
        return None, f"GitHub API request failed resolving the PR associated with {commit_sha}: {e}"
    if not isinstance(body, list) or not body:
        return None, None
    first = body[0]
    if not isinstance(first, dict) or not isinstance(first.get("number"), int):
        return None, f"unexpected response shape resolving the PR associated with {commit_sha}"
    return first["number"], None


def _fetch_pr_branch_tip_sha(
    repository: str, pr_number: int, headers: Dict[str, str], timeout: int
) -> Tuple[Optional[str], Optional[str]]:
    """Resolves the real pre-squash/pre-rebase branch-tip commit SHA --
    the last (most recent) entry of GET /repos/{repo}/pulls/{number}/
    commits, which GitHub returns in chronological order regardless of
    what merging did to the base branch. Returns (sha, None) on success,
    (None, failure_reason) on any transport/shape/empty-list failure."""
    url = f"{GITHUB_API_BASE}/repos/{repository}/pulls/{pr_number}/commits?per_page=100"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return None, f"GitHub API request failed (HTTP {e.code}) resolving PR #{pr_number}'s commits: {_extract_http_error_detail(e)}"
    except urllib.error.URLError as e:
        return None, f"GitHub API request failed resolving PR #{pr_number}'s commits: {e.reason}"
    except (json.JSONDecodeError, ValueError, OSError, RecursionError) as e:
        return None, f"GitHub API request failed resolving PR #{pr_number}'s commits: {e}"
    if not isinstance(body, list) or not body:
        return None, f"PR #{pr_number} has no commits on record to walk back to"
    last = body[-1]
    if not isinstance(last, dict) or not isinstance(last.get("sha"), str) or not _SHA_RE.match(last["sha"]):
        return None, f"unexpected response shape in PR #{pr_number}'s commit list"
    return last["sha"], None


def _resolve_squash_or_rebase_source(
    repository: str, commit_sha: str, headers: Dict[str, str], timeout: int
) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """Fallback for a web-flow-signed commit with no second parent to
    walk through (see this module's docstring's "Squash/rebase-merge
    correction"): resolves the real pre-squash/pre-rebase PR branch-tip
    commit via the associated PR's own retained commit list, then fetches
    that commit's body so its own commit.verification can be evaluated
    instead of the synthetic GitHub-generated commit's. Returns
    (source_body, source_sha, None) on success, or (None, None,
    failure_reason) on any failure -- including no associated PR at all
    (unexpected on a branch that requires PRs, reported honestly rather
    than assumed impossible)."""
    pr_number, error = _fetch_associated_pr_number(repository, commit_sha, headers, timeout)
    if error is not None:
        return None, None, error
    if pr_number is None:
        return None, None, (
            f"commit {commit_sha} is GitHub-generated (web-flow) with no second parent to walk back through, "
            "and GitHub reports no pull request associated with it (a squash/rebase merge should have one -- "
            "this may be a merge GitHub hasn't indexed yet)"
        )
    source_sha, error = _fetch_pr_branch_tip_sha(repository, pr_number, headers, timeout)
    if error is not None:
        return None, None, error
    source_body, error_report = _fetch_commit_body(repository, source_sha, headers, timeout)
    if error_report is not None:
        return None, None, f"could not fetch PR #{pr_number}'s real branch-tip commit {source_sha}: {error_report.reason}"
    if not isinstance(source_body, dict):
        return None, None, f"unexpected response shape fetching PR #{pr_number}'s branch-tip commit {source_sha}"
    return source_body, source_sha, None


def _resolve_signature_source(
    repository: str, commit_sha: str, body: Dict[str, Any], headers: Dict[str, str], timeout: int
) -> Tuple[Dict[str, Any], Optional[str], Optional[str]]:
    """Walks back through GitHub-web-flow merge commits (see
    _web_flow_merge_second_parent) until reaching a commit whose own
    signature genuinely reflects a human's commit-signing configuration,
    bounded to _MAX_WEB_FLOW_WALK_BACK_HOPS hops -- a provably-
    terminating walk, never unbounded. On the very first hop, a
    web-flow-signed commit with no second parent to walk through (squash/
    rebase merge, see _resolve_squash_or_rebase_source) is redirected
    through that fallback instead of being credited as-is. Returns
    (signature_source_body, source_sha_or_None_if_no_walk_back_was_needed,
    failure_reason_or_None). On a failure partway through (transport
    error, unexpected shape, or the hop bound exhausted), the failure
    reason is returned and the caller must not credit any signature seen
    so far -- an incomplete walk proves nothing either way."""
    current = body
    source_sha: Optional[str] = None
    for hop in range(_MAX_WEB_FLOW_WALK_BACK_HOPS):
        next_sha = _web_flow_merge_second_parent(current)
        if next_sha is None:
            if hop == 0 and _is_web_flow_committer(current):
                fallback_body, fallback_sha, fallback_error = _resolve_squash_or_rebase_source(
                    repository, commit_sha, headers, timeout
                )
                if fallback_error is not None:
                    return current, source_sha, fallback_error
                return fallback_body, fallback_sha, None
            return current, source_sha, None
        next_body, error_report = _fetch_commit_body(repository, next_sha, headers, timeout)
        if error_report is not None:
            return current, source_sha, (
                f"could not walk back through a GitHub-generated merge commit to inspect the underlying "
                f"PR head commit {next_sha}: {error_report.reason}"
            )
        if not isinstance(next_body, dict):
            return current, source_sha, (
                f"could not walk back through a GitHub-generated merge commit: unexpected response shape "
                f"for {next_sha}"
            )
        current = next_body
        source_sha = next_sha
    return current, source_sha, (
        f"gave up walking back through GitHub-generated merge commits after "
        f"{_MAX_WEB_FLOW_WALK_BACK_HOPS} hops without reaching a non-merge commit"
    )


def _report_from_commit_body(
    body: Any,
    commit_sha: str,
    *,
    sig_source_body: Optional[Dict[str, Any]] = None,
    sig_source_sha: Optional[str] = None,
    walk_back_failure: Optional[str] = None,
) -> CommitAuthorReport:
    if not isinstance(body, dict):
        return _unavailable(commit_sha, "unexpected response shape from GitHub commits API")

    commit_obj = _as_dict(body.get("commit"))
    author_obj = _as_dict(commit_obj.get("author"))
    name = author_obj.get("name")
    email = author_obj.get("email")

    # The *linked GitHub account* (null unless GitHub matched the commit's
    # author email to a verified account) -- distinct from commit_obj's
    # free-text author name/email above, and the only field this check
    # trusts as "verified". Always read off the originally-requested
    # commit, never the walk-back target -- a merge commit's own author
    # honestly is the human who merged it, no walk-back needed here.
    login = _as_dict(body.get("author")).get("login")
    login = login if isinstance(login, str) and login else None

    if walk_back_failure is not None:
        # Not determined -- never silently falls back to crediting
        # whatever signature the (possibly GitHub-generated) requested
        # commit itself carries.
        signature_verified: Optional[bool] = None
        signature_reason: Optional[str] = walk_back_failure
        signature_type: Optional[str] = None
    else:
        sig_body = sig_source_body if isinstance(sig_source_body, dict) else body
        sig_commit_obj = _as_dict(sig_body.get("commit"))
        verification = _as_dict(sig_commit_obj.get("verification"))
        signature_verified = verification.get("verified")
        signature_verified = signature_verified if isinstance(signature_verified, bool) else None
        signature_reason = verification.get("reason")
        signature_reason = signature_reason if isinstance(signature_reason, str) and signature_reason else None
        signature_type = _signature_type_from_blob(verification.get("signature"))

    return CommitAuthorReport(
        available=True,
        commit_sha=commit_sha,
        name=name if isinstance(name, str) else None,
        email=email if isinstance(email, str) else None,
        github_login=login,
        verified_github_account=login is not None,
        reason=(
            f"commit author email resolved to verified GitHub account '{login}'"
            if login
            else "commit author email does not resolve to a linked, verified GitHub account"
        ),
        commit_signature_verified=signature_verified,
        commit_signature_reason=signature_reason,
        commit_signature_type=signature_type,
        commit_signature_source_sha=sig_source_sha,
    )


def inspect_commit_author(
    repository: str,
    commit_sha: str,
    token: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> CommitAuthorReport:
    """Inspects `GET /repos/{repository}/commits/{commit_sha}` and reports
    whether the commit's author resolves to a linked, verified GitHub
    account, authenticating with the ambient GITHUB_TOKEN when `token`
    isn't supplied explicitly.

    Fails closed to available=False (never raises) on invalid input, a
    missing token, or any transport/auth/parse/shape failure -- callers
    (cli.verify's Source Level 3 check) must treat available=False the
    same as "not verified", never as "check skipped, assume fine".
    """
    if not isinstance(repository, str) or not _REPO_RE.match(repository):
        return _unavailable(commit_sha, f"invalid repository identifier {repository!r}; expected 'owner/repo'")

    if not isinstance(commit_sha, str) or not _SHA_RE.match(commit_sha):
        return _unavailable(commit_sha, f"invalid commit sha {commit_sha!r}")

    resolved_token = _resolve_token(token)
    if not resolved_token:
        return _unavailable(commit_sha, "no GITHUB_TOKEN available (neither passed explicitly nor set in the "
                                          "environment); commit author identity could not be verified")

    headers = {
        "Authorization": f"Bearer {resolved_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "lucid-assay",
    }
    body, error_report = _fetch_commit_body(repository, commit_sha, headers, timeout)
    if error_report is not None:
        return error_report

    if not isinstance(body, dict):
        return _report_from_commit_body(body, commit_sha)

    sig_source_body, sig_source_sha, walk_back_failure = _resolve_signature_source(
        repository, commit_sha, body, headers, timeout
    )
    return _report_from_commit_body(
        body,
        commit_sha,
        sig_source_body=sig_source_body,
        sig_source_sha=sig_source_sha,
        walk_back_failure=walk_back_failure,
    )
