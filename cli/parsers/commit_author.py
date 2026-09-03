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


def _report_from_commit_body(body: Any, commit_sha: str) -> CommitAuthorReport:
    if not isinstance(body, dict):
        return _unavailable(commit_sha, "unexpected response shape from GitHub commits API")

    commit_obj = _as_dict(body.get("commit"))
    author_obj = _as_dict(commit_obj.get("author"))
    name = author_obj.get("name")
    email = author_obj.get("email")

    # The *linked GitHub account* (null unless GitHub matched the commit's
    # author email to a verified account) -- distinct from commit_obj's
    # free-text author name/email above, and the only field this check
    # trusts as "verified".
    login = _as_dict(body.get("author")).get("login")
    login = login if isinstance(login, str) and login else None

    verification = _as_dict(commit_obj.get("verification"))
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

    return _report_from_commit_body(body, commit_sha)
