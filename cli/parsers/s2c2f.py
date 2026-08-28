"""
S2C2F (Secure Supply Chain Consumption Framework, Microsoft OSSF) control
evaluation.

This module deliberately does NOT attempt every control in the published
S2C2F catalog (see tenax-console's `lib/s2c2f.ts` for the full Level 1-4
taxonomy). It evaluates only the subset a CI-time tool can honestly assess
from data this pipeline already has, or a cheap, well-defined new signal
(a GitHub API call or a local config-file check) -- every other control
(malware scans, source-cloning restrictions, denylists, curated feeds,
trusted rebuilding, SBOM validation, ...) is an org-level policy/tooling
decision with no generic, repo-visible signal, and is simply never emitted
here rather than guessed at. `evaluate_s2c2f()`'s caller (cli.builder) is
expected to render "not evaluated" for every control id this module never
returns, exactly the same "absent, not fabricated" contract every other
optional block in the predicate already follows (see cli.real_coverage,
cli.parsers.sarif's "not configured" states).

Each control that *is* evaluated gets one of three honest outcomes:
  - "met":              a real, positive signal was found.
  - "unmet":            evaluation succeeded and found the control is not
                         satisfied (e.g. a reachable API confirmed the
                         feature is off).
  - "not_yet_reported": evaluation could not be completed (no token, a
                         network/auth failure, or -- for a couple of
                         controls, e.g. UPD-1 -- no generic technical
                         signal exists for this control at all). Never
                         conflated with "unmet": a check that couldn't run
                         must never be indistinguishable from one that ran
                         and failed.

Hardened against (mirrors cli.parsers.github_rules/commit_author -- see
those modules' docstrings for the shared rationale, reused here directly
rather than re-implemented):
  - Missing/expired GITHUB_TOKEN (every network-backed control degrades to
    not_yet_reported, never crashes)
  - Path/URL injection via `repository` (same strict `owner/repo` allowlist)
  - Rate limits, transport failures, and non-2xx/404 responses on every
    GitHub endpoint touched here (vulnerability-alerts, dependabot/alerts,
    community/profile) -- each control is evaluated independently, so one
    endpoint's failure never taints another control's result
  - Unreadable/non-UTF8 local config files (skipped, not raised)
"""
from __future__ import annotations

import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .github_rules import (
    DEFAULT_TIMEOUT,
    GITHUB_API_BASE,
    BranchGovernanceReport,
    GitHubAPIError,
    _REPO_RE,
    _github_api_get,
)
from .sarif import SarifSummaryReport

STATUS_MET = "met"
STATUS_UNMET = "unmet"
STATUS_NOT_YET_REPORTED = "not_yet_reported"


@dataclass
class S2C2FControlResult:
    __test__ = False
    id: str
    label: str
    level: int
    status: str  # STATUS_MET / STATUS_UNMET / STATUS_NOT_YET_REPORTED
    detail: str

    def as_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "label": self.label, "level": self.level, "status": self.status, "detail": self.detail}


@dataclass
class S2C2FReport:
    __test__ = False
    controls: List[S2C2FControlResult] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "framework": "S2C2F",
            "framework_version": "v1",
            "evaluated_controls": len(self.controls),
            "controls": [c.as_dict() for c in self.controls],
        }


def _control(id: str, label: str, level: int, status: str, detail: str = "") -> S2C2FControlResult:
    return S2C2FControlResult(id=id, label=label, level=level, status=status, detail=detail)


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------


def _github_api_status(path: str, token: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[int]:
    """GET a GitHub REST API path and return just the HTTP status code.

    Some GitHub endpoints (e.g. GET .../vulnerability-alerts) are
    boolean-shaped: 204 means "enabled", 404 means "disabled", and neither
    response carries a JSON body -- reusing cli.parsers.github_rules.
    _github_api_get's json.loads()-always contract would raise on the empty
    204 body. Returns None on any transport failure (timeout, DNS,
    connection reset) -- never raises -- since every caller here already
    treats "couldn't determine" as its own honest not_yet_reported outcome,
    same as a definitive negative status.
    """
    req = urllib.request.Request(
        f"{GITHUB_API_BASE}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "tenax-assay",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError:
        return None


def _resolve_github_context(repository: str, token: Optional[str]) -> Optional[str]:
    """Returns a usable token, or None when the network-backed controls in
    this module cannot run at all (invalid repository shape, or no token
    available -- falling back to the ambient GITHUB_TOKEN env var when
    `token` isn't supplied explicitly, same convention as
    cli.parsers.github_rules.inspect_branch_governance/
    cli.parsers.commit_author.inspect_commit_author). Callers report every
    network-backed control as not_yet_reported with a shared reason in
    that case, rather than firing off doomed requests."""
    if not isinstance(repository, str) or not _REPO_RE.match(repository):
        return None
    return token if token is not None else os.environ.get("GITHUB_TOKEN")


# ---------------------------------------------------------------------------
# Local, filesystem-only signals (no GitHub API / token required)
# ---------------------------------------------------------------------------

_UPDATE_AUTOMATION_CONFIG_PATHS = (
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    "renovate.json",
    ".github/renovate.json",
    ".renovaterc.json",
)


def _find_update_automation_config(repo_dir: str) -> Optional[str]:
    """Returns the first dependency-update-automation config file found
    under repo_dir (Dependabot or Renovate), or None if none of the
    well-known paths exist. A Dependabot/Renovate config is what actually
    produces the automated "a newer version is available" pull requests
    S2C2F's UPD-3 (PR Alerts) describes."""
    for rel_path in _UPDATE_AUTOMATION_CONFIG_PATHS:
        try:
            if (Path(repo_dir) / rel_path).is_file():
                return rel_path
        except OSError:
            continue
    return None


_PACKAGE_PROXY_CONFIG_FILES = (".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini")
_PUBLIC_REGISTRY_HOSTS = ("registry.npmjs.org", "pypi.org", "files.pythonhosted.org")


def _find_private_package_proxy_config(repo_dir: str) -> Optional[str]:
    """Best-effort ING-2 ("retain a local copy of ingested OSS components")
    signal: a package-manager config file at the repo root whose
    registry/index-url points somewhere other than the ecosystem's default
    public registry -- typically an internal Artifactory/Nexus/Verdaccio
    proxy that mirrors and retains a local copy of every package actually
    consumed. Returns the config file's relative path when such an
    override is found, else None.

    Deliberately a soft heuristic, not a strong claim either way: a repo
    with no such file in these specific locations may still consume
    through an org-wide proxy configured outside the repo (e.g. a CI
    runner's global ~/.npmrc) -- that case honestly reports "unmet"
    (checked, not found here), never a false "confirmed absent".
    """
    for rel_path in _PACKAGE_PROXY_CONFIG_FILES:
        candidate = Path(repo_dir) / rel_path
        try:
            if not candidate.is_file():
                continue
            text = candidate.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            lowered = line.strip().lower()
            if lowered.startswith("#") or "=" not in lowered:
                continue
            if "registry" not in lowered and "index-url" not in lowered:
                continue
            value = line.split("=", 1)[1].strip()
            if value and not any(host in value for host in _PUBLIC_REGISTRY_HOSTS):
                return rel_path
    return None


# SARIF tool-name substring patterns identifying a software-composition-
# analysis (vulnerability) vs. license-scanning tool, matched case-
# insensitively against SarifSummaryReport.tools_scanned -- same "name-
# pattern matching against a SARIF tool list" convention cli.main's
# _merge_sonar_metrics/parse_sonar_metrics_file already uses for
# identifying a SonarQube tool by name.
_SCA_TOOL_NAME_PATTERNS = ("trivy", "grype", "snyk", "osv-scanner", "npm-audit", "safety", "pip-audit", "dependabot")
_LICENSE_TOOL_NAME_PATTERNS = ("license-checker", "licensee", "fossa", "scancode", "license-finder")


def _sarif_tool_name_matches(tools_scanned: List[str], patterns: tuple) -> Optional[str]:
    for name in tools_scanned:
        lowered = (name or "").lower()
        for pattern in patterns:
            if pattern in lowered:
                return name
    return None


# Same digest-algorithm set cli.verify._slsa_check_materialized_dependencies
# uses for its Build Level 3 hermeticity check -- duplicated as a literal
# here rather than imported, matching cli.verify's own stated preference
# (see its _ALLOWED_DEGRADED_REASONS docstring) for this module's parsers/
# side not reaching into cli.verify's admission-gate internals, and vice
# versa: verify.py operates on decoded JSON only, never on this package's
# dataclasses.
_MATERIALIZED_DIGEST_ALGORITHMS = ("sha256", "sha512")


def _has_materialized_package_dependency(resolved_dependencies: List[Dict[str, Any]]) -> bool:
    for dep in resolved_dependencies:
        if not isinstance(dep, dict):
            continue
        uri = dep.get("uri")
        digest = dep.get("digest")
        if isinstance(uri, str) and uri.startswith("pkg:") and isinstance(digest, dict):
            if any(isinstance(digest.get(a), str) and digest.get(a).strip() for a in _MATERIALIZED_DIGEST_ALGORITHMS):
                return True
    return False


# ---------------------------------------------------------------------------
# Level 1 controls
# ---------------------------------------------------------------------------


def _eval_ing1_package_managers(resolved_dependencies: List[Dict[str, Any]]) -> S2C2FControlResult:
    pkg_count = sum(1 for d in resolved_dependencies if isinstance(d, dict) and str(d.get("uri", "")).startswith("pkg:"))
    if pkg_count > 0:
        return _control("ING-1", "Package Managers", 1, STATUS_MET, f"{pkg_count} package-manager-resolved dependenc{'y' if pkg_count == 1 else 'ies'} detected from a lockfile")
    return _control("ING-1", "Package Managers", 1, STATUS_UNMET, "no lockfile with package-manager-resolved dependencies was found under the repo")


def _eval_ing2_local_copies(repo_dir: str) -> S2C2FControlResult:
    found = _find_private_package_proxy_config(repo_dir)
    if found:
        return _control("ING-2", "Local Copies", 1, STATUS_MET, f"{found} configures a non-default registry/index-url, consistent with an internal package proxy/cache")
    return _control(
        "ING-2", "Local Copies", 1, STATUS_UNMET,
        "no .npmrc/.yarnrc/pip.conf at the repo root names a private registry/index-url; "
        "an org-wide proxy configured outside the repo would not be visible here",
    )


def _eval_sca1_vulnerability_scans(sarif_tools_scanned: List[str], vuln_alerts_status: Optional[int]) -> S2C2FControlResult:
    tool_match = _sarif_tool_name_matches(sarif_tools_scanned, _SCA_TOOL_NAME_PATTERNS)
    if tool_match:
        return _control("SCA-1", "Vulnerability Scans", 1, STATUS_MET, f"SARIF findings from a recognized SCA tool ({tool_match})")
    if vuln_alerts_status == 204:
        return _control("SCA-1", "Vulnerability Scans", 1, STATUS_MET, "GitHub Dependabot vulnerability alerts are enabled for this repository")
    if vuln_alerts_status == 404:
        return _control("SCA-1", "Vulnerability Scans", 1, STATUS_UNMET, "GitHub Dependabot vulnerability alerts are not enabled, and no SARIF input came from a recognized SCA tool")
    return _control("SCA-1", "Vulnerability Scans", 1, STATUS_NOT_YET_REPORTED, "no SARIF input from a recognized SCA tool, and the GitHub vulnerability-alerts API could not be reached (missing token or network failure)")


def _eval_sca2_license_checks(sarif_tools_scanned: List[str]) -> S2C2FControlResult:
    tool_match = _sarif_tool_name_matches(sarif_tools_scanned, _LICENSE_TOOL_NAME_PATTERNS)
    if tool_match:
        return _control("SCA-2", "License Checks", 1, STATUS_MET, f"SARIF findings from a recognized license-scanning tool ({tool_match})")
    return _control("SCA-2", "License Checks", 1, STATUS_NOT_YET_REPORTED, "no --sarif input came from a recognized license-scanning tool; no other generic signal is available")


def _eval_inv1_inventory(resolved_dependencies: List[Dict[str, Any]]) -> S2C2FControlResult:
    count = len(resolved_dependencies)
    if count > 0:
        return _control("INV-1", "Inventory", 1, STATUS_MET, f"a live inventory of {count} resolved dependencies is recorded (predicate.resolved_dependencies)")
    return _control("INV-1", "Inventory", 1, STATUS_UNMET, "predicate.resolved_dependencies is empty; no recognized lockfile was found")


def _eval_upd1_manual_updates() -> S2C2FControlResult:
    # S2C2F's UPD-1 describes a documented *process* for manually updating
    # OSS components when auto-update isn't available -- a policy fact, not
    # a technical artifact this pipeline can observe in a repo checkout or
    # via the GitHub API. Always not_yet_reported, honestly, rather than
    # inferred from an unrelated proxy signal.
    return _control("UPD-1", "Manual Updates", 1, STATUS_NOT_YET_REPORTED, "no generic, repo-observable signal exists for a documented manual-update process")


# ---------------------------------------------------------------------------
# Level 2 controls (subset with a real, checkable signal)
# ---------------------------------------------------------------------------


def _eval_sca3_eol_scans(dependabot_alerts_status: Optional[int]) -> S2C2FControlResult:
    if dependabot_alerts_status == 200:
        return _control("SCA-3", "EOL Scans", 2, STATUS_MET, "GitHub Dependabot alerts API is enabled and reachable for this repository (closest available signal for automated deprecated/EOL package flagging)")
    if dependabot_alerts_status == 404:
        return _control("SCA-3", "EOL Scans", 2, STATUS_UNMET, "GitHub Dependabot alerts are not enabled for this repository")
    if dependabot_alerts_status == 403:
        return _control("SCA-3", "EOL Scans", 2, STATUS_NOT_YET_REPORTED, "GitHub Dependabot alerts API returned 403; the token likely lacks 'Dependabot alerts: Read' permission")
    return _control("SCA-3", "EOL Scans", 2, STATUS_NOT_YET_REPORTED, "GitHub Dependabot alerts API could not be reached (missing token or network failure)")


def _eval_inv2_incident_plans(security_md_present: Optional[bool]) -> S2C2FControlResult:
    if security_md_present is True:
        return _control("INV-2", "Incident Plans", 2, STATUS_MET, "a SECURITY.md is present (GitHub community profile)")
    if security_md_present is False:
        return _control("INV-2", "Incident Plans", 2, STATUS_UNMET, "no SECURITY.md was found via the GitHub community profile API")
    return _control("INV-2", "Incident Plans", 2, STATUS_NOT_YET_REPORTED, "the GitHub community profile API could not be reached (missing token or network failure)")


def _eval_upd3_pr_alerts(repo_dir: str) -> S2C2FControlResult:
    found = _find_update_automation_config(repo_dir)
    if found:
        return _control("UPD-3", "PR Alerts", 2, STATUS_MET, f"{found} configures automated dependency-update pull requests")
    return _control("UPD-3", "PR Alerts", 2, STATUS_UNMET, "no Dependabot or Renovate configuration file was found under the repo")


def _eval_aud2_consumption_audits(resolved_dependencies: List[Dict[str, Any]]) -> S2C2FControlResult:
    count = len(resolved_dependencies)
    if count > 0:
        return _control("AUD-2", "Consumption Audits", 2, STATUS_MET, f"an auditable record of {count} consumed dependencies is recorded (predicate.resolved_dependencies)")
    return _control("AUD-2", "Consumption Audits", 2, STATUS_UNMET, "predicate.resolved_dependencies is empty; no recognized lockfile was found")


def _eval_aud3_integrity_validation(resolved_dependencies: List[Dict[str, Any]]) -> S2C2FControlResult:
    if _has_materialized_package_dependency(resolved_dependencies):
        return _control("AUD-3", "Integrity Validation", 2, STATUS_MET, "at least one resolved dependency carries a pkg: PURL with a sha256/sha512 digest")
    return _control("AUD-3", "Integrity Validation", 2, STATUS_UNMET, "no resolved dependency carries both a pkg: PURL and a sha256/sha512 digest")


def _eval_enf1_secure_source_config(branch_governance: BranchGovernanceReport) -> S2C2FControlResult:
    if not branch_governance.available:
        return _control("ENF-1", "Secure Source Config", 2, STATUS_NOT_YET_REPORTED, "branch governance could not be verified (see predicate.branch_governance.reason)")
    if branch_governance.pull_request_required and branch_governance.direct_push_prevented:
        return _control("ENF-1", "Secure Source Config", 2, STATUS_MET, "the branch requires a pull request and prevents direct pushes")
    return _control("ENF-1", "Secure Source Config", 2, STATUS_UNMET, "the branch does not both require a pull request and prevent direct pushes")


# ---------------------------------------------------------------------------
# Level 3 controls (subset with a real, checkable signal)
# ---------------------------------------------------------------------------

_PROVENANCE_STATUS_CHECK_PATTERNS = ("tenax", "assay", "attest", "provenance", "slsa", "verify")


def _eval_aud1_enforcing_provenance(branch_governance: BranchGovernanceReport) -> S2C2FControlResult:
    if not branch_governance.available:
        return _control("AUD-1", "Enforcing Provenance", 3, STATUS_NOT_YET_REPORTED, "branch governance could not be verified (see predicate.branch_governance.reason)")
    contexts = branch_governance.required_status_check_contexts or []
    match = next((c for c in contexts if any(p in c.lower() for p in _PROVENANCE_STATUS_CHECK_PATTERNS)), None)
    if match:
        return _control("AUD-1", "Enforcing Provenance", 3, STATUS_MET, f"required status check '{match}' enforces provenance/attestation verification before merge")
    return _control("AUD-1", "Enforcing Provenance", 3, STATUS_UNMET, "no required status check on the branch names a provenance/attestation verification job")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def evaluate_s2c2f(
    *,
    repo_dir: str,
    repository: str,
    resolved_dependencies: Optional[List[Dict[str, Any]]],
    sarif_report: Optional[SarifSummaryReport],
    branch_governance: BranchGovernanceReport,
    token: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> S2C2FReport:
    """Evaluates every S2C2F control this module supports (see module
    docstring for why that's a subset of the full catalog) and returns an
    S2C2FReport. Never raises: every network-backed control independently
    degrades to STATUS_NOT_YET_REPORTED on a missing token, rate limit, or
    any other API/transport failure, exactly like every other GitHub-API-
    backed check in this package (cli.parsers.github_rules/commit_author)."""
    resolved_dependencies = resolved_dependencies or []
    sarif_tools_scanned = list(sarif_report.tools_scanned) if sarif_report is not None else []

    resolved_token = _resolve_github_context(repository, token)
    vuln_alerts_status: Optional[int] = None
    dependabot_alerts_status: Optional[int] = None
    security_md_present: Optional[bool] = None

    if resolved_token:
        vuln_alerts_status = _github_api_status(f"/repos/{repository}/vulnerability-alerts", resolved_token, timeout)
        dependabot_alerts_status = _github_api_status(f"/repos/{repository}/dependabot/alerts?per_page=1", resolved_token, timeout)
        try:
            profile = _github_api_get(f"/repos/{repository}/community/profile", resolved_token, timeout)
        except GitHubAPIError:
            profile = None
        if isinstance(profile, dict):
            files = profile.get("files")
            security_md_present = bool(isinstance(files, dict) and files.get("security"))

    controls = [
        _eval_ing1_package_managers(resolved_dependencies),
        _eval_ing2_local_copies(repo_dir),
        _eval_sca1_vulnerability_scans(sarif_tools_scanned, vuln_alerts_status),
        _eval_sca2_license_checks(sarif_tools_scanned),
        _eval_inv1_inventory(resolved_dependencies),
        _eval_upd1_manual_updates(),
        _eval_sca3_eol_scans(dependabot_alerts_status),
        _eval_inv2_incident_plans(security_md_present),
        _eval_upd3_pr_alerts(repo_dir),
        _eval_aud2_consumption_audits(resolved_dependencies),
        _eval_aud3_integrity_validation(resolved_dependencies),
        _eval_enf1_secure_source_config(branch_governance),
        _eval_aud1_enforcing_provenance(branch_governance),
    ]
    return S2C2FReport(controls=controls)
