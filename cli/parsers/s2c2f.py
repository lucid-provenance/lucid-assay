"""
S2C2F (Secure Supply Chain Consumption Framework, Microsoft OSSF) control
evaluation.

This module deliberately does NOT attempt every control in the published
S2C2F catalog (see lucid-console's `lib/s2c2f.ts` for the full Level 1-4
taxonomy). It evaluates only the subset a CI-time tool can honestly assess
from data this pipeline already has, or a cheap, well-defined new signal
(a GitHub API call, a local config-file check, or a checked-in policy
artifact) -- every other control (trusted rebuilding, SBOM validation,
...) is an org-level policy/tooling decision with no generic, repo-visible
signal, and is simply never emitted here rather than guessed at.
`evaluate_s2c2f()`'s caller (cli.builder) is expected to render "not
evaluated" for every control id this module never returns, exactly the
same "absent, not fabricated" contract every other optional block in the
predicate already follows (see cli.real_coverage, cli.parsers.sarif's "not
configured" states).

ING-3 (Denylists), ING-2 (Local Copies), and ENF-2 (Curated Feeds) were
promoted in here 2026-09-18 from `scripts/_ingestion_lib.py`, which was
deliberately pre-production, own-repo-only scaffolding (never part of the
packaged `cli` module -- see `pyproject.toml`'s own package-discovery
config) run only inside lucid-assay's own dogfood CI, never by any caller
repo invoking the real, published pipeline. That scaffold is retired now
that its signal has run for real (since 2026-09-10/12) and is judged
trustworthy -- see this module's own git history and CLAUDE.md for the
full account of why this repo's own s2c2f-evidence-telemetry never
actually made these controls repo-observable for any repo but this one.
ING-2's evaluator is upgraded in the same move: a real per-dependency
feed-provenance check for npm (classifying every resolved URL by host),
config-presence for pip/maven -- strictly stronger than the config-
presence-only check this module used before, and shared with ENF-2's
enforcement framing of the identical signal.

ING-4 (Source Cloning), SCA-4 (Malware Scans), and SCA-5 (Proactive
Reviews) are new the same day. ING-4's real S2C2F definition is mirroring
the upstream *source* of a consumed OSS component -- a materially
different, harder claim than ING-2's registry/package-level pinning, and
this project operates no such source-mirroring infrastructure today, so
its evaluator reports the honest gap (`not_yet_reported`) rather than a
fabricated signal, the same treatment UPD-1 already gets. SCA-4 checks for
a recognized malware-scanning tool's SARIF findings (OSV-Scanner by
default -- OSV.dev aggregates the OpenSSF `ossf/malicious-packages`
advisory feed; MVP-scoped to "did a malware-capable tool run", the same
shape SCA-1/SCA-2 already use, not a claim this pipeline itself performs
any scanning). SCA-5 checks for a CODEOWNERS entry covering common
dependency-manifest files plus a real branch-ruleset
`require_code_owner_review` boolean.

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
    contents) -- each control is evaluated independently, so one
    endpoint's failure never taints another control's result
  - Unreadable/non-UTF8 local config files (skipped, not raised)
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..common import UnsafePathError, safe_resolve_path
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


# Single source of truth for every control this module evaluates: its
# published S2C2F label and level. Looked up by _control() below rather
# than repeated as a literal at every met/unmet/not_yet_reported call site
# in each _eval_* function -- multiple call sites in the same function
# previously duplicated the same label literal 3-4 times over.
_CONTROL_CATALOG: Dict[str, Tuple[str, int]] = {
    "ING-1": ("Package Managers", 1),
    "ING-2": ("Local Copies", 1),
    "SCA-1": ("Vulnerability Scans", 1),
    "SCA-2": ("License Checks", 1),
    "INV-1": ("Inventory", 1),
    "UPD-1": ("Manual Updates", 1),
    "SCA-3": ("EOL Scans", 2),
    "INV-2": ("Incident Plans", 2),
    "UPD-2": ("Auto-Updates", 2),
    "UPD-3": ("PR Alerts", 2),
    "AUD-2": ("Consumption Audits", 2),
    "AUD-3": ("Integrity Validation", 2),
    "ENF-1": ("Secure Source Config", 2),
    "AUD-1": ("Enforcing Provenance", 3),
    "ING-3": ("Denylists", 3),
    "ING-4": ("Source Cloning", 3),
    "SCA-4": ("Malware Scans", 3),
    "SCA-5": ("Proactive Reviews", 3),
    "ENF-2": ("Curated Feeds", 3),
}


def _control(id: str, status: str, detail: str = "") -> S2C2FControlResult:
    label, level = _CONTROL_CATALOG[id]
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
            "User-Agent": "lucid-assay",
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

def _resolve_repo_dir(repo_dir: str) -> Optional[Path]:
    """Resolves `repo_dir` via cli.common.safe_resolve_path() -- rejecting
    null-byte-laced/unrepresentable path strings before any of this
    module's local, filesystem-only checks join a (fixed, internal)
    relative filename onto it -- and confirms it's actually a directory.
    Returns None on either failure, same "can't be checked, not fabricated
    absent" contract every other check in this module follows; every
    caller below only ever joins one of its own hardcoded relative
    filenames onto the resolved result, never a caller-supplied one."""
    try:
        resolved = safe_resolve_path(repo_dir)
    except UnsafePathError:
        return None
    return resolved if resolved.is_dir() else None


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
    well-known paths exist (or repo_dir itself can't be resolved/isn't a
    directory). A Dependabot/Renovate config is what actually produces the
    automated "a newer version is available" pull requests S2C2F's UPD-3
    (PR Alerts) describes."""
    resolved_dir = _resolve_repo_dir(repo_dir)
    if resolved_dir is None:
        return None
    for rel_path in _UPDATE_AUTOMATION_CONFIG_PATHS:
        try:
            if (resolved_dir / rel_path).is_file():
                return rel_path
        except OSError:
            continue
    return None


_PACKAGE_PROXY_CONFIG_FILES = (".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini")
_PUBLIC_REGISTRY_HOSTS = ("registry.npmjs.org", "pypi.org", "files.pythonhosted.org")


def _line_names_private_registry(line: str) -> bool:
    """True if `line` is a non-comment `key=value` config line naming a
    registry/index-url override whose value isn't one of the ecosystem's
    default public registries. Split out of
    _config_file_names_private_registry purely to keep cognitive
    complexity within budget (same rationale as cli.verify's
    _format_vcs_lines/_format_pipeline_lines split)."""
    lowered = line.strip().lower()
    if lowered.startswith("#") or "=" not in lowered:
        return False
    if "registry" not in lowered and "index-url" not in lowered:
        return False
    value = line.split("=", 1)[1].strip()
    return bool(value) and not any(host in value for host in _PUBLIC_REGISTRY_HOSTS)


def _config_file_names_private_registry(path: Path) -> bool:
    """True if `path` is a readable text file with at least one line
    matching _line_names_private_registry. Unreadable/non-UTF8 files
    degrade to False (checked, not found), never raise."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return any(_line_names_private_registry(line) for line in text.splitlines())


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
    resolved_dir = _resolve_repo_dir(repo_dir)
    if resolved_dir is None:
        return None
    for rel_path in _PACKAGE_PROXY_CONFIG_FILES:
        candidate = resolved_dir / rel_path
        if candidate.is_file() and _config_file_names_private_registry(candidate):
            return rel_path
    return None


# SARIF tool-name substring patterns identifying a software-composition-
# analysis (vulnerability) vs. license-scanning tool, matched case-
# insensitively against SarifSummaryReport.tools_scanned -- same "name-
# pattern matching against a SARIF tool list" convention cli.main's
# _merge_sonar_metrics/parse_sonar_metrics_file already uses for
# identifying a SonarQube tool by name.
_SCA_TOOL_NAME_PATTERNS = ("trivy", "grype", "snyk", "osv-scanner", "npm-audit", "safety", "pip-audit", "dependabot")
# "sbom-license" matches cli.parsers.sbom.SBOM_LICENSE_TOOL_NAME
# ("lucid-assay-sbom-license-policy") -- this module's own synthetic SARIF
# tool for --sbom-derived license-policy findings. Unlike a real
# multi-purpose scanner (e.g. Trivy, which shares one driver name across
# vulnerability/license/secret/misconfig scan classes), that tool only
# ever emits license findings, so a plain name match here is unambiguous
# and correct -- no tag-based corroboration needed.
_LICENSE_TOOL_NAME_PATTERNS = ("license-checker", "licensee", "fossa", "scancode", "license-finder", "sbom-license")


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
        return _control("ING-1", STATUS_MET, f"{pkg_count} package-manager-resolved dependenc{'y' if pkg_count == 1 else 'ies'} detected from a lockfile")
    return _control("ING-1", STATUS_UNMET, "no lockfile with package-manager-resolved dependencies was found under the repo")


# ---------------------------------------------------------------------------
# Feed-provenance signal shared by ING-2 and ENF-2 (promoted 2026-09-18 from
# scripts/_ingestion_lib.py -- see that history in this module's own
# docstring). A real, per-dependency check for npm (classifies every
# resolved URL in package-lock.json by host); config-presence-only for
# pip/maven, same caveat _find_private_package_proxy_config's own docstring
# already carries.
# ---------------------------------------------------------------------------


@dataclass
class _FeedProvenanceResult:
    ecosystem: str
    met: bool
    detail: str


def _iter_npm_resolved_urls_v1(deps: Dict[str, Any]):
    for _name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        resolved = meta.get("resolved")
        if isinstance(resolved, str):
            yield resolved
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            yield from _iter_npm_resolved_urls_v1(nested)


def _iter_npm_resolved_urls(data: Dict[str, Any]):
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if key == "":
                continue  # the root project's own entry, not a dependency
            if isinstance(meta, dict):
                resolved = meta.get("resolved")
                if isinstance(resolved, str):
                    yield resolved
        return
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        yield from _iter_npm_resolved_urls_v1(deps)


_PUBLIC_NPM_HOST = "registry.npmjs.org"


def _evaluate_npm_feed(repo_dir: Path, internal_hosts: List[str]) -> Optional[_FeedProvenanceResult]:
    """Strong, per-dependency signal: classifies every resolved URL in
    package-lock.json by host. Returns None when no package-lock.json is
    present (npm isn't applicable here), never when it's present but
    empty/malformed -- that's a real, reportable unmet, not an
    "inapplicable" skip."""
    lockfile = repo_dir / "package-lock.json"
    if not lockfile.is_file():
        return None
    try:
        data = json.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return _FeedProvenanceResult("npm", False, "package-lock.json is present but unreadable/malformed JSON")
    urls = list(_iter_npm_resolved_urls(data))
    total = len(urls)
    if total == 0:
        return _FeedProvenanceResult("npm", False, "package-lock.json carries no resolved dependency URLs to evaluate")
    internal = public = other = 0
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        if any(h and h in host for h in internal_hosts):
            internal += 1
        elif host == _PUBLIC_NPM_HOST:
            public += 1
        else:
            other += 1
    if public > 0 or other > 0:
        return _FeedProvenanceResult(
            "npm", False,
            f"{total} resolved dependenc{'y' if total == 1 else 'ies'}: {internal} via a configured internal host, "
            f"{public} direct from {_PUBLIC_NPM_HOST}, {other} from another unclassified host",
        )
    return _FeedProvenanceResult("npm", True, f"all {total} resolved dependenc{'y' if total == 1 else 'ies'} came from a configured internal host")


_PIP_MANIFEST_FILES = ("requirements.txt", "pyproject.toml", "Pipfile")


def _evaluate_pip_feed(repo_dir: Path) -> Optional[_FeedProvenanceResult]:
    """Weaker, presence-only signal (same caveat
    _find_private_package_proxy_config's own docstring already carries).
    Only applicable when this repo actually looks like a pip consumer at
    all -- otherwise "no pip.conf found" would misreport a repo that
    doesn't use pip as a curated-feed violation."""
    if not any((repo_dir / name).is_file() for name in _PIP_MANIFEST_FILES):
        return None
    found = _find_private_package_proxy_config(str(repo_dir))
    if found:
        return _FeedProvenanceResult("pip", True, f"{found} names a non-default index-url, consistent with an internal package proxy")
    return _FeedProvenanceResult(
        "pip", False,
        "a pip manifest is present but no pip.conf/pip.ini at the repo root names a private index-url; "
        "an org-wide proxy configured outside the repo would not be visible here",
    )


_MAVEN_CENTRAL_HOSTS = ("repo.maven.apache.org", "repo1.maven.org", "central.sonatype.com")
_POM_REPOSITORY_RE = re.compile(r"<repository>(.*?)</repository>", re.DOTALL)
_POM_URL_RE = re.compile(r"<url>\s*([^<\s]+)\s*</url>")


def _evaluate_maven_feed(repo_dir: Path) -> Optional[_FeedProvenanceResult]:
    """Best-effort, regex-based scan of pom.xml <repository> declarations
    -- same "purpose-built line/regex scanner, stdlib-only" convention
    cli.parsers.lockfiles uses for pnpm-lock.yaml/yarn.lock. Doesn't
    resolve Maven's inherited/settings.xml-level mirror configuration, so
    like the pip check this is a presence signal, not a per-dependency
    one."""
    pom = repo_dir / "pom.xml"
    if not pom.is_file():
        return None
    try:
        text = pom.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return _FeedProvenanceResult("maven", False, "pom.xml is present but unreadable")
    for block in _POM_REPOSITORY_RE.findall(text):
        match = _POM_URL_RE.search(block)
        if match and not any(host in match.group(1) for host in _MAVEN_CENTRAL_HOSTS):
            return _FeedProvenanceResult("maven", True, f"pom.xml declares a <repository> outside Maven Central ({match.group(1)})")
    return _FeedProvenanceResult(
        "maven", False,
        "pom.xml declares no <repository> outside Maven Central; settings.xml-level mirrors (outside this repo) would not be visible here",
    )


def _evaluate_feed_provenance(repo_dir: Path, internal_hosts: List[str]) -> List[_FeedProvenanceResult]:
    """Runs every applicable ecosystem's feed-provenance check and returns
    the results actually applicable to this repo (empty list when none of
    npm/pip/maven's manifests are present at all)."""
    results = []
    for fn in (lambda: _evaluate_npm_feed(repo_dir, internal_hosts), lambda: _evaluate_pip_feed(repo_dir), lambda: _evaluate_maven_feed(repo_dir)):
        result = fn()
        if result is not None:
            results.append(result)
    return results


def _eval_ing2_local_copies(feed_results: List[_FeedProvenanceResult]) -> S2C2FControlResult:
    if not feed_results:
        return _control("ING-2", STATUS_NOT_YET_REPORTED, "no npm/pip/maven manifest was found under the repo to evaluate feed provenance against")
    failing = [r for r in feed_results if not r.met]
    detail = "; ".join(f"{r.ecosystem}: {r.detail}" for r in feed_results)
    status = STATUS_UNMET if failing else STATUS_MET
    return _control("ING-2", status, detail)


def _eval_enf2_curated_feeds(feed_results: List[_FeedProvenanceResult]) -> S2C2FControlResult:
    if not feed_results:
        return _control("ENF-2", STATUS_NOT_YET_REPORTED, "no npm/pip/maven manifest was found under the repo to evaluate curated-feed enforcement against")
    failing = [r for r in feed_results if not r.met]
    if failing:
        detail = "a build enforcing curated-feed consumption would break here: " + "; ".join(f"{r.ecosystem}: {r.detail}" for r in failing)
        return _control("ENF-2", STATUS_UNMET, detail)
    detail = "no dependency resolution bypassed the required curated feed(s); enforcement would not break this build: " + "; ".join(
        f"{r.ecosystem}: {r.detail}" for r in feed_results
    )
    return _control("ENF-2", STATUS_MET, detail)


# ---------------------------------------------------------------------------
# ING-3: Denylists (promoted 2026-09-18 from scripts/_ingestion_lib.py)
# ---------------------------------------------------------------------------

DENYLIST_SCHEMA_VERSION = "s2c2f-denylist/v1"


def _canonical_entries_bytes(entries: List[Dict[str, Any]]) -> bytes:
    return json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_denylist_digest(entries: List[Dict[str, Any]]) -> str:
    return hashlib.sha256(_canonical_entries_bytes(entries)).hexdigest()


def load_denylist(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Returns (parsed_document, None) on success, or (None, reason) on any
    failure -- missing file, malformed JSON, a schema violation, or a
    digest mismatch (tamper-evidence, not just presence). Never raises."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None, f"no denylist policy artifact found at {path}"
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        return None, f"{path} is not valid JSON ({e})"
    if not isinstance(doc, dict):
        return None, f"{path}'s top-level document must be a JSON object"
    if doc.get("schema_version") != DENYLIST_SCHEMA_VERSION:
        return None, f"{path} has an unrecognized schema_version (expected {DENYLIST_SCHEMA_VERSION!r})"
    entries = doc.get("entries")
    if not isinstance(entries, list):
        return None, f"{path}'s 'entries' must be a list"
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("ecosystem") or not entry.get("name") or not entry.get("reason"):
            return None, f"{path} has an entry missing a required 'ecosystem'/'name'/'reason' field"
    recorded_digest = doc.get("digest_sha256")
    if not isinstance(recorded_digest, str) or not recorded_digest:
        return None, f"{path} is missing 'digest_sha256'"
    actual_digest = compute_denylist_digest(entries)
    if recorded_digest != actual_digest:
        return None, f"{path}'s digest_sha256 does not match its own entries (recorded {recorded_digest}, recomputed {actual_digest}) -- possible tampering"
    return doc, None


def _eval_ing3_denylists(denylist_path: Path, resolved_dependencies: List[Dict[str, Any]]) -> S2C2FControlResult:
    doc, error = load_denylist(denylist_path)
    if doc is None:
        return _control("ING-3", STATUS_UNMET, error or "denylist artifact could not be loaded")
    entries = doc["entries"]
    matches = []
    for dep in resolved_dependencies:
        uri = dep.get("uri") if isinstance(dep, dict) else None
        if not isinstance(uri, str):
            continue
        for entry in entries:
            token = f"pkg:{entry['ecosystem']}/{entry['name']}"
            if uri.startswith(token):
                matches.append(entry["name"])
    if matches:
        names = ", ".join(sorted(set(matches)))
        return _control("ING-3", STATUS_UNMET, f"{len(matches)} resolved dependency(ies) matched a denylisted package: {names}")
    return _control(
        "ING-3", STATUS_MET,
        f"denylist artifact present, schema-valid, digest-verified ({len(entries)} entries); "
        f"none matched the {len(resolved_dependencies)} resolved dependenc{'y' if len(resolved_dependencies) == 1 else 'ies'} checked",
    )


# ---------------------------------------------------------------------------
# ING-4: Source Cloning
# ---------------------------------------------------------------------------


def _eval_ing4_source_cloning() -> S2C2FControlResult:
    # S2C2F's ING-4 means mirroring the upstream *source* of a consumed OSS
    # component (distinct from ING-2's registry/package-level pinning) --
    # this project operates no such source-mirroring infrastructure today.
    # Honest gap, not a fabricated signal, same treatment UPD-1 already
    # gets: a real "not yet built" is itself a valid, non-guessed outcome.
    return _control("ING-4", STATUS_NOT_YET_REPORTED, "no generic, repo-observable signal exists for upstream-source mirroring; no such infrastructure is operated today")


# ---------------------------------------------------------------------------
# SCA-4: Malware Scans
# ---------------------------------------------------------------------------

# Tools specifically known for maintaining a malicious-package advisory
# feed (distinct from SCA-1's broader CVE/vulnerability-scan tool list,
# which OSV-Scanner also appears on -- SCA-1 asks "did a vulnerability
# scan run", SCA-4 asks "did a scan that also checks malicious-package
# advisories run"). OSV-Scanner is the MVP default: OSV.dev aggregates the
# OpenSSF `ossf/malicious-packages` advisory feed alongside ordinary CVE
# data. Deliberately a named, narrow allowlist, not every SCA-1 tool --
# most (Trivy, Grype, npm-audit, ...) are CVE-focused without a dedicated
# malicious-package feed. Socket/Phylum are commercial alternatives a
# caller can point --sarif at instead; this module makes no distinction
# between them beyond tool-name recognition.
_MALWARE_SCAN_TOOL_PATTERNS = ("osv-scanner", "socket", "phylum")


def _eval_sca4_malware_scans(sarif_tools_scanned: List[str]) -> S2C2FControlResult:
    tool_match = _sarif_tool_name_matches(sarif_tools_scanned, _MALWARE_SCAN_TOOL_PATTERNS)
    if tool_match:
        return _control("SCA-4", STATUS_MET, f"SARIF findings from a recognized malware/malicious-package-scanning tool ({tool_match})")
    return _control("SCA-4", STATUS_NOT_YET_REPORTED, "no --sarif input came from a recognized malware-scanning tool (default: OSV-Scanner); no other generic signal is available")


# ---------------------------------------------------------------------------
# SCA-5: Proactive Reviews
# ---------------------------------------------------------------------------

_CODEOWNERS_CANDIDATE_PATHS = ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")

# Common dependency-manifest filenames across the ecosystems this pipeline
# already parses (cli.parsers.lockfiles) plus a few more, matched against
# each CODEOWNERS pattern via fnmatch -- a best-effort, gitignore-style
# glob match, not full CODEOWNERS path semantics (directory-scoped `/**`
# nesting, negation, ...). Same "soft heuristic, honestly caveated" class
# of signal as _find_private_package_proxy_config.
_DEPENDENCY_MANIFEST_NAMES = (
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock", "Pipfile", "Pipfile.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
    "Gemfile", "Gemfile.lock",
)


def _codeowners_pattern_covers_manifest(pattern: str) -> Optional[str]:
    """Returns the manifest filename a CODEOWNERS pattern line appears to
    cover, or None. Strips a leading '/' (CODEOWNERS patterns are
    repo-root-relative) and a trailing '/**' before matching; a bare '*'
    (covers everything) matches trivially."""
    normalized = pattern.strip().lstrip("/")
    if normalized.endswith("/**"):
        normalized = normalized[:-3]
    for name in _DEPENDENCY_MANIFEST_NAMES:
        if fnmatch.fnmatch(name, normalized) or normalized in ("*", "**", name):
            return name
    return None


def _find_codeowners_manifest_coverage(repo_dir: str) -> Optional[Tuple[str, str]]:
    """Returns (codeowners_path, matched_manifest_name) for the first
    CODEOWNERS entry (checked at GitHub's three recognized locations) that
    appears to cover a real dependency-manifest filename, or None if no
    CODEOWNERS file exists at any of them, or none of its entries do."""
    resolved_dir = _resolve_repo_dir(repo_dir)
    if resolved_dir is None:
        return None
    for rel_path in _CODEOWNERS_CANDIDATE_PATHS:
        candidate = resolved_dir / rel_path
        if not candidate.is_file():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            pattern = stripped.split()[0]
            matched = _codeowners_pattern_covers_manifest(pattern)
            if matched:
                return rel_path, matched
    return None


def _eval_sca5_proactive_reviews(repo_dir: str, branch_governance: BranchGovernanceReport) -> S2C2FControlResult:
    if not branch_governance.available:
        return _control("SCA-5", STATUS_NOT_YET_REPORTED, "branch governance could not be verified (see predicate.branch_governance.reason)")
    coverage = _find_codeowners_manifest_coverage(repo_dir)
    if coverage is None:
        return _control("SCA-5", STATUS_UNMET, "no CODEOWNERS entry (checked CODEOWNERS/.github/CODEOWNERS/docs/CODEOWNERS) covers a recognized dependency-manifest file")
    codeowners_path, manifest_name = coverage
    if not branch_governance.require_code_owner_review:
        return _control(
            "SCA-5", STATUS_UNMET,
            f"{codeowners_path} covers {manifest_name}, but the branch does not require code-owner review (require_code_owner_review is false)",
        )
    return _control(
        "SCA-5", STATUS_MET,
        f"{codeowners_path} covers {manifest_name}, and the branch requires code-owner review before merge",
    )


def _eval_sca1_vulnerability_scans(sarif_tools_scanned: List[str], vuln_alerts_status: Optional[int]) -> S2C2FControlResult:
    tool_match = _sarif_tool_name_matches(sarif_tools_scanned, _SCA_TOOL_NAME_PATTERNS)
    if tool_match:
        return _control("SCA-1", STATUS_MET, f"SARIF findings from a recognized SCA tool ({tool_match})")
    if vuln_alerts_status == 204:
        return _control("SCA-1", STATUS_MET, "GitHub Dependabot vulnerability alerts are enabled for this repository")
    if vuln_alerts_status == 404:
        return _control("SCA-1", STATUS_UNMET, "GitHub Dependabot vulnerability alerts are not enabled, and no SARIF input came from a recognized SCA tool")
    return _control("SCA-1", STATUS_NOT_YET_REPORTED, "no SARIF input from a recognized SCA tool, and the GitHub vulnerability-alerts API could not be reached (missing token or network failure)")


def _eval_sca2_license_checks(sarif_tools_scanned: List[str]) -> S2C2FControlResult:
    tool_match = _sarif_tool_name_matches(sarif_tools_scanned, _LICENSE_TOOL_NAME_PATTERNS)
    if tool_match:
        return _control("SCA-2", STATUS_MET, f"SARIF findings from a recognized license-scanning tool ({tool_match})")
    return _control("SCA-2", STATUS_NOT_YET_REPORTED, "no --sarif input came from a recognized license-scanning tool; no other generic signal is available")


def _eval_inv1_inventory(resolved_dependencies: List[Dict[str, Any]]) -> S2C2FControlResult:
    count = len(resolved_dependencies)
    if count > 0:
        return _control("INV-1", STATUS_MET, f"a live inventory of {count} resolved dependencies is recorded (predicate.resolved_dependencies)")
    return _control("INV-1", STATUS_UNMET, "predicate.resolved_dependencies is empty; no recognized lockfile was found")


# S2C2F's UPD-1 describes a documented *process* for manually updating OSS
# components when auto-update isn't available -- a policy fact a fuzzy
# markdown-content heuristic can't honestly infer (2026-09-18: deliberately
# rejected a "scan CONTRIBUTING.md for update-sounding text" heuristic in
# favor of this -- an explicit, checked-in assertion, verified where it
# can be, not guessed at). Two ways a repo can assert this control, both
# real and checkable rather than scraped:
#   1. `.lucid/manual-updates.json`'s `process_ref` -- a relative repo path
#      (verified to actually exist -- a dangling pointer is a real,
#      reportable unmet, not silently trusted) or an http(s) URL (not
#      fetched -- same trust-the-human-asserter model
#      `--license-curations`' own entries already use, since this
#      pipeline has no network-egress budget for verifying arbitrary
#      external URLs are live).
#   2. A dedicated runbook file at one of `_MANUAL_UPDATES_FALLBACK_PATHS`,
#      when no config points elsewhere.
MANUAL_UPDATES_SCHEMA_VERSION = "s2c2f-manual-updates/v1"
_MANUAL_UPDATES_CONFIG_PATH = ".lucid/manual-updates.json"
_MANUAL_UPDATES_FALLBACK_PATHS = ("UPDATING.md", "docs/manual-updates.md")


def _load_manual_updates_process_ref(repo_dir: Path) -> Optional[str]:
    """Returns the real `process_ref` string from `.lucid/manual-updates.json`,
    or None on anything short of a fully valid, schema-matching assertion
    (missing file, malformed JSON, wrong/missing schema_version, missing/
    empty process_ref) -- never raises, never guesses."""
    try:
        text = (repo_dir / _MANUAL_UPDATES_CONFIG_PATH).read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict) or doc.get("schema_version") != MANUAL_UPDATES_SCHEMA_VERSION:
        return None
    process_ref = doc.get("process_ref")
    return process_ref if isinstance(process_ref, str) and process_ref.strip() else None


def _process_ref_is_url(process_ref: str) -> bool:
    parsed = urlparse(process_ref)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def _eval_upd1_manual_updates(repo_dir: str) -> S2C2FControlResult:
    resolved_dir = _resolve_repo_dir(repo_dir)
    if resolved_dir is None:
        return _control("UPD-1", STATUS_NOT_YET_REPORTED, f"repo_dir {repo_dir!r} could not be resolved")

    process_ref = _load_manual_updates_process_ref(resolved_dir)
    if process_ref:
        if _process_ref_is_url(process_ref):
            return _control("UPD-1", STATUS_MET, f".lucid/manual-updates.json asserts a documented manual-update process at {process_ref}")
        if (resolved_dir / process_ref).is_file():
            return _control("UPD-1", STATUS_MET, f".lucid/manual-updates.json asserts a documented manual-update process at {process_ref}, and that file exists in the repo")
        return _control(
            "UPD-1", STATUS_UNMET,
            f".lucid/manual-updates.json's process_ref ({process_ref!r}) does not exist in the repo -- a stale or broken assertion",
        )

    for rel_path in _MANUAL_UPDATES_FALLBACK_PATHS:
        if (resolved_dir / rel_path).is_file():
            return _control("UPD-1", STATUS_MET, f"{rel_path} is present as a dedicated manual-update runbook")

    return _control(
        "UPD-1", STATUS_UNMET,
        "no .lucid/manual-updates.json process_ref, and neither UPDATING.md nor docs/manual-updates.md exists -- "
        "no documented manual-update process asserted",
    )


# ---------------------------------------------------------------------------
# UPD-2: Auto-Updates
# ---------------------------------------------------------------------------


# 2026-09-18, rewritten same day: the first version of this check read
# GET /repos/{owner}/{repo}'s allow_auto_merge field -- confirmed against
# a real run, then independently against a real *unauthenticated* call,
# that GitHub omits that field entirely unless the caller has *push*
# access to the repo. Every GitHub-API-backed check in this pipeline
# deliberately uses a read-only token (see this repo's own README/
# CLAUDE.md) -- allow_auto_merge was therefore structurally unreachable
# from day one, not a permission this App could ever be granted without
# abandoning that posture. Replaced with a real, local, no-API signal
# instead: whether a workflow under .github/workflows/ actually wires up
# Dependabot-PR auto-merge, detected via `dependabot/fetch-metadata` --
# the de facto standard building block every real "gh pr merge --auto"-
# style Dependabot automation is built on (it's what exposes the PR's
# own update-type/dependency metadata to a workflow's own `if:`
# condition). More specific than the old signal would even have been:
# a bare allow_auto_merge=true says nothing about whether *dependency*
# PRs specifically get auto-merged, just that auto-merge is possible for
# some PR, by someone, for any reason.
_DEPENDABOT_AUTOMERGE_MARKER = "dependabot/fetch-metadata"


def _find_dependabot_automerge_workflow(repo_dir: str) -> Optional[str]:
    resolved_dir = _resolve_repo_dir(repo_dir)
    if resolved_dir is None:
        return None
    workflows_dir = resolved_dir / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return None
    try:
        entries = sorted(workflows_dir.iterdir())
    except OSError:
        return None
    for entry in entries:
        if entry.suffix not in (".yml", ".yaml") or not entry.is_file():
            continue
        try:
            text = entry.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if _DEPENDABOT_AUTOMERGE_MARKER in text:
            return f".github/workflows/{entry.name}"
    return None


def _eval_upd2_auto_updates(repo_dir: str) -> S2C2FControlResult:
    found = _find_update_automation_config(repo_dir)
    if not found:
        return _control("UPD-2", STATUS_UNMET, "no Dependabot or Renovate configuration file was found under the repo, so there is nothing for auto-merge to apply to")
    automerge_workflow = _find_dependabot_automerge_workflow(repo_dir)
    if automerge_workflow:
        return _control("UPD-2", STATUS_MET, f"{found} configures automated dependency-update pull requests, and {automerge_workflow} auto-merges them (dependabot/fetch-metadata)")
    return _control(
        "UPD-2", STATUS_UNMET,
        f"{found} configures automated dependency-update pull requests, but no workflow under .github/workflows/ appears to auto-merge them "
        "(no dependabot/fetch-metadata usage found); updates still require a manual merge",
    )


# ---------------------------------------------------------------------------
# Level 2 controls (subset with a real, checkable signal)
# ---------------------------------------------------------------------------


def _eval_sca3_eol_scans(dependabot_alerts_status: Optional[int]) -> S2C2FControlResult:
    if dependabot_alerts_status == 200:
        return _control("SCA-3", STATUS_MET, "GitHub Dependabot alerts API is enabled and reachable for this repository (closest available signal for automated deprecated/EOL package flagging)")
    if dependabot_alerts_status == 404:
        return _control("SCA-3", STATUS_UNMET, "GitHub Dependabot alerts are not enabled for this repository")
    if dependabot_alerts_status == 403:
        return _control("SCA-3", STATUS_NOT_YET_REPORTED, "GitHub Dependabot alerts API returned 403; the token likely lacks 'Dependabot alerts: Read' permission")
    return _control("SCA-3", STATUS_NOT_YET_REPORTED, "GitHub Dependabot alerts API could not be reached (missing token or network failure)")


# Fixed 2026-09-10: GitHub's GET /repos/{owner}/{repo}/community/profile
# response's `files` object has never had a `security` key at all --
# confirmed against a real repo with a genuine, committed SECURITY.md
# (this repo's own) coming back with no such key in that response, then
# against GitHub's own published REST API schema for this endpoint (only
# code_of_conduct/code_of_conduct_file/license/contributing/readme/
# issue_template/pull_request_template). The original
# `files.get("security")` check this control used to run was checking a
# field that was never real -- INV-2 could never have reported MET for
# any repository, regardless of whether a real SECURITY.md existed.
#
# Fixed by replicating GitHub's own documented SECURITY.md discovery/
# fallback logic explicitly, since no single API reports the *effective*
# (org-default-inclusive) answer: check the repo's own three recognized
# locations via the Contents API; if none found, check the same three
# locations in the org's own `.github` repository (GitHub's org-wide
# default community health file mechanism -- a repo with no SECURITY.md
# of its own inherits the org's, and this control should credit that the
# same way GitHub's own UI does).
_SECURITY_MD_CANDIDATE_PATHS = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")


def _has_security_md_at(repository: str, token: str, timeout: int) -> Optional[bool]:
    """True if `repository` has a SECURITY.md at any of GitHub's three
    recognized locations, False if a definitive check of all three found
    none, None if any check couldn't complete (auth/network failure) --
    never guesses False when a check simply didn't run."""
    for rel_path in _SECURITY_MD_CANDIDATE_PATHS:
        try:
            result = _github_api_get(f"/repos/{repository}/contents/{rel_path}", token, timeout)
        except GitHubAPIError:
            return None
        if result is not None:
            return True
    return False


def _detect_security_md(repository: str, token: str, timeout: int) -> Optional[bool]:
    """`repository`'s own SECURITY.md, falling back to the org's `.github`
    repo's default the same way GitHub itself does. Propagates None
    (couldn't determine) rather than collapsing an inconclusive org-level
    check into a false "unmet" once the repo's own copy is confirmed
    absent."""
    own = _has_security_md_at(repository, token, timeout)
    if own is not False:
        return own  # True, or None (repo's own check itself failed)
    org = repository.split("/", 1)[0]
    return _has_security_md_at(f"{org}/.github", token, timeout)


def _eval_inv2_incident_plans(security_md_present: Optional[bool]) -> S2C2FControlResult:
    if security_md_present is True:
        return _control("INV-2", STATUS_MET, "a SECURITY.md is present (this repository's own, or the organization's default via its .github repo)")
    if security_md_present is False:
        return _control("INV-2", STATUS_UNMET, "no SECURITY.md was found in this repository or the organization's default .github repo")
    return _control("INV-2", STATUS_NOT_YET_REPORTED, "the GitHub Contents API could not be reached to check for a SECURITY.md (missing token or network failure)")


def _eval_upd3_pr_alerts(repo_dir: str) -> S2C2FControlResult:
    found = _find_update_automation_config(repo_dir)
    if found:
        return _control("UPD-3", STATUS_MET, f"{found} configures automated dependency-update pull requests")
    return _control("UPD-3", STATUS_UNMET, "no Dependabot or Renovate configuration file was found under the repo")


def _eval_aud2_consumption_audits(resolved_dependencies: List[Dict[str, Any]]) -> S2C2FControlResult:
    count = len(resolved_dependencies)
    if count > 0:
        return _control("AUD-2", STATUS_MET, f"an auditable record of {count} consumed dependencies is recorded (predicate.resolved_dependencies)")
    return _control("AUD-2", STATUS_UNMET, "predicate.resolved_dependencies is empty; no recognized lockfile was found")


def _eval_aud3_integrity_validation(resolved_dependencies: List[Dict[str, Any]]) -> S2C2FControlResult:
    if _has_materialized_package_dependency(resolved_dependencies):
        return _control("AUD-3", STATUS_MET, "at least one resolved dependency carries a pkg: PURL with a sha256/sha512 digest")
    return _control("AUD-3", STATUS_UNMET, "no resolved dependency carries both a pkg: PURL and a sha256/sha512 digest")


def _eval_enf1_secure_source_config(branch_governance: BranchGovernanceReport) -> S2C2FControlResult:
    if not branch_governance.available:
        return _control("ENF-1", STATUS_NOT_YET_REPORTED, "branch governance could not be verified (see predicate.branch_governance.reason)")
    if branch_governance.pull_request_required and branch_governance.direct_push_prevented:
        return _control("ENF-1", STATUS_MET, "the branch requires a pull request and prevents direct pushes")
    return _control("ENF-1", STATUS_UNMET, "the branch does not both require a pull request and prevent direct pushes")


# ---------------------------------------------------------------------------
# Level 3 controls (subset with a real, checkable signal)
# ---------------------------------------------------------------------------

_PROVENANCE_STATUS_CHECK_PATTERNS = ("lucid", "assay", "attest", "provenance", "slsa", "verify")


def _eval_aud1_enforcing_provenance(branch_governance: BranchGovernanceReport) -> S2C2FControlResult:
    if not branch_governance.available:
        return _control("AUD-1", STATUS_NOT_YET_REPORTED, "branch governance could not be verified (see predicate.branch_governance.reason)")
    contexts = branch_governance.required_status_check_contexts or []
    match = next((c for c in contexts if any(p in c.lower() for p in _PROVENANCE_STATUS_CHECK_PATTERNS)), None)
    if match:
        return _control("AUD-1", STATUS_MET, f"required status check '{match}' enforces provenance/attestation verification before merge")
    return _control("AUD-1", STATUS_UNMET, "no required status check on the branch names a provenance/attestation verification job")


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
    denylist_path: Optional[str] = None,
    internal_registry_hosts: Optional[List[str]] = None,
) -> S2C2FReport:
    """Evaluates every S2C2F control this module supports (see module
    docstring for why that's a subset of the full catalog) and returns an
    S2C2FReport. Never raises: every network-backed control independently
    degrades to STATUS_NOT_YET_REPORTED on a missing token, rate limit, or
    any other API/transport failure, exactly like every other GitHub-API-
    backed check in this package (cli.parsers.github_rules/commit_author).

    `denylist_path` defaults to `.lucid/denylist.json` relative to
    `repo_dir` (ING-3); `internal_registry_hosts` defaults to `[]` (no
    internal/curated registry configured -- every resolved dependency then
    reads as "not from an internal host" for ING-2/ENF-2's feed-provenance
    check, an honest reflection of "none declared", not a guess)."""
    resolved_dependencies = resolved_dependencies or []
    sarif_tools_scanned = list(sarif_report.tools_scanned) if sarif_report is not None else []
    internal_hosts = internal_registry_hosts or []

    resolved_token = _resolve_github_context(repository, token)
    vuln_alerts_status: Optional[int] = None
    dependabot_alerts_status: Optional[int] = None
    security_md_present: Optional[bool] = None

    if resolved_token:
        vuln_alerts_status = _github_api_status(f"/repos/{repository}/vulnerability-alerts", resolved_token, timeout)
        dependabot_alerts_status = _github_api_status(f"/repos/{repository}/dependabot/alerts?per_page=1", resolved_token, timeout)
        security_md_present = _detect_security_md(repository, resolved_token, timeout)

    resolved_repo_dir = _resolve_repo_dir(repo_dir)
    feed_results = _evaluate_feed_provenance(resolved_repo_dir, internal_hosts) if resolved_repo_dir is not None else []
    resolved_denylist_path = Path(denylist_path) if denylist_path is not None else Path(repo_dir) / ".lucid" / "denylist.json"

    controls = [
        _eval_ing1_package_managers(resolved_dependencies),
        _eval_ing2_local_copies(feed_results),
        _eval_sca1_vulnerability_scans(sarif_tools_scanned, vuln_alerts_status),
        _eval_sca2_license_checks(sarif_tools_scanned),
        _eval_inv1_inventory(resolved_dependencies),
        _eval_upd1_manual_updates(repo_dir),
        _eval_sca3_eol_scans(dependabot_alerts_status),
        _eval_inv2_incident_plans(security_md_present),
        _eval_upd2_auto_updates(repo_dir),
        _eval_upd3_pr_alerts(repo_dir),
        _eval_aud2_consumption_audits(resolved_dependencies),
        _eval_aud3_integrity_validation(resolved_dependencies),
        _eval_enf1_secure_source_config(branch_governance),
        _eval_aud1_enforcing_provenance(branch_governance),
        _eval_ing3_denylists(resolved_denylist_path, resolved_dependencies),
        _eval_ing4_source_cloning(),
        _eval_sca4_malware_scans(sarif_tools_scanned),
        _eval_sca5_proactive_reviews(repo_dir, branch_governance),
        _eval_enf2_curated_feeds(feed_results),
    ]
    return S2C2FReport(controls=controls)
