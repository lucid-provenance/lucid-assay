"""
Shared S2C2F Level 2/3 ingestion-control evidence logic, used by both
`scripts.verify_ingestion` (the enforceable CLI gate) and
`scripts.emit_s2c2f_evidence` (the non-blocking telemetry emitter).

This is pre-production scaffolding, not part of `cli/parsers/s2c2f.py` --
see `scripts/__init__.py` for why the two stay separate. It evaluates
three controls:

  ING-3 (Denylists, L3)     -- a checked-in denylist policy artifact
                            exists, is schema-valid and tamper-evident (its
                            own recorded digest matches a fresh
                            recomputation over its `entries`), and no
                            dependency this repo actually resolved (via
                            cli.parsers.lockfiles.detect_and_parse_dependencies)
                            matches an entry on it.

  ING-2 (Local Copies, L2) -- relabeled from an earlier draft that
                            reported this signal as ING-4 (Source Cloning)
                            -- see git history for that correction. Whether
                            resolved package-manager dependencies were
                            pulled through a declared internal/curated feed
                            rather than directly off a public registry.
                            `cli/parsers/s2c2f.py`'s own `_eval_ing2_local_copies`
                            already evaluates a related, correctly-labeled
                            ING-2 signal in the real attestation pipeline
                            (presence of a proxy config file only) -- this
                            module's version is a stronger, per-dependency
                            check for npm (real resolved URLs, not just
                            config presence) and should be treated as a
                            second, independent measurement of the same
                            control, not a duplicate to be deduplicated
                            against the real pipeline's. True ING-4 (Source
                            Cloning -- mirroring the upstream *source* of a
                            consumed OSS component) has no evaluator here
                            and is left unfulfilled; don't repurpose this
                            function for it without a genuinely new signal.

  ENF-2 (Curated Feeds, L3) -- the enforcement framing of the same
                            registry-provenance signal ING-2 detects here:
                            would a build that *broke* on a non-curated
                            feed actually have broken.

Status contract mirrors cli.parsers.s2c2f's met/unmet/not_yet_reported
exactly, renamed to match what was asked for here:
  - "PASS":  a real, positive signal was found.
  - "FAIL":  evaluation succeeded and found the control is not satisfied.
  - "AUDIT": evaluation could not be completed at all (no applicable
             lockfile/manifest to check, an unreadable repo_dir, ...).
             Never conflated with FAIL -- "couldn't check" must never be
             indistinguishable from "checked and failed".

Hardened against (same fail-closed contract as cli/parsers/*):
  - Missing/unreadable/malformed lockfiles and config files (never raises;
    degrades to AUDIT / a reported FAIL with an honest reason, never a
    fabricated PASS)
  - A denylist artifact that's missing, malformed, or whose digest doesn't
    match its own contents (tamper-evidence, not just presence)
  - Path traversal via repo_dir/denylist path (reuses
    cli.common.safe_resolve_path, same as every cli/parsers/* module)
  - "internal registry" is inherently org-specific -- this module never
    guesses a default; callers must supply --internal-registry/
    LUCID_INTERNAL_REGISTRY_HOSTS or every npm/config-presence check
    degrades honestly rather than silently assuming no internal feed
    exists.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from cli.common import UnsafePathError, safe_resolve_path
from cli.parsers.s2c2f import _find_private_package_proxy_config

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_AUDIT = "AUDIT"

DENYLIST_SCHEMA_VERSION = "s2c2f-denylist/v1"

_CONTROL_CATALOG = {
    "ING-3": ("Denylists", 3),
    "ING-2": ("Local Copies", 2),
    "ENF-2": ("Curated Feeds", 3),
}

_PUBLIC_NPM_HOST = "registry.npmjs.org"


@dataclass
class ControlEvidence:
    id: str
    label: str
    level: int
    status: str
    detail: str
    note: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        out = {"id": self.id, "label": self.label, "level": self.level, "status": self.status, "detail": self.detail}
        if self.note:
            out["note"] = self.note
        if self.evidence:
            out["evidence"] = self.evidence
        return out


def _evidence(id: str, status: str, detail: str, note: str = "", evidence: Optional[Dict[str, Any]] = None) -> ControlEvidence:
    label, level = _CONTROL_CATALOG[id]
    return ControlEvidence(id=id, label=label, level=level, status=status, detail=detail, note=note, evidence=evidence or {})


def _resolve_repo_dir(repo_dir: str) -> Optional[Path]:
    try:
        resolved = safe_resolve_path(repo_dir)
    except UnsafePathError:
        return None
    return resolved if resolved.is_dir() else None


# ---------------------------------------------------------------------------
# Feed-provenance signal shared by ING-2 and ENF-2
# ---------------------------------------------------------------------------


@dataclass
class FeedProvenanceResult:
    ecosystem: str
    signal_strength: str  # "per_dependency" | "config_presence"
    status: str
    detail: str
    source_path: Optional[str] = None


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


def _evaluate_npm_feed(repo_dir: Path, internal_hosts: List[str]) -> Optional[FeedProvenanceResult]:
    """Strong, per-dependency signal: classifies every resolved URL in
    package-lock.json by host. Returns None when no package-lock.json is
    present (npm isn't applicable here), never when it's present but
    empty/malformed -- that's a real, reportable FAIL, not an
    "inapplicable" skip."""
    lockfile = repo_dir / "package-lock.json"
    if not lockfile.is_file():
        return None
    try:
        data = json.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return FeedProvenanceResult(
            ecosystem="npm", signal_strength="per_dependency", status=STATUS_FAIL,
            detail="package-lock.json is present but unreadable/malformed JSON",
            source_path="package-lock.json",
        )
    urls = list(_iter_npm_resolved_urls(data))
    total = len(urls)
    if total == 0:
        return FeedProvenanceResult(
            ecosystem="npm", signal_strength="per_dependency", status=STATUS_FAIL,
            detail="package-lock.json carries no resolved dependency URLs to evaluate",
            source_path="package-lock.json",
        )
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
        status = STATUS_FAIL
        detail = f"{total} resolved dependenc{'y' if total == 1 else 'ies'}: {internal} via a configured internal host, {public} direct from {_PUBLIC_NPM_HOST}, {other} from another unclassified host"
    else:
        status = STATUS_PASS
        detail = f"all {total} resolved dependenc{'y' if total == 1 else 'ies'} came from a configured internal host"
    return FeedProvenanceResult(ecosystem="npm", signal_strength="per_dependency", status=status, detail=detail, source_path="package-lock.json")


_PIP_MANIFEST_FILES = ("requirements.txt", "pyproject.toml", "Pipfile")


def _evaluate_pip_feed(repo_dir: Path) -> Optional[FeedProvenanceResult]:
    """Weaker, presence-only signal (same caveat
    cli.parsers.s2c2f._find_private_package_proxy_config's own docstring
    already carries: a repo with no matching config file may still consume
    through an org-wide proxy configured outside the repo). Only
    applicable when this repo actually looks like a pip consumer at all --
    otherwise "no pip.conf found" would misreport a repo that doesn't use
    pip as a curated-feed violation."""
    if not any((repo_dir / name).is_file() for name in _PIP_MANIFEST_FILES):
        return None
    found = _find_private_package_proxy_config(str(repo_dir))
    if found:
        return FeedProvenanceResult(
            ecosystem="pip", signal_strength="config_presence", status=STATUS_PASS,
            detail=f"{found} names a non-default index-url, consistent with an internal package proxy",
            source_path=found,
        )
    return FeedProvenanceResult(
        ecosystem="pip", signal_strength="config_presence", status=STATUS_FAIL,
        detail="a pip manifest is present but no pip.conf/pip.ini at the repo root names a private index-url; "
        "an org-wide proxy configured outside the repo would not be visible here",
    )


_MAVEN_CENTRAL_HOSTS = ("repo.maven.apache.org", "repo1.maven.org", "central.sonatype.com")
_POM_REPOSITORY_RE = re.compile(r"<repository>(.*?)</repository>", re.DOTALL)
_POM_URL_RE = re.compile(r"<url>\s*([^<\s]+)\s*</url>")


def _evaluate_maven_feed(repo_dir: Path) -> Optional[FeedProvenanceResult]:
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
        return FeedProvenanceResult(ecosystem="maven", signal_strength="config_presence", status=STATUS_FAIL, detail="pom.xml is present but unreadable")
    for block in _POM_REPOSITORY_RE.findall(text):
        match = _POM_URL_RE.search(block)
        if match and not any(host in match.group(1) for host in _MAVEN_CENTRAL_HOSTS):
            return FeedProvenanceResult(
                ecosystem="maven", signal_strength="config_presence", status=STATUS_PASS,
                detail=f"pom.xml declares a <repository> outside Maven Central ({match.group(1)})", source_path="pom.xml",
            )
    return FeedProvenanceResult(
        ecosystem="maven", signal_strength="config_presence", status=STATUS_FAIL,
        detail="pom.xml declares no <repository> outside Maven Central; settings.xml-level mirrors (outside this repo) would not be visible here",
    )


def evaluate_feed_provenance(repo_dir: Path, internal_hosts: List[str]) -> List[FeedProvenanceResult]:
    """Runs every applicable ecosystem's feed-provenance check and returns
    the results actually applicable to this repo (empty list when none of
    npm/pip/maven's manifests are present at all)."""
    results = []
    for fn in (lambda: _evaluate_npm_feed(repo_dir, internal_hosts), lambda: _evaluate_pip_feed(repo_dir), lambda: _evaluate_maven_feed(repo_dir)):
        result = fn()
        if result is not None:
            results.append(result)
    return results


def evaluate_ing2_local_copies(feed_results: List[FeedProvenanceResult]) -> ControlEvidence:
    """See this module's docstring: a second, independent ING-2 signal
    from cli/parsers/s2c2f.py's own `_eval_ing2_local_copies` -- stronger
    for npm (real per-dependency resolved URLs), config-presence-only for
    pip/maven, same as that function."""
    if not feed_results:
        return _evidence("ING-2", STATUS_AUDIT, "no npm/pip/maven manifest was found under repo_dir to evaluate feed provenance against")
    failing = [r for r in feed_results if r.status == STATUS_FAIL]
    detail = "; ".join(f"{r.ecosystem}: {r.detail}" for r in feed_results)
    status = STATUS_FAIL if failing else STATUS_PASS
    return _evidence("ING-2", status, detail, evidence={"ecosystems": [r.__dict__ for r in feed_results]})


def evaluate_enf2_curated_feeds(feed_results: List[FeedProvenanceResult]) -> ControlEvidence:
    if not feed_results:
        return _evidence("ENF-2", STATUS_AUDIT, "no npm/pip/maven manifest was found under repo_dir to evaluate curated-feed enforcement against")
    failing = [r for r in feed_results if r.status == STATUS_FAIL]
    if failing:
        detail = "a build enforcing curated-feed consumption would break here: " + "; ".join(f"{r.ecosystem}: {r.detail}" for r in failing)
        return _evidence("ENF-2", STATUS_FAIL, detail, evidence={"ecosystems": [r.__dict__ for r in feed_results]})
    detail = "no dependency resolution bypassed the required curated feed(s); enforcement would not break this build: " + "; ".join(f"{r.ecosystem}: {r.detail}" for r in feed_results)
    return _evidence("ENF-2", STATUS_PASS, detail, evidence={"ecosystems": [r.__dict__ for r in feed_results]})


# ---------------------------------------------------------------------------
# ING-3: Denylists
# ---------------------------------------------------------------------------


def _canonical_entries_bytes(entries: List[Dict[str, Any]]) -> bytes:
    return json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_denylist_digest(entries: List[Dict[str, Any]]) -> str:
    return hashlib.sha256(_canonical_entries_bytes(entries)).hexdigest()


def load_denylist(path: Path) -> "tuple[Optional[Dict[str, Any]], Optional[str]]":
    """Returns (parsed_document, None) on success, or (None, reason) on
    any failure -- missing file, malformed JSON, a schema violation, or a
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


def evaluate_ing3_denylists(denylist_path: Path, resolved_dependencies: List[Dict[str, Any]]) -> ControlEvidence:
    doc, error = load_denylist(denylist_path)
    if doc is None:
        return _evidence("ING-3", STATUS_FAIL, error or "denylist artifact could not be loaded")
    entries = doc["entries"]
    matches = []
    for dep in resolved_dependencies:
        uri = dep.get("uri") if isinstance(dep, dict) else None
        if not isinstance(uri, str):
            continue
        for entry in entries:
            token = f"pkg:{entry['ecosystem']}/{entry['name']}"
            if uri.startswith(token):
                matches.append({"uri": uri, "denylist_entry": entry["name"], "reason": entry["reason"]})
    if matches:
        names = ", ".join(sorted({m["denylist_entry"] for m in matches}))
        return _evidence("ING-3", STATUS_FAIL, f"{len(matches)} resolved dependency(ies) matched a denylisted package: {names}", evidence={"matches": matches})
    return _evidence(
        "ING-3", STATUS_PASS,
        f"denylist artifact present, schema-valid, digest-verified ({len(entries)} entries); "
        f"none matched the {len(resolved_dependencies)} resolved dependenc{'y' if len(resolved_dependencies) == 1 else 'ies'} checked",
    )


# ---------------------------------------------------------------------------
# Entry point shared by both CLI scripts
# ---------------------------------------------------------------------------


def run_ingestion_checks(
    *, repo_dir: Path, internal_hosts: List[str], denylist_path: Path, resolved_dependencies: List[Dict[str, Any]],
) -> Dict[str, ControlEvidence]:
    """Never raises: a repo_dir that fails to resolve degrades every
    control to AUDIT rather than letting an exception escape into either
    CLI's main()."""
    resolved_dir = _resolve_repo_dir(str(repo_dir))
    if resolved_dir is None:
        reason = f"repo_dir {repo_dir!r} could not be resolved or is not a directory"
        return {
            "ING-3": _evidence("ING-3", STATUS_AUDIT, reason),
            "ING-2": _evidence("ING-2", STATUS_AUDIT, reason),
            "ENF-2": _evidence("ENF-2", STATUS_AUDIT, reason),
        }
    feed_results = evaluate_feed_provenance(resolved_dir, internal_hosts)
    return {
        "ING-3": evaluate_ing3_denylists(denylist_path, resolved_dependencies),
        "ING-2": evaluate_ing2_local_copies(feed_results),
        "ENF-2": evaluate_enf2_curated_feeds(feed_results),
    }
