"""
SARIF 2.1.0 static-analysis ingestion: parses one or more `--sarif` inputs
(e.g. semgrep, trivy, CodeQL, SonarQube) into a normalized report, and
cross-references each finding's file/line against the patch's changed lines
(see `cli.patch_coverage.compute_patch_modified_lines`) so the scorer can
weigh a *newly introduced* finding differently from a pre-existing baseline
one.

On top of the differential per-finding report, this module also builds a
per-tool breakdown (`SarifSummaryReport.tools`): driver metadata (name,
version, informationUri), findings grouped by level and by rule ID/category/
tags, a SHA-256 integrity hash of the raw report file, and an extensible
`extensions` bag for tool-specific enrichments (currently SonarQube quality
gate / cognitive complexity / technical debt, sourced from a SARIF run's own
`properties` bag or merged in externally via `parse_sonar_metrics_file` +
`merge_sonar_metrics_into_tools` for tools that don't embed them).

Hardened against:
  - Missing/unreadable/malformed SARIF files (`available=False`, never raises)
  - Non-object / missing `runs`/`results` SARIF documents
  - Absolute or CI-runner-workspace-prefixed artifact URIs that don't match
    the repo-root-relative paths git diff produces (suffix-match fallback,
    mirroring cli.patch_coverage._lookup_file_coverage)
  - Missing/unrecognized `level` values (defaults to "warning", per the
    SARIF spec's own default for a result with no reportingConfiguration
    override); "none" is a spec-valid explicit level and is counted as its
    own bucket rather than folded into "warning"
  - Aggregating a mix of good and bad SARIF inputs: any unavailable input
    taints the whole aggregate (fails closed), the same way a bad/under-
    scoped GitHub token taints the whole branch-governance report (see
    cli.parsers.github_rules) -- a partial differential-scan result must
    never be silently reported as a clean bill of health
  - Malformed/missing driver `rules[]` descriptors, `properties` bags, or
    `--sonar-metrics` exports: all degrade to omitted/empty enrichment data
    rather than raising -- tool-specific extensions are informational only
    and must never be able to crash or block a run the way a core finding
    count can
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..common import UnsafePathError, safe_resolve_path

MAX_SARIF_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

VALID_LEVELS = {"error", "warning", "note", "none"}
DEFAULT_LEVEL = "warning"

# api/measures/component metric keys -> our extension key names.
_SONAR_METRIC_ALIASES = {
    "cognitive_complexity": "cognitive_complexity",
    "sqale_index": "technical_debt_minutes",  # SonarQube reports tech debt in minutes
}
# SonarQube quality-gate statuses, old (OK/WARN/ERROR/NONE) and new
# (PASSED/FAILED) naming, normalized to the schema's enum.
_SONAR_QUALITY_GATE_ALIASES = {
    "OK": "PASSED",
    "PASSED": "PASSED",
    "ERROR": "FAILED",
    "FAILED": "FAILED",
    "WARN": "WARN",
    "NONE": "NONE",
}


@dataclass
class SarifFinding:
    __test__ = False
    tool_name: str
    rule_id: str
    level: str
    message: str
    file_path: str
    start_line: int
    is_new_in_patch: bool = False
    category: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "rule_id": self.rule_id,
            "level": self.level,
            "message": self.message,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "is_new_in_patch": self.is_new_in_patch,
            "category": self.category,
            "tags": self.tags,
        }


@dataclass
class SarifRuleGroup:
    __test__ = False
    rule_id: str
    count: int
    category: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "count": self.count,
            "category": self.category,
            "tags": self.tags,
        }


@dataclass
class SarifToolSummary:
    """Per-tool breakdown for one SARIF input file. `report_hash` is the
    SHA-256 of the raw file this tool's results were parsed from -- every
    tool driver found within the same file shares that one hash, since it's
    a property of the file, not of any individual tool inside it."""
    __test__ = False
    name: str
    version: Optional[str] = None
    information_uri: Optional[str] = None
    errors_count: int = 0
    warnings_count: int = 0
    notes_count: int = 0
    none_count: int = 0
    total_findings: int = 0
    rules: List[SarifRuleGroup] = field(default_factory=list)
    extensions: Dict[str, Any] = field(default_factory=dict)
    report_hash: Optional[Dict[str, str]] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "information_uri": self.information_uri,
            "summary": {
                "errors": self.errors_count,
                "warnings": self.warnings_count,
                "notes": self.notes_count,
                "none": self.none_count,
                "total_findings": self.total_findings,
            },
            "rules": [r.as_dict() for r in self.rules],
            "extensions": self.extensions,
            "report_hash": self.report_hash,
        }


@dataclass
class SarifSummaryReport:
    __test__ = False
    available: bool
    total_findings: int = 0
    errors_count: int = 0
    warnings_count: int = 0
    notes_count: int = 0
    none_count: int = 0
    patch_errors_count: int = 0
    patch_warnings_count: int = 0
    findings: List[SarifFinding] = field(default_factory=list)
    tools_scanned: List[str] = field(default_factory=list)
    tools: List[SarifToolSummary] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "total_findings": self.total_findings,
            "errors_count": self.errors_count,
            "warnings_count": self.warnings_count,
            "notes_count": self.notes_count,
            "none_count": self.none_count,
            "patch_errors_count": self.patch_errors_count,
            "patch_warnings_count": self.patch_warnings_count,
            "findings": [f.as_dict() for f in self.findings],
            "tools_scanned": self.tools_scanned,
            "tools": [t.as_dict() for t in self.tools],
            "reasons": self.reasons,
        }


def _normalize_sarif_path(uri: str) -> str:
    """Normalize a SARIF `artifactLocation.uri` for cross-referencing
    against git-diff-derived patch_modified_lines keys (repo-root-relative,
    e.g. "cli/verify.py"). Strips a `file://` scheme, percent-decodes, then
    collapses `./`/`../` segments the same way cli.patch_coverage does."""
    p = uri.strip().strip('"').strip("'")
    if p.startswith("file://"):
        p = p[len("file://"):]
    try:
        p = urllib.parse.unquote(p)
    except (ValueError, UnicodeDecodeError):
        pass
    # Guard against traversal - os.path.normpath on "../../etc/passwd" is still "../../etc/passwd"
    # We want to ensure it doesn't escape the repo root if interpreted as relative.
    p = os.path.normpath(p)
    # If it's absolute (starts with / or \ after normpath), strip it to make it relative.
    # If it still has ../ at the beginning, it's a traversal attempt or outside repo.
    while p.startswith("..") or p.startswith(os.sep):
        p = p.lstrip(".").lstrip(os.sep)
    return p


def _path_components(path_str: str) -> List[str]:
    return [part for part in path_str.replace("\\", "/").split("/") if part]


def _lookup_modified_lines(
    patch_modified_lines: Dict[str, Set[int]], file_path: str
) -> Optional[Set[int]]:
    """Resolve a normalized SARIF artifact path against patch_modified_lines
    keys. SARIF tools frequently emit absolute or CI-workspace-prefixed
    paths rather than repo-relative ones, so a direct match is tried first,
    then fall back to suffix matching on path components (never on raw
    substrings). An ambiguous suffix match (multiple candidates tied for the
    longest match) is treated as no match rather than guessed at -- mirrors
    cli.patch_coverage._lookup_file_coverage."""
    if not file_path:
        return None

    direct = patch_modified_lines.get(file_path)
    if direct is not None:
        return direct

    sarif_parts = _path_components(file_path)
    if not sarif_parts:
        return None

    best_match: Optional[Set[int]] = None
    best_len = 0
    ambiguous = False

    for diff_path, lines in patch_modified_lines.items():
        diff_parts = _path_components(diff_path)
        if not diff_parts:
            continue

        shorter, longer = (
            (diff_parts, sarif_parts) if len(diff_parts) <= len(sarif_parts) else (sarif_parts, diff_parts)
        )
        if longer[-len(shorter):] != shorter:
            continue

        match_len = len(shorter)
        if match_len > best_len:
            best_len = match_len
            best_match = lines
            ambiguous = False
        elif match_len == best_len:
            ambiguous = True

    return None if ambiguous else best_match


def _normalize_level(raw_level: Any) -> str:
    if not isinstance(raw_level, str) or not raw_level.strip():
        return DEFAULT_LEVEL
    level = raw_level.strip().lower()
    return level if level in VALID_LEVELS else DEFAULT_LEVEL


def _extract_location(result: Dict[str, Any]) -> tuple:
    """Returns (normalized_file_path, start_line) for a SARIF result's
    first location, or ("", 0) if none is present/parseable."""
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return "", 0

    loc0 = locations[0] if isinstance(locations[0], dict) else {}
    phys = loc0.get("physicalLocation")
    phys = phys if isinstance(phys, dict) else {}

    artifact = phys.get("artifactLocation")
    artifact = artifact if isinstance(artifact, dict) else {}
    uri = artifact.get("uri")
    file_path = _normalize_sarif_path(uri) if isinstance(uri, str) and uri else ""

    region = phys.get("region")
    region = region if isinstance(region, dict) else {}
    try:
        start_line = int(region.get("startLine") or 0)
        if start_line < 0:
            start_line = 0
    except (TypeError, ValueError):
        start_line = 0

    return file_path, start_line


def _extract_rule_descriptors(driver: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Maps ruleId -> {"category": str|None, "tags": [str, ...]} from a
    SARIF tool driver's `rules` array (ReportingDescriptor objects). Missing/
    malformed entries are skipped individually rather than discarding the
    whole descriptor table."""
    descriptors: Dict[str, Dict[str, Any]] = {}
    rules = driver.get("rules")
    if not isinstance(rules, list):
        return descriptors

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            continue

        props = rule.get("properties")
        props = props if isinstance(props, dict) else {}

        tags = props.get("tags")
        tags = [str(t) for t in tags if isinstance(t, (str, int, float))] if isinstance(tags, list) else []

        category = props.get("category")
        category = str(category) if isinstance(category, (str, int)) else None

        descriptors[rule_id] = {"category": category, "tags": tags}

    return descriptors


def _extract_driver_metadata(driver: Dict[str, Any]) -> Dict[str, Optional[str]]:
    name = driver.get("name")
    name = name.strip() if isinstance(name, str) and name.strip() else "unknown"

    version = driver.get("version") or driver.get("semanticVersion")
    version = str(version) if isinstance(version, (str, int, float)) else None

    info_uri = driver.get("informationUri")
    info_uri = info_uri if isinstance(info_uri, str) and info_uri.strip() else None

    return {"name": name, "version": version, "information_uri": info_uri}


def _extract_int_metric(bag: Dict[str, Any], in_keys: Tuple[str, ...]) -> Optional[int]:
    """Looks up the first usable, non-negative-clamped integer value among
    `in_keys` (metric name aliases across SonarQube export shapes) in
    `bag`. A present-but-non-finite value (NaN/inf) is skipped in favor of
    the next alias; a present value that raises on numeric coercion stops
    the search entirely with no value -- mirrors the exact control flow of
    the inline loop this was extracted from, alias-skip vs. hard-stop
    included."""
    for in_key in in_keys:
        if in_key not in bag or bag[in_key] is None:
            continue
        try:
            fval = float(bag[in_key])
            if not math.isfinite(fval):
                continue
            return max(0, int(fval))  # Clamp to non-negative
        except (TypeError, ValueError, OverflowError):
            return None
    return None


def _extract_sonarqube_extension(run: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Looks for tool-specific enrichment data in a SARIF run's `properties`
    bag: preferentially a nested `properties.sonarqube` object, falling back
    to the top-level `properties` bag itself in case a tool writes these
    keys directly (export shapes vary). Recognizes both SonarQube's older
    alert_status-style values (OK/WARN/ERROR/NONE) and the newer PASSED/
    FAILED naming, normalized to the schema's enum. Returns None (never an
    empty dict) when nothing recognizable was found, so callers can treat
    "no extension" and "empty extension" identically."""
    props = run.get("properties")
    props = props if isinstance(props, dict) else {}

    nested = props.get("sonarqube")
    bag = nested if isinstance(nested, dict) else props

    result: Dict[str, Any] = {}

    quality_gate = bag.get("quality_gate", bag.get("qualityGate", bag.get("alert_status")))
    if isinstance(quality_gate, str):
        mapped = _SONAR_QUALITY_GATE_ALIASES.get(quality_gate.strip().upper())
        if mapped:
            result["quality_gate"] = mapped

    for out_key, in_keys in (
        ("cognitive_complexity", ("cognitive_complexity", "cognitiveComplexity")),
        ("technical_debt_minutes", ("technical_debt_minutes", "technicalDebtMinutes")),
    ):
        metric = _extract_int_metric(bag, in_keys)
        if metric is not None:
            result[out_key] = metric

    return result or None


def _init_tool_state() -> Dict[str, Any]:
    return {
        "version": None,
        "information_uri": None,
        "counts": {"error": 0, "warning": 0, "note": 0, "none": 0},
        "rules": {},  # rule_id -> {"count": int, "category": ..., "tags": [...]}
        "extensions": {},
    }


def _extract_driver_info(run: Dict[str, Any]) -> Tuple[Dict[str, Optional[str]], Dict[str, Any]]:
    """Returns (driver_metadata, raw_driver_dict) for one SARIF run --
    driver_metadata is the same shape _extract_driver_metadata() always
    produced; raw_driver_dict is handed back too since callers (rule
    descriptor extraction) need the full driver node, not just its
    normalized name/version/informationUri."""
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    driver = driver if isinstance(driver, dict) else {}
    return _extract_driver_metadata(driver), driver


def _update_tool_state_metadata(state: Dict[str, Any], meta: Dict[str, Optional[str]], run: Dict[str, Any]) -> None:
    """Merges one run's driver metadata (version/informationUri --
    first-seen-wins across every run driven by the same tool) and any
    embedded SonarQube-style extension data into `state` in place."""
    if state["version"] is None and meta["version"]:
        state["version"] = meta["version"]
    if state["information_uri"] is None and meta["information_uri"]:
        state["information_uri"] = meta["information_uri"]

    sonarqube_ext = _extract_sonarqube_extension(run)
    if sonarqube_ext:
        merged = dict(state["extensions"].get("sonarqube") or {})
        merged.update(sonarqube_ext)
        state["extensions"]["sonarqube"] = merged


def _build_finding(
    result: Dict[str, Any],
    tool_name: str,
    rule_descriptors: Dict[str, Dict[str, Any]],
    patch_modified_lines: Dict[str, Set[int]],
) -> SarifFinding:
    """Parses one SARIF `result` object into a SarifFinding: resolves its
    rule's category/tags from the driver's descriptors and whether it
    lands on a patch-modified line."""
    rule_id = result.get("ruleId")
    rule_id = str(rule_id) if rule_id else "unknown-rule"

    level = _normalize_level(result.get("level"))

    message_obj = result.get("message")
    message = message_obj.get("text") if isinstance(message_obj, dict) else None
    message = str(message) if message else ""

    file_path_norm, start_line = _extract_location(result)

    descriptor = rule_descriptors.get(rule_id, {})
    category = descriptor.get("category")
    tags = list(descriptor.get("tags") or [])

    is_new = False
    if file_path_norm and start_line:
        modified = _lookup_modified_lines(patch_modified_lines, file_path_norm)
        if modified and start_line in modified:
            is_new = True

    return SarifFinding(
        tool_name=tool_name,
        rule_id=rule_id,
        level=level,
        message=message,
        file_path=file_path_norm,
        start_line=start_line,
        is_new_in_patch=is_new,
        category=category,
        tags=tags,
    )


def _record_finding_in_tool_state(state: Dict[str, Any], finding: SarifFinding) -> None:
    state["counts"][finding.level] += 1
    rule_state = state["rules"].setdefault(
        finding.rule_id, {"count": 0, "category": finding.category, "tags": finding.tags}
    )
    rule_state["count"] += 1
    if not rule_state["category"] and finding.category:
        rule_state["category"] = finding.category
    if not rule_state["tags"] and finding.tags:
        rule_state["tags"] = finding.tags


def _extract_results(
    run: Dict[str, Any],
    tool_name: str,
    rule_descriptors: Dict[str, Dict[str, Any]],
    state: Dict[str, Any],
    patch_modified_lines: Dict[str, Set[int]],
) -> List[SarifFinding]:
    """Parses one run's `results` array into SarifFindings, updating
    `state`'s per-level counts and per-rule grouping in place as it goes.
    Returns [] (not an error) when `results` is missing/malformed -- SARIF
    allows a run with no results at all."""
    results = run.get("results")
    if not isinstance(results, list):
        return []

    findings: List[SarifFinding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        finding = _build_finding(result, tool_name, rule_descriptors, patch_modified_lines)
        findings.append(finding)
        _record_finding_in_tool_state(state, finding)
    return findings


def _process_run(
    run: Dict[str, Any],
    tool_state: Dict[str, Dict[str, Any]],
    tools_scanned: List[str],
    patch_modified_lines: Dict[str, Set[int]],
) -> List[SarifFinding]:
    """Processes one SARIF run: resolves its tool identity, merges driver
    metadata/SonarQube extension data into that tool's accumulated state
    (creating it on first sight, keyed by tool name so multiple runs from
    the same tool merge), and parses its results into findings.
    tool_state/tools_scanned are updated in place; returns the findings
    parsed from this run."""
    meta, driver = _extract_driver_info(run)
    tool_name = meta["name"]
    if tool_name not in tools_scanned:
        tools_scanned.append(tool_name)

    state = tool_state.setdefault(tool_name, _init_tool_state())
    _update_tool_state_metadata(state, meta, run)

    rule_descriptors = _extract_rule_descriptors(driver)
    return _extract_results(run, tool_name, rule_descriptors, state, patch_modified_lines)


def _count_findings_by_level(findings: List[SarifFinding]) -> Dict[str, int]:
    return {
        "errors_count": sum(1 for f in findings if f.level == "error"),
        "warnings_count": sum(1 for f in findings if f.level == "warning"),
        "notes_count": sum(1 for f in findings if f.level == "note"),
        "none_count": sum(1 for f in findings if f.level == "none"),
    }


def _count_patch_differential_findings(findings: List[SarifFinding]) -> Dict[str, int]:
    return {
        "patch_errors_count": sum(1 for f in findings if f.is_new_in_patch and f.level == "error"),
        "patch_warnings_count": sum(1 for f in findings if f.is_new_in_patch and f.level == "warning"),
    }


def _summarize_findings(findings: List[SarifFinding]) -> Dict[str, int]:
    """The six aggregate counts (errors/warnings/notes/none, and
    patch-differential errors/warnings) derived from a findings list --
    shared by parse_sarif_file and aggregate_sarif_reports so the two
    can never drift out of sync with each other."""
    return {**_count_findings_by_level(findings), **_count_patch_differential_findings(findings)}


def _build_tool_summaries(
    tools_scanned: List[str], tool_state: Dict[str, Dict[str, Any]], report_hash: Dict[str, str]
) -> List[SarifToolSummary]:
    tools: List[SarifToolSummary] = []
    for name in tools_scanned:
        state = tool_state[name]
        counts = state["counts"]
        rule_groups = [
            SarifRuleGroup(rule_id=rid, count=info["count"], category=info["category"], tags=info["tags"])
            for rid, info in sorted(state["rules"].items())
        ]
        tools.append(
            SarifToolSummary(
                name=name,
                version=state["version"],
                information_uri=state["information_uri"],
                errors_count=counts["error"],
                warnings_count=counts["warning"],
                notes_count=counts["note"],
                none_count=counts["none"],
                total_findings=sum(counts.values()),
                rules=rule_groups,
                extensions=state["extensions"],
                report_hash=dict(report_hash),
            )
        )
    return tools


def parse_sarif_file(
    file_path: Union[str, Path],
    patch_modified_lines: Optional[Dict[str, Set[int]]] = None,
) -> SarifSummaryReport:
    """Parses a single SARIF 2.1.0 log file into a SarifSummaryReport,
    flagging `is_new_in_patch=True` on any finding whose file/line
    intersects `patch_modified_lines` (as produced by
    cli.patch_coverage.compute_patch_modified_lines), and building a
    per-tool breakdown (`.tools`) with driver metadata, rule-ID/category/tag
    grouping, any embedded SonarQube-style extension data, and the SHA-256
    of the raw file. Never raises: missing files, unreadable files, and
    malformed JSON all degrade to `available=False` with the failure
    captured in `reasons`.

    Orchestrates (see each helper's own docstring): file loading/
    validation stays inline below (a flat sequence of guard clauses, not
    itself a complexity source); per-run processing delegates to
    _process_run() (-> _extract_driver_info()/_update_tool_state_metadata()/
    _extract_results()/_build_finding()/_record_finding_in_tool_state());
    final per-tool assembly delegates to _build_tool_summaries().
    """
    patch_modified_lines = patch_modified_lines or {}

    try:
        path = safe_resolve_path(file_path)
    except UnsafePathError as e:
        return SarifSummaryReport(available=False, reasons=[f"unsafe SARIF file path: {e}"])

    try:
        if path.stat().st_size > MAX_SARIF_FILE_SIZE:
            return SarifSummaryReport(
                available=False,
                reasons=[f"SARIF file {path} exceeds size limit of {MAX_SARIF_FILE_SIZE} bytes"]
            )
        with open(path, "rb") as f:
            raw_bytes = f.read()
    except FileNotFoundError:
        return SarifSummaryReport(available=False, reasons=[f"SARIF file not found: {path}"])
    except OSError as e:
        return SarifSummaryReport(available=False, reasons=[f"failed to read SARIF file {path}: {e}"])

    report_hash = {"algorithm": "sha256", "value": hashlib.sha256(raw_bytes).hexdigest()}

    try:
        doc = json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return SarifSummaryReport(available=False, reasons=[f"failed to read/parse SARIF file {path}: {e}"])

    if not isinstance(doc, dict):
        return SarifSummaryReport(available=False, reasons=[f"SARIF file {path} does not contain a JSON object"])

    runs = doc.get("runs")
    if not isinstance(runs, list):
        return SarifSummaryReport(available=False, reasons=[f"SARIF file {path} has no 'runs' array"])

    findings: List[SarifFinding] = []
    tools_scanned: List[str] = []
    # name -> aggregation state, merged across every run in this file driven
    # by the same tool name.
    tool_state: Dict[str, Dict[str, Any]] = {}

    for run in runs:
        if not isinstance(run, dict):
            continue
        findings.extend(_process_run(run, tool_state, tools_scanned, patch_modified_lines))

    tools = _build_tool_summaries(tools_scanned, tool_state, report_hash)
    counts = _summarize_findings(findings)

    return SarifSummaryReport(
        available=True,
        total_findings=len(findings),
        findings=findings,
        tools_scanned=tools_scanned,
        tools=tools,
        reasons=[],
        **counts,
    )


def _collect_unavailable_reasons(reports: List[SarifSummaryReport]) -> Tuple[bool, List[str]]:
    """Returns (any_unavailable, reasons). `reasons` accumulates every
    input report's own `.reasons` unconditionally (available or not);
    when at least one input is unavailable and none of them supplied a
    reason of their own, a generic fallback summary is used instead of
    an empty list."""
    reasons: List[str] = []
    for r in reports:
        reasons.extend(r.reasons)

    unavailable = [r for r in reports if not r.available]
    if unavailable and not reasons:
        reasons = [f"{len(unavailable)} of {len(reports)} SARIF report(s) were unavailable"]
    return bool(unavailable), reasons


def _merge_reports(
    reports: List[SarifSummaryReport],
) -> Tuple[List[SarifFinding], List[str], List[SarifToolSummary]]:
    """Concatenates findings/tools across reports and unions tools_scanned
    (preserving first-seen order). Assumes every input is already known
    available -- see aggregate_sarif_reports' fail-closed check above this."""
    findings: List[SarifFinding] = []
    tools_scanned: List[str] = []
    tools: List[SarifToolSummary] = []
    for r in reports:
        findings.extend(r.findings)
        tools.extend(r.tools)
        for t in r.tools_scanned:
            if t not in tools_scanned:
                tools_scanned.append(t)
    return findings, tools_scanned, tools


def aggregate_sarif_reports(reports: List[SarifSummaryReport]) -> SarifSummaryReport:
    """Merges multiple per-file SarifSummaryReports (e.g. one per `--sarif`
    flag) into a single composite report.

    Fails closed: if any input report is unavailable (unreadable/corrupt
    file), the aggregate itself is `available=False` -- a partial
    differential-scan result must never be silently reported as a clean
    bill of health. Callers that want to report per-file warnings before
    aggregating (e.g. cli.main) should do so against the individual
    `parse_sarif_file` results.

    Per-tool summaries (`.tools`) are concatenated, not merged by name,
    across input files: each carries its own file's `report_hash`, and
    collapsing two same-named tools from two different files would leave no
    single honest hash to attach to the merged entry. Same-tool-across-
    multiple-runs *within* one file is still merged (see `parse_sarif_file`),
    since that's genuinely one file with one hash.
    """
    if not reports:
        return SarifSummaryReport(available=False, reasons=["no SARIF reports supplied"])

    any_unavailable, reasons = _collect_unavailable_reasons(reports)
    if any_unavailable:
        return SarifSummaryReport(available=False, reasons=reasons)

    findings, tools_scanned, tools = _merge_reports(reports)
    counts = _summarize_findings(findings)

    return SarifSummaryReport(
        available=True,
        total_findings=len(findings),
        findings=findings,
        tools_scanned=tools_scanned,
        tools=tools,
        reasons=reasons,
        **counts,
    )


def _load_sonar_metrics_doc(file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """Reads and JSON-decodes a --sonar-metrics export, resolving the path
    via safe_resolve_path() first. Returns None (never raises) on any
    read/parse/shape failure -- this is enrichment data only and must
    never be able to fail a run."""
    try:
        resolved = safe_resolve_path(file_path)
        with open(resolved, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, UnsafePathError):
        return None
    return doc if isinstance(doc, dict) else None


def _apply_sonar_measure(result: Dict[str, Any], measure: Dict[str, Any]) -> None:
    """Merges one `measures[]` entry (a {"metric": ..., "value": ...} pair)
    from a SonarQube export into `result`, in place. Unrecognized metrics
    and non-coercible values are silently skipped -- this is best-effort
    enrichment only."""
    metric = measure.get("metric")
    value = measure.get("value")

    if metric == "alert_status" and isinstance(value, str):
        mapped = _SONAR_QUALITY_GATE_ALIASES.get(value.strip().upper())
        if mapped:
            result["quality_gate"] = mapped
    elif metric in _SONAR_METRIC_ALIASES and value is not None:
        try:
            result[_SONAR_METRIC_ALIASES[metric]] = int(float(value))
        except (TypeError, ValueError):
            pass


def parse_sonar_metrics_file(file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """Parses a SonarQube `api/measures/component` JSON export (the
    `--sonar-metrics` CLI flag) into the same {quality_gate,
    cognitive_complexity, technical_debt_minutes} shape
    `_extract_sonarqube_extension` produces from an embedded SARIF
    properties bag -- for a scanner that doesn't embed SonarQube metrics in
    its own SARIF output. Never raises: any read/parse/shape failure
    returns None rather than propagating, since this is enrichment data
    only and must never be able to fail a run."""
    doc = _load_sonar_metrics_doc(file_path)
    if doc is None:
        return None

    component = doc.get("component")
    component = component if isinstance(component, dict) else doc
    measures = component.get("measures")
    if not isinstance(measures, list):
        return None

    result: Dict[str, Any] = {}
    for m in measures:
        if isinstance(m, dict):
            _apply_sonar_measure(result, m)

    return result or None


def merge_sonar_metrics_into_tools(tools: List[SarifToolSummary], extension: Dict[str, Any]) -> bool:
    """Merges an externally-supplied SonarQube extension dict (from
    `parse_sonar_metrics_file`) into every tool summary whose driver name
    looks like SonarQube, or -- if none matched by name but there's exactly
    one tool in the report -- into that sole tool (a single-tool run is an
    unambiguous target even when the driver name doesn't say "sonar").
    Returns True if the extension was attached anywhere, False if there was
    no unambiguous target (caller should warn, not raise -- this is
    enrichment data, not a scoring input)."""
    if not extension:
        return False

    targets = [t for t in tools if "sonar" in t.name.lower()]
    if not targets and len(tools) == 1:
        targets = tools

    for t in targets:
        merged = dict(t.extensions.get("sonarqube") or {})
        merged.update(extension)
        t.extensions["sonarqube"] = merged

    return bool(targets)
