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
import os
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

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
        for in_key in in_keys:
            if in_key in bag and bag[in_key] is not None:
                try:
                    val = int(float(bag[in_key]))
                    result[out_key] = max(0, val)  # Clamp to non-negative
                except (TypeError, ValueError):
                    pass
                break

    return result or None


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
    captured in `reasons`."""
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

        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        driver = driver if isinstance(driver, dict) else {}
        meta = _extract_driver_metadata(driver)
        tool_name = meta["name"]
        if tool_name not in tools_scanned:
            tools_scanned.append(tool_name)

        state = tool_state.setdefault(
            tool_name,
            {
                "version": None,
                "information_uri": None,
                "counts": {"error": 0, "warning": 0, "note": 0, "none": 0},
                "rules": {},  # rule_id -> {"count": int, "category": ..., "tags": [...]}
                "extensions": {},
            },
        )
        if state["version"] is None and meta["version"]:
            state["version"] = meta["version"]
        if state["information_uri"] is None and meta["information_uri"]:
            state["information_uri"] = meta["information_uri"]

        sonarqube_ext = _extract_sonarqube_extension(run)
        if sonarqube_ext:
            merged = dict(state["extensions"].get("sonarqube") or {})
            merged.update(sonarqube_ext)
            state["extensions"]["sonarqube"] = merged

        rule_descriptors = _extract_rule_descriptors(driver)

        results = run.get("results")
        if not isinstance(results, list):
            continue

        for result in results:
            if not isinstance(result, dict):
                continue

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

            findings.append(
                SarifFinding(
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
            )

            state["counts"][level] += 1
            rule_state = state["rules"].setdefault(
                rule_id, {"count": 0, "category": category, "tags": tags}
            )
            rule_state["count"] += 1
            if not rule_state["category"] and category:
                rule_state["category"] = category
            if not rule_state["tags"] and tags:
                rule_state["tags"] = tags

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

    errors_count = sum(1 for f in findings if f.level == "error")
    warnings_count = sum(1 for f in findings if f.level == "warning")
    notes_count = sum(1 for f in findings if f.level == "note")
    none_count = sum(1 for f in findings if f.level == "none")
    patch_errors_count = sum(1 for f in findings if f.is_new_in_patch and f.level == "error")
    patch_warnings_count = sum(1 for f in findings if f.is_new_in_patch and f.level == "warning")

    return SarifSummaryReport(
        available=True,
        total_findings=len(findings),
        errors_count=errors_count,
        warnings_count=warnings_count,
        notes_count=notes_count,
        none_count=none_count,
        patch_errors_count=patch_errors_count,
        patch_warnings_count=patch_warnings_count,
        findings=findings,
        tools_scanned=tools_scanned,
        tools=tools,
        reasons=[],
    )


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

    reasons: List[str] = []
    for r in reports:
        reasons.extend(r.reasons)

    unavailable = [r for r in reports if not r.available]
    if unavailable:
        if not reasons:
            reasons = [f"{len(unavailable)} of {len(reports)} SARIF report(s) were unavailable"]
        return SarifSummaryReport(available=False, reasons=reasons)

    findings: List[SarifFinding] = []
    tools_scanned: List[str] = []
    tools: List[SarifToolSummary] = []
    for r in reports:
        findings.extend(r.findings)
        tools.extend(r.tools)
        for t in r.tools_scanned:
            if t not in tools_scanned:
                tools_scanned.append(t)

    errors_count = sum(1 for f in findings if f.level == "error")
    warnings_count = sum(1 for f in findings if f.level == "warning")
    notes_count = sum(1 for f in findings if f.level == "note")
    none_count = sum(1 for f in findings if f.level == "none")
    patch_errors_count = sum(1 for f in findings if f.is_new_in_patch and f.level == "error")
    patch_warnings_count = sum(1 for f in findings if f.is_new_in_patch and f.level == "warning")

    return SarifSummaryReport(
        available=True,
        total_findings=len(findings),
        errors_count=errors_count,
        warnings_count=warnings_count,
        notes_count=notes_count,
        none_count=none_count,
        patch_errors_count=patch_errors_count,
        patch_warnings_count=patch_warnings_count,
        findings=findings,
        tools_scanned=tools_scanned,
        tools=tools,
        reasons=reasons,
    )


def parse_sonar_metrics_file(file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """Parses a SonarQube `api/measures/component` JSON export (the
    `--sonar-metrics` CLI flag) into the same {quality_gate,
    cognitive_complexity, technical_debt_minutes} shape
    `_extract_sonarqube_extension` produces from an embedded SARIF
    properties bag -- for a scanner that doesn't embed SonarQube metrics in
    its own SARIF output. Never raises: any read/parse/shape failure
    returns None rather than propagating, since this is enrichment data
    only and must never be able to fail a run."""
    try:
        resolved = safe_resolve_path(file_path)
        with open(resolved, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, UnsafePathError):
        return None

    if not isinstance(doc, dict):
        return None

    component = doc.get("component")
    component = component if isinstance(component, dict) else doc
    measures = component.get("measures")
    if not isinstance(measures, list):
        return None

    result: Dict[str, Any] = {}
    for m in measures:
        if not isinstance(m, dict):
            continue
        metric = m.get("metric")
        value = m.get("value")

        if metric == "alert_status" and isinstance(value, str):
            mapped = _SONAR_QUALITY_GATE_ALIASES.get(value.strip().upper())
            if mapped:
                result["quality_gate"] = mapped
        elif metric in _SONAR_METRIC_ALIASES and value is not None:
            try:
                result[_SONAR_METRIC_ALIASES[metric]] = int(float(value))
            except (TypeError, ValueError):
                pass

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
