"""
SARIF 2.1.0 static-analysis ingestion: parses one or more `--sarif` inputs
(e.g. semgrep, trivy, CodeQL) into a normalized report, and cross-references
each finding's file/line against the patch's changed lines (see
`cli.patch_coverage.compute_patch_modified_lines`) so the scorer can weigh a
*newly introduced* finding differently from a pre-existing baseline one.

Hardened against:
  - Missing/unreadable/malformed SARIF files (`available=False`, never raises)
  - Non-object / missing `runs`/`results` SARIF documents
  - Absolute or CI-runner-workspace-prefixed artifact URIs that don't match
    the repo-root-relative paths git diff produces (suffix-match fallback,
    mirroring cli.patch_coverage._lookup_file_coverage)
  - Missing/unrecognized `level` values (defaults to "warning", per the
    SARIF spec's own default for a result with no reportingConfiguration
    override)
  - Aggregating a mix of good and bad SARIF inputs: any unavailable input
    taints the whole aggregate (fails closed), the same way a bad/under-
    scoped GitHub token taints the whole branch-governance report (see
    cli.parsers.github_rules) -- a partial differential-scan result must
    never be silently reported as a clean bill of health
"""
from __future__ import annotations

import json
import os
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

VALID_LEVELS = {"error", "warning", "note"}
DEFAULT_LEVEL = "warning"


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

    def as_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "rule_id": self.rule_id,
            "level": self.level,
            "message": self.message,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "is_new_in_patch": self.is_new_in_patch,
        }


@dataclass
class SarifSummaryReport:
    __test__ = False
    available: bool
    total_findings: int = 0
    errors_count: int = 0
    warnings_count: int = 0
    notes_count: int = 0
    patch_errors_count: int = 0
    patch_warnings_count: int = 0
    findings: List[SarifFinding] = field(default_factory=list)
    tools_scanned: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "total_findings": self.total_findings,
            "errors_count": self.errors_count,
            "warnings_count": self.warnings_count,
            "notes_count": self.notes_count,
            "patch_errors_count": self.patch_errors_count,
            "patch_warnings_count": self.patch_warnings_count,
            "findings": [f.as_dict() for f in self.findings],
            "tools_scanned": self.tools_scanned,
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
    p = os.path.normpath(p)
    return p.lstrip(os.sep)


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
    except (TypeError, ValueError):
        start_line = 0

    return file_path, start_line


def parse_sarif_file(
    file_path: Union[str, Path],
    patch_modified_lines: Optional[Dict[str, Set[int]]] = None,
) -> SarifSummaryReport:
    """Parses a single SARIF 2.1.0 log file into a SarifSummaryReport,
    flagging `is_new_in_patch=True` on any finding whose file/line
    intersects `patch_modified_lines` (as produced by
    cli.patch_coverage.compute_patch_modified_lines). Never raises: missing
    files, unreadable files, and malformed JSON all degrade to
    `available=False` with the failure captured in `reasons`."""
    path = Path(file_path)
    patch_modified_lines = patch_modified_lines or {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        return SarifSummaryReport(available=False, reasons=[f"SARIF file not found: {path}"])
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
        return SarifSummaryReport(available=False, reasons=[f"failed to read/parse SARIF file {path}: {e}"])

    if not isinstance(doc, dict):
        return SarifSummaryReport(available=False, reasons=[f"SARIF file {path} does not contain a JSON object"])

    runs = doc.get("runs")
    if not isinstance(runs, list):
        return SarifSummaryReport(available=False, reasons=[f"SARIF file {path} has no 'runs' array"])

    findings: List[SarifFinding] = []
    tools_scanned: List[str] = []

    for run in runs:
        if not isinstance(run, dict):
            continue

        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        tool_name = driver.get("name") if isinstance(driver, dict) else None
        tool_name = tool_name if isinstance(tool_name, str) and tool_name.strip() else "unknown"
        if tool_name not in tools_scanned:
            tools_scanned.append(tool_name)

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
                )
            )

    errors_count = sum(1 for f in findings if f.level == "error")
    warnings_count = sum(1 for f in findings if f.level == "warning")
    notes_count = sum(1 for f in findings if f.level == "note")
    patch_errors_count = sum(1 for f in findings if f.is_new_in_patch and f.level == "error")
    patch_warnings_count = sum(1 for f in findings if f.is_new_in_patch and f.level == "warning")

    return SarifSummaryReport(
        available=True,
        total_findings=len(findings),
        errors_count=errors_count,
        warnings_count=warnings_count,
        notes_count=notes_count,
        patch_errors_count=patch_errors_count,
        patch_warnings_count=patch_warnings_count,
        findings=findings,
        tools_scanned=tools_scanned,
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
    for r in reports:
        findings.extend(r.findings)
        for t in r.tools_scanned:
            if t not in tools_scanned:
                tools_scanned.append(t)

    errors_count = sum(1 for f in findings if f.level == "error")
    warnings_count = sum(1 for f in findings if f.level == "warning")
    notes_count = sum(1 for f in findings if f.level == "note")
    patch_errors_count = sum(1 for f in findings if f.is_new_in_patch and f.level == "error")
    patch_warnings_count = sum(1 for f in findings if f.is_new_in_patch and f.level == "warning")

    return SarifSummaryReport(
        available=True,
        total_findings=len(findings),
        errors_count=errors_count,
        warnings_count=warnings_count,
        notes_count=notes_count,
        patch_errors_count=patch_errors_count,
        patch_warnings_count=patch_warnings_count,
        findings=findings,
        tools_scanned=tools_scanned,
        reasons=reasons,
    )
