"""
Coverage report parsing: Cobertura XML and LCOV.

Hardened against:
  - Path normalization mismatches (stripping absolute prefixes and relative ./ tokens)
  - Missing/corrupted line number attributes
  - Unbounded rate bounds (clamped to [0.0, 1.0])
  - Non-standard LCOV negative hit counts
"""
from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from ..common import safe_resolve_path


def _normalize_path(path_str: str) -> str:
    """Normalize file paths so git diff keys and coverage report keys match."""
    p = os.path.normpath(path_str.strip())
    # Strip leading slashes to prevent absolute vs relative diff lookup failures
    return p.lstrip(os.sep)


@dataclass
class FileCoverage:
    __test__ = False
    line_hits: Dict[int, int] = field(default_factory=dict)


@dataclass
class CoverageReport:
    __test__ = False
    overall_line_rate: float
    overall_branch_rate: Optional[float]
    files: Dict[str, FileCoverage] = field(default_factory=dict)


def _parse_clamped_rate(raw: Optional[str]) -> float:
    """Parses a Cobertura rate attribute (e.g. line-rate="0.87"), clamping
    to [0.0, 1.0] and defaulting to 0.0 when missing or unparseable."""
    try:
        return max(0.0, min(1.0, float(raw or 0.0)))
    except (ValueError, TypeError):
        return 0.0


def _parse_optional_clamped_rate(raw: Optional[str]) -> Optional[float]:
    """Same as _parse_clamped_rate, but returns None (rather than 0.0)
    when the attribute is absent or unparseable -- used for branch-rate,
    which Cobertura doesn't always emit."""
    if raw is None:
        return None
    try:
        return max(0.0, min(1.0, float(raw)))
    except (ValueError, TypeError):
        return None


def _parse_cobertura_class_lines(cls: ET.Element, fc: FileCoverage) -> None:
    """Merges one <class>'s <line> hit counts into `fc.line_hits`, in
    place -- max-of-hits across duplicate <class> entries for the same
    filename (Cobertura can emit more than one <class> per file)."""
    lines_el = cls.find("lines")
    if lines_el is None:
        return
    for line in lines_el.findall("line"):
        raw_num = line.get("number")
        if not raw_num:
            continue
        try:
            num = int(raw_num)
            hits = max(0, int(line.get("hits", "0") or 0))
        except (ValueError, TypeError):
            continue
        fc.line_hits[num] = max(fc.line_hits.get(num, 0), hits)


def parse_cobertura(path: str) -> CoverageReport:
    """Cobertura XML stream/tree parser with strict attribute validation."""
    tree = ET.parse(safe_resolve_path(path))
    root = tree.getroot()

    overall_line_rate = _parse_clamped_rate(root.get("line-rate"))
    overall_branch_rate = _parse_optional_clamped_rate(root.get("branch-rate"))

    files: Dict[str, FileCoverage] = {}
    for cls in root.iter("class"):
        raw_filename = cls.get("filename")
        if not raw_filename:
            continue

        filename = _normalize_path(raw_filename)
        fc = files.setdefault(filename, FileCoverage())
        _parse_cobertura_class_lines(cls, fc)

    return CoverageReport(overall_line_rate, overall_branch_rate, files)


_LCOV_SF = re.compile(r"^SF:(.+)$")
_LCOV_DA = re.compile(r"^DA:(\d+),(-?\d+)")


def _parse_da_record(m_da: "re.Match[str]") -> Optional[Tuple[int, int]]:
    """Parses one `DA:<line>,<hits>` LCOV record into (line_number,
    hit_count), clamping a non-standard negative hit count to 0. Returns
    None if either field isn't parseable."""
    try:
        num = int(m_da.group(1))
        hits = max(int(m_da.group(2)), 0)
    except (ValueError, TypeError):
        return None
    return num, hits


class _LcovState:
    """Mutable parse state threaded through _process_lcov_line() -- avoids
    a long parameter list and lets each line-handling branch update just
    the fields it needs, in place."""

    __slots__ = ("files", "current", "total_lines", "covered_lines")

    def __init__(self) -> None:
        self.files: Dict[str, FileCoverage] = {}
        self.current: Optional[str] = None
        self.total_lines = 0
        self.covered_lines = 0


def _process_lcov_line(line: str, state: _LcovState) -> None:
    """Handles one already-stripped, non-blank LCOV tracefile line,
    updating `state` in place: SF: starts a new current file, DA: records
    one line's hit count against it, and end_of_record clears it."""
    m_sf = _LCOV_SF.match(line)
    if m_sf:
        state.current = _normalize_path(m_sf.group(1))
        state.files.setdefault(state.current, FileCoverage())
        return

    m_da = _LCOV_DA.match(line)
    if m_da and state.current is not None:
        record = _parse_da_record(m_da)
        if record is not None:
            num, hits = record
            state.files[state.current].line_hits[num] = hits
            state.total_lines += 1
            if hits > 0:
                state.covered_lines += 1
        return

    if line == "end_of_record":
        state.current = None


def parse_lcov(path: str) -> CoverageReport:
    """LCOV tracefile parser with path canonicalization and safe rate bounds."""
    state = _LcovState()

    with open(safe_resolve_path(path), "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n").strip()
            if line:
                _process_lcov_line(line, state)

    overall_line_rate = (state.covered_lines / state.total_lines) if state.total_lines > 0 else 0.0
    overall_line_rate = max(0.0, min(1.0, overall_line_rate))
    return CoverageReport(overall_line_rate, None, state.files)
