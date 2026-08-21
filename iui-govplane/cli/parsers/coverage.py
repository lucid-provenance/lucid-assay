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
from typing import Dict, Optional


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


def parse_cobertura(path: str) -> CoverageReport:
    """Cobertura XML stream/tree parser with strict attribute validation."""
    tree = ET.parse(path)
    root = tree.getroot()

    try:
        raw_line_rate = float(root.get("line-rate", "0") or 0.0)
        overall_line_rate = max(0.0, min(1.0, raw_line_rate))
    except (ValueError, TypeError):
        overall_line_rate = 0.0

    overall_branch_rate = None
    branch_attr = root.get("branch-rate")
    if branch_attr is not None:
        try:
            overall_branch_rate = max(0.0, min(1.0, float(branch_attr)))
        except (ValueError, TypeError):
            overall_branch_rate = None

    files: Dict[str, FileCoverage] = {}
    for cls in root.iter("class"):
        raw_filename = cls.get("filename")
        if not raw_filename:
            continue

        filename = _normalize_path(raw_filename)
        fc = files.setdefault(filename, FileCoverage())

        lines_el = cls.find("lines")
        if lines_el is None:
            continue

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

    return CoverageReport(overall_line_rate, overall_branch_rate, files)


_LCOV_SF = re.compile(r"^SF:(.+)$")
_LCOV_DA = re.compile(r"^DA:(\d+),(-?\d+)")


def parse_lcov(path: str) -> CoverageReport:
    """LCOV tracefile parser with path canonicalization and safe rate bounds."""
    files: Dict[str, FileCoverage] = {}
    current: Optional[str] = None
    total_lines = 0
    covered_lines = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n").strip()
            if not line:
                continue

            m_sf = _LCOV_SF.match(line)
            if m_sf:
                current = _normalize_path(m_sf.group(1))
                files.setdefault(current, FileCoverage())
                continue

            m_da = _LCOV_DA.match(line)
            if m_da and current is not None:
                try:
                    num = int(m_da.group(1))
                    hits = max(int(m_da.group(2)), 0)
                except (ValueError, TypeError):
                    continue

                files[current].line_hits[num] = hits
                total_lines += 1
                if hits > 0:
                    covered_lines += 1
                continue

            if line == "end_of_record":
                current = None

    overall_line_rate = (covered_lines / total_lines) if total_lines > 0 else 0.0
    overall_line_rate = max(0.0, min(1.0, overall_line_rate))
    return CoverageReport(overall_line_rate, None, files)
