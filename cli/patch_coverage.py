"""
Patch coverage: what fraction of *lines changed in this diff* are covered
by tests, as opposed to overall repo coverage which can hide an uncovered
new code path behind a high legacy baseline.

Hardened against:
  - Git CLI option injection (explicit '--' separator)
  - Quoted/escaped filenames in diff headers (-c core.quotepath=false)
  - Path normalization discrepancies between git and coverage parsers
  - Binary / deleted file diffs (/dev/null filtering)
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional

from .parsers.coverage import CoverageReport


def _normalize_path(path_str: str) -> str:
    p = os.path.normpath(path_str.strip().strip('"').strip("'"))
    return p.lstrip(os.sep)


_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_DIFF_PLUS = re.compile(r"^\+\+\+ b/(.*)$")


@dataclass
class PatchCoverageResult:
    __test__ = False
    available: bool
    line_rate: Optional[float]
    lines_changed: int
    lines_covered: int
    reason: str


def _changed_lines_by_file(base_sha: str, head_sha: str, cwd: str) -> Dict[str, List[int]]:
    """Returns {file_path: [added_line_numbers]} for the diff base_sha...head_sha."""
    # -c core.quotepath=false prevents git from double-quoting unicode/spaced paths
    # '--' ensures commit SHAs cannot be parsed as arbitrary git flags
    proc = subprocess.run(
        [
            "git",
            "-c",
            "core.quotepath=false",
            "diff",
            "--unified=0",
            "--no-color",
            "--",
            f"{base_sha}...{head_sha}",
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )

    result: Dict[str, List[int]] = {}
    current_file: Optional[str] = None
    next_new_line: Optional[int] = None

    for line in proc.stdout.splitlines():
        # Track targeted target file, skipping deleted files (+++ /dev/null)
        if line.startswith("+++ "):
            m_plus = _DIFF_PLUS.match(line)
            if m_plus:
                raw_path = m_plus.group(1)
                if raw_path != "/dev/null":
                    current_file = _normalize_path(raw_path)
                    result.setdefault(current_file, [])
                else:
                    current_file = None
            else:
                current_file = None
            continue

        m_hunk = _HUNK_HEADER.match(line)
        if m_hunk:
            next_new_line = int(m_hunk.group(1))
            continue

        if current_file is None or next_new_line is None:
            continue

        # In unified=0 diffs, '+' indicates an added/modified line in the new revision
        if line.startswith("+") and not line.startswith("+++"):
            result[current_file].append(next_new_line)
            next_new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            pass  # Deletions do not advance the new file line counter
        elif line.startswith("\\"):
            pass  # "\ No newline at end of file"

    return result


def compute_patch_coverage(
    base_sha: Optional[str],
    head_sha: str,
    repo_dir: str,
    coverage: CoverageReport,
) -> PatchCoverageResult:
    if not base_sha:
        return PatchCoverageResult(
            available=False,
            line_rate=None,
            lines_changed=0,
            lines_covered=0,
            reason="no base_commit_sha available (e.g. push to default branch or shallow clone)",
        )

    try:
        changed = _changed_lines_by_file(base_sha, head_sha, repo_dir)
    except subprocess.CalledProcessError as e:
        return PatchCoverageResult(
            available=False,
            line_rate=None,
            lines_changed=0,
            lines_covered=0,
            reason=f"git diff failed: {e.stderr.strip()[:200]}",
        )

    total_changed = 0
    total_covered = 0
    for file_path, line_numbers in changed.items():
        file_cov = coverage.files.get(file_path)
        for ln in line_numbers:
            # Only count lines registered as executable/coverable by the coverage tool
            if file_cov is None or ln not in file_cov.line_hits:
                continue
            total_changed += 1
            if file_cov.line_hits[ln] > 0:
                total_covered += 1

    if total_changed == 0:
        return PatchCoverageResult(
            available=False,
            line_rate=None,
            lines_changed=0,
            lines_covered=0,
            reason="diff contained no coverable changed lines (docs/config-only change)",
        )

    return PatchCoverageResult(
        available=True,
        line_rate=total_covered / total_changed,
        lines_changed=total_changed,
        lines_covered=total_covered,
        reason="computed from git diff intersected with coverage report",
    )
