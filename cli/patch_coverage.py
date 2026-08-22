"""
Patch coverage: what fraction of *lines changed in this diff* are covered
by tests, as opposed to overall repo coverage which can hide an uncovered
new code path behind a high legacy baseline.

Hardened against:
  - Git CLI option injection (explicit '--' separator)
  - Quoted/escaped filenames in diff headers (-c core.quotepath=false)
  - Path normalization discrepancies between git and coverage parsers
  - Binary / deleted file diffs (/dev/null filtering)
  - Relative-root discrepancies between git diff paths (repo-root-relative,
    e.g. "cli/verify.py") and coverage tool keys (source-root-relative,
    e.g. Cobertura's "verify.py" when <source>cli</source> is configured)
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from .parsers.coverage import CoverageReport, FileCoverage


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
    # '--end-of-options' ensures the revision range can't be parsed as arbitrary git
    # flags (e.g. a SHA-like string starting with '-'). Note this must precede the
    # revision range, not follow it: a bare '--' here would instead tell git to treat
    # the range as a pathspec, silently producing an empty diff.
    proc = subprocess.run(
        [
            "git",
            "-c",
            "core.quotepath=false",
            "diff",
            "--unified=0",
            "--no-color",
            "--end-of-options",
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


def compute_patch_modified_lines(
    base_sha: Optional[str], head_sha: str, repo_dir: str
) -> Dict[str, Set[int]]:
    """Public wrapper around _changed_lines_by_file for callers (e.g. SARIF
    differential scoring, see cli.parsers.sarif) that only need "which
    lines changed", independent of any coverage report. Returns {} when no
    base_commit_sha is available or the diff itself fails -- callers should
    treat an empty mapping as "nothing known to be new", the same fail-open
    behavior compute_patch_coverage uses for a missing base SHA."""
    if not base_sha:
        return {}
    try:
        changed = _changed_lines_by_file(base_sha, head_sha, repo_dir)
    except subprocess.CalledProcessError:
        return {}
    return {path: set(lines) for path, lines in changed.items()}


def _path_components(path_str: str) -> List[str]:
    return [part for part in path_str.replace("\\", "/").split("/") if part]


def _lookup_file_coverage(coverage: CoverageReport, file_path: str) -> Optional[FileCoverage]:
    """Resolve a git-diff path against coverage report keys.

    Coverage tools frequently key files relative to a configured source
    root rather than the repo root — e.g. Cobertura emits "verify.py"
    for cli/verify.py when <source>cli</source> is set. Try a direct
    match first, then fall back to suffix matching on path components
    (never on raw substrings, to avoid "erify.py" style false matches).
    An ambiguous suffix match (multiple candidates tied for the longest
    match) is treated as no match rather than guessed at.
    """
    direct = coverage.files.get(file_path)
    if direct is not None:
        return direct

    diff_parts = _path_components(file_path)
    if not diff_parts:
        return None

    best_match: Optional[FileCoverage] = None
    best_len = 0
    ambiguous = False

    for cov_path, fc in coverage.files.items():
        cov_parts = _path_components(cov_path)
        if not cov_parts:
            continue

        shorter, longer = (
            (cov_parts, diff_parts) if len(cov_parts) <= len(diff_parts) else (diff_parts, cov_parts)
        )
        if longer[-len(shorter):] != shorter:
            continue

        match_len = len(shorter)
        if match_len > best_len:
            best_len = match_len
            best_match = fc
            ambiguous = False
        elif match_len == best_len:
            ambiguous = True

    return None if ambiguous else best_match


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
        file_cov = _lookup_file_coverage(coverage, file_path)
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
