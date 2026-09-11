"""
Go mutation testing runner: gremlins (github.com/go-gremlins/gremlins),
scoped to just the `*.go` lines a diff actually changed via gremlins'
own native `--diff <ref>` flag.

Chose gremlins over jonbaldie/go-mutesting (a 5-star fork of a dormant
project whose README markets `--changed-since`/an "agentic JSON"
report) the same way PIT was chosen over ArcMutate-only claims and
mutmut/Stryker were chosen as each ecosystem's real mainstream tool --
real community adoption (409 stars, active releases) over a flashier
but unproven README. Confirmed empirically (real `go install ...@latest`
this session, not assumed from stale 0.2-era docs which claimed no path
argument and no diff mode at all): the *current* `gremlins unleash
[path] --diff <ref>` genuinely does real git-diff-scoped mutation
testing -- a mutant outside the diff range reports `status: "SKIPPED"`
in the JSON report; one inside it reports `KILLED`/`LIVED`/
`"NOT COVERED"`/`TIMED OUT`/`NOT VIABLE`. Unlike every other runner in
this package, gremlins needs no hand-built wildcard/glob/targetClasses
translation at all -- it does its own git diffing internally, so this
module only ever needs to hand it `base_sha`, never a file list.

Hardened against:
  - Git ref injection: `base_sha` is validated via
    `patch_coverage._validate_git_ref()` (reused, not reimplemented --
    same hardened allowlist regex every other git-ref-consuming call in
    this codebase goes through) before it ever reaches
    `subprocess.run()`, even though the dispatcher should never call
    this runner with an unvalidated/missing base_sha in practice (an
    invalid base_sha upstream already means compute_patch_modified_lines
    returned {} and no *.go files would have been classified at all) --
    defense in depth, not reliance on that invariant holding forever.
  - "SKIPPED" (outside --diff's scope) being miscounted as a real
    mutant: excluded entirely from every count, the same way a mutant
    mutmut generated for an untouched file never counts either.
  - "NOT COVERED" being treated as anything other than a real,
    undetected mutant: confirmed empirically that a genuinely-reached
    but insufficiently-asserted branch reports "NOT COVERED", not
    "LIVED", for a reason specific to gremlins' own coverage
    granularity (verified against a real `go test -coverprofile`
    showing partial, not zero, coverage on the same line) -- this is
    the same "escaped detection" signal as LIVED, not a lesser one, so
    it's folded into `survived` for scoring, not silently dropped.
  - Runaway CI time: an outer `subprocess.run(timeout=...)` is the hard,
    provably-bounded backstop, same pattern as every other runner here.
  - Unsafe/unresolvable repo_dir: the dispatcher already resolves
    repo_dir via common.safe_resolve_path() once, before calling any
    runner -- this module receives an already-safe Path.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from ..patch_coverage import UnsafeGitRefError, _validate_git_ref
from .common import LANGUAGE_GO, LanguageRunResult, REASON_CODE_NO_COVERABLE_LINES, SurvivingMutant

_UNDETECTED_STATUSES = {"LIVED", "NOT COVERED"}
_IGNORED_STATUSES = {"SKIPPED", "NOT VIABLE"}


def _go_mod_present(repo_dir: Path) -> bool:
    return (repo_dir / "go.mod").is_file()


def _run_gremlins(base_sha: str, report_path: Path, *, cwd: Path, timeout_seconds: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["gremlins", "unleash", ".", "--diff", base_sha, "-o", str(report_path)],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )


def _collect_from_report(report_path: Path, max_detail: int) -> LanguageRunResult:
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return LanguageRunResult(
            language=LANGUAGE_GO, status="unavailable",
            reason="gremlins ran but its results could not be read",
        )

    files = report.get("files")
    files = files if isinstance(files, list) else []

    killed = survived = timeout_ct = total_generated = 0
    scoped_files: List[str] = []
    surviving: List[SurvivingMutant] = []
    for file_entry in files:
        if not isinstance(file_entry, dict):
            continue
        file_name = file_entry.get("file_name", "")
        file_had_in_scope_mutants = False
        for mutation in file_entry.get("mutations") or []:
            if not isinstance(mutation, dict):
                continue
            status = mutation.get("status", "")
            if status in _IGNORED_STATUSES:
                continue
            file_had_in_scope_mutants = True
            total_generated += 1
            if status == "KILLED":
                killed += 1
            elif status in _UNDETECTED_STATUSES:
                survived += 1
                if len(surviving) < max_detail:
                    surviving.append(
                        SurvivingMutant(
                            language=LANGUAGE_GO,
                            file=file_name,
                            function=mutation.get("type", "unknown"),
                            status="survived",
                            diff=f"{mutation.get('type', '')} at {file_name}:{mutation.get('line')}:{mutation.get('column')}",
                            line=mutation.get("line"),
                        )
                    )
            elif status == "TIMED OUT":
                timeout_ct += 1
                if len(surviving) < max_detail:
                    surviving.append(
                        SurvivingMutant(
                            language=LANGUAGE_GO,
                            file=file_name,
                            function=mutation.get("type", "unknown"),
                            status="timeout",
                            diff=f"{mutation.get('type', '')} at {file_name}:{mutation.get('line')}:{mutation.get('column')}",
                            line=mutation.get("line"),
                        )
                    )
        if file_had_in_scope_mutants:
            scoped_files.append(file_name)

    if killed + survived + timeout_ct == 0:
        return LanguageRunResult(
            language=LANGUAGE_GO, status="ran",
            scoped_files=scoped_files, reason=REASON_CODE_NO_COVERABLE_LINES,
        )

    return LanguageRunResult(
        language=LANGUAGE_GO,
        status="ran",
        killed=killed,
        survived=survived,
        timeout=timeout_ct,
        total_generated=total_generated,
        scoped_files=scoped_files,
        surviving_mutants=surviving,
    )


def run(
    repo_dir: Path,
    changed_files: List[str],
    *,
    timeout_seconds: int,
    max_surviving_detail: int,
    base_sha: Optional[str] = None,
) -> LanguageRunResult:
    """changed_files: already filtered to real, non-test *.go files by
    the dispatcher -- used here only to short-circuit when there's
    nothing to attempt; the actual scoping is gremlins' own `--diff`,
    not a wildcard built from this list, since gremlins does its own
    git diffing internally."""
    existing_files = [f for f in changed_files if (repo_dir / f).is_file()]
    if not existing_files:
        return LanguageRunResult(language=LANGUAGE_GO, status="not_configured")

    if not _go_mod_present(repo_dir):
        return LanguageRunResult(language=LANGUAGE_GO, status="not_configured")

    if not base_sha:
        # Should be unreachable in practice -- compute_patch_modified_lines
        # already needs a real base_sha to have produced any *.go files
        # for the dispatcher to have called this runner with at all --
        # but never trust that invariant blindly (see module docstring).
        return LanguageRunResult(
            language=LANGUAGE_GO, status="unavailable", reason="no base_sha available to diff against"
        )
    try:
        safe_base_sha = _validate_git_ref(base_sha, "base_sha")
    except UnsafeGitRefError as e:
        return LanguageRunResult(language=LANGUAGE_GO, status="unavailable", reason=f"gremlins refused: {e}")

    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "gremlins-report.json"
        try:
            proc = _run_gremlins(safe_base_sha, report_path, cwd=repo_dir, timeout_seconds=timeout_seconds)
        except subprocess.TimeoutExpired:
            return LanguageRunResult(
                language=LANGUAGE_GO, status="unavailable",
                reason=f"gremlins exceeded the {timeout_seconds}s time budget",
            )
        except OSError as e:
            return LanguageRunResult(
                language=LANGUAGE_GO, status="unavailable", reason=f"gremlins could not be invoked: {e}"
            )

        if not report_path.exists():
            if proc.returncode == 0:
                return LanguageRunResult(
                    language=LANGUAGE_GO, status="ran", reason=REASON_CODE_NO_COVERABLE_LINES,
                )
            return LanguageRunResult(
                language=LANGUAGE_GO, status="unavailable",
                reason=f"gremlins run failed (exit {proc.returncode}): {(proc.stderr or '').strip()[:300]}",
            )

        return _collect_from_report(report_path, max_surviving_detail)
