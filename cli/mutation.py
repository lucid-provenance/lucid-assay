"""
Diff-scoped mutation testing: mutates only the `cli/*.py` lines that
actually changed in this diff (via mutmut) and reports a real kill-rate
signal that `cli.scorer` folds into RCS as a *multiplier* -- not a scored
bucket -- over the test_health/patch_coverage/overall_coverage cluster.
Coverage and assertion density can both be satisfied by a test that
executes a line without ever verifying its behavior; mutation testing is
the check on whether that's actually happening, so a 95%-covered diff
with a 20% mutation kill rate reads as decorative, not solid.

Not a `parsers/*` module (which stay pure/side-effect-free by design --
see CLAUDE.md's "Module boundary discipline"): running mutmut means
spawning the test suite many times over, the same inherently-side-
effecting tier `patch_coverage.py` (git subprocess) and `oidc_signer.py`
(network) already occupy.

Hardened against:
  - Stats leaking across unrelated files: mutmut's own `export-cicd-stats`
    aggregates across its *entire* `mutants/` cache directory, not just
    whatever a given invocation just tested -- confirmed empirically
    against a real mutmut 3.7.0 install, not assumed from its docs. This
    module always deletes any pre-existing `mutants/`/`.mutmut-cache`
    before running, so a stale result from a previous, differently-scoped
    PR/run can never bleed into this run's mutation_score. A generated
    mutant with no recorded exit code (never selected for testing by any
    wildcard) doesn't count in mutmut's own aggregate either way -- also
    confirmed empirically -- but starting clean removes any doubt.
  - A wildcard filter matching zero mutants: mutmut's own `run <wildcard>`
    raises an uncaught AssertionError when every wildcard's filter is
    empty (confirmed empirically) -- e.g. a diff that only touched
    comments/docstrings/type hints, where no executable statement
    actually changed. Detected via that specific, distinguishing stderr
    marker (not any non-zero exit code, which would also fire on a
    genuine mutmut crash) and reported as the zero-mutant exemption
    (grade="not_applicable", full credit) rather than a crash or a
    fail-closed penalty.
  - Runaway CI time: mutmut restricts each mutant's test run to only the
    tests that actually cover the mutated line (its own coverage-gathered
    baseline), which is what keeps this bounded against a 1000+-test
    suite in the common case -- but an outer `subprocess.run(timeout=...)`
    is the hard, provably-bounded backstop regardless, same pattern as
    `oidc_signer.py`'s OIDC-fetch retry.
  - Skipping mutation testing being the easy way to game the very control
    meant to stop gaming: `available=False` (tool missing, timed out, or
    the caller opted out) never defaults to full credit -- see
    `cli.scorer._score_mutation_testing`, which applies the same
    non-punitive-but-not-free multiplier as the "weak" tier.
  - A single surviving mutant out of one generated mutant reading as a 0%
    kill rate that halves the whole Test & Coverage score:
    MUTATION_MIN_SAMPLE_SIZE gates whether the tiered multiplier applies
    at all (grade="insufficient_sample" below it, full credit, honest
    reason string) -- same spirit as the zero-mutant exemption, just for
    "ran, but not enough signal yet" instead of "nothing to run at all".
  - Git CLI/subprocess injection: this module never runs git itself --
    diff scoping reuses `patch_coverage.compute_patch_modified_lines()`,
    the same already-hardened public wrapper `cli.parsers.sarif` depends
    on for its own differential scoring, so there's no second,
    independently-written git invocation to get wrong.
  - Unsafe/unresolvable repo_dir reaching subprocess.run(cwd=...):
    resolved via `common.safe_resolve_path()`, the same guard every other
    subprocess-invoking module in this codebase applies to its cwd.
"""
from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from .common import UnsafePathError, safe_resolve_path

MUTATION_SCORE_PASS_THRESHOLD = 80.0
MUTATION_SCORE_DEGRADED_THRESHOLD = 60.0
MUTATION_MIN_SAMPLE_SIZE_DEFAULT = 3

MULTIPLIER_PASSED = 1.0
MULTIPLIER_DEGRADED = 0.85
MULTIPLIER_FAILED = 0.50
# Unavailable/skip both use the same non-punitive-but-not-free multiplier
# as the "weak" tier -- see the module docstring's fail-closed note.
# "Not applicable" (no cli/*.py changed at all, a zero-mutant
# comment/docstring-only diff, or too small a sample to trust) is the one
# family of outcomes that gets full credit, since none of those is a
# control anyone dodged.
MULTIPLIER_UNAVAILABLE = 0.85
MULTIPLIER_NOT_APPLICABLE = 1.0

REASON_CODE_WEAK = "weak_assertion_coverage"
REASON_CODE_DECORATIVE = "decorative_coverage"
REASON_CODE_UNAVAILABLE = "unavailable"
REASON_CODE_SKIPPED = "skipped"
REASON_CODE_NO_CLI_CHANGES = "no_cli_changes"
REASON_CODE_NO_COVERABLE_LINES = "no_coverable_lines"
REASON_CODE_INSUFFICIENT_SAMPLE = "insufficient_sample"

DEFAULT_TIMEOUT_SECONDS = 90
DEFAULT_MAX_SURVIVING_DETAIL = 5
MUTATION_SOURCE_PREFIX = "cli/"

_NO_MATCH_MARKER = "Filtered for specific mutants, but nothing matches"
_MUTANT_KEY_RE = re.compile(r"^x_(?P<func>.+)__mutmut_\d+$")
_RESULT_LINE_RE = re.compile(r"^\s*(?P<key>\S+):\s*(?P<status>\S+)\s*$")


class MutationToolError(RuntimeError):
    """Raised internally when mutmut itself fails for a reason other than
    the recognized zero-mutant/timeout cases -- always caught at the
    run_mutation_testing() boundary and turned into an unavailable report,
    never propagated to the caller."""


@dataclass
class SurvivingMutant:
    file: str
    function: str
    status: str  # "survived" or "timeout"
    diff: str
    line: Optional[int] = None

    def as_dict(self) -> Dict:
        return {
            "file": self.file,
            "function": self.function,
            "status": self.status,
            "line": self.line,
            "diff": self.diff,
        }


@dataclass
class MutationTestReport:
    __test__ = False
    available: bool
    grade: str  # passed | degraded | failed | not_applicable | insufficient_sample
    multiplier: float
    mutation_score: Optional[float]
    killed: int
    survived: int
    timeout: int
    total_generated: int
    reason: str
    reason_code: Optional[str] = None
    scoped_files: List[str] = field(default_factory=list)
    surviving_mutants: List[SurvivingMutant] = field(default_factory=list)

    @property
    def tested(self) -> int:
        return self.killed + self.survived + self.timeout

    def as_dict(self) -> Dict:
        return {
            "available": self.available,
            "grade": self.grade,
            "multiplier": self.multiplier,
            "mutation_score": self.mutation_score,
            "killed": self.killed,
            "survived": self.survived,
            "timeout": self.timeout,
            "tested": self.tested,
            "total_generated": self.total_generated,
            "scoped_files": self.scoped_files,
            "top_surviving_mutants": [m.as_dict() for m in self.surviving_mutants],
            "reason": self.reason,
            "reason_code": self.reason_code,
        }


def _not_applicable_report(reason: str, reason_code: str = REASON_CODE_NO_CLI_CHANGES) -> MutationTestReport:
    return MutationTestReport(
        available=False,
        grade="not_applicable",
        multiplier=MULTIPLIER_NOT_APPLICABLE,
        mutation_score=None,
        killed=0,
        survived=0,
        timeout=0,
        total_generated=0,
        reason=reason,
        reason_code=reason_code,
    )


def _unavailable_report(reason: str, reason_code: str = REASON_CODE_UNAVAILABLE) -> MutationTestReport:
    return MutationTestReport(
        available=False,
        grade="degraded",
        multiplier=MULTIPLIER_UNAVAILABLE,
        mutation_score=None,
        killed=0,
        survived=0,
        timeout=0,
        total_generated=0,
        reason=reason,
        reason_code=reason_code,
    )


def skipped_report(reason: str = "mutation testing skipped via --skip-mutation-testing") -> MutationTestReport:
    """Public constructor for the explicit opt-out path -- cli.main calls
    this directly instead of invoking run_mutation_testing() at all when
    --skip-mutation-testing is passed, keeping the "should we even try"
    decision in the caller rather than threading a skip flag through this
    module's own run logic."""
    return _unavailable_report(reason, REASON_CODE_SKIPPED)


def select_changed_python_files(patch_modified_lines: Dict[str, Set[int]]) -> List[str]:
    """Filters the already-computed diff (patch_coverage.compute_patch_modified_lines,
    repo-root-relative paths) down to `cli/*.py` files -- "new code only,
    assay logic", never tests/ or schema/. Deterministic order (sorted)
    so wildcard argv order, and therefore mutmut's own stable-sort output,
    doesn't vary run to run."""
    return sorted(
        f for f in patch_modified_lines
        if f.startswith(MUTATION_SOURCE_PREFIX) and f.endswith(".py")
    )


def _dotted_module(file_path: str) -> str:
    """"cli/parsers/sarif.py" -> "cli.parsers.sarif" -- mirrors mutmut's
    own dotted mutant-key namespacing, confirmed empirically (a mutant in
    pkg/mathy.py surfaces as "pkg.mathy.x_<func>__mutmut_<n>")."""
    return file_path[: -len(".py")].replace("/", ".")


def _wildcard_for(file_path: str) -> str:
    return f"{_dotted_module(file_path)}.*"


def _run_mutmut(args: List[str], *, cwd: Path, timeout_seconds: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "mutmut", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )


def _reset_mutmut_cache(repo_dir: Path) -> None:
    """Deletes any pre-existing mutants/ cache dir and .mutmut-cache file
    under repo_dir -- see the module docstring's "Stats leaking across
    unrelated files" hardening note for why this must happen every run,
    not just the first."""
    shutil.rmtree(repo_dir / "mutants", ignore_errors=True)
    (repo_dir / ".mutmut-cache").unlink(missing_ok=True)


def _resolve_function_line(repo_dir: Path, file_path: str, func_name: str) -> Optional[int]:
    """Best-effort: parses the real, unmutated source file with `ast` and
    returns the lineno of the first top-level-or-nested function/method
    named func_name. Ambiguous when multiple functions share a name
    (e.g. same-named methods on different classes) -- returns the first
    match rather than guessing further; the diff snippet itself (not this
    line number) is the ground-truth evidence for a surviving mutant, per
    CLAUDE.md's Ground-Truth-Only invariant, so an imprecise locator here
    never overstates its own confidence."""
    try:
        source = (repo_dir / file_path).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=file_path)
    except (OSError, SyntaxError, ValueError):
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            return node.lineno
    return None


def _parse_mutant_key(key: str, scoped_files: List[str]) -> Optional[tuple]:
    """Resolves a mutmut mutant key (e.g. "cli.parsers.sarif.x_foo__mutmut_1")
    back to one of our own scoped files + the real function name, by
    reversing the exact dotted-module transform this module applied when
    building the run wildcards -- no guessing at mutmut's internal naming
    beyond what was already confirmed empirically for the file/prefix
    half of the key."""
    for file_path in scoped_files:
        prefix = _dotted_module(file_path) + "."
        if key.startswith(prefix):
            tail = key[len(prefix):]
            m = _MUTANT_KEY_RE.match(tail)
            if m:
                return file_path, m.group("func")
    return None


def _collect_surviving_detail(
    repo_dir: Path,
    scoped_files: List[str],
    *,
    timeout_seconds: int,
    max_detail: int,
) -> List[SurvivingMutant]:
    try:
        proc = _run_mutmut(["results"], cwd=repo_dir, timeout_seconds=timeout_seconds)
    except (subprocess.TimeoutExpired, OSError):
        return []

    candidates: List[tuple] = []
    for line in proc.stdout.splitlines():
        m = _RESULT_LINE_RE.match(line)
        if not m or m.group("status") not in ("survived", "timeout"):
            continue
        resolved = _parse_mutant_key(m.group("key"), scoped_files)
        if resolved is not None:
            candidates.append((m.group("key"), m.group("status"), *resolved))

    detail: List[SurvivingMutant] = []
    for key, status, file_path, func_name in candidates[:max_detail]:
        try:
            show_proc = _run_mutmut(["show", key], cwd=repo_dir, timeout_seconds=timeout_seconds)
            diff_text = show_proc.stdout.strip()
        except (subprocess.TimeoutExpired, OSError):
            diff_text = ""
        detail.append(
            SurvivingMutant(
                file=file_path,
                function=func_name,
                status=status,
                diff=diff_text,
                line=_resolve_function_line(repo_dir, file_path, func_name),
            )
        )
    return detail


def _grade_from_score(score: float) -> tuple:
    if score >= MUTATION_SCORE_PASS_THRESHOLD:
        return "passed", MULTIPLIER_PASSED, None
    if score >= MUTATION_SCORE_DEGRADED_THRESHOLD:
        return "degraded", MULTIPLIER_DEGRADED, REASON_CODE_WEAK
    return "failed", MULTIPLIER_FAILED, REASON_CODE_DECORATIVE


def _discount_reason(grade: str, multiplier: float, score: Optional[float], survived: int, tested: int) -> str:
    if grade == "passed":
        return f"no discount -- {score:.0f}% mutation kill rate ({tested} mutant(s) tested)"
    if grade in ("degraded", "failed"):
        pct = round((1.0 - multiplier) * 100)
        return (
            f"Test & Coverage score discounted by {pct}% due to {score:.0f}% "
            f"Mutation Kill Rate ({survived} surviving mutant(s))"
        )
    return ""  # not_applicable / insufficient_sample callers set their own reason


def run_mutation_testing(
    repo_dir: str,
    patch_modified_lines: Dict[str, Set[int]],
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    min_sample_size: int = MUTATION_MIN_SAMPLE_SIZE_DEFAULT,
    max_surviving_detail: int = DEFAULT_MAX_SURVIVING_DETAIL,
    report_out: Optional[str] = None,
) -> MutationTestReport:
    scoped_files = select_changed_python_files(patch_modified_lines)
    if not scoped_files:
        report = _not_applicable_report(
            "no cli/*.py source changed in this diff (mutation testing not applicable)"
        )
        _write_report(report, report_out)
        return report

    try:
        safe_repo_dir = safe_resolve_path(repo_dir)
    except UnsafePathError as e:
        report = _unavailable_report(f"mutation testing refused: unsafe repo_dir: {e}")
        _write_report(report, report_out)
        return report

    existing_files = [f for f in scoped_files if (safe_repo_dir / f).is_file()]
    if not existing_files:
        report = _not_applicable_report(
            "no cli/*.py source changed in this diff (mutation testing not applicable)"
        )
        _write_report(report, report_out)
        return report

    _reset_mutmut_cache(safe_repo_dir)
    wildcards = [_wildcard_for(f) for f in existing_files]

    try:
        run_proc = _run_mutmut(["run", *wildcards], cwd=safe_repo_dir, timeout_seconds=timeout_seconds)
    except subprocess.TimeoutExpired:
        report = _unavailable_report(f"mutation testing exceeded the {timeout_seconds}s time budget")
        _write_report(report, report_out)
        return report
    except OSError as e:
        report = _unavailable_report(f"mutmut could not be invoked: {e}")
        _write_report(report, report_out)
        return report

    if run_proc.returncode != 0:
        if _NO_MATCH_MARKER in (run_proc.stderr or ""):
            report = _not_applicable_report(
                "no coverable statements in the changed cli/*.py lines "
                "(comment/docstring/type-annotation-only diff)",
                REASON_CODE_NO_COVERABLE_LINES,
            )
            report.scoped_files = existing_files
            _write_report(report, report_out)
            return report
        report = _unavailable_report(
            f"mutmut run failed (exit {run_proc.returncode}): {(run_proc.stderr or '').strip()[:300]}"
        )
        _write_report(report, report_out)
        return report

    try:
        export_proc = _run_mutmut(["export-cicd-stats"], cwd=safe_repo_dir, timeout_seconds=timeout_seconds)
        stats_path = safe_repo_dir / "mutants" / "mutmut-cicd-stats.json"
        stats = json.loads(stats_path.read_text(encoding="utf-8"))
    except (subprocess.TimeoutExpired, OSError, ValueError, json.JSONDecodeError):
        report = _unavailable_report("mutation testing ran but its results could not be read")
        _write_report(report, report_out)
        return report

    killed = int(stats.get("killed", 0))
    survived = int(stats.get("survived", 0))
    timeout_ct = int(stats.get("timeout", 0))
    total_generated = int(stats.get("total", 0))
    tested = killed + survived + timeout_ct
    denom = killed + survived  # mutation_score's own denominator, per spec

    if tested == 0:
        report = _not_applicable_report(
            "no coverable statements in the changed cli/*.py lines "
            "(comment/docstring/type-annotation-only diff)",
            REASON_CODE_NO_COVERABLE_LINES,
        )
        report.scoped_files = existing_files
        report.total_generated = total_generated
        _write_report(report, report_out)
        return report

    score = (killed / denom * 100.0) if denom else None

    if tested < min_sample_size or score is None:
        report = MutationTestReport(
            available=True,
            grade="insufficient_sample",
            multiplier=MULTIPLIER_NOT_APPLICABLE,
            mutation_score=score,
            killed=killed,
            survived=survived,
            timeout=timeout_ct,
            total_generated=total_generated,
            reason=(
                f"sample too small ({tested} mutant(s) tested, need >= {min_sample_size}) "
                "to apply a confidence discount"
            ),
            reason_code=REASON_CODE_INSUFFICIENT_SAMPLE,
            scoped_files=existing_files,
        )
        _write_report(report, report_out)
        return report

    grade, multiplier, reason_code = _grade_from_score(score)
    surviving_detail = _collect_surviving_detail(
        safe_repo_dir, existing_files, timeout_seconds=timeout_seconds, max_detail=max_surviving_detail
    ) if survived or timeout_ct else []

    report = MutationTestReport(
        available=True,
        grade=grade,
        multiplier=multiplier,
        mutation_score=score,
        killed=killed,
        survived=survived,
        timeout=timeout_ct,
        total_generated=total_generated,
        reason=_discount_reason(grade, multiplier, score, survived, tested),
        reason_code=reason_code,
        scoped_files=existing_files,
        surviving_mutants=surviving_detail,
    )
    _write_report(report, report_out)
    return report


def _write_report(report: MutationTestReport, report_out: Optional[str]) -> None:
    """Best-effort: writes the full structured report to a deterministic
    path (default reports/mutation/mutation-report.json) for CI artifact
    upload/archival, independent of what gets folded into the signed
    predicate. Never raises -- a report that can't be written to disk
    must not take down the rest of the pipeline over a diagnostics
    artifact."""
    if report_out is None:
        return
    try:
        out_path = safe_resolve_path(report_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report.as_dict(), indent=2), encoding="utf-8")
    except (UnsafePathError, OSError):
        pass
