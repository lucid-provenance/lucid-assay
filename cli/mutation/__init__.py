"""
Diff-scoped mutation testing: mutates only the source lines that
actually changed in this diff -- across Python (mutmut), TypeScript/
JavaScript (Stryker), and Java (PIT) -- and reports a real, combined
kill-rate signal that `cli.scorer` folds into RCS as a *multiplier* --
not a scored bucket -- over the test_health/patch_coverage/
overall_coverage cluster. Coverage and assertion density can both be
satisfied by a test that executes a line without ever verifying its
behavior; mutation testing is the check on whether that's actually
happening, so a 95%-covered diff with a 20% mutation kill rate reads as
decorative, not solid.

This package is a **dispatcher**: it classifies a diff's changed files
by language, hands each language's own subset to its own runner module
(python_runner.py/tsjs_runner.py/java_runner.py -- see each one's own
docstring for that language's specific hardening/verification notes),
and sums their killed/survived/timeout counts into one combined score
before grading once (see `.common.grade_from_score`) -- no per-language
weighting, no "worst grade wins" branching. A language with no
mutation-testing tool configured in the target repo at all (no `mutmut`
config, no Stryker config, no `pitest-maven` plugin) contributes
nothing, same "not evaluated, not penalized" contract the whole feature
already uses for "nothing in this diff to evaluate."

Deliberately **not** gated to lucid-assay's own `cli/` layout, for any
language -- lucid-assay is a generic tool other repos run against their
own checkout (lucid-console, lucid-dsse-collector, lucid-attest-service
all invoke it in their own CI); a directory-name filter would silently
do nothing for every one of them. Every tool's own scoping config
(mutmut's `source_paths`, Stryker's config file, PIT's `pom.xml` plugin
declaration) is read from the *target* repo, never lucid-assay's own,
since every subprocess call in every runner runs with `cwd=repo_dir`.

Not a `parsers/*` module (which stay pure/side-effect-free by design --
see CLAUDE.md's "Module boundary discipline"): running any of these
tools means spawning the test suite many times over, the same
inherently-side-effecting tier `patch_coverage.py` (git subprocess) and
`oidc_signer.py` (network) already occupy.

Hardened against (see each runner module's own docstring for the
language-specific detail this summarizes):
  - Skipping mutation testing being the easy way to game the very
    control meant to stop gaming: `available=False` (a tool missing,
    timed out, or the caller opted out) never defaults to full credit
    -- see `.common.MULTIPLIER_UNAVAILABLE`, the same non-punitive-but-
    not-free multiplier the "weak" tier uses.
  - A single surviving mutant out of one generated mutant reading as a
    0% kill rate that halves the whole Test & Coverage score:
    `min_sample_size` gates whether the tiered multiplier applies at
    all (grade="insufficient_sample" below it, full credit, honest
    reason string) -- same spirit as the zero-mutant exemption, just
    for "ran, but not enough signal yet" instead of "nothing to run at
    all". Applied once, after combining every language's counts --
    3 total mutants tested across two languages is still 3, not
    "1 language passed the floor and one didn't."
  - Git CLI/subprocess injection: diff scoping reuses
    `patch_coverage.compute_patch_modified_lines()`, the same already-
    hardened public wrapper `cli.parsers.sarif` depends on for its own
    differential scoring -- no runner here invokes git itself.
  - Unsafe/unresolvable repo_dir reaching subprocess.run(cwd=...):
    resolved via `common.safe_resolve_path()` once, here, before any
    runner is ever called.
"""
from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Set

from ..common import UnsafePathError, safe_resolve_path
from . import go_runner, java_runner, python_runner, tsjs_runner
from .common import (
    DEFAULT_MAX_SURVIVING_DETAIL,
    DEFAULT_TIMEOUT_SECONDS,
    LANGUAGE_GO,
    LANGUAGE_JAVA,
    LANGUAGE_PYTHON,
    LANGUAGE_TSJS,
    LanguageRunResult,
    MULTIPLIER_DEGRADED,
    MULTIPLIER_FAILED,
    MULTIPLIER_NOT_APPLICABLE,
    MULTIPLIER_PASSED,
    MULTIPLIER_UNAVAILABLE,
    MUTATION_MIN_SAMPLE_SIZE_DEFAULT,
    MUTATION_SCORE_DEGRADED_THRESHOLD,
    MUTATION_SCORE_PASS_THRESHOLD,
    MutationTestReport,
    REASON_CODE_DECORATIVE,
    REASON_CODE_INSUFFICIENT_SAMPLE,
    REASON_CODE_NO_COVERABLE_LINES,
    REASON_CODE_NO_SOURCE_CHANGES,
    REASON_CODE_SKIPPED,
    REASON_CODE_UNAVAILABLE,
    REASON_CODE_WEAK,
    SurvivingMutant,
    discount_reason,
    grade_from_score,
    not_applicable_report,
    skipped_report,
    unavailable_report,
)

# Naming-convention heuristics for "this file is a test, not source" --
# mutating test code is never meaningful, for any repo. Deliberately
# heuristics, not a claim of certainty: a file that slips past one of
# these just becomes a wildcard/glob/class-name that language's own
# tool-side scoping config (read from the target repo, never lucid-
# assay's own) will filter out anyway, not a crash.
_PYTHON_TEST_DIR_NAMES = {"tests", "test"}
_PYTHON_TEST_FILE_RE = re.compile(r"^test_.*\.py$|^.*_test\.py$")
# Mirrors tsjs_visitor.py's own discovery convention.
_TSJS_TEST_FILE_RE = re.compile(r"\.(test|spec)\.[jt]sx?$")
_TSJS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
# Mirrors java_visitor.py's own discovery convention.
_JAVA_TEST_FILE_RE = re.compile(r"^(?:.*Test|.*Tests|.*TestCase)\.java$")
# Mirrors go_visitor.py's own discovery convention.
_GO_TEST_FILE_RE = re.compile(r"^.*_test\.go$")

_RUNNERS = {
    LANGUAGE_PYTHON: python_runner.run,
    LANGUAGE_TSJS: tsjs_runner.run,
    LANGUAGE_JAVA: java_runner.run,
    LANGUAGE_GO: go_runner.run,
}


def _is_python_test_path(file_path: str) -> bool:
    parts = file_path.replace("\\", "/").split("/")
    if any(p in _PYTHON_TEST_DIR_NAMES for p in parts[:-1]):
        return True
    return bool(_PYTHON_TEST_FILE_RE.match(parts[-1]))


def _is_tsjs_test_path(file_path: str) -> bool:
    parts = file_path.replace("\\", "/").split("/")
    if "__tests__" in parts[:-1]:
        return True
    return bool(_TSJS_TEST_FILE_RE.search(parts[-1]))


def _is_java_test_path(file_path: str) -> bool:
    name = file_path.replace("\\", "/").split("/")[-1]
    return bool(_JAVA_TEST_FILE_RE.match(name))


def _is_go_test_path(file_path: str) -> bool:
    name = file_path.replace("\\", "/").split("/")[-1]
    return bool(_GO_TEST_FILE_RE.match(name))


def _classify_changed_files(patch_modified_lines: Dict[str, Set[int]]) -> Dict[str, List[str]]:
    """The already-computed diff (patch_coverage.compute_patch_modified_lines,
    repo-root-relative paths), split by language and stripped of test
    files -- "new code only", wherever it lives in the repo (never gated
    to any particular directory name -- see the package docstring).
    Deterministic order (sorted) so wildcard/glob/class-name argv order
    -- and therefore each tool's own stable-sort output -- doesn't vary
    run to run."""
    by_language: Dict[str, List[str]] = {}
    for f in sorted(patch_modified_lines):
        if f.endswith(".py") and not _is_python_test_path(f):
            by_language.setdefault(LANGUAGE_PYTHON, []).append(f)
        elif f.endswith(_TSJS_EXTENSIONS) and not _is_tsjs_test_path(f):
            by_language.setdefault(LANGUAGE_TSJS, []).append(f)
        elif f.endswith(".java") and not _is_java_test_path(f):
            by_language.setdefault(LANGUAGE_JAVA, []).append(f)
        elif f.endswith(".go") and not _is_go_test_path(f):
            by_language.setdefault(LANGUAGE_GO, []).append(f)
    return by_language


def select_changed_python_files(patch_modified_lines: Dict[str, Set[int]]) -> List[str]:
    """Backward-compatible convenience wrapper: just the Python slice of
    _classify_changed_files(), for callers/tests that only care about
    that one language's own scoping."""
    return _classify_changed_files(patch_modified_lines).get(LANGUAGE_PYTHON, [])


def run_mutation_testing(
    repo_dir: str,
    patch_modified_lines: Dict[str, Set[int]],
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    min_sample_size: int = MUTATION_MIN_SAMPLE_SIZE_DEFAULT,
    max_surviving_detail: int = DEFAULT_MAX_SURVIVING_DETAIL,
    report_out: Optional[str] = None,
    base_sha: Optional[str] = None,
) -> MutationTestReport:
    """`base_sha` is only actually consumed by go_runner.py -- gremlins
    does its own git diffing internally via `--diff <ref>`, unlike every
    other runner here, which is handed an already-diffed file list and
    builds its own wildcard/glob/targetClasses from it. Every runner
    receives it for a uniform calling convention regardless; the other
    three simply never look at it."""
    by_language = _classify_changed_files(patch_modified_lines)
    if not by_language:
        report = not_applicable_report(
            "no *.py/*.ts/*.tsx/*.js/*.jsx/*.java/*.go source changed in this diff "
            "(mutation testing not applicable)"
        )
        _write_report(report, report_out)
        return report

    try:
        safe_repo_dir = safe_resolve_path(repo_dir)
    except UnsafePathError as e:
        report = unavailable_report(f"mutation testing refused: unsafe repo_dir: {e}")
        _write_report(report, report_out)
        return report

    results: List[LanguageRunResult] = [
        _RUNNERS[language](
            safe_repo_dir,
            files,
            timeout_seconds=timeout_seconds,
            max_surviving_detail=max_surviving_detail,
            base_sha=base_sha,
        )
        for language, files in by_language.items()
    ]

    report = _combine_results(results, min_sample_size=min_sample_size, max_surviving_detail=max_surviving_detail)
    _write_report(report, report_out)
    return report


def _combine_results(
    results: List[LanguageRunResult], *, min_sample_size: int, max_surviving_detail: int
) -> MutationTestReport:
    ran = [r for r in results if r.status == "ran"]
    unavailable = [r for r in results if r.status == "unavailable"]

    if not ran:
        if unavailable:
            reasons = "; ".join(f"{r.language}: {r.reason}" for r in unavailable)
            return unavailable_report(f"mutation testing failed for every touched language ({reasons})")
        return not_applicable_report(
            "no mutation-testing tool is configured in this repo for any language "
            "this diff touched (no [tool.mutmut]/no Stryker config/no pitest-maven plugin)"
        )

    killed = sum(r.killed for r in ran)
    survived = sum(r.survived for r in ran)
    timeout_ct = sum(r.timeout for r in ran)
    total_generated = sum(r.total_generated for r in ran)
    scoped_files = sorted(f for r in ran for f in r.scoped_files)
    surviving_mutants = [m for r in ran for m in r.surviving_mutants][:max_surviving_detail]
    by_language_detail = {
        r.language: {
            "killed": r.killed,
            "survived": r.survived,
            "timeout": r.timeout,
            "total_generated": r.total_generated,
            "scoped_files": r.scoped_files,
        }
        for r in ran
    }

    tested = killed + survived + timeout_ct
    denom = killed + survived

    if tested == 0:
        report = not_applicable_report(
            "no coverable statements in the changed source lines "
            "(comment/docstring/type-annotation-only diff)",
            REASON_CODE_NO_COVERABLE_LINES,
        )
        report.scoped_files = scoped_files
        report.total_generated = total_generated
        report.by_language = by_language_detail
        return report

    score = (killed / denom * 100.0) if denom else None

    if tested < min_sample_size or score is None:
        return MutationTestReport(
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
            scoped_files=scoped_files,
            by_language=by_language_detail,
        )

    grade, multiplier, reason_code = grade_from_score(score)

    return MutationTestReport(
        available=True,
        grade=grade,
        multiplier=multiplier,
        mutation_score=score,
        killed=killed,
        survived=survived,
        timeout=timeout_ct,
        total_generated=total_generated,
        reason=discount_reason(grade, multiplier, score, survived, tested),
        reason_code=reason_code,
        scoped_files=scoped_files,
        surviving_mutants=surviving_mutants,
        by_language=by_language_detail,
    )


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
