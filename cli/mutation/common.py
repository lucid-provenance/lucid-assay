"""
Shared shapes and scoring-policy constants for diff-scoped mutation
testing, used by every per-language runner (python_runner.py,
tsjs_runner.py, java_runner.py) and by the dispatcher in __init__.py.
One source of truth for the tier thresholds/multipliers regardless of
which language(s) contributed to a given run's combined mutation_score.

Hardened against:
  - Two different places deciding what a "weak"/"decorative" kill rate
    means: _grade_from_score/_discount_reason are the only functions
    that ever compute a grade/multiplier from a score -- every runner
    and the dispatcher both call through here, never duplicate the
    tiers locally.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

MUTATION_SCORE_PASS_THRESHOLD = 80.0
MUTATION_SCORE_DEGRADED_THRESHOLD = 60.0
MUTATION_MIN_SAMPLE_SIZE_DEFAULT = 3

MULTIPLIER_PASSED = 1.0
MULTIPLIER_DEGRADED = 0.85
MULTIPLIER_FAILED = 0.50
# Unavailable/skip both use the same non-punitive-but-not-free multiplier
# as the "weak" tier -- see cli.mutation's module docstring's fail-closed
# note. "Not applicable" (no source in a supported language changed at
# all, a zero-mutant comment/docstring-only diff, or too small a sample
# to trust) is the one family of outcomes that gets full credit, since
# none of those is a control anyone dodged.
MULTIPLIER_UNAVAILABLE = 0.85
MULTIPLIER_NOT_APPLICABLE = 1.0

REASON_CODE_WEAK = "weak_assertion_coverage"
REASON_CODE_DECORATIVE = "decorative_coverage"
REASON_CODE_UNAVAILABLE = "unavailable"
REASON_CODE_SKIPPED = "skipped"
REASON_CODE_NO_SOURCE_CHANGES = "no_source_changes"
REASON_CODE_NO_COVERABLE_LINES = "no_coverable_lines"
REASON_CODE_INSUFFICIENT_SAMPLE = "insufficient_sample"

DEFAULT_TIMEOUT_SECONDS = 90
DEFAULT_MAX_SURVIVING_DETAIL = 5

LANGUAGE_PYTHON = "python"
LANGUAGE_TSJS = "typescript_javascript"
LANGUAGE_JAVA = "java"


@dataclass
class SurvivingMutant:
    language: str
    file: str
    function: str
    status: str  # "survived" or "timeout"
    diff: str
    line: Optional[int] = None

    def as_dict(self) -> Dict:
        return {
            "language": self.language,
            "file": self.file,
            "function": self.function,
            "status": self.status,
            "line": self.line,
            "diff": self.diff,
        }


@dataclass
class LanguageRunResult:
    """One language's own raw contribution to the combined report --
    never scored/graded on its own; the dispatcher in __init__.py sums
    these across every language that actually ran before grading once.

    `status`:
      - "ran": the tool actually executed (even if it found zero
        mutants, e.g. a comment-only diff in that language -- see
        `total_generated`/killed+survived+timeout for whether it found
        anything real).
      - "not_configured": this language's tool isn't set up in the
        target repo at all (no stryker config, no pitest-maven plugin,
        ...) -- contributes nothing, and on its own is not a penalty
        (same as no changes in this diff at all).
      - "unavailable": the tool *was* configured but a real attempt
        failed (missing binary, crashed, timed out) -- fail-closed,
        never treated the same as "not_configured".
    """
    language: str
    status: str
    killed: int = 0
    survived: int = 0
    timeout: int = 0
    total_generated: int = 0
    scoped_files: List[str] = field(default_factory=list)
    surviving_mutants: List[SurvivingMutant] = field(default_factory=list)
    reason: Optional[str] = None  # meaningful for "unavailable" only


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
    # Per-language breakdown (killed/survived/timeout/scoped_files),
    # keyed by language id -- mirrors predicate.assertion_density's own
    # existing per-language precedent. Omitted (empty) for a single-
    # language run's not_applicable/unavailable short circuits, where
    # there's nothing per-language worth breaking out.
    by_language: Dict[str, Dict] = field(default_factory=dict)

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
            "by_language": self.by_language,
            "reason": self.reason,
            "reason_code": self.reason_code,
        }


def not_applicable_report(reason: str, reason_code: str = REASON_CODE_NO_SOURCE_CHANGES) -> MutationTestReport:
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


def unavailable_report(reason: str, reason_code: str = REASON_CODE_UNAVAILABLE) -> MutationTestReport:
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
    decision in the caller rather than threading a skip flag through
    every language's own run logic."""
    return unavailable_report(reason, REASON_CODE_SKIPPED)


def grade_from_score(score: float) -> tuple:
    if score >= MUTATION_SCORE_PASS_THRESHOLD:
        return "passed", MULTIPLIER_PASSED, None
    if score >= MUTATION_SCORE_DEGRADED_THRESHOLD:
        return "degraded", MULTIPLIER_DEGRADED, REASON_CODE_WEAK
    return "failed", MULTIPLIER_FAILED, REASON_CODE_DECORATIVE


def discount_reason(grade: str, multiplier: float, score: Optional[float], survived: int, tested: int) -> str:
    if grade == "passed":
        return f"no discount -- {score:.0f}% mutation kill rate ({tested} mutant(s) tested)"
    if grade in ("degraded", "failed"):
        pct = round((1.0 - multiplier) * 100)
        return (
            f"Test & Coverage score discounted by {pct}% due to {score:.0f}% "
            f"Mutation Kill Rate ({survived} surviving mutant(s))"
        )
    return ""  # not_applicable / insufficient_sample callers set their own reason
