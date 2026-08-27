"""
Vanity-test-aware "real" coverage.

Line coverage (cli.parsers.coverage) and assertion validity (cli.parsers.ast)
are computed as two independent signals today: a "vanity" test (an empty
body, or one whose only assertions are tautological, e.g. `assert True`)
still *executes* whatever code it calls before failing to actually verify
anything -- so it inflates the reported line-coverage percentage exactly
as much as a real test would, without providing any of the assurance that
percentage is meant to imply.

This module answers the question raw line coverage can't: how much of the
reported coverage is exercised *only* by vanity tests? It cross-references
cli.parsers.coverage_contexts' per-test line-coverage attribution (which
test(s) executed each line) against cli.parsers.ast's per-function
assertion classification (which tests are vanity), for both total/overall
coverage and patch/new-code coverage.

A source line counts as "vanity-only covered" when it has at least one
attributed covering test (context) AND every one of them resolves to a
vanity test. A line with NO attributed context at all (covered outside
any dynamic context, e.g. at module import time, or a file/line the
coverage-context export simply didn't mention) is left alone -- there is
no evidence it's vanity-only, so "real" coverage never discounts a line
it can't actually implicate. This is a deliberate asymmetry: this module
can only ever narrow "how much of measured coverage is real", never
inflate it past what was actually measured.

"Real" coverage subtracts vanity-only-covered lines from the numerator
only, keeping the exact same denominator (and the exact same underlying
line-hit data) the existing CoverageReport/PatchCoverageResult already
use for "measured" coverage -- so "measured" and "real" are always
apples-to-apples comparable, never computed from two different line sets.

Python-only, currently: coverage.py's dynamic-context mechanism has no
equivalent wired up for the other three languages' test runners
(Jest/Vitest, `go test`, JUnit) in this pipeline, so a TS/JS/Go/Java
vanity test can simply never appear in a coverage context. That's
harmless, not a false negative this module claims to catch -- it just
means those languages' vanity tests currently only show up in the
assertion_density.valid_test_ratio signal, not here.

Hardened against:
  - Any missing input (no coverage-context data, no AST metrics, no
    coverage report, no patch data) degrading this to available=False
    (per track) rather than raising or fabricating a number
  - File-path convention mismatches between the coverage-context export,
    the AST engine's own file paths, and the Cobertura/LCOV report's
    paths (source-root-relative vs repo-root-relative): the same
    suffix-match-with-ambiguity-rejection idiom used throughout this
    codebase (see cli.patch_coverage._lookup_file_coverage /
    cli.parsers.sarif._lookup_modified_lines) -- an ambiguous match is
    treated as "can't attribute", never guessed at
  - A context label whose file portion can't be resolved to any AST-known
    test file at all: treated as "not proven vanity" (counts toward real
    coverage), the same fail-safe default as an entirely absent context
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from .parsers.ast.common import TestSuiteMetrics
from .parsers.coverage import CoverageReport
from .parsers.coverage_contexts import CoverageContextReport
from .parsers.coverage_contexts import _normalize_path as _normalize_coverage_path


@dataclass
class CoverageTrackResult:
    """One track's (overall or patch) measured-vs-real comparison."""
    __test__ = False
    available: bool
    reason: str = ""
    measured_line_rate: Optional[float] = None
    real_line_rate: Optional[float] = None
    total_lines: int = 0
    measured_covered_lines: int = 0
    vanity_only_lines: int = 0

    def as_dict(self) -> Dict[str, object]:
        return {
            "available": self.available,
            "reason": self.reason,
            "measured_line_rate": self.measured_line_rate,
            "real_line_rate": self.real_line_rate,
            "total_lines": self.total_lines,
            "measured_covered_lines": self.measured_covered_lines,
            "vanity_only_lines": self.vanity_only_lines,
        }


@dataclass
class RealCoverageResult:
    __test__ = False
    overall: CoverageTrackResult
    patch: CoverageTrackResult

    def as_dict(self) -> Dict[str, object]:
        return {"overall": self.overall.as_dict(), "patch": self.patch.as_dict()}


def _path_components(path_str: str) -> List[str]:
    return [part for part in path_str.replace("\\", "/").split("/") if part]


def _suffix_match_len(a_parts: List[str], b_parts: List[str]) -> Optional[int]:
    """Returns the number of trailing path components `a_parts` and
    `b_parts` share (i.e. the shorter one is a full suffix of the
    longer), or None if neither is a suffix of the other."""
    shorter, longer = (a_parts, b_parts) if len(a_parts) <= len(b_parts) else (b_parts, a_parts)
    if not shorter or longer[-len(shorter):] != shorter:
        return None
    return len(shorter)


def _resolve_by_suffix(target: str, candidates: Dict[str, Any]) -> Optional[str]:
    """Resolves `target` (a normalized file path) against `candidates`'
    keys -- only the keys matter, so any dict keyed by candidate file
    paths works regardless of its value type: exact match first, then
    suffix-matching on path components (mirrors
    cli.patch_coverage._lookup_file_coverage). An ambiguous suffix match
    (multiple candidates tied for the longest match) is treated as no
    match rather than guessed at. Returns the matched key, not the
    value, so callers with a small-cardinality cache can reuse this
    across many lookups against the same `candidates` map."""
    if target in candidates:
        return target

    target_parts = _path_components(target)
    if not target_parts:
        return None

    best_key: Optional[str] = None
    best_len = 0
    ambiguous = False

    for candidate in candidates:
        match_len = _suffix_match_len(_path_components(candidate), target_parts)
        if match_len is None:
            continue
        if match_len > best_len:
            best_len, best_key, ambiguous = match_len, candidate, False
        elif match_len == best_len:
            ambiguous = True

    return None if ambiguous else best_key


def _vanity_remainders_by_file(metrics: TestSuiteMetrics) -> Dict[str, Set[str]]:
    """{normalized_file_path: {"Class::method" or "function", ...}} for
    every non-skipped, Python, zero-real-assertion ("vanity") test
    function. The value strings are the exact suffix a pytest node id
    carries after its first '::' (path::Class::method or
    path::function) -- see _is_vanity_context."""
    by_file: Dict[str, Set[str]] = {}
    for f in metrics.files:
        if f.language != "python":
            continue
        vanity = {
            f"{fn.class_name}::{fn.name}" if fn.class_name else fn.name
            for fn in f.test_functions
            if not fn.is_skipped and fn.assertion_count == 0
        }
        if vanity:
            by_file[_normalize_coverage_path(f.path)] = vanity
    return by_file


def _split_node_id(node_id: str) -> Tuple[str, str]:
    """Splits a pytest node id ('path::Class::method' or 'path::function')
    into (path, remainder) at the first '::'."""
    if "::" not in node_id:
        return node_id, ""
    path, _, remainder = node_id.partition("::")
    return path, remainder


class _VanityClassifier:
    """Classifies coverage-context labels as vanity-or-not against a
    precomputed vanity_by_file map, caching each label's file-path
    resolution (many lines share the same handful of covering tests, so
    the same file path is resolved from a context label over and over)."""

    def __init__(self, vanity_by_file: Dict[str, Set[str]]):
        self._vanity_by_file = vanity_by_file
        self._resolved_path_cache: Dict[str, Optional[str]] = {}

    def _resolve_file(self, raw_path: str) -> Optional[str]:
        normalized = _normalize_coverage_path(raw_path)
        if normalized not in self._resolved_path_cache:
            self._resolved_path_cache[normalized] = _resolve_by_suffix(normalized, self._vanity_by_file)
        return self._resolved_path_cache[normalized]

    def is_vanity(self, context_label: str) -> bool:
        """True only when `context_label`'s file resolves to a known
        AST-scanned Python test file AND its Class::method/function
        remainder is one that file's vanity set. Unresolvable file or
        non-vanity remainder both mean "not proven vanity"."""
        raw_path, remainder = _split_node_id(context_label)
        resolved = self._resolve_file(raw_path)
        if resolved is None:
            return False
        return remainder in self._vanity_by_file.get(resolved, set())


def _is_vanity_only_line(contexts: FrozenSet[str], classifier: _VanityClassifier) -> bool:
    """A covered line is vanity-only iff it has at least one attributed
    context and every one of them is a vanity test -- an empty context
    set ("covered, no known covering test") is never vanity-only, per
    this module's fail-safe-toward-"real" contract."""
    return bool(contexts) and all(classifier.is_vanity(c) for c in contexts)


def _line_contexts(
    context_report: CoverageContextReport, file_cache: Dict[str, Optional[str]], file_path: str, lineno: int
) -> FrozenSet[str]:
    """Looks up one (file, line)'s covering-context set from
    `context_report`, resolving `file_path` against its keys by suffix
    (cached in `file_cache` across the many lines of the same file).
    Returns frozenset() -- "no known covering test" -- for an unresolved
    file or a line the export simply didn't mention, identical treatment
    to an explicit empty context."""
    if file_path not in file_cache:
        file_cache[file_path] = _resolve_by_suffix(file_path, context_report.files)
    resolved = file_cache[file_path]
    if resolved is None:
        return frozenset()
    return context_report.files[resolved].get(lineno, frozenset())


def _score_lines(
    line_hits_by_file: Dict[str, Dict[int, int]],
    context_report: CoverageContextReport,
    classifier: _VanityClassifier,
) -> CoverageTrackResult:
    """Shared scoring loop for both overall and patch tracks: given
    {file: {line: hit_count}}, tallies total/measured-covered/
    vanity-only-covered lines and derives both rates from the same
    counts. `line_hits_by_file` is the ONLY line-set input -- overall and
    patch differ solely in what's passed here (every coverable line vs.
    just the diff's changed-and-coverable lines), so measured/real stay
    apples-to-apples with whichever baseline number the caller is
    comparing against."""
    file_cache: Dict[str, Optional[str]] = {}
    total = 0
    measured_covered = 0
    vanity_only = 0

    for file_path, hits in line_hits_by_file.items():
        for lineno, hit_count in hits.items():
            total += 1
            if hit_count <= 0:
                continue
            measured_covered += 1
            contexts = _line_contexts(context_report, file_cache, file_path, lineno)
            if _is_vanity_only_line(contexts, classifier):
                vanity_only += 1

    if total == 0:
        return CoverageTrackResult(available=False, reason="no coverable lines in this track")

    measured_rate = measured_covered / total
    real_rate = (measured_covered - vanity_only) / total
    return CoverageTrackResult(
        available=True,
        measured_line_rate=measured_rate,
        real_line_rate=real_rate,
        total_lines=total,
        measured_covered_lines=measured_covered,
        vanity_only_lines=vanity_only,
    )


def _overall_line_hits(coverage: CoverageReport) -> Dict[str, Dict[int, int]]:
    return {path: dict(fc.line_hits) for path, fc in coverage.files.items()}


def _patch_line_hits(
    coverage: CoverageReport, patch_modified_lines: Dict[str, Set[int]]
) -> Dict[str, Dict[int, int]]:
    """Same {file: {line: hits}} shape as _overall_line_hits, narrowed to
    only the diff's changed lines that the coverage report registered as
    coverable at all -- mirrors cli.patch_coverage.compute_patch_coverage's
    own filtering exactly, so the patch track's denominator matches
    PatchCoverageResult.lines_changed."""
    result: Dict[str, Dict[int, int]] = {}
    for file_path, line_numbers in patch_modified_lines.items():
        resolved = _resolve_by_suffix(file_path, coverage.files)
        if resolved is None:
            continue
        file_cov = coverage.files[resolved]
        hits = {ln: file_cov.line_hits[ln] for ln in line_numbers if ln in file_cov.line_hits}
        if hits:
            result[file_path] = hits
    return result


def compute_real_coverage(
    *,
    test_suite_metrics: TestSuiteMetrics,
    coverage: CoverageReport,
    context_report: CoverageContextReport,
    patch_modified_lines: Optional[Dict[str, Set[int]]] = None,
) -> RealCoverageResult:
    """Computes vanity-test-discounted "real" coverage for both the
    overall/total-code track and the patch/new-code track. Each track
    degrades independently to available=False (never raises): the
    overall track needs `context_report.available` and at least one
    coverable line in `coverage`; the patch track additionally needs a
    non-empty `patch_modified_lines` (the same {file: {changed lines}}
    cli.patch_coverage.compute_patch_modified_lines() already produces).
    """
    if not context_report.available:
        unavailable = CoverageTrackResult(available=False, reason=context_report.reason or "coverage contexts unavailable")
        return RealCoverageResult(overall=unavailable, patch=unavailable)

    vanity_by_file = _vanity_remainders_by_file(test_suite_metrics)
    classifier = _VanityClassifier(vanity_by_file)

    overall = _score_lines(_overall_line_hits(coverage), context_report, classifier)

    if not patch_modified_lines:
        patch = CoverageTrackResult(available=False, reason="no patch-modified-lines data available")
    else:
        patch = _score_lines(_patch_line_hits(coverage, patch_modified_lines), context_report, classifier)

    return RealCoverageResult(overall=overall, patch=patch)
