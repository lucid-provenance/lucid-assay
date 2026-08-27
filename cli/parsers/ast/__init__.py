"""
Multi-language assertion integrity engine: dispatches repo-wide (or
diff-scoped) test-file discovery across every registered language visitor
and aggregates their results into one `TestSuiteMetrics`.

Reference standard: `python_visitor.py` (stdlib `ast`). The other three --
`tsjs_visitor.py` (TypeScript/JavaScript, Jest/Vitest/Mocha),
`go_visitor.py` (Go, `testing`/testify), `java_visitor.py` (JUnit 4/5,
AssertJ, Hamcrest) -- run on Tree-sitter grammars, since none of those
languages ship a first-party parser accessible from Python.

Hardened against:
  - One language's discovery/parse failure tainting another's: each
    `FileInspectionResult.parse_error` is scoped to its own file, and
    aggregation continues past it (matching the fail-per-file, not
    fail-the-scan, convention of the Python-only engine this replaces).
  - Skipped/disabled tests (any language's `@Disabled`/`@Ignore`/
    `it.skip`/`t.Skip`-wholesale) inflating "zero-assertion" counts --
    they're aggregated into `skipped_test_functions` and excluded from
    `total_test_functions`/`total_assertions`/density instead.
  - Ambiguous file ownership: visitors are matched by mutually exclusive
    extension/suffix conventions (`.py` vs `*_test.go` vs `*Test.java` vs
    `.test.ts`/`__tests__/`), so a given path is claimed by exactly one
    visitor -- discovery order does not affect the result.
  - `target_files` narrowing to only conventionally-*named* test files: an
    explicitly-passed path (diff-scoped scanning) is still resolved by
    extension when it doesn't match any visitor's discovery naming
    convention, since the caller already asserted "scan this file" -- the
    naming convention only exists to drive *repo-wide* discovery, not to
    second-guess an explicit request. (The single-language engine this
    replaces never filtered `target_files` by name at all.)
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

from .base import AssertionVisitor
from .common import FileInspectionResult, LanguageMetrics, TestFunctionMetrics, TestSuiteMetrics, SKIP_DIR_NAMES
from .go_visitor import GoAssertionVisitor
from .java_visitor import JavaAssertionVisitor
from .python_visitor import PythonAssertionVisitor
from .tsjs_visitor import TsJsAssertionVisitor

__all__ = [
    "AssertionVisitor",
    "FileInspectionResult",
    "LanguageMetrics",
    "TestFunctionMetrics",
    "TestSuiteMetrics",
    "inspect_test_suite",
]

_python_visitor = PythonAssertionVisitor()
_tsjs_visitor = TsJsAssertionVisitor()
_go_visitor = GoAssertionVisitor()
_java_visitor = JavaAssertionVisitor()

# Order is irrelevant to correctness (see module docstring) but is kept
# stable/deterministic for reproducible `languages` iteration order in the
# aggregated report and predicate output.
_VISITORS: List[AssertionVisitor] = [_python_visitor, _tsjs_visitor, _go_visitor, _java_visitor]

# Extension-only fallback, consulted for explicitly-passed `target_files`
# paths that don't satisfy any visitor's *discovery* naming convention
# (e.g. a diff-touched `conftest.py` or a helper module) -- see module
# docstring. Never consulted during repo-wide discovery.
_EXTENSION_FALLBACK: Dict[str, AssertionVisitor] = {
    "py": _python_visitor,
    "ts": _tsjs_visitor,
    "tsx": _tsjs_visitor,
    "js": _tsjs_visitor,
    "jsx": _tsjs_visitor,
    "mjs": _tsjs_visitor,
    "cjs": _tsjs_visitor,
    "go": _go_visitor,
    "java": _java_visitor,
}


def _visitor_for(path: str, *, explicit: bool = False) -> Optional[AssertionVisitor]:
    for visitor in _VISITORS:
        if visitor.matches(path):
            return visitor
    if explicit:
        basename = path.replace("\\", "/").rsplit("/", 1)[-1]
        if "." in basename:
            return _EXTENSION_FALLBACK.get(basename.rsplit(".", 1)[-1].lower())
    return None


def _discover_candidates(repo_dir: str) -> List[Tuple[str, AssertionVisitor]]:
    matches: List[Tuple[str, AssertionVisitor]] = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIR_NAMES and not d.startswith(".")]
        for fname in files:
            full = os.path.join(root, fname)
            visitor = _visitor_for(full)
            if visitor is not None:
                matches.append((full, visitor))
    return sorted(matches, key=lambda pair: pair[0])


def _tally(metrics: TestSuiteMetrics, lang_metrics: LanguageMetrics, fn: TestFunctionMetrics) -> None:
    if fn.is_skipped:
        metrics.skipped_test_functions += 1
        lang_metrics.skipped_test_functions += 1
        return
    # assertion_count and tautological_count are disjoint counters -- every
    # visitor increments exactly one or the other per assertion call (see
    # e.g. python_visitor.py's _visit_assert), so assertion_count already
    # excludes tautological ones. "Valid" is therefore simply "has at
    # least one counted (real) assertion"; an empty-bodied function has
    # assertion_count == 0 the same as a not-empty, all-tautological one,
    # so no separate empty-body branch is needed here.
    is_valid = fn.assertion_count > 0
    for target in (metrics, lang_metrics):
        target.total_test_functions += 1
        target.total_assertions += fn.assertion_count
        target.tautological_assertions += fn.tautological_count
        if fn.is_empty_body:
            target.empty_test_bodies += 1
        if is_valid:
            target.valid_test_functions += 1


def inspect_test_suite(repo_dir: str, target_files: Optional[List[str]] = None) -> TestSuiteMetrics:
    """Aggregates assertion-integrity metrics across a test suite, across
    every registered language.

    If `target_files` is given, only those files are inspected (paths may
    be absolute or relative to `repo_dir`) -- useful for scoping the scan
    to diff-touched test files; a path that doesn't match any visitor's
    discovery naming convention still gets resolved and scanned by
    extension (see module docstring). Otherwise every file any registered
    visitor's naming convention recognizes is discovered under `repo_dir`
    and scanned. A path with no recognized extension at all (in either
    mode) is silently skipped, not reported as an error.
    """
    if target_files is not None:
        candidates: List[Tuple[str, AssertionVisitor]] = []
        for path in target_files:
            full = path if os.path.isabs(path) else os.path.join(repo_dir, path)
            visitor = _visitor_for(full, explicit=True)
            if visitor is not None:
                candidates.append((full, visitor))
    else:
        candidates = _discover_candidates(repo_dir)

    metrics = TestSuiteMetrics()
    for path, visitor in candidates:
        result = visitor.inspect_file(path)
        metrics.files.append(result)
        metrics.files_scanned += 1

        lang_metrics = metrics.languages.setdefault(result.language, LanguageMetrics(language=result.language))
        lang_metrics.files_scanned += 1

        if result.parse_error is not None:
            metrics.parse_errors.append(f"{path}: {result.parse_error}")
            continue

        for fn in result.test_functions:
            _tally(metrics, lang_metrics, fn)

    return metrics
