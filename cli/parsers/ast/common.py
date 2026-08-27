"""
Shared data model + repo-walk plumbing for the multi-language assertion
integrity engine. Every per-language visitor (`python_visitor.py`,
`tsjs_visitor.py`, `go_visitor.py`, `java_visitor.py`) produces these same
dataclasses so `cli/parsers/ast/__init__.py::inspect_test_suite` can
aggregate across languages without caring which one did the walking.

Hardened against:
  - Walking into vendor/dependency/build directories during repo-wide
    discovery (shared skip-list, language-agnostic).
  - A single language's parse/discovery failure (bad grammar load, one
    corrupt file) tainting metrics for every *other* language's files --
    each `FileInspectionResult.parse_error` is scoped to its own file.
  - Skipped/disabled tests being silently folded into "zero-assertion"
    counts: they're tracked in their own bucket instead, since a test a
    human explicitly disabled is a different signal than one that ran and
    asserted nothing.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import List, Optional

# Directories skipped during repo-wide test discovery; matched by basename.
# Shared across every language -- vendor/build trees look the same
# regardless of what language lives inside them.
SKIP_DIR_NAMES = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".tox",
    "site-packages",
    "dist",
    "build",
    "target",  # Java/Maven, Go build output
    "vendor",  # Go vendored deps
    "bin",
    "obj",
    ".mypy_cache",
    ".pytest_cache",
    ".eggs",
    ".next",
    ".nuxt",
}


@dataclass
class TestFunctionMetrics:
    __test__ = False
    name: str
    file: str
    lineno: int
    language: str = "python"
    assertion_count: int = 0
    tautological_count: int = 0
    is_empty_body: bool = False
    is_skipped: bool = False


@dataclass
class FileInspectionResult:
    __test__ = False
    path: str
    language: str = "python"
    test_functions: List[TestFunctionMetrics] = field(default_factory=list)
    parse_error: Optional[str] = None


@dataclass
class LanguageMetrics:
    """Per-language rollup, embedded in `TestSuiteMetrics.languages` and the
    DSSE predicate's `assertion_density.languages` block for transparency."""
    __test__ = False
    language: str
    files_scanned: int = 0
    total_test_functions: int = 0
    total_assertions: int = 0
    tautological_assertions: int = 0
    empty_test_bodies: int = 0
    skipped_test_functions: int = 0
    # Non-skipped test functions with at least one *real* (non-tautological)
    # assertion -- i.e. total_test_functions minus "vanity" tests (empty
    # bodies + tests whose only assertions are tautological). See
    # cli.parsers.ast._tally for the exact per-function classification.
    valid_test_functions: int = 0

    def as_dict(self) -> dict:
        # `language` is deliberately omitted -- it's already the dict key
        # one level up in `TestSuiteMetrics.languages`.
        return {k: v for k, v in dataclasses.asdict(self).items() if k != "language"}


@dataclass
class TestSuiteMetrics:
    __test__ = False
    files_scanned: int = 0
    total_test_functions: int = 0
    total_assertions: int = 0
    tautological_assertions: int = 0
    empty_test_bodies: int = 0
    skipped_test_functions: int = 0
    # See LanguageMetrics.valid_test_functions -- same definition, summed
    # across every language.
    valid_test_functions: int = 0
    files: List[FileInspectionResult] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)
    languages: "dict[str, LanguageMetrics]" = field(default_factory=dict)

    @property
    def assertion_density(self) -> float:
        if self.total_test_functions <= 0:
            return 0.0
        return self.total_assertions / self.total_test_functions

    @property
    def valid_test_ratio(self) -> float:
        """valid_test_functions / total_test_functions -- the fraction of
        non-skipped test functions that have at least one real assertion,
        as opposed to a "vanity" test (an empty body, or one whose only
        assertions are tautological, e.g. `assert True`). 0.0 when there
        are no non-skipped test functions to compute a ratio from."""
        if self.total_test_functions <= 0:
            return 0.0
        return self.valid_test_functions / self.total_test_functions
