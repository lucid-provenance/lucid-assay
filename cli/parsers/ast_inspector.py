"""
Backward-compatible shim. The AST assertion integrity engine moved to
`cli/parsers/ast/` (a language-agnostic registry/dispatcher covering
Python, TypeScript/JavaScript, Go, and Java -- see that package's
docstring) as part of the multi-language rollout. This module re-exports
the same public names from the new location so existing imports
(`from cli.parsers.ast_inspector import inspect_test_suite`) keep working
unmodified.

New code should import from `cli.parsers.ast` directly.
"""
from __future__ import annotations

from .ast import (
    FileInspectionResult,
    LanguageMetrics,
    TestFunctionMetrics,
    TestSuiteMetrics,
    inspect_test_suite,
)

__all__ = [
    "FileInspectionResult",
    "LanguageMetrics",
    "TestFunctionMetrics",
    "TestSuiteMetrics",
    "inspect_test_suite",
]
