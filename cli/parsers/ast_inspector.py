"""
AST assertion integrity engine: walks Python test files to measure how much
of a test suite is backed by real assertions versus bogus/tautological ones
or empty stand-in bodies.

Hardened against:
  - Unparseable test files (SyntaxError) short-circuiting the whole scan
  - Self-referential/tautological assertions masquerading as real checks
    (`assert True`, `assert 1 == 1`, `assert not False`,
    `self.assertTrue(True)`, `self.assertEqual(x, x)`)
  - Empty test bodies (`pass`-only / docstring-only / `...`-only) being
    counted as exercised coverage
  - Walking into vendor/venv/build directories during repo-wide discovery
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

# Directories skipped during repo-wide test discovery; matched by basename.
_SKIP_DIR_NAMES = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".tox",
    "site-packages",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".eggs",
}

_TEST_FILENAME_RE = re.compile(r"^(test_.*\.py|.*_test\.py)$")
_TEST_FUNC_NAME_RE_PREFIX = re.compile(r"^test_")
_TEST_FUNC_NAME_RE_SUFFIX = re.compile(r"_test$")

# unittest-style assertion methods we recognize as real checks when NOT
# matched by a tautology heuristic below (assertTrue/assertFalse/assertEqual
# with self-referential/literal-constant args, etc).
_TAUTOLOGICAL_BOOL_METHODS = {"assertTrue", "assertFalse"}
_TAUTOLOGICAL_EQ_METHODS = {"assertEqual", "assertIs"}


@dataclass
class TestFunctionMetrics:
    __test__ = False
    name: str
    file: str
    lineno: int
    assertion_count: int = 0
    tautological_count: int = 0
    is_empty_body: bool = False


@dataclass
class FileInspectionResult:
    __test__ = False
    path: str
    test_functions: List[TestFunctionMetrics] = field(default_factory=list)
    parse_error: Optional[str] = None


@dataclass
class TestSuiteMetrics:
    __test__ = False
    files_scanned: int = 0
    total_test_functions: int = 0
    total_assertions: int = 0
    tautological_assertions: int = 0
    empty_test_bodies: int = 0
    files: List[FileInspectionResult] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)

    @property
    def assertion_density(self) -> float:
        if self.total_test_functions <= 0:
            return 0.0
        return self.total_assertions / self.total_test_functions


def _is_test_function_name(name: str) -> bool:
    """Matches the `test_*` / `*_test` naming convention required by the task."""
    return bool(_TEST_FUNC_NAME_RE_PREFIX.match(name)) or bool(_TEST_FUNC_NAME_RE_SUFFIX.search(name))


def _is_docstring_stmt(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)


def _is_ellipsis_stmt(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis


def _is_empty_body(body: List[ast.stmt]) -> bool:
    """A body is "empty" if, once docstrings are discounted, it contains
    nothing but `pass` and/or `...` placeholders (or nothing at all)."""
    meaningful = [stmt for stmt in body if not _is_docstring_stmt(stmt)]
    if not meaningful:
        return True
    return all(isinstance(stmt, ast.Pass) or _is_ellipsis_stmt(stmt) for stmt in meaningful)


def _same_expr(a: ast.expr, b: ast.expr) -> bool:
    """Structural equality: catches both literal duplication (`1 == 1`) and
    self-comparison (`x == x`)."""
    return ast.dump(a) == ast.dump(b)


def _is_tautological_test_expr(test: ast.expr) -> bool:
    """`assert True`, `assert not False`, `assert 1 == 1`, `assert x == x`."""
    if isinstance(test, ast.Constant) and test.value is True:
        return True

    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        operand = test.operand
        if isinstance(operand, ast.Constant) and operand.value is False:
            return True

    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
        left, right = test.left, test.comparators[0]
        if _same_expr(left, right):
            return True
        if (
            isinstance(left, ast.Constant)
            and isinstance(right, ast.Constant)
            and type(left.value) is type(right.value)
            and left.value == right.value
        ):
            return True

    return False


def _assert_method_name(call: ast.Call) -> Optional[str]:
    """Returns the method name (e.g. "assertTrue") for a `<obj>.assert*(...)`
    call, or None if `call` isn't one."""
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr.startswith("assert") and func.attr != "assert":
        return func.attr
    return None


def _is_tautological_assert_call(call: ast.Call, method: str) -> bool:
    """`self.assertTrue(True)`, `self.assertFalse(False)`, `self.assertEqual(x, x)`."""
    if method in _TAUTOLOGICAL_BOOL_METHODS and call.args:
        arg = call.args[0]
        if isinstance(arg, ast.Constant):
            if method == "assertTrue" and arg.value is True:
                return True
            if method == "assertFalse" and arg.value is False:
                return True
        if isinstance(arg, ast.Compare) and _is_tautological_test_expr(arg):
            return True

    if method in _TAUTOLOGICAL_EQ_METHODS and len(call.args) >= 2:
        if _same_expr(call.args[0], call.args[1]):
            return True

    return False


def _is_pytest_raises_or_warns(call: ast.Call) -> bool:
    """Matches `pytest.raises(...)` / `pytest.warns(...)`, however they're
    reached (directly or via `with`), including a namespaced import like
    `some_pkg.pytest.raises`."""
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr in ("raises", "warns")):
        return False

    base = func.value
    if isinstance(base, ast.Name) and base.id == "pytest":
        return True
    if isinstance(base, ast.Attribute) and base.attr == "pytest":
        return True
    return False


def _analyze_function(node: ast.AST, filename: str) -> TestFunctionMetrics:
    assertion_count = 0
    tautological_count = 0

    for sub in ast.walk(node):
        if isinstance(sub, ast.Assert):
            if _is_tautological_test_expr(sub.test):
                tautological_count += 1
            else:
                assertion_count += 1
            continue

        if isinstance(sub, ast.Call):
            method = _assert_method_name(sub)
            if method is not None:
                if _is_tautological_assert_call(sub, method):
                    tautological_count += 1
                else:
                    assertion_count += 1
            elif _is_pytest_raises_or_warns(sub):
                assertion_count += 1

    return TestFunctionMetrics(
        name=node.name,  # type: ignore[attr-defined]
        file=filename,
        lineno=node.lineno,  # type: ignore[attr-defined]
        assertion_count=assertion_count,
        tautological_count=tautological_count,
        is_empty_body=_is_empty_body(node.body),  # type: ignore[attr-defined]
    )


class _TestFunctionVisitor(ast.NodeVisitor):
    """Collects metrics for every `test_*`/`*_test` function or method in a
    module, including ones nested inside `unittest.TestCase` classes."""

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.functions: List[TestFunctionMetrics] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle(node)

    def _handle(self, node: ast.AST) -> None:
        if _is_test_function_name(node.name):  # type: ignore[attr-defined]
            self.functions.append(_analyze_function(node, self.filename))
        self.generic_visit(node)


def _inspect_file(path: str) -> FileInspectionResult:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError as exc:
        return FileInspectionResult(path=path, parse_error=str(exc))

    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return FileInspectionResult(path=path, parse_error=f"SyntaxError: {exc}")

    visitor = _TestFunctionVisitor(filename=path)
    visitor.visit(tree)
    return FileInspectionResult(path=path, test_functions=visitor.functions)


def _discover_test_files(repo_dir: str) -> List[str]:
    matches: List[str] = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIR_NAMES and not d.startswith(".")]
        for fname in files:
            if _TEST_FILENAME_RE.match(fname):
                matches.append(os.path.join(root, fname))
    return sorted(matches)


def inspect_test_suite(repo_dir: str, target_files: Optional[List[str]] = None) -> TestSuiteMetrics:
    """Aggregates assertion-integrity metrics across a test suite.

    If `target_files` is given, only those files are inspected (paths may be
    absolute or relative to `repo_dir`) — useful for scoping the scan to
    diff-touched test files. Otherwise every `test_*.py`/`*_test.py` file
    under `repo_dir` is discovered and scanned.
    """
    if target_files is not None:
        candidate_paths = [
            path if os.path.isabs(path) else os.path.join(repo_dir, path) for path in target_files
        ]
    else:
        candidate_paths = _discover_test_files(repo_dir)

    metrics = TestSuiteMetrics()
    for path in candidate_paths:
        result = _inspect_file(path)
        metrics.files.append(result)
        metrics.files_scanned += 1

        if result.parse_error is not None:
            metrics.parse_errors.append(f"{path}: {result.parse_error}")
            continue

        for fn in result.test_functions:
            metrics.total_test_functions += 1
            metrics.total_assertions += fn.assertion_count
            metrics.tautological_assertions += fn.tautological_count
            if fn.is_empty_body:
                metrics.empty_test_bodies += 1

    return metrics
