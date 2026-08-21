"""
AST assertion integrity engine: walks Python test files to measure how much
of a test suite is backed by real assertions versus bogus/tautological ones
or empty stand-in bodies.

Hardened against:
  - Unparseable test files (SyntaxError) short-circuiting the whole scan
  - Self-referential/tautological assertions masquerading as real checks
    (`assert True`, `assert 1 == 1`, `assert not False`, `assert not not True`,
    `assert False or True`, `self.assertTrue(True)`, `self.assertEqual(x, x)`,
    `x is x`, `"a" in "abc"`)
  - Bare non-boolean literal/collection assertions that always pass trivially
    (`assert [1, 2]`, `assert "string"`, `assert 123`)
  - Empty test bodies (`pass`-only / docstring-only / `...`-only) being
    counted as exercised coverage, including empty `with pytest.raises(...)`/
    `with pytest.warns(...)` blocks
  - Assertions that are statically unreachable: inside a dead `if False:`
    branch, inside a nested function/lambda/class defined in the test body
    (never proven to execute), or inside a `try:` whose `except
    (AssertionError, ...): pass` silently swallows the failure
  - Mock typo bypasses (`mock.assert_called()` instead of a real
    `unittest.mock` assertion method) being credited as real checks
  - Walking into vendor/venv/build directories during repo-wide discovery
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple

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

# unittest.mock's real assertion API (snake_case, unlike unittest.TestCase's
# camelCase `assert*` methods). Anything snake_case starting with `assert_`
# that ISN'T in this set is either a typo (`mock.assert_called()` when the
# author meant `assert_called_once()`) or an unverifiable custom stand-in
# (`MockObj.assert_called()` defined as a no-op) — either way it must not be
# credited as a real check just because it's spelled like one.
_MOCK_ASSERT_ALLOWLIST = {
    "assert_called_once",
    "assert_called_with",
    "assert_called_once_with",
    "assert_any_call",
    "assert_has_calls",
    "assert_not_called",
}

# except-handler types that indicate a handler is positioned to swallow a
# failed assertion.
_ASSERTION_SWALLOWING_EXCEPTION_NAMES = {"AssertionError", "Exception", "BaseException"}


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
    self-comparison (`x == x`), regardless of whether `a`/`b` are distinct
    AST node instances."""
    return ast.dump(a) == ast.dump(b)


def _fold_constant(expr: ast.expr) -> Tuple[bool, Any]:
    """Best-effort compile-time evaluation of `expr`, restricted to
    operations that are safe and meaningful without executing any code:
    literal constants, literal list/tuple/set/dict containers (of
    themselves-foldable elements), `not`/unary +/-, `and`/`or`, and
    Eq/NotEq/In/NotIn comparisons.

    Returns (True, value) if `expr` folds to a concrete Python value, or
    (False, None) if it depends on anything we can't prove at parse time
    (a name, a call, an unsupported operator, ...). Deliberately does NOT
    fold arithmetic (`2 - 1`) or `is`/`is not` — those require either real
    evaluation semantics or aren't safe to approximate with the folded
    value's Python identity, and are conservatively left as "real" checks.
    """
    if isinstance(expr, ast.Constant):
        return True, expr.value

    if isinstance(expr, ast.UnaryOp):
        ok, val = _fold_constant(expr.operand)
        if not ok:
            return False, None
        if isinstance(expr.op, ast.Not):
            return True, not val
        if isinstance(expr.op, ast.UAdd):
            return True, +val
        if isinstance(expr.op, ast.USub):
            return True, -val
        return False, None

    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        values = []
        for elt in expr.elts:
            ok, val = _fold_constant(elt)
            if not ok:
                return False, None
            values.append(val)
        container = {ast.List: list, ast.Tuple: tuple, ast.Set: set}[type(expr)]
        try:
            return True, container(values)
        except TypeError:
            return False, None

    if isinstance(expr, ast.Dict):
        result: dict = {}
        for key_expr, val_expr in zip(expr.keys, expr.values):
            if key_expr is None:  # `**unpacking` inside the literal
                return False, None
            ok_k, key = _fold_constant(key_expr)
            ok_v, val = _fold_constant(val_expr)
            if not (ok_k and ok_v):
                return False, None
            try:
                result[key] = val
            except TypeError:
                return False, None
        return True, result

    if isinstance(expr, ast.BoolOp):
        values = []
        for sub in expr.values:
            ok, val = _fold_constant(sub)
            if not ok:
                return False, None
            values.append(val)
        if isinstance(expr.op, ast.And):
            result = values[0]
            for val in values[1:]:
                result = result and val
            return True, result
        if isinstance(expr.op, ast.Or):
            result = values[0]
            for val in values[1:]:
                result = result or val
            return True, result
        return False, None

    if isinstance(expr, ast.Compare):
        ok, current = _fold_constant(expr.left)
        if not ok:
            return False, None
        overall = True
        for op, comparator in zip(expr.ops, expr.comparators):
            ok, right = _fold_constant(comparator)
            if not ok:
                return False, None
            try:
                if isinstance(op, ast.Eq):
                    step = current == right
                elif isinstance(op, ast.NotEq):
                    step = current != right
                elif isinstance(op, ast.In):
                    step = current in right
                elif isinstance(op, ast.NotIn):
                    step = current not in right
                else:
                    return False, None
            except TypeError:
                return False, None
            overall = overall and step
            current = right
        return True, overall

    return False, None


def _handler_catches_assertion_error(handler: ast.ExceptHandler) -> bool:
    """True if this `except` clause is positioned to catch AssertionError:
    a bare `except:`, `except AssertionError:`, `except Exception:`, or a
    tuple form containing one of those (`except (AssertionError, ValueError):`)."""
    if handler.type is None:
        return True

    candidates = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    for candidate in candidates:
        if isinstance(candidate, ast.Name) and candidate.id in _ASSERTION_SWALLOWING_EXCEPTION_NAMES:
            return True
        if isinstance(candidate, ast.Attribute) and candidate.attr in _ASSERTION_SWALLOWING_EXCEPTION_NAMES:
            return True
    return False


def _is_tautological_test_expr(test: ast.expr) -> bool:
    """`assert True`, `assert not not True`, `assert False or True`,
    `assert 1 == 1`, `assert x == x`, `assert x is x`, `assert "a" in "abc"`,
    `assert [1, 2]`, `assert "string"`, `assert 123`."""
    # Self-referential comparisons: tautologically true regardless of the
    # runtime value of the (possibly non-literal) operand.
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], (ast.Eq, ast.Is, ast.In)):
        if _same_expr(test.left, test.comparators[0]):
            return True

    # Anything that folds to a concrete, truthy compile-time value is a
    # hardcoded no-op assertion: it can never meaningfully fail, whether
    # it's `True`, `not False`, `0 == 0`, `"a" in "abc"`, or a bare literal
    # constant/collection (`[1, 2]`, `"string"`, `123`).
    ok, value = _fold_constant(test)
    return bool(ok and value)


def _assert_method_name(call: ast.Call) -> Optional[str]:
    """Returns the method name (e.g. "assertTrue") for a `<obj>.assert*(...)`
    call, or None if `call` isn't one."""
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr.startswith("assert") and func.attr != "assert":
        return func.attr
    return None


def _is_mock_style_name(name: str) -> bool:
    """unittest.mock's assertion API is snake_case (`assert_called_once`);
    unittest.TestCase's is camelCase (`assertEqual`). Used to route
    snake_case names through the mock allowlist instead of the
    tautology-aware unittest-method handling."""
    return "_" in name


def _is_tautological_assert_call(call: ast.Call, method: str) -> bool:
    """`self.assertTrue(True)`, `self.assertFalse(False)`,
    `self.assertTrue(123)` (any hardcoded truthy/falsy literal that makes
    the call trivially pass), and `self.assertEqual(x, x)`."""
    if method in _TAUTOLOGICAL_BOOL_METHODS and call.args:
        arg = call.args[0]
        ok, value = _fold_constant(arg)
        if ok:
            if method == "assertTrue" and value:
                return True
            if method == "assertFalse" and not value:
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


def _is_matcher_expectation_call(call: ast.Call) -> bool:
    """`expect(x).to_equal(...)` / `expect(x).to_be_true()`-style fluent
    matcher idiom (Jasmine/Chai-flavored expectation libraries)."""
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr.startswith("to_")):
        return False

    base = func.value
    if not isinstance(base, ast.Call):
        return False
    base_func = base.func
    if isinstance(base_func, ast.Name) and base_func.id == "expect":
        return True
    if isinstance(base_func, ast.Attribute) and base_func.attr == "expect":
        return True
    return False


def _is_assert_that_call(call: ast.Call) -> bool:
    """`assert_that(x, matcher)` (PyHamcrest-style), invoked as a bare
    function or via a module attribute (e.g. `hamcrest.assert_that(...)`)."""
    func = call.func
    if isinstance(func, ast.Name) and func.id == "assert_that":
        return True
    if isinstance(func, ast.Attribute) and func.attr == "assert_that":
        return True
    return False


class _TestBodyVisitor(ast.NodeVisitor):
    """Walks the *body* of a single test function/method, tallying real vs.
    tautological assertions.

    Deliberately scoped: this is not `ast.walk`. A nested function/lambda/
    class defined inside the test body is a separate lexical scope whose
    contents are never proven to execute (or to execute with the values
    visible at the definition site), so traversal stops there rather than
    crediting/blaming the outer test for what's inside. Dead `if` branches
    and `try` bodies guarded by an assertion-swallowing `except` are pruned
    the same way — statically unreachable-as-a-check code is not scanned.
    """

    def __init__(self) -> None:
        self.assertion_count = 0
        self.tautological_count = 0

    # -- scope boundaries: do not descend -------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    # -- statically prunable control flow -------------------------------------

    def visit_If(self, node: ast.If) -> None:
        ok, value = _fold_constant(node.test)
        if ok:
            for stmt in (node.body if value else node.orelse):
                self.visit(stmt)
            return
        # Not statically decidable: both branches are potentially live.
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_Try(self, node: ast.Try) -> None:
        swallows_assertions = any(
            _handler_catches_assertion_error(handler) and _is_empty_body(handler.body)
            for handler in node.handlers
        )
        if not swallows_assertions:
            for stmt in node.body:
                self.visit(stmt)
        for handler in node.handlers:
            for stmt in handler.body:
                self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)
        for stmt in node.finalbody:
            self.visit(stmt)

    def visit_With(self, node: ast.With) -> None:
        self._handle_with(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._handle_with(node)

    def _handle_with(self, node) -> None:
        for item in node.items:
            call = item.context_expr
            if isinstance(call, ast.Call) and _is_pytest_raises_or_warns(call):
                # An empty `with pytest.raises(...): pass` body never
                # actually exercises the code under test — nothing raises,
                # so nothing is actually verified.
                if not _is_empty_body(node.body):
                    self.assertion_count += 1
        for stmt in node.body:
            self.visit(stmt)

    # -- the actual assertion sites --------------------------------------------

    def visit_Assert(self, node: ast.Assert) -> None:
        if _is_tautological_test_expr(node.test):
            self.tautological_count += 1
        else:
            self.assertion_count += 1

    def visit_Call(self, node: ast.Call) -> None:
        method = _assert_method_name(node)
        if method is not None:
            if _is_mock_style_name(method):
                if method in _MOCK_ASSERT_ALLOWLIST:
                    self.assertion_count += 1
                # else: unrecognized snake_case `assert_*` method (typo, or
                # an unverifiable custom no-op stand-in) — not credited.
            elif _is_tautological_assert_call(node, method):
                self.tautological_count += 1
            else:
                self.assertion_count += 1
        elif _is_matcher_expectation_call(node) or _is_assert_that_call(node):
            self.assertion_count += 1
        self.generic_visit(node)


def _analyze_function(node: ast.AST, filename: str) -> TestFunctionMetrics:
    visitor = _TestBodyVisitor()
    for stmt in node.body:  # type: ignore[attr-defined]
        visitor.visit(stmt)

    return TestFunctionMetrics(
        name=node.name,  # type: ignore[attr-defined]
        file=filename,
        lineno=node.lineno,  # type: ignore[attr-defined]
        assertion_count=visitor.assertion_count,
        tautological_count=visitor.tautological_count,
        is_empty_body=_is_empty_body(node.body),  # type: ignore[attr-defined]
    )


class _TestFunctionVisitor(ast.NodeVisitor):
    """Discovers every `test_*`/`*_test` function or method in a module,
    including ones nested inside `unittest.TestCase` classes, and hands each
    one to `_analyze_function` for scoped assertion counting."""

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
        # Deliberately do not descend into the function's own body here: a
        # `def` nested inside it is a separate lexical scope to discover
        # test functions in, not a sibling to enumerate at this level.
        # `unittest.TestCase` methods are still found because we never
        # override visit_ClassDef, so the default traversal keeps walking
        # into class bodies.


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
