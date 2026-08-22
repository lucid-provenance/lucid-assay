"""
Python assertion visitor -- the reference-standard implementation. Walks
`test_*`/`*_test` functions (including `unittest.TestCase` methods) via the
stdlib `ast` module and distinguishes real assertions from bogus ones.

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
  - Skipped tests (`@pytest.mark.skip`/`@pytest.mark.skipif`/
    `@unittest.skip*`) being counted as zero-assertion rather than
    tracked separately
"""
from __future__ import annotations

import ast
import re
from typing import Any, List, Optional, Tuple

from .common import FileInspectionResult, TestFunctionMetrics

LANGUAGE = "python"

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
# (`MockObj.assert_called()` defined as a no-op) -- either way it must not be
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

# Decorator names (bare or dotted-suffix) that mark a test as skipped/
# disabled without it ever executing.
_SKIP_DECORATOR_NAMES = {"skip", "skipif", "skipUnless", "skipIf"}


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


def _fold_unary_op(expr: ast.UnaryOp) -> Tuple[bool, Any]:
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


def _fold_container_literal(expr: ast.expr) -> Tuple[bool, Any]:
    """Folds an ast.List/Tuple/Set literal of themselves-foldable elements."""
    values = []
    for elt in expr.elts:  # type: ignore[attr-defined]
        ok, val = _fold_constant(elt)
        if not ok:
            return False, None
        values.append(val)
    container = {ast.List: list, ast.Tuple: tuple, ast.Set: set}[type(expr)]
    try:
        return True, container(values)
    except TypeError:
        return False, None


def _fold_dict_literal(expr: ast.Dict) -> Tuple[bool, Any]:
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


def _fold_bool_op(expr: ast.BoolOp) -> Tuple[bool, Any]:
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


def _fold_compare_step(op: ast.cmpop, current: Any, right: Any) -> Tuple[bool, Any]:
    """One step of a chained comparison (`a OP b OP c ...`): returns
    (ok, step_result) for a single (op, current, right) triple. ok=False
    for both an unsupported operator and a TypeError during evaluation
    (e.g. comparing incompatible types) -- the caller treats either the
    same way, as "can't fold"."""
    try:
        if isinstance(op, ast.Eq):
            return True, current == right
        if isinstance(op, ast.NotEq):
            return True, current != right
        if isinstance(op, ast.In):
            return True, current in right
        if isinstance(op, ast.NotIn):
            return True, current not in right
    except TypeError:
        return False, None
    return False, None


def _fold_compare(expr: ast.Compare) -> Tuple[bool, Any]:
    ok, current = _fold_constant(expr.left)
    if not ok:
        return False, None
    overall = True
    for op, comparator in zip(expr.ops, expr.comparators):
        ok, right = _fold_constant(comparator)
        if not ok:
            return False, None
        ok, step = _fold_compare_step(op, current, right)
        if not ok:
            return False, None
        overall = overall and step
        current = right
    return True, overall


def _fold_constant(expr: ast.expr) -> Tuple[bool, Any]:
    """Best-effort compile-time evaluation of `expr`, restricted to
    operations that are safe and meaningful without executing any code:
    literal constants, literal list/tuple/set/dict containers (of
    themselves-foldable elements), `not`/unary +/-, `and`/`or`, and
    Eq/NotEq/In/NotIn comparisons.

    Returns (True, value) if `expr` folds to a concrete Python value, or
    (False, None) if it depends on anything we can't prove at parse time
    (a name, a call, an unsupported operator, ...). Deliberately does NOT
    fold arithmetic (`2 - 1`) or `is`/`is not` -- those require either real
    evaluation semantics or aren't safe to approximate with the folded
    value's Python identity, and are conservatively left as "real" checks.

    Dispatches by node type to a same-named `_fold_*` helper per case,
    each handling exactly one AST node kind (see each helper's docstring).
    """
    if isinstance(expr, ast.Constant):
        return True, expr.value
    if isinstance(expr, ast.UnaryOp):
        return _fold_unary_op(expr)
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return _fold_container_literal(expr)
    if isinstance(expr, ast.Dict):
        return _fold_dict_literal(expr)
    if isinstance(expr, ast.BoolOp):
        return _fold_bool_op(expr)
    if isinstance(expr, ast.Compare):
        return _fold_compare(expr)
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


def _decorator_name(dec: ast.expr) -> Optional[str]:
    """Returns the trailing name of a decorator expression, however it's
    invoked: `@skip`, `@skip("reason")`, `@pytest.mark.skip`,
    `@pytest.mark.skipif(cond)`, `@unittest.skip(...)`."""
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _is_skip_decorated(decorator_list: List[ast.expr]) -> bool:
    return any(_decorator_name(dec) in _SKIP_DECORATOR_NAMES for dec in decorator_list)


class _TestBodyVisitor(ast.NodeVisitor):
    """Walks the *body* of a single test function/method, tallying real vs.
    tautological assertions.

    Deliberately scoped: this is not `ast.walk`. A nested function/lambda/
    class defined inside the test body is a separate lexical scope whose
    contents are never proven to execute (or to execute with the values
    visible at the definition site), so traversal stops there rather than
    crediting/blaming the outer test for what's inside. Dead `if` branches
    and `try` bodies guarded by an assertion-swallowing `except` are pruned
    the same way -- statically unreachable-as-a-check code is not scanned.
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
                # actually exercises the code under test -- nothing raises,
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
                # an unverifiable custom no-op stand-in) -- not credited.
            elif _is_tautological_assert_call(node, method):
                self.tautological_count += 1
            else:
                self.assertion_count += 1
        elif _is_matcher_expectation_call(node) or _is_assert_that_call(node):
            self.assertion_count += 1
        self.generic_visit(node)


def _analyze_function(node: ast.AST, filename: str, class_skipped: bool = False) -> TestFunctionMetrics:
    visitor = _TestBodyVisitor()
    for stmt in node.body:  # type: ignore[attr-defined]
        visitor.visit(stmt)

    return TestFunctionMetrics(
        name=node.name,  # type: ignore[attr-defined]
        file=filename,
        lineno=node.lineno,  # type: ignore[attr-defined]
        language=LANGUAGE,
        assertion_count=visitor.assertion_count,
        tautological_count=visitor.tautological_count,
        is_empty_body=_is_empty_body(node.body),  # type: ignore[attr-defined]
        is_skipped=class_skipped or _is_skip_decorated(node.decorator_list),  # type: ignore[attr-defined]
    )


class _TestFunctionVisitor(ast.NodeVisitor):
    """Discovers every `test_*`/`*_test` function or method in a module,
    including ones nested inside `unittest.TestCase` classes, and hands each
    one to `_analyze_function` for scoped assertion counting."""

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.functions: List[TestFunctionMetrics] = []
        # Tracks whether the innermost enclosing class was itself
        # `@skip`-decorated (`@unittest.skip(...)` on a `TestCase`
        # subclass disables every method inside it, not just ones
        # individually decorated) -- a stack rather than a single bool
        # since class bodies can nest.
        self._class_skip_stack: List[bool] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_skip_stack.append(_is_skip_decorated(node.decorator_list))
        self.generic_visit(node)
        self._class_skip_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle(node)

    def _handle(self, node: ast.AST) -> None:
        if _is_test_function_name(node.name):  # type: ignore[attr-defined]
            class_skipped = any(self._class_skip_stack)
            self.functions.append(_analyze_function(node, self.filename, class_skipped))
        # Deliberately do not descend into the function's own body here: a
        # `def` nested inside it is a separate lexical scope to discover
        # test functions in, not a sibling to enumerate at this level.
        # `unittest.TestCase` methods are still found via visit_ClassDef
        # above, which keeps walking into class bodies (while tracking
        # class-level skip decoration for everything found inside).


class PythonAssertionVisitor:
    """Registry entry for `.py` test files. See module docstring."""

    language = LANGUAGE

    def matches(self, path: str) -> bool:
        return bool(_TEST_FILENAME_RE.match(_basename(path)))

    def inspect_file(self, path: str) -> FileInspectionResult:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except OSError as exc:
            return FileInspectionResult(path=path, language=LANGUAGE, parse_error=str(exc))

        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError as exc:
            return FileInspectionResult(path=path, language=LANGUAGE, parse_error=f"SyntaxError: {exc}")

        visitor = _TestFunctionVisitor(filename=path)
        visitor.visit(tree)
        return FileInspectionResult(path=path, language=LANGUAGE, test_functions=visitor.functions)


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]
