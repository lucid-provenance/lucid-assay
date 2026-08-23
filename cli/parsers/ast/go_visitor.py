"""
Go assertion visitor (`testing.T` + `testify`), via Tree-sitter's
`tree-sitter-go` grammar.

Discovery: `*_test.go` -- Go's own compiler/tooling convention, not a
heuristic.

Test functions: top-level `func TestXxx(t *testing.T) { ... }`
declarations (the `go test` convention: exported, `Test`-prefixed, single
`*testing.T` parameter).

Hardened against:
  - `t.Skip(...)`/`t.SkipNow()`/`t.Skipf(...)` used as the test's very
    first statement (the "temporarily disable this test" idiom) being
    counted as a zero-assertion failure rather than tracked as skipped.
    A *conditional* skip further down (`if testing.Short() { t.Skip() }`)
    is deliberately NOT treated as whole-test-skipped -- the common path
    still runs and asserts, and flagging it would hide real gaming.
  - Tautological testify calls: `assert.True(t, true)`,
    `assert.Equal(t, 1, 1)`, `require.False(t, false)` -- argument
    indices are offset by the leading `t` parameter testify's API takes.
  - `assert`/`require` package calls being confused with a same-named
    local variable's `.Equal`/`.True` methods is a known false-positive
    risk this module accepts (Tree-sitter has no type information), same
    as every other language visitor here trusts identifier conventions
    over full semantic resolution.
"""
from __future__ import annotations

from typing import Any, List, Optional, Tuple

from tree_sitter import Node

from ._ts_util import basename, call_args, get_parser, literal_or_structural_equal, node_text
from .common import FileInspectionResult, TestFunctionMetrics

LANGUAGE = "go"

_TESTIFY_PACKAGES = {"assert", "require"}
_FAILURE_METHODS = {"Error", "Errorf", "Fatal", "Fatalf", "Fail", "FailNow"}
_SKIP_METHODS = {"Skip", "Skipf", "SkipNow"}


def _go_language():
    import tree_sitter_go as tsgo

    return tsgo.language()


def _fold_number_literal(node: Node, src: bytes) -> Tuple[bool, Any]:
    text = node_text(node, src)
    try:
        return True, (int(text, 0) if node.type == "int_literal" else float(text))
    except ValueError:
        return False, None


def _fold_interpreted_string(node: Node, src: bytes) -> Tuple[bool, Any]:
    frags = [c for c in node.children if c.type == "interpreted_string_literal_content"]
    return True, "".join(node_text(f, src) for f in frags)


def _fold_unary_expression(node: Node, src: bytes) -> Tuple[bool, Any]:
    op = node_text(node.children[0], src) if node.children else ""
    operand = node.child_by_field_name("operand")
    ok, val = _fold_go_literal(operand, src)
    if ok and op == "!":
        return True, not val
    return False, None


def _fold_parenthesized(node: Node, src: bytes) -> Tuple[bool, Any]:
    inner = [c for c in node.children if c.is_named]
    return _fold_go_literal(inner[0], src) if inner else (False, None)


def _fold_go_literal(node: Optional[Node], src: bytes) -> Tuple[bool, Any]:
    if node is None:
        return False, None
    if node.type == "true":
        return True, True
    if node.type == "false":
        return True, False
    if node.type == "nil":
        return True, None
    if node.type in ("int_literal", "float_literal"):
        return _fold_number_literal(node, src)
    if node.type == "interpreted_string_literal":
        return _fold_interpreted_string(node, src)
    if node.type == "raw_string_literal":
        return True, node_text(node, src).strip("`")
    if node.type == "unary_expression":
        return _fold_unary_expression(node, src)
    if node.type == "parenthesized_expression":
        return _fold_parenthesized(node, src)
    return False, None


def _is_test_function(node: Node, src: bytes) -> Optional[str]:
    """Returns the parameter name bound to `*testing.T` if `node` is a
    `func TestXxx(t *testing.T)` declaration, else None."""
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return None
    name = node_text(name_node, src)
    if not (name.startswith("Test") and len(name) > 4 and name[4].isupper()):
        return None
    params = node.child_by_field_name("parameters")
    if params is None:
        return None
    for decl in params.children:
        if decl.type != "parameter_declaration":
            continue
        type_node = decl.child_by_field_name("type")
        # Exact match on the pointer type text, not a substring check --
        # "testing.T" is also a substring of "testing.TB" (the shared
        # Test/Benchmark helper interface used by `func Helper(tb
        # testing.TB)`-style reuse helpers, which `go test` never invokes
        # directly and must not be misclassified as a real test).
        if type_node is not None and node_text(type_node, src).strip() == "*testing.T":
            ident = decl.child_by_field_name("name")
            return node_text(ident, src) if ident is not None else "t"
    return None


def _classify_testify_call(node: Node, method: str, src: bytes) -> bool:
    """Returns is_tautological for a recognized `assert.*`/`require.*`
    testify call. Argument indices are offset by 1: testify's API takes
    the leading `t *testing.T` as args[0]."""
    args = call_args(node.child_by_field_name("arguments"))
    taut = False
    if method == "True" and len(args) >= 2:
        ok, val = _fold_go_literal(args[1], src)
        taut = ok and bool(val)
    elif method == "False" and len(args) >= 2:
        ok, val = _fold_go_literal(args[1], src)
        taut = ok and not val
    elif method in ("Equal", "Same") and len(args) >= 3:
        taut = literal_or_structural_equal(args[1], args[2], src, _fold_go_literal)
    return taut


def _classify_call(node: Node, src: bytes) -> Optional[Tuple[bool, bool]]:
    """Returns (is_assertion, is_tautological) for a call_expression, or
    None if it isn't a recognized assertion/failure call."""
    func = node.child_by_field_name("function")
    if func is None or func.type != "selector_expression":
        return None
    base = func.child_by_field_name("operand")
    field = func.child_by_field_name("field")
    if base is None or field is None or base.type != "identifier":
        return None
    base_name = node_text(base, src)
    method = node_text(field, src)

    if base_name in _TESTIFY_PACKAGES:
        return True, _classify_testify_call(node, method, src)

    if method in _FAILURE_METHODS:
        return True, False

    return None


def _is_skip_call(node: Node, src: bytes) -> bool:
    func = node.child_by_field_name("function")
    if func is None or func.type != "selector_expression":
        return False
    field = func.child_by_field_name("field")
    return field is not None and node_text(field, src) in _SKIP_METHODS


def _block_statements(body: Node) -> List[Node]:
    """A Go `block`'s direct named child is a single `statement_list`
    wrapper (or none at all for an empty `{}`), not the statements
    themselves -- unwrap it to get the actual top-level statements."""
    for child in body.children:
        if child.type == "statement_list":
            return [c for c in child.children if c.is_named and c.type != "comment"]
    return []


def _first_meaningful_stmt(stmts: List[Node]) -> Optional[Node]:
    return stmts[0] if stmts else None


def _stmt_is_skip_call(stmt: Node, src: bytes) -> bool:
    if stmt.type != "expression_statement":
        return False
    call = stmt.children[0] if stmt.children else None
    return call is not None and call.type == "call_expression" and _is_skip_call(call, src)


class _BodyWalker:
    """Scoped assertion walker. Descends into `func_literal` bodies
    (`t.Run("case", func(t *testing.T) {...})`, goroutines) since Go's
    idiomatic table-driven-subtest pattern puts real assertions there and
    they do run as part of the test -- unlike Python's stray nested `def`,
    Go has no equivalent "declared but never invoked" footgun since
    `func_literal`s can't be declared standalone without immediately being
    used as a value."""

    def __init__(self) -> None:
        self.assertion_count = 0
        self.tautological_count = 0

    def walk(self, node: Node, src: bytes) -> None:
        if node.type == "call_expression":
            classified = _classify_call(node, src)
            if classified is not None:
                is_assertion, is_taut = classified
                if is_taut:
                    self.tautological_count += 1
                else:
                    self.assertion_count += 1
                return
        if node.type == "if_statement":
            # `if false { t.Error(...) }` (or `if true { ... } else { ... }`)
            # is statically dead/live -- prune to the branch that actually
            # runs rather than crediting an unreachable one, mirroring
            # python_visitor.py's visit_If.
            ok, value = _fold_go_literal(node.child_by_field_name("condition"), src)
            if ok:
                branch = node.child_by_field_name("consequence" if value else "alternative")
                if branch is not None:
                    self.walk(branch, src)
                return
        for child in node.children:
            self.walk(child, src)


def _collect_test_functions(node: Node, src: bytes, out: List[Tuple[Node, str]]) -> None:
    if node.type == "function_declaration":
        param_name = _is_test_function(node, src)
        if param_name is not None:
            out.append((node, param_name))
        return  # Go disallows nested func declarations, nothing more to find inside
    for child in node.children:
        _collect_test_functions(child, src, out)


def _analyze_test_function(node: Node, src: bytes, filename: str) -> TestFunctionMetrics:
    name_node = node.child_by_field_name("name")
    name = node_text(name_node, src)
    body = node.child_by_field_name("body")

    is_skipped = False
    is_empty = True
    walker = _BodyWalker()
    if body is not None:
        stmts = _block_statements(body)
        is_empty = len(stmts) == 0
        first = _first_meaningful_stmt(stmts)
        if first is not None and _stmt_is_skip_call(first, src):
            is_skipped = True
        for stmt in stmts:
            walker.walk(stmt, src)

    return TestFunctionMetrics(
        name=name,
        file=filename,
        lineno=node.start_point[0] + 1,
        language=LANGUAGE,
        assertion_count=walker.assertion_count,
        tautological_count=walker.tautological_count,
        is_empty_body=is_empty,
        is_skipped=is_skipped,
    )


class GoAssertionVisitor:
    """Registry entry for `*_test.go` files."""

    language = LANGUAGE

    def matches(self, path: str) -> bool:
        return basename(path).endswith("_test.go")

    def inspect_file(self, path: str) -> FileInspectionResult:
        try:
            with open(path, "rb") as f:
                src = f.read()
        except OSError as exc:
            return FileInspectionResult(path=path, language=LANGUAGE, parse_error=str(exc))

        try:
            parser = get_parser("go", _go_language)
            tree = parser.parse(src)
        except Exception as exc:  # pragma: no cover - grammar/runtime failure
            return FileInspectionResult(path=path, language=LANGUAGE, parse_error=f"ParseError: {exc}")

        found: List[Tuple[Node, str]] = []
        _collect_test_functions(tree.root_node, src, found)

        functions = [_analyze_test_function(node, src, path) for node, _param in found]
        return FileInspectionResult(path=path, language=LANGUAGE, test_functions=functions)
