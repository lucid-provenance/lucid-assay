"""
Java assertion visitor (JUnit 4/5, AssertJ, Hamcrest), via Tree-sitter's
`tree-sitter-java` grammar.

Discovery: `*Test.java`, `*Tests.java`, `*TestCase.java` -- the three
suffixes Maven Surefire/Gradle's default test-class matchers use.

Test methods: any `method_declaration` annotated `@Test` (JUnit 4's
`org.junit.Test` or JUnit 5's `org.junit.jupiter.api.Test` -- Tree-sitter
has no import resolution, so both are matched by annotation name alone,
same tradeoff every visitor here makes).

Hardened against:
  - `@Disabled` (JUnit 5) / `@Ignore` (JUnit 4) annotated methods being
    counted as executed, zero-assertion tests rather than tracked as
    skipped
  - Tautological assertions: `assertTrue(true)`, `assertEquals(1, 1)`,
    `assertThat(true).isTrue()`, `assertThat(x).isEqualTo(x)`
    (self-reference)
  - Double-counting an AssertJ fluent chain: `assertThat(x).isEqualTo(y)`
    is one assertion, not two just because `assertThat(x)` is itself a
    method call whose name starts with `assert` -- the chain is evaluated
    at its outermost (terminal) call and the inner `assertThat(...)` link
    is deliberately not re-visited
  - Hamcrest's non-chained 2-arg form (`assertThat(x, matcher)`) still
    being recognized: it's caught by the same "name starts with assert"
    rule as JUnit's static-import assertions, since it isn't a chain at all
"""
from __future__ import annotations

from typing import Any, List, Optional, Tuple

from tree_sitter import Node

from ._ts_util import basename, call_args, get_parser, literal_or_structural_equal, node_text
from .common import FileInspectionResult, TestFunctionMetrics

LANGUAGE = "java"

_TEST_SUFFIXES = ("Test.java", "Tests.java", "TestCase.java")
_TEST_ANNOTATIONS = {"Test", "ParameterizedTest", "RepeatedTest", "TestFactory", "TestTemplate"}
_SKIP_ANNOTATIONS = {"Disabled", "Ignore"}
_JUNIT_QUALIFIERS = {"Assertions", "Assert"}

_ASSERTJ_TRUE_TERMINALS = {"isTrue"}
_ASSERTJ_FALSE_TERMINALS = {"isFalse"}
_ASSERTJ_EQUALITY_TERMINALS = {"isEqualTo", "isSameAs"}

# node types the body walker will not descend into: nested type
# declarations (local/anonymous classes) that may define their own
# unrelated methods, never proven to execute as part of this test.
_SCOPE_BOUNDARY_TYPES = {"class_declaration", "interface_declaration", "enum_declaration"}


def _java_language():
    import tree_sitter_java as tsjava

    return tsjava.language()


def _fold_number_literal(node: Node, src: bytes) -> Tuple[bool, Any]:
    text = node_text(node, src).rstrip("lLfFdD").replace("_", "")
    try:
        return True, (int(text, 0) if "integer" in node.type else float(text))
    except ValueError:
        return False, None


def _fold_string_literal(node: Node, src: bytes) -> Tuple[bool, Any]:
    frags = [c for c in node.children if c.type == "string_fragment"]
    if frags:
        return True, "".join(node_text(f, src) for f in frags)
    return True, node_text(node, src).strip('"')


def _fold_unary_expression(node: Node, src: bytes) -> Tuple[bool, Any]:
    op = node_text(node.children[0], src) if node.children else ""
    operand = node.child_by_field_name("operand")
    ok, val = _fold_java_literal(operand, src)
    if ok and op == "!":
        return True, not val
    return False, None


def _fold_parenthesized(node: Node, src: bytes) -> Tuple[bool, Any]:
    inner = node.child_by_field_name("expression")
    if inner is None:
        named = [c for c in node.children if c.is_named]
        inner = named[0] if named else None
    return _fold_java_literal(inner, src)


def _fold_java_literal(node: Optional[Node], src: bytes) -> Tuple[bool, Any]:
    if node is None:
        return False, None
    if node.type == "true":
        return True, True
    if node.type == "false":
        return True, False
    if node.type == "null_literal":
        return True, None
    if node.type.endswith("_integer_literal") or node.type.endswith("_floating_point_literal"):
        return _fold_number_literal(node, src)
    if node.type == "string_literal":
        return _fold_string_literal(node, src)
    if node.type == "unary_expression":
        return _fold_unary_expression(node, src)
    if node.type == "parenthesized_expression":
        return _fold_parenthesized(node, src)
    return False, None


def _annotation_names(declaration: Node, src: bytes) -> List[str]:
    names: List[str] = []
    for child in declaration.children:
        if child.type != "modifiers":
            continue
        for ann in child.children:
            if ann.type not in ("marker_annotation", "annotation"):
                continue
            name_node = ann.child_by_field_name("name")
            if name_node is not None:
                # `@org.junit.Ignore` is legal (a fully-qualified annotation
                # reference) as well as the far more common bare `@Ignore`
                # after a static/type import -- match on the trailing
                # component either way.
                names.append(node_text(name_node, src).rsplit(".", 1)[-1])
    return names


def _trace_assertthat_arg(node: Optional[Node], src: bytes) -> Optional[Node]:
    """Walks a chain's `object` links back to a bare/qualified
    `assertThat(x)` call and returns `x`, or None if the chain doesn't
    originate there."""
    cur = node
    while cur is not None and cur.type == "method_invocation":
        name_node = cur.child_by_field_name("name")
        name = node_text(name_node, src) if name_node is not None else ""
        if name == "assertThat":
            args = call_args(cur.child_by_field_name("arguments"))
            return args[0] if args else None
        cur = cur.child_by_field_name("object")
    return None


def _classify_junit_style_assertion(name: str, obj: Optional[Node], args: List[Node], src: bytes) -> Optional[bool]:
    """Returns is_tautological for a bare/statically-qualified
    `assert*(...)` call (JUnit's `Assert`/`Assertions` or Hamcrest's
    non-chained `assertThat(x, matcher)`), or None if `name`/`obj` don't
    match that shape at all -- the caller then tries the AssertJ fluent
    chain instead, rather than treating "not a JUnit-qualified assert
    name" as "not an assertion"."""
    if not (name.startswith("assert") and name != "assert"):
        return None
    is_bare_or_qualified = obj is None or (obj.type == "identifier" and node_text(obj, src) in _JUNIT_QUALIFIERS)
    if not is_bare_or_qualified:
        return None

    taut = False
    if name == "assertTrue" and args:
        ok, val = _fold_java_literal(args[0], src)
        taut = ok and bool(val)
    elif name == "assertFalse" and args:
        ok, val = _fold_java_literal(args[0], src)
        taut = ok and not val
    elif name in ("assertEquals", "assertSame") and len(args) >= 2:
        taut = literal_or_structural_equal(args[0], args[1], src, _fold_java_literal)
    return taut


def _classify_assertj_chain(
    name: str, obj: Optional[Node], args: List[Node], src: bytes
) -> Optional[Tuple[bool, Optional[Node]]]:
    """Returns (is_tautological, subtree_to_skip) for an AssertJ fluent
    terminal call (`assertThat(x).isEqualTo(y)`, `.isTrue()`, ...), or
    None if `obj` doesn't trace back to an `assertThat(...)` receiver."""
    if obj is None:
        return None
    base_arg = _trace_assertthat_arg(obj, src)
    if base_arg is None:
        return None

    taut = False
    if name in _ASSERTJ_TRUE_TERMINALS:
        ok, val = _fold_java_literal(base_arg, src)
        taut = ok and bool(val)
    elif name in _ASSERTJ_FALSE_TERMINALS:
        ok, val = _fold_java_literal(base_arg, src)
        taut = ok and not val
    elif name in _ASSERTJ_EQUALITY_TERMINALS and args:
        taut = literal_or_structural_equal(base_arg, args[0], src, _fold_java_literal)
    # else: any other AssertJ/fluent terminal (isNotNull, hasSize,
    # contains, ...) still counts as a real assertion call (taut=False).
    return taut, obj


def _classify_method_invocation(node: Node, src: bytes) -> Optional[Tuple[bool, Optional[Node]]]:
    """Returns (is_tautological, subtree_to_skip) for a `method_invocation`
    that qualifies as an assertion call, else None. `subtree_to_skip` is
    the already-traced `object` chain link the caller should not re-walk
    (it's either the whole AssertJ receiver chain, already accounted for
    by this classification, or None when there's nothing to skip)."""
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return None
    name = node_text(name_node, src)
    obj = node.child_by_field_name("object")
    args = call_args(node.child_by_field_name("arguments"))

    junit_taut = _classify_junit_style_assertion(name, obj, args, src)
    if junit_taut is not None:
        return junit_taut, None

    return _classify_assertj_chain(name, obj, args, src)


class _BodyWalker:
    """Scoped assertion walker over one `@Test` method's body. Descends
    into lambda bodies (`assertThrows(Foo.class, () -> { ... })`) since
    those run synchronously as part of the assertion call itself, but not
    into a nested local/anonymous class's own method bodies."""

    def __init__(self) -> None:
        self.assertion_count = 0
        self.tautological_count = 0

    def walk(self, node: Node, src: bytes) -> None:
        if node.type in _SCOPE_BOUNDARY_TYPES:
            return
        if node.type == "method_invocation":
            classified = _classify_method_invocation(node, src)
            if classified is not None:
                is_taut, skip_subtree = classified
                if is_taut:
                    self.tautological_count += 1
                else:
                    self.assertion_count += 1
                for child in node.children:
                    if skip_subtree is not None and child == skip_subtree:
                        continue
                    self.walk(child, src)
                return
        if node.type == "if_statement":
            # `if (false) { assertTrue(...); }` is statically dead/live --
            # prune to the branch that actually runs, mirroring
            # python_visitor.py's visit_If.
            ok, value = _fold_java_literal(node.child_by_field_name("condition"), src)
            if ok:
                branch = node.child_by_field_name("consequence" if value else "alternative")
                if branch is not None:
                    self.walk(branch, src)
                return
        for child in node.children:
            self.walk(child, src)


def _collect_test_methods(node: Node, out: List[Node]) -> None:
    if node.type == "method_declaration":
        out.append(node)
        return  # don't hunt for further test methods inside this one's body
    for child in node.children:
        _collect_test_methods(child, out)


def _is_empty_block(body: Optional[Node]) -> bool:
    if body is None:
        return True
    meaningful = [c for c in body.children if c.is_named and c.type != "line_comment" and c.type != "block_comment"]
    return len(meaningful) == 0


def _analyze_test_method(node: Node, src: bytes, filename: str, annotations: List[str]) -> TestFunctionMetrics:
    name_node = node.child_by_field_name("name")
    name = node_text(name_node, src) if name_node is not None else "<unknown>"
    body = node.child_by_field_name("body")
    is_skipped = any(a in _SKIP_ANNOTATIONS for a in annotations)

    walker = _BodyWalker()
    if body is not None:
        for stmt in body.children:
            if stmt.is_named:
                walker.walk(stmt, src)

    return TestFunctionMetrics(
        name=name,
        file=filename,
        lineno=node.start_point[0] + 1,
        language=LANGUAGE,
        assertion_count=walker.assertion_count,
        tautological_count=walker.tautological_count,
        is_empty_body=_is_empty_block(body),
        is_skipped=is_skipped,
    )


class JavaAssertionVisitor:
    """Registry entry for `*Test.java`/`*Tests.java`/`*TestCase.java` files."""

    language = LANGUAGE

    def matches(self, path: str) -> bool:
        name = basename(path)
        return name.endswith(_TEST_SUFFIXES)

    def inspect_file(self, path: str) -> FileInspectionResult:
        try:
            with open(path, "rb") as f:
                src = f.read()
        except OSError as exc:
            return FileInspectionResult(path=path, language=LANGUAGE, parse_error=str(exc))

        try:
            parser = get_parser("java", _java_language)
            tree = parser.parse(src)
        except Exception as exc:  # pragma: no cover - grammar/runtime failure
            return FileInspectionResult(path=path, language=LANGUAGE, parse_error=f"ParseError: {exc}")

        methods: List[Node] = []
        _collect_test_methods(tree.root_node, methods)

        # Annotations are computed once per method and reused for both the
        # "is this a @Test method at all" filter and the is_skipped check
        # inside _analyze_test_method, instead of re-walking the same
        # `modifiers` node twice.
        annotated = [(m, _annotation_names(m, src)) for m in methods]
        functions = [
            _analyze_test_method(m, src, path, annotations)
            for m, annotations in annotated
            if any(a in _TEST_ANNOTATIONS for a in annotations)
        ]
        return FileInspectionResult(path=path, language=LANGUAGE, test_functions=functions)
