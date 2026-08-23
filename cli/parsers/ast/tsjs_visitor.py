"""
TypeScript / JavaScript assertion visitor (Jest/Vitest/Mocha idioms), via
Tree-sitter's `tree-sitter-typescript`/`tree-sitter-javascript` grammars.

Discovery: `*.test.{ts,tsx,js,jsx,mjs,cjs}`, `*.spec.{...}`, or any file
under a `__tests__/` directory -- the three conventions Jest/Vitest/Mocha
runners actually pick up by default.

Hardened against:
  - `it.skip(...)`/`test.skip(...)`/`xit(...)`/`xtest(...)`/`it.todo(...)`
    being credited as executed, zero-assertion test bodies rather than
    tracked as skipped
  - Tautological matcher chains: `expect(true).toBe(true)`,
    `expect(1).toEqual(1)`, `expect(x).toBe(x)` (self-reference), and bare
    `assert(true)` / chai's `assert.equal(1, 1)`
  - `expect(...).not.toBe(...)` never being misclassified as tautological
    just because its un-negated form would fold true -- negation disables
    the tautology check entirely rather than inverting it
  - A nested `it(...)`/`test(...)` discovered inside another test's own
    callback being double-counted as both an independent test unit and an
    assertion site of its parent
  - A named, non-invoked `function helper() { ... }` declared inside a
    test body being credited as executed code (its assertions, if any,
    aren't proven to run) -- distinguished from inline arrow/function
    *expressions* passed straight to `.then()`/`.forEach()`/callbacks,
    which do run synchronously as part of the test and are walked
"""
from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple

from tree_sitter import Node

from ._ts_util import basename, call_args, get_parser, literal_or_structural_equal, node_text, path_parts
from .common import FileInspectionResult, TestFunctionMetrics

LANGUAGE = "typescript_javascript"  # visitor/registry identity; see _LANGUAGE_BY_EXT for the per-file label

# The visitor implementation is shared (one Tree-sitter grammar pair
# handles both), but "language" in the reported telemetry/DSSE predicate
# should reflect what the file actually is, not how it's implemented --
# an auditor asking "is our TypeScript well-tested?" can't get that answer
# out of a single merged "typescript_javascript" bucket.
_LANGUAGE_BY_EXT = {
    "ts": "typescript",
    "tsx": "typescript",
    "js": "javascript",
    "jsx": "javascript",
    "mjs": "javascript",
    "cjs": "javascript",
}

# Canonical grammar identity per extension, used as the Parser cache key:
# .js/.jsx/.mjs/.cjs all parse with the exact same JavaScript grammar, so
# they share one cached Parser instead of get_parser building (and
# caching) four functionally-identical ones.
_GRAMMAR_KEY_BY_EXT = {
    "ts": "ts",
    "tsx": "tsx",
    "js": "js",
    "jsx": "js",
    "mjs": "js",
    "cjs": "js",
}

_EXT_TEST_RE = re.compile(r"\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$", re.IGNORECASE)
_EXT_RE = re.compile(r"\.(ts|tsx|js|jsx|mjs|cjs)$", re.IGNORECASE)

_TEST_CALL_IDENTS = {"it", "test"}
_SKIP_ALIAS_IDENTS = {"xit", "xtest"}
_SKIP_MEMBERS = {"skip", "todo"}
_RUNNABLE_MEMBERS = {"only", "concurrent"}  # still executes; not skipped

# `it.each(table)(name, fn)`/`test.each(table)(name, fn)` is a curried call:
# the outer call's `function` is itself a call_expression, not an
# identifier/member_expression, so it's never matched by
# `_classify_test_call` at all -- deliberately NOT treated as a plain
# runnable member here, since doing so would match the *inner*
# `it.each(table)` call instead and record a spurious "<anonymous>",
# zero-assertion test unit for it while the real `(name, fn)` pair (and its
# assertions) in the outer call goes undiscovered entirely. Left
# unsupported rather than misreported; `.each` tables are not otherwise
# scanned by this visitor.

_EXPECT_CHAIN_PASSTHROUGH = {"not", "resolves", "rejects"}
_EXPECT_EQUALITY_MATCHERS = {"toBe", "toEqual", "toStrictEqual"}

_CHAI_ASSERT_EQUALITY_METHODS = {"equal", "strictEqual", "deepEqual", "deepStrictEqual"}
_CHAI_ASSERT_TRUE_METHODS = {"isTrue", "ok"}
_CHAI_ASSERT_FALSE_METHODS = {"isFalse", "notOk"}

_FUNCTION_LIKE_TYPES = {"arrow_function", "function_expression"}
_SCOPE_BOUNDARY_TYPES = {"function_declaration", "generator_function_declaration"}


def _language_for(ext: str):
    ext = ext.lower()
    if ext == "tsx":
        import tree_sitter_typescript as tsts

        return tsts.language_tsx
    if ext == "ts":
        import tree_sitter_typescript as tsts

        return tsts.language_typescript
    import tree_sitter_javascript as tsjs

    return tsjs.language


def _fold_parenthesized(node: Node, src: bytes) -> Tuple[bool, Any]:
    inner = [c for c in node.children if c.is_named]
    return _fold_js_literal(inner[0], src) if inner else (False, None)


def _fold_number_literal(node: Node, src: bytes) -> Tuple[bool, Any]:
    text = node_text(node, src)
    try:
        return True, (int(text, 0) if not any(c in text for c in ".eE") else float(text))
    except ValueError:
        return False, None


def _fold_string_literal(node: Node, src: bytes) -> Tuple[bool, Any]:
    frags = [c for c in node.children if c.type == "string_fragment"]
    return True, "".join(node_text(f, src) for f in frags)


def _fold_unary_expression(node: Node, src: bytes) -> Tuple[bool, Any]:
    op = node_text(node.children[0], src) if node.children else ""
    operand = node.child_by_field_name("argument")
    ok, val = _fold_js_literal(operand, src)
    if not ok:
        return False, None
    if op == "!":
        return True, not val
    return False, None


# Dispatch table for _fold_js_literal: node.type -> (node, src) -> (ok, value).
# Keeps the dispatcher itself a flat lookup instead of a long if/elif chain.
_LITERAL_FOLDERS = {
    "parenthesized_expression": _fold_parenthesized,
    "number": _fold_number_literal,
    "string": _fold_string_literal,
    "unary_expression": _fold_unary_expression,
}


def _fold_js_literal(node: Optional[Node], src: bytes) -> Tuple[bool, Any]:
    if node is None:
        return False, None
    if node.type == "true":
        return True, True
    if node.type == "false":
        return True, False
    if node.type in ("null", "undefined"):
        return True, None
    folder = _LITERAL_FOLDERS.get(node.type)
    if folder is not None:
        return folder(node, src)
    return False, None


def _extract_name(args: List[Node], src: bytes) -> str:
    for arg in args:
        if arg.type == "string":
            frags = [c for c in arg.children if c.type == "string_fragment"]
            return "".join(node_text(f, src) for f in frags)
        if arg.type == "template_string":
            return node_text(arg, src).strip("`")
    return "<anonymous>"


def _extract_callback(args: List[Node]) -> Optional[Node]:
    for arg in reversed(args):
        if arg.type in _FUNCTION_LIKE_TYPES:
            return arg
    return None


def _classify_identifier_test_call(func: Node, src: bytes) -> Optional[Tuple[str, bool]]:
    """`_classify_test_call`'s bare-identifier case: `it(...)`/`test(...)`
    or one of their skip aliases (`xit(...)`, `xtest(...)`, ...)."""
    ident = node_text(func, src)
    if ident in _TEST_CALL_IDENTS:
        return ident, False
    if ident in _SKIP_ALIAS_IDENTS:
        return ident, True
    return None


def _classify_member_test_call(func: Node, src: bytes) -> Optional[Tuple[str, bool]]:
    """`_classify_test_call`'s member-expression case:
    `it.skip(...)`/`test.only(...)`/etc."""
    obj = func.child_by_field_name("object")
    prop = func.child_by_field_name("property")
    if obj is None or prop is None or obj.type != "identifier":
        return None
    base = node_text(obj, src)
    if base not in _TEST_CALL_IDENTS:
        return None
    member = node_text(prop, src)
    if member in _SKIP_MEMBERS:
        return base, True
    if member in _RUNNABLE_MEMBERS:
        return base, False
    return None


def _classify_test_call(node: Node, src: bytes) -> Optional[Tuple[str, bool]]:
    """Returns (matched_ident_label, is_skipped) if `node` is an
    it(...)/test(...) call site (any of the skip/only/todo/xit/xtest
    variants), else None."""
    func = node.child_by_field_name("function")
    if func is None:
        return None
    if func.type == "identifier":
        return _classify_identifier_test_call(func, src)
    if func.type == "member_expression":
        return _classify_member_test_call(func, src)
    return None


def _expect_chain_hop(cur: Node, src: bytes) -> Optional[Tuple[Optional[Node], bool]]:
    """One step of _trace_expect_chain: given a `member_expression` link in
    the chain, returns (next_node_to_examine, hop_is_negation) when it's a
    recognized passthrough (.not/.resolves/.rejects), else None to signal
    the chain doesn't continue toward a bare expect(...) call from here."""
    prop = cur.child_by_field_name("property")
    member = node_text(prop, src)
    if member not in _EXPECT_CHAIN_PASSTHROUGH:
        return None
    return cur.child_by_field_name("object"), member == "not"


def _match_expect_call(cur: Node, src: bytes) -> Tuple[bool, Optional[Node]]:
    """Returns (is_expect_call, arg_or_None) for a `call_expression` node.
    is_expect_call is True only when the call's function is the bare
    identifier `expect`; arg is its first argument, or None if it was
    called with none -- which is a distinct case from "not an expect(...)
    call at all" (is_expect_call False), so both are returned rather than
    folding them into one Optional value."""
    func = cur.child_by_field_name("function")
    if func is None or func.type != "identifier" or node_text(func, src) != "expect":
        return False, None
    args = call_args(cur.child_by_field_name("arguments"))
    return True, (args[0] if args else None)


def _trace_expect_chain(node: Optional[Node], src: bytes) -> Optional[Tuple[Optional[Node], bool]]:
    """Peels `.not`/`.resolves`/`.rejects` off a member-expression chain to
    find whether it originates at a bare `expect(...)` call. Returns
    (expect_arg_or_None, negated) on success, else None."""
    negated = False
    cur = node
    while cur is not None:
        if cur.type == "call_expression":
            is_expect, arg = _match_expect_call(cur, src)
            return (arg, negated) if is_expect else None
        if cur.type != "member_expression":
            return None
        hop = _expect_chain_hop(cur, src)
        if hop is None:
            return None
        cur, hop_negated = hop
        negated = negated or hop_negated
    return None


class _TestBodyWalker:
    """Scoped assertion walker for one test callback's body. Descends into
    inline arrow/function *expressions* (`.then(() => {...})`,
    `array.forEach(x => {...})`) since those run synchronously as part of
    the test, but not into named `function` declarations, which are merely
    defined -- never proven to execute -- and not into a nested
    it(...)/test(...) call, which is its own separately-discovered unit."""

    def __init__(self) -> None:
        self.assertion_count = 0
        self.tautological_count = 0

    def walk(self, node: Node, src: bytes) -> None:
        if node.type in _SCOPE_BOUNDARY_TYPES:
            return
        if node.type == "call_expression":
            if _classify_test_call(node, src) is not None:
                return  # a nested test unit; handled independently
            if self._handle_call(node, src):
                return  # matched call: its own subtree is opaque past this point
        if node.type == "if_statement":
            self._walk_if_statement(node, src)
            return
        for child in node.children:
            self.walk(child, src)

    def _walk_if_statement(self, node: Node, src: bytes) -> None:
        # `if (false) { expect(...).toBe(...); }` is statically dead/live --
        # prune to the branch that actually runs, mirroring
        # python_visitor.py's visit_If.
        ok, value = _fold_js_literal(node.child_by_field_name("condition"), src)
        if not ok:
            return
        branch = node.child_by_field_name("consequence" if value else "alternative")
        if branch is not None and branch.type == "else_clause":
            named = [c for c in branch.children if c.is_named]
            branch = named[0] if named else None
        if branch is not None:
            self.walk(branch, src)

    def _handle_call(self, node: Node, src: bytes) -> bool:
        func = node.child_by_field_name("function")
        if func is None:
            return False

        if func.type == "identifier":
            return self._handle_bare_assert_call(node, func, src)

        if func.type == "member_expression":
            obj = func.child_by_field_name("object")
            prop = func.child_by_field_name("property")
            member = node_text(prop, src)

            trace = _trace_expect_chain(obj, src)
            if trace is not None:
                return self._handle_expect_chain_call(node, member, trace, src)

            if obj is not None and obj.type == "identifier" and node_text(obj, src) in ("assert", "chai"):
                return self._handle_chai_assert_call(node, member, src)

        return False

    def _handle_bare_assert_call(self, node: Node, func: Node, src: bytes) -> bool:
        """Node `assert(...)` (bare Node assert, not chai's `assert.*`)."""
        ident = node_text(func, src)
        if ident != "assert":
            return False
        args = call_args(node.child_by_field_name("arguments"))
        taut = False
        if args:
            ok, val = _fold_js_literal(args[0], src)
            taut = ok and bool(val)
        self._record(taut)
        return True

    def _handle_expect_chain_call(
        self, node: Node, member: str, trace: Tuple[Optional[Node], bool], src: bytes
    ) -> bool:
        """`expect(x)[.not/.resolves/.rejects].<matcher>(...)` terminal call."""
        expect_arg, negated = trace
        if member in _EXPECT_CHAIN_PASSTHROUGH:
            return False  # part of the chain, not its terminal matcher
        args = call_args(node.child_by_field_name("arguments"))
        taut = False
        if not negated and member in _EXPECT_EQUALITY_MATCHERS and expect_arg is not None and args:
            taut = literal_or_structural_equal(expect_arg, args[0], src, _fold_js_literal)
        self._record(taut)
        return True

    def _handle_chai_assert_call(self, node: Node, member: str, src: bytes) -> bool:
        """`assert.equal(...)`/`chai.isTrue(...)`/etc."""
        args = call_args(node.child_by_field_name("arguments"))
        taut = False
        if member in _CHAI_ASSERT_EQUALITY_METHODS and len(args) >= 2:
            taut = literal_or_structural_equal(args[0], args[1], src, _fold_js_literal)
        elif member in _CHAI_ASSERT_TRUE_METHODS and args:
            ok, val = _fold_js_literal(args[0], src)
            taut = ok and bool(val)
        elif member in _CHAI_ASSERT_FALSE_METHODS and args:
            ok, val = _fold_js_literal(args[0], src)
            taut = ok and not val
        self._record(taut)
        return True

    def _record(self, tautological: bool) -> None:
        if tautological:
            self.tautological_count += 1
        else:
            self.assertion_count += 1


def _is_empty_callback_body(body: Optional[Node]) -> bool:
    if body is None:
        return True
    if body.type != "statement_block":
        return False  # a direct-expression arrow body (`() => expect(1).toBe(1)`) is never empty
    meaningful = [c for c in body.children if c.is_named and c.type != "comment"]
    return len(meaningful) == 0


def _collect_test_calls(node: Node, src: bytes, out: List[Tuple[Node, str, bool]]) -> None:
    if node.type == "call_expression":
        classified = _classify_test_call(node, src)
        if classified is not None:
            ident, is_skipped = classified
            out.append((node, ident, is_skipped))
            return  # don't hunt for further test units inside this one's body
    for child in node.children:
        _collect_test_calls(child, src, out)


def _analyze_test_call(
    node: Node, ident: str, is_skipped: bool, src: bytes, filename: str, language: str
) -> TestFunctionMetrics:
    args = call_args(node.child_by_field_name("arguments"))
    name = _extract_name(args, src)
    callback = _extract_callback(args)
    body = callback.child_by_field_name("body") if callback is not None else None

    walker = _TestBodyWalker()
    if body is not None:
        if body.type == "statement_block":
            for stmt in body.children:
                if stmt.is_named:
                    walker.walk(stmt, src)
        else:
            walker.walk(body, src)

    return TestFunctionMetrics(
        name=name,
        file=filename,
        lineno=node.start_point[0] + 1,
        language=language,
        assertion_count=walker.assertion_count,
        tautological_count=walker.tautological_count,
        is_empty_body=_is_empty_callback_body(body),
        is_skipped=is_skipped,
    )


class TsJsAssertionVisitor:
    """Registry entry for `.ts`/`.tsx`/`.js`/`.jsx`/`.mjs`/`.cjs` test files."""

    language = LANGUAGE

    def matches(self, path: str) -> bool:
        name = basename(path)
        if _EXT_TEST_RE.search(name):
            return True
        if not _EXT_RE.search(name):
            return False
        return "__tests__" in path_parts(path)

    def inspect_file(self, path: str) -> FileInspectionResult:
        ext_match = _EXT_RE.search(basename(path))
        ext = (ext_match.group(1) if ext_match else "js").lower()
        language = _LANGUAGE_BY_EXT.get(ext, LANGUAGE)

        try:
            with open(path, "rb") as f:
                src = f.read()
        except OSError as exc:
            return FileInspectionResult(path=path, language=language, parse_error=str(exc))

        try:
            parser = get_parser(f"tsjs:{_GRAMMAR_KEY_BY_EXT.get(ext, 'js')}", _language_for(ext))
            tree = parser.parse(src)
        except Exception as exc:  # pragma: no cover - grammar/runtime failure
            return FileInspectionResult(path=path, language=language, parse_error=f"ParseError: {exc}")

        calls: List[Tuple[Node, str, bool]] = []
        _collect_test_calls(tree.root_node, src, calls)

        functions = [
            _analyze_test_call(node, ident, skipped, src, path, language) for node, ident, skipped in calls
        ]
        return FileInspectionResult(path=path, language=language, test_functions=functions)
