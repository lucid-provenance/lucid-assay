"""
Shared Tree-sitter plumbing used by every non-Python visitor
(`tsjs_visitor.py`, `go_visitor.py`, `java_visitor.py`): lazy per-grammar
`Parser` construction (grammar loading isn't free, so each `Language` is
built once per process) plus small node-text/literal-folding helpers that
stand in for what `ast.dump`/constant-folding gives the Python visitor for
free -- Tree-sitter hands back a raw concrete syntax tree over source
bytes, not a typed AST, so "is this the same expression" and "does this
literal fold to True" both have to be reimplemented against node types.
"""
from __future__ import annotations

from typing import Any, List, Optional, Tuple

from tree_sitter import Language, Node, Parser

_parser_cache: dict = {}


def get_parser(cache_key: str, language_factory) -> Parser:
    """Returns a cached `Parser` for `cache_key`, building it via
    `language_factory()` (a zero-arg callable returning a `tree_sitter.Language`)
    on first use. Building a `Language`/`Parser` pair isn't free, and this
    module may inspect many files per run, so each grammar is constructed
    exactly once per process."""
    parser = _parser_cache.get(cache_key)
    if parser is None:
        parser = Parser(Language(language_factory()))
        _parser_cache[cache_key] = parser
    return parser


def node_text(node: Optional[Node], src: bytes) -> str:
    if node is None:
        return ""
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def normalized_text(node: Optional[Node], src: bytes) -> str:
    """Whitespace-collapsed source text, used for structural
    self-reference comparisons (`expect(x).toBe(x)`, `assertEquals(x, x)`)
    where two distinct node instances must be compared by what they say,
    not by identity."""
    return " ".join(node_text(node, src).split())


def structurally_equal(a: Optional[Node], b: Optional[Node], src: bytes) -> bool:
    if a is None or b is None:
        return False
    return normalized_text(a, src) == normalized_text(b, src)


def call_args(arguments_node: Optional[Node]) -> List[Node]:
    """Filters a call's `arguments`/`argument_list` node down to the actual
    argument expressions, dropping punctuation tokens (`(`, `)`, `,`)."""
    if arguments_node is None:
        return []
    return [c for c in arguments_node.children if c.is_named]


def path_parts(path: str) -> List[str]:
    return [p for p in path.replace("\\", "/").split("/") if p]


def basename(path: str) -> str:
    parts = path_parts(path)
    return parts[-1] if parts else path


def literal_or_structural_equal(a: Node, b: Node, src: bytes, fold) -> bool:
    """True if `a` and `b` are the "same value" for tautology purposes:
    either both fold to an equal compile-time literal, or they're the same
    source expression re-typed (self-comparison gaming, e.g. `x == x`)."""
    ok_a, va = fold(a, src)
    ok_b, vb = fold(b, src)
    if ok_a and ok_b:
        return va == vb
    return structurally_equal(a, b, src)
