"""
coverage.py per-test line-coverage attribution ("dynamic contexts"),
consumed by cli.real_coverage to compute a vanity-test-aware "real
coverage" figure -- distinct from cli.parsers.coverage, which parses
Cobertura/LCOV's aggregate line-rate with no per-test attribution at
all.

Requires the coverage run to have been collected with dynamic contexts
enabled (`pytest --cov-context=test`, or coverage.py's own
`dynamic_context = test_function` config) and then exported via
`coverage json --show-contexts -o <path>` -- NOT the JSON `coverage
json` produces by default, which omits the per-line `contexts` map
entirely.

Hardened against:
  - Missing/unreadable/malformed JSON files (`available=False`, never raises)
  - Pathologically deep JSON nesting (RecursionError, not
    json.JSONDecodeError -- see cli.parsers.sarif's own docstring for why
    these are caught alongside each other rather than assumed to be the
    same exception type)
  - A JSON export produced without --show-contexts (no file has a
    `contexts` key at all): degrades to available=False with a distinct,
    actionable reason ("you forgot the flag"), not a generic parse failure
  - Non-numeric line-number keys, non-list/non-string context entries:
    skipped individually, never raise
  - The synthetic "|run"/"|setup"/"|teardown" phase suffix coverage.py
    appends to a context label: stripped before comparison, and the
    empty-string context (a line executed with no active dynamic context
    at all, e.g. at module import time) is dropped from a line's context
    set rather than treated as "covered by a test literally named ''" --
    a line can still end up with an empty frozenset of contexts this way,
    which callers must read as "covered, but with no known covering
    test", never as "not covered"
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Optional, Union

from ..common import UnsafePathError, safe_resolve_path


def _normalize_path(path_str: str) -> str:
    """Mirrors cli.parsers.coverage._normalize_path so file keys line up
    with the Cobertura/LCOV report's own normalized paths."""
    p = os.path.normpath(path_str.strip())
    return p.lstrip(os.sep)


@dataclass
class CoverageContextReport:
    __test__ = False
    available: bool
    # {normalized_path: {line_no: frozenset(covering pytest node ids)}}.
    # An empty frozenset means "covered, no known covering test" (see
    # module docstring) -- distinct from the line being absent entirely,
    # which means coverage.py never reported a context map for it (still
    # possibly covered per the underlying Cobertura/LCOV report; this
    # module only ever narrows "covered", never widens it).
    files: Dict[str, Dict[int, FrozenSet[str]]] = field(default_factory=dict)
    reason: str = ""


def _clean_context_label(raw: Any) -> Optional[str]:
    """Strips coverage.py's synthetic '|run'/'|setup'/'|teardown' phase
    suffix from one context label. Returns None for the empty-string
    context or any non-string entry -- both mean "no real test id here"."""
    if not isinstance(raw, str) or not raw:
        return None
    label = raw.rsplit("|", 1)[0] if "|" in raw else raw
    return label or None


def _parse_file_contexts(raw_contexts: Any) -> Dict[int, FrozenSet[str]]:
    """Parses one file's `contexts` map ({"<lineno>": ["<ctx>", ...]})
    into {int(lineno): frozenset(cleaned, non-empty context labels)}."""
    result: Dict[int, FrozenSet[str]] = {}
    if not isinstance(raw_contexts, dict):
        return result
    for raw_lineno, raw_labels in raw_contexts.items():
        try:
            lineno = int(raw_lineno)
        except (TypeError, ValueError):
            continue
        if not isinstance(raw_labels, list):
            continue
        labels = {_clean_context_label(lbl) for lbl in raw_labels}
        labels.discard(None)
        result[lineno] = frozenset(labels)
    return result


def _load_contexts_doc(path: Union[str, Path]) -> Any:
    """Resolves and JSON-decodes the export file. Raises the same narrow
    set of exceptions parse_coverage_contexts() already expects to
    catch -- split out purely to keep that function's own guard-clause
    sequence flat rather than nesting a second try/except inside it."""
    resolved = safe_resolve_path(path)
    with open(resolved, "r", encoding="utf-8") as f:
        return json.load(f)


def _files_from_doc(doc: Dict[str, Any]) -> Optional[Dict[str, Dict[int, FrozenSet[str]]]]:
    """Extracts and normalizes the per-file contexts map from a decoded
    export document. Returns None if no file in the export carries a
    `contexts` key at all (the file exists and parses, but wasn't
    generated with --show-contexts) -- the caller turns that into a
    distinct, actionable `reason`."""
    raw_files = doc.get("files")
    if not isinstance(raw_files, dict):
        return None

    files: Dict[str, Dict[int, FrozenSet[str]]] = {}
    saw_any_contexts_key = False
    for raw_path, file_entry in raw_files.items():
        if not isinstance(file_entry, dict):
            continue
        if "contexts" in file_entry:
            saw_any_contexts_key = True
        files[_normalize_path(raw_path)] = _parse_file_contexts(file_entry.get("contexts"))

    return files if saw_any_contexts_key else None


def parse_coverage_contexts(path: Union[str, Path]) -> CoverageContextReport:
    """Parses a `coverage json --show-contexts` export into a
    CoverageContextReport. Returns available=False (never raises) on any
    missing/unreadable/malformed input, or a well-formed coverage.py JSON
    export that simply wasn't generated with --show-contexts."""
    try:
        doc = _load_contexts_doc(path)
    except (UnsafePathError, OSError) as e:
        return CoverageContextReport(available=False, reason=f"failed to read coverage contexts file: {e}")
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as e:
        return CoverageContextReport(available=False, reason=f"failed to parse coverage contexts file: {e}")

    if not isinstance(doc, dict):
        return CoverageContextReport(available=False, reason="coverage contexts file is not a JSON object")

    files = _files_from_doc(doc)
    if files is None:
        return CoverageContextReport(
            available=False,
            reason=(
                "no file in this export has a 'contexts' key -- generate it with "
                "`coverage json --show-contexts` (collected with `--cov-context=test` "
                "or coverage.py's `dynamic_context = test_function`)"
            ),
        )

    return CoverageContextReport(available=True, files=files)
