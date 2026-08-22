"""
The per-language visitor contract. Every entry in the registry
(`cli/parsers/ast/__init__.py::_VISITORS`) implements this: a filename
predicate that both drives repo-wide discovery *and* decides whether an
explicitly-passed `target_files` path belongs to this language, plus a
single-file inspector that never raises -- parse/read failures are reported
via `FileInspectionResult.parse_error`, matching the fail-closed-per-file
convention every other parser in this codebase follows.
"""
from __future__ import annotations

from typing import Protocol

from .common import FileInspectionResult


class AssertionVisitor(Protocol):
    language: str

    def matches(self, path: str) -> bool:
        """True if `path` (a file's basename or full path) is a test file
        this visitor owns, by this language's naming convention."""
        ...

    def inspect_file(self, path: str) -> FileInspectionResult:
        """Read + parse + walk a single file. Must not raise -- I/O and
        parse errors are reported on the returned result's `parse_error`."""
        ...
