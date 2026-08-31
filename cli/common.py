"""
Shared path-safety helpers, applied before any operator-supplied file path
(--junit-xml, --coverage-report, --sarif, --sonar-metrics, --out, the
`verify` envelope argument, ...) is opened, hashed, or size-checked.

Hardened against:
  - Null-byte injection (a NUL embedded in a path string is never valid on
    any real filesystem; historically it's been a way to make a check
    performed against one representation of a path diverge from what the
    underlying C-level open() syscall actually receives)
  - Malformed/unrepresentable path strings raising an inconsistent,
    unexpected exception type at some arbitrary downstream open() call
    site, rather than one clear, consistently-typed error at the point of
    validation
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Union


class UnsafePathError(ValueError):
    """Raised by safe_resolve_path() when a path string is null-byte-laced
    or otherwise can't be safely resolved. A ValueError subclass (not a
    bare Exception) so callers that already catch ValueError for bad CLI
    input handle this the same way, without needing a new except clause."""


JSON_SUFFIX = ".json"


def derive_signed_path(out_path: str) -> str:
    """Derive the DSSE signed envelope path from --out, without
    double-appending the .dsse.json suffix when --out already ends in
    .dsse.json or .json (e.g. avoid *.dsse.dsse.json).

    Lives here, not in cli.main, specifically so cli.sign can depend on it
    without importing cli.main -- cli.main's own top-level imports pull in
    the entire scoring/parsing pipeline (cli.scorer, cli.parsers.*,
    cli.builder), which a standalone signing process has no business
    loading into its own address space. See Milestone #18's "narrow code
    footprint" requirement in the Lucid roadmap for why this matters beyond
    tidiness. cli.main still exposes this name (re-exported, not
    redefined) for existing callers/tests that import it from there."""
    if out_path.endswith(".dsse.json"):
        return out_path
    if out_path.endswith(JSON_SUFFIX):
        base_out = out_path[: -len(JSON_SUFFIX)]
        if base_out.endswith(".unsigned"):
            base_out = base_out[: -len(".unsigned")]
        return f"{base_out}.dsse.json"
    return f"{out_path}.dsse.json"


def safe_resolve_path(path_str: Union[str, "os.PathLike[str]"]) -> Path:
    """Resolves `path_str` to an absolute Path with `.`/`..` segments and
    symlinks normalized away, rejecting null bytes and non-string/empty
    input before the value ever reaches open()/os.path.getsize()/
    ET.parse()/etc.

    This deliberately does NOT enforce a single fixed root/allowlist
    directory: every path this is applied to (--junit-xml,
    --coverage-report, --sarif, --sonar-metrics, --out, the `verify`
    envelope argument) is operator-supplied at CLI invocation time, the
    same way any file-taking CLI tool's arguments are (cp, tar, grep, ...)
    -- there is no single "repo root" they're all guaranteed to live
    under (a coverage report or SARIF file routinely lives in a shared
    CI artifacts directory outside the checkout). What this guards
    against is a value that can't be safely turned into a real filesystem
    path at all, and gives every caller one canonical, already-resolved
    Path instead of each repeating ad hoc normalization.

    Does not require the path to exist: like `Path.resolve()` itself,
    a nonexistent file resolves to its would-be absolute path without
    raising -- the existing FileNotFoundError handling at each call site
    is unchanged, this only rejects unsafe path *strings*, not missing
    files.
    """
    if not isinstance(path_str, (str, os.PathLike)) or not str(path_str):
        raise UnsafePathError(f"path must be a non-empty string or path-like object, got {path_str!r}")

    text = os.fspath(path_str)
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="surrogateescape")

    if "\x00" in text:
        raise UnsafePathError(f"path contains a null byte: {text!r}")

    try:
        return Path(text).resolve()
    except (OSError, ValueError) as e:
        raise UnsafePathError(f"could not resolve path {text!r}: {e}") from e
