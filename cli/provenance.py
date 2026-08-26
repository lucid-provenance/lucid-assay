#!/usr/bin/env python3
"""
tenax-assay provenance: standalone SLSA v1.0 provenance-statement
CONSTRUCTION subcommand (cli.slsa_provenance.build_slsa_provenance_statement).

Why this exists as its own subcommand, separate from `cli.main`'s
`--emit-slsa-provenance` flag (which still works exactly as before, for a
caller not using the split-signer architecture): SLSA Build Level 3
requires provenance to be *constructed* by the same isolated, trusted
build platform that signs it -- not merely signed there after being
assembled by an untrusted build job (see cli/verify.py's
`_slsa_check_isolated_provenance_generation` docstring for exactly why
that distinction matters). `tenax-assay provenance` is the narrow surface
that makes that possible: run it from inside `tenax-attest`'s isolated
`sign` job (see that repo's `sign.yml`), and it builds the statement
using *that job's own* ambient GitHub Actions context (GITHUB_REPOSITORY/
_SHA/_WORKFLOW_REF/RUNNER_ENVIRONMENT, as seen by the trusted job, not
whatever the untrusted build job claims) plus a read-only, code-never-
executed checkout of the source commit for lockfile scanning. It performs
zero pipeline logic beyond that -- no scoring, coverage, or SARIF
ingestion, and no signing (pair with `tenax-assay sign` for that) -- so a
job invoking only this subcommand never needs read access to any of it.

Reuses cli.slsa_provenance.build_slsa_provenance_statement() and
cli.parsers.lockfiles.detect_and_parse_dependencies() completely
unchanged -- this is a new entry point for existing, already-hardened,
ground-truth-only logic, not new provenance-construction logic itself.

Hardened against:
  - An unsafe output path (null bytes, malformed) reaching open()
    unresolved (cli.common.safe_resolve_path(), same as every other
    operator-supplied path in cli/)
  - A malformed/bare-hex --subject-digest (normalized the same way
    cli.main normalizes --image-digest)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import List, Optional

from .common import UnsafePathError, safe_resolve_path
from .parsers.lockfiles import detect_and_parse_dependencies
from .slsa_provenance import build_slsa_provenance_statement

EXIT_PASS = 0
EXIT_FILE_ERROR = 1


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_digest(raw: str) -> str:
    """sha256:<hex> or bare hex -> clean lowercase hex, same normalization
    cli.main applies to --image-digest before calling build_statement()."""
    digest = raw.strip().lower()
    if digest.startswith("sha256:"):
        digest = digest[len("sha256:"):]
    return digest


def _control_plane_builder_id() -> Optional[str]:
    """Derives *this process's own* trusted workflow identity from ambient
    GITHUB_WORKFLOW_REF (e.g. 'tenax-io/tenax-attest/.github/workflows/
    sign.yml@<ref>' -> 'https://github.com/tenax-io/tenax-attest/.github/
    workflows/sign.yml') -- the same job-workflow-ref identity Fulcio's
    GitHub Actions OIDC certificate extension encodes for whatever job
    calls this. Deliberately not hardcoded to any specific repo/path: this
    subcommand is meant to run inside an isolated signer job wherever one
    is hosted, and its output should assert that job's own real identity,
    not a value invented here. None (never fabricated) when
    GITHUB_WORKFLOW_REF isn't set (off-CI) or doesn't contain the expected
    '<path>@<ref>' shape."""
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF")
    if not workflow_ref or "@" not in workflow_ref:
        return None
    path, _ref = workflow_ref.rsplit("@", 1)
    if not path:
        return None
    return f"https://github.com/{path}"


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="tenax-assay provenance",
        description="Construct a SLSA v1.0 provenance in-toto Statement from this process's own ambient "
        "GitHub Actions context -- intended to run inside an isolated, trusted signer job (see "
        "tenax-io/tenax-attest's sign.yml), not the untrusted job that built the subject artifact.",
    )
    p.add_argument("--subject-name", required=True, help="the attested artifact's name, e.g. an image ref")
    p.add_argument("--subject-digest", required=True, help="sha256:<hex> or bare hex")
    p.add_argument(
        "--repo-dir",
        default=".",
        help="read-only checkout of the source commit, scanned for lockfiles only -- never executed "
        "(default: current directory)",
    )
    p.add_argument("--out", required=True, help="output path for the unsigned provenance statement JSON")
    p.add_argument(
        "--started-at",
        default=None,
        help="ISO 8601 UTC pipeline start time (default: now -- this subcommand doesn't itself observe "
        "the build's actual start, so a caller that knows it should pass it explicitly)",
    )
    p.add_argument("--finished-at", default=None, help="ISO 8601 UTC pipeline finish time (default: now)")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    try:
        out_path = safe_resolve_path(args.out)
    except UnsafePathError as e:
        print(f"ERROR: unsafe output path: {e}", file=sys.stderr)
        return EXIT_FILE_ERROR

    resolved_dependencies = detect_and_parse_dependencies(args.repo_dir)
    started_at = args.started_at or _now_iso()
    finished_at = args.finished_at or _now_iso()

    statement = build_slsa_provenance_statement(
        subject_name=args.subject_name,
        subject_sha256=_normalize_digest(args.subject_digest),
        started_at=started_at,
        finished_at=finished_at,
        resolved_dependencies=resolved_dependencies,
        builder_id=_control_plane_builder_id(),
    )

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(statement, f, indent=2)
    except OSError as e:
        print(f"ERROR: failed to write provenance statement to {args.out}: {e}", file=sys.stderr)
        return EXIT_FILE_ERROR

    print(f"provenance statement written to {out_path}", file=sys.stderr)
    return EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
