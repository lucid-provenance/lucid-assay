#!/usr/bin/env python3
"""
lucid-assay provenance: standalone SLSA v1.0 provenance-statement
CONSTRUCTION subcommand (cli.slsa_provenance.build_slsa_provenance_statement).

Why this exists as its own subcommand, separate from `cli.main`'s
`--emit-slsa-provenance` flag (which still works exactly as before, for a
caller not using the split-signer architecture): SLSA Build Level 3
requires provenance to be *constructed* by the same isolated, trusted
build platform that signs it -- not merely signed there after being
assembled by an untrusted build job (see cli/verify.py's
`_slsa_check_isolated_provenance_generation` docstring for exactly why
that distinction matters). `lucid-assay provenance` is the narrow surface
that makes that possible: run it from inside `lucid-attest`'s isolated
`sign` job (see that repo's `sign.yml`), and it builds the statement
using *that job's own* ambient GitHub Actions context (GITHUB_REPOSITORY/
_SHA/RUNNER_ENVIRONMENT, as seen by the trusted job, not whatever the
untrusted build job claims) plus a read-only, code-never-executed
checkout of the source commit for lockfile scanning. The one exception is
`runDetails.builder.id` itself: the caller must pass `--builder-id`
explicitly (see `_control_plane_builder_id`'s docstring for why ambient
GITHUB_WORKFLOW_REF can't supply this when running inside a
`workflow_call` job -- a real run proved it wrong, not a hypothetical).
This subcommand performs zero pipeline logic beyond construction -- no
scoring, coverage, or SARIF ingestion, and no signing (pair with
`lucid-assay sign` for that) -- so a job invoking only this subcommand
never needs read access to any of it.

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
    """Best-effort fallback for --builder-id when the caller doesn't pass
    one explicitly: derives an identity from ambient GITHUB_WORKFLOW_REF
    (e.g. 'org/repo/.github/workflows/foo.yml@<ref>' ->
    'https://github.com/org/repo/.github/workflows/foo.yml').

    Disproven by a real run, do not re-derive this assumption: this does
    NOT reliably identify "the isolated signer workflow currently
    executing this job" when this subcommand runs inside a
    `workflow_call` job (lucid-attest's sign.yml, invoked by some other
    repo's caller workflow). GITHUB_WORKFLOW_REF is a *run-level* context
    value -- constant for every job in the run, always the ref of the
    top-level, *calling* workflow that GitHub's UI attributes the run to
    -- not a *job*-level one. A real run observed this directly: invoked
    from lucid-dsse-collector's assay.yml, this returned
    'https://github.com/lucid-provenance/lucid-dsse-collector/.github/workflows/
    assay.yml' -- the caller's own workflow, not
    'https://github.com/lucid-provenance/lucid-attest/.github/workflows/sign.yml'
    -- so cli/verify.py's SLSA Build Level 2/3 checks correctly failed
    the resulting statement's builder-identity claim.

    (Fulcio's job_workflow_ref OIDC certificate extension -- what
    --cert-identity checks -- does not have this problem: it genuinely
    scopes to the specific reusable workflow file that defines the
    executing job, which is exactly why identity verification has always
    worked correctly here. GITHUB_WORKFLOW_REF and job_workflow_ref are
    two different GitHub Actions concepts that happen to look similar;
    this function's whole existence was conflating them.)

    lucid-attest's sign.yml now always passes --builder-id explicitly
    (it's the one caller that authoritatively knows its own identity,
    hardcoded the same way TRUSTED_SIGNER_SHA is), so this fallback is
    only ever exercised by a direct, non-nested invocation -- where
    GITHUB_WORKFLOW_REF genuinely is this process's own top-level
    workflow, and the derivation is correct. None (never fabricated) when
    GITHUB_WORKFLOW_REF isn't set (off-CI) or doesn't contain the
    expected '<path>@<ref>' shape."""
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF")
    if not workflow_ref or "@" not in workflow_ref:
        return None
    path, _ref = workflow_ref.rsplit("@", 1)
    if not path:
        return None
    return f"https://github.com/{path}"


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="lucid-assay provenance",
        description="Construct a SLSA v1.0 provenance in-toto Statement from this process's own ambient "
        "GitHub Actions context -- intended to run inside an isolated, trusted signer job (see "
        "lucid-provenance/lucid-attest's sign.yml), not the untrusted job that built the subject artifact.",
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
        "--builder-id",
        default=None,
        dest="builder_id",
        help="explicit runDetails.builder.id to assert, e.g. https://github.com/lucid-provenance/lucid-attest/"
        ".github/workflows/sign.yml -- the caller's own known identity, not derived here. Required for "
        "correctness when running inside a workflow_call job (see _control_plane_builder_id's docstring "
        "for why ambient GITHUB_WORKFLOW_REF can't supply this in that case); falls back to a best-effort "
        "ambient derivation when omitted, correct only for a direct, non-nested invocation.",
    )
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
        builder_id=args.builder_id or _control_plane_builder_id(),
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
