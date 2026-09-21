"""Standalone `functional-adequacy` subcommand: evaluates a tier's journeys
(.lucid/functional-verification.json) against real test-report file(s) and
prints the resulting `predicate.functional_verification` JSON.

Exists for the post-deploy (`cd`) stage. The attestation pipeline
(`cli.main`) evaluates the `ci` tier as part of building the signed build
statement, but a repo's post-deploy job runs *after* that statement is
already signed, with its own live-suite reports -- it needs the same
evaluator, not a second implementation of the scoring. This is a thin
wrapper over cli.parsers.functional_adequacy.evaluate_functional_adequacy;
all scoring, tiering and fail-closed behavior lives there.

Exit status: 0 whenever an evaluation result was produced -- *including*
`met: false`, `execution_aborted`, or `config_invalid`. Those are results
to be recorded and shown, not tool failures, and a caller must be able to
submit them (the point of `execution_aborted` is that an operational
failure never vanishes). A non-zero status means the tool itself could not
run: 2 for unusable arguments (argparse), 1 for an unsafe --out path.

Hardened against:
  - An unsafe --out path (null byte, empty) -- rejected before any write
    (cli.common.safe_resolve_path)
  - A missing/unreadable/malformed report -- never a crash; reported as
    a result (see the evaluator's own docstring)
  - An unknown --functional-tier -- rejected by argparse choices, so the
    evaluator's ValueError guard is unreachable from here
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .common import UnsafePathError, safe_resolve_path
from .parsers.functional_adequacy import EVALUATION_TIERS, evaluate_functional_adequacy


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="lucid-assay functional-adequacy",
        description="Evaluate a tier's declared journeys against real test report(s) and print "
        "predicate.functional_verification as JSON.",
    )
    p.add_argument("--repo-dir", default=".", help="repository checkout holding .lucid/functional-verification.json (default: .)")
    p.add_argument(
        "--functional-tier",
        required=True,
        choices=list(EVALUATION_TIERS),
        help="the stage being evaluated; required (no default) so a post-deploy caller can never "
        "silently evaluate the wrong tier",
    )
    p.add_argument(
        "--functional-report",
        action="append",
        default=None,
        help="path to a structured test report; repeatable (e.g. one JUnit file per post-deploy stage). "
        "A path that does not exist is not an error here: at the cd tier it is recorded as "
        "execution_aborted",
    )
    p.add_argument("--functional-env", default=None, help="environment the suite ran against (descriptive only)")
    p.add_argument("--functional-report-uri", default=None, help="optional link to the full report artifact (descriptive only)")
    p.add_argument("--out", default=None, help="write the JSON here instead of stdout")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    report = evaluate_functional_adequacy(
        args.repo_dir,
        args.functional_report,
        target_env=args.functional_env,
        report_uri=args.functional_report_uri,
        tier=args.functional_tier,
    )
    payload = json.dumps(report.as_dict(), indent=2, sort_keys=True) + "\n"
    if args.out is None:
        sys.stdout.write(payload)
        return 0
    try:
        out_path = safe_resolve_path(args.out)
    except UnsafePathError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    out_path.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
