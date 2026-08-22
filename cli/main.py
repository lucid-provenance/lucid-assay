#!/usr/bin/env python3
"""
plinth-assay: single-binary CI attestation & governance engine.

Hardened against:
  - Unsafe output filename collision during DSSE envelope output
  - Unchecked exit codes on policy/gate breaches (--min-rcs)
  - Unguarded background worker termination
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from .builder import build_statement
from .hashing import sha256_file, worm_uri
from .parsers.ast_inspector import inspect_test_suite
from .parsers.coverage import parse_cobertura, parse_lcov
from .parsers.github_rules import bypass_permits_unreviewed_change, inspect_branch_governance
from .parsers.junit import parse_junit_xml
from .parsers.sarif import aggregate_sarif_reports, parse_sarif_file
from .patch_coverage import compute_patch_coverage, compute_patch_modified_lines
from .scorer import score_pipeline

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="worm-upload")


def derive_signed_path(out_path: str) -> str:
    """Derive the DSSE signed envelope path from --out, without
    double-appending the .dsse.json suffix when --out already ends in
    .dsse.json or .json (e.g. avoid *.dsse.dsse.json)."""
    if out_path.endswith(".dsse.json"):
        return out_path
    if out_path.endswith(".json"):
        base_out = out_path[: -len(".json")]
        if base_out.endswith(".unsigned"):
            base_out = base_out[: -len(".unsigned")]
        return f"{base_out}.dsse.json"
    return f"{out_path}.dsse.json"


def upload_to_worm_async(local_path: str, sha256_hex: str, bucket: str = "evidence"):
    """Fire-and-forget evidence storage dispatch."""
    def _upload():
        # Integration point for S3/MinIO Object Lock COMPLIANCE storage
        pass

    return _executor.submit(_upload)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="plinth-assay",
        description="plinth-assay: single-binary CI attestation & governance engine.",
    )
    p.add_argument("--junit-xml", required=True)
    p.add_argument("--coverage-format", choices=["cobertura", "lcov"], default="cobertura")
    p.add_argument("--coverage-report", required=True, dest="coverage_report")
    p.add_argument("--image-ref", required=True)
    p.add_argument("--image-digest", required=True, help="sha256:<hex> or bare hex")
    p.add_argument("--base-sha", default=None)
    p.add_argument("--head-sha", required=True)
    p.add_argument("--repo-dir", default=".")
    p.add_argument("--repository", required=True)
    p.add_argument("--branch", required=True)
    p.add_argument("--pr-number", type=int, default=None)
    p.add_argument("--pr-approvers", default="", help="comma-separated handles")
    p.add_argument("--pr-required-approvals", type=int, default=0)
    p.add_argument("--pr-review-state", default="not_applicable")
    p.add_argument(
        "--github-token",
        default=None,
        help="GitHub token for branch governance/ruleset inspection (default: ambient GITHUB_TOKEN env var)",
    )
    p.add_argument(
        "--sarif",
        action="append",
        type=str,
        default=None,
        help="path to a SARIF 2.1.0 static-analysis report (repeatable; e.g. semgrep, trivy)",
    )
    p.add_argument("--patch-coverage-min", type=float, default=0.80)
    p.add_argument("--overall-coverage-min", type=float, default=0.60)
    p.add_argument("--min-rcs", type=int, default=0, help="Minimum acceptable RCS score threshold")
    p.add_argument("--out", default="attestation.unsigned.json")
    p.add_argument("--sign", action="store_true", help="perform keyless Sigstore signing")
    p.add_argument("--dry-run-sign", action="store_true", help="simulate DSSE envelope creation without OIDC")
    p.add_argument("--skip-perf-budget-check", action="store_true")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    raw_argv = argv if argv is not None else sys.argv[1:]

    # `plinth`/`plinth-assay verify ...` dispatches to the standalone
    # admission gatekeeper instead of the attestation-building pipeline below.
    if raw_argv and raw_argv[0] == "verify":
        from .verify import main as verify_main

        return verify_main(raw_argv[1:])

    args = parse_args(argv or sys.argv[1:])
    t_start = time.perf_counter()

    # 1. Parse test report
    test_totals = parse_junit_xml(args.junit_xml)

    # 2. Parse coverage report
    if args.coverage_format == "cobertura":
        coverage = parse_cobertura(args.coverage_report)
    else:
        coverage = parse_lcov(args.coverage_report)

    # 3. Patch coverage via git diff
    patch_cov = compute_patch_coverage(args.base_sha, args.head_sha, args.repo_dir, coverage)

    # 3b. Branch governance / ruleset inspection (ambient GITHUB_TOKEN unless overridden)
    branch_governance = inspect_branch_governance(args.repository, args.branch, token=args.github_token)

    # 3c. SARIF static-analysis ingestion (optional, --sarif may repeat).
    # sarif_report stays None when --sarif wasn't passed at all -- scorer
    # and builder both treat that as "not configured", not as a failure.
    sarif_report = None
    if args.sarif:
        patch_modified_lines = compute_patch_modified_lines(args.base_sha, args.head_sha, args.repo_dir)
        parsed_reports = []
        for sarif_path in args.sarif:
            report = parse_sarif_file(sarif_path, patch_modified_lines=patch_modified_lines)
            if not report.available:
                print(
                    f"WARNING: SARIF report '{sarif_path}' could not be read/parsed: "
                    f"{'; '.join(report.reasons)}",
                    file=sys.stderr,
                )
            parsed_reports.append(report)
        sarif_report = aggregate_sarif_reports(parsed_reports)
        if not sarif_report.available:
            print(
                f"WARNING: static analysis (SARIF) ingestion degraded: {'; '.join(sarif_report.reasons)}",
                file=sys.stderr,
            )

    # 4. Hash evidence artifacts
    test_report_sha = sha256_file(args.junit_xml)
    coverage_report_sha = sha256_file(args.coverage_report)
    image_digest = args.image_digest.strip().lower()
    if image_digest.startswith("sha256:"):
        image_digest = image_digest[7:]

    # 5. Assertion metrics (AST-walked test suite scoped to args.repo_dir)
    ast_metrics = inspect_test_suite(args.repo_dir)
    total_assertions = ast_metrics.total_assertions
    total_test_functions = ast_metrics.total_test_functions
    empty_bodies = ast_metrics.empty_test_bodies
    tautological = ast_metrics.tautological_assertions

    # 6. Deterministic scoring
    pr_approvers = [a.strip() for a in args.pr_approvers.split(",") if a.strip()]
    rcs = score_pipeline(
        test_totals=test_totals,
        patch_coverage=patch_cov,
        overall_line_rate=coverage.overall_line_rate,
        total_assertions=total_assertions,
        total_test_functions=total_test_functions,
        pr_present=args.pr_number is not None,
        approvers_count=len(pr_approvers),
        required_approvals=args.pr_required_approvals,
        review_state=args.pr_review_state,
        patch_coverage_min=args.patch_coverage_min,
        overall_coverage_min=args.overall_coverage_min,
        branch_governance=branch_governance,
        sarif_report=sarif_report,
    )

    # 7. Build unsigned in-toto Statement
    statement = build_statement(
        subject_name=args.image_ref,
        subject_sha256=image_digest,
        vcs_provider="github",
        repository=args.repository,
        branch=args.branch,
        commit_sha=args.head_sha,
        base_commit_sha=args.base_sha,
        pr_number=args.pr_number,
        pr_target_branch=args.branch,
        pr_approvers=pr_approvers,
        pr_required_approvals=args.pr_required_approvals,
        pr_review_state=args.pr_review_state,
        branch_governance=branch_governance,
        test_framework="junit",
        test_report_sha256=test_report_sha,
        test_report_uri=worm_uri(test_report_sha),
        test_totals=test_totals,
        coverage_format=f"{args.coverage_format}-xml" if args.coverage_format == "cobertura" else "lcov",
        coverage_report_sha256=coverage_report_sha,
        coverage_report_uri=worm_uri(coverage_report_sha),
        coverage=coverage,
        patch_coverage=patch_cov,
        patch_coverage_min=args.patch_coverage_min,
        overall_coverage_min=args.overall_coverage_min,
        total_assertions=total_assertions,
        total_test_functions=total_test_functions,
        empty_test_bodies=empty_bodies,
        assertion_only_true=tautological,
        rcs=rcs,
        sarif_report=sarif_report,
    )

    blocking_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(statement, f, indent=2)

    # 8. Async WORM uploads
    upload_to_worm_async(args.junit_xml, test_report_sha)
    upload_to_worm_async(args.coverage_report, coverage_report_sha)

    # 9. Keyless signing
    if args.sign or args.dry_run_sign:
        from .oidc_signer import sign_statement

        with open(args.out, "rb") as f:
            envelope = sign_statement(f.read(), dry_run=args.dry_run_sign)

        signed_path = derive_signed_path(args.out)

        with open(signed_path, "w", encoding="utf-8") as f:
            f.write(envelope.to_json())
        print(f"signed envelope written to {signed_path}", file=sys.stderr)

    print(
        f"RCS={rcs.value} blocking_overhead_ms={blocking_elapsed_ms:.2f} degraded={rcs.degraded}",
        file=sys.stderr,
    )

    if not branch_governance.available:
        print(
            f"WARNING: branch governance for '{args.branch}' could not be verified: {branch_governance.reason}",
            file=sys.stderr,
        )
    elif bypass_permits_unreviewed_change(branch_governance):
        print(
            f"WARNING: branch '{args.branch}' rules permit an unreviewed bypass", file=sys.stderr
        )
    for w in branch_governance.warnings:
        print(f"WARNING: branch governance: {w}", file=sys.stderr)

    if not args.skip_perf_budget_check and blocking_elapsed_ms > 50.0:
        print(
            f"WARNING: blocking overhead {blocking_elapsed_ms:.2f}ms exceeded the 50ms budget",
            file=sys.stderr,
        )

    # 10. Gate enforcement
    if rcs.value < args.min_rcs:
        print(
            f"ERROR: RCS score {rcs.value} is below required gate threshold of {args.min_rcs}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
