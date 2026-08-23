#!/usr/bin/env python3
"""
tenax-assay: single-binary CI attestation & governance engine.

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
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .builder import build_statement
from .common import safe_resolve_path
from .hashing import sha256_file, worm_uri
from .parsers.ast import inspect_test_suite
from .parsers.coverage import parse_cobertura, parse_lcov
from .parsers.github_rules import BranchGovernanceReport, bypass_permits_unreviewed_change, inspect_branch_governance
from .parsers.junit import parse_junit_xml
from .parsers.lockfiles import detect_and_parse_dependencies
from .parsers.sarif import (
    SarifSummaryReport,
    aggregate_sarif_reports,
    merge_sonar_metrics_into_tools,
    parse_sarif_file,
    parse_sonar_metrics_file,
)
from .patch_coverage import compute_patch_coverage, compute_patch_modified_lines
from .scorer import RCSResult, score_pipeline
from .slsa_provenance import build_slsa_provenance_statement

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="worm-upload")

# Ordered (stage_ns key, display label) pairs for the --debug stage-timing
# report. A stage's key can be accumulated into from more than one code
# block (e.g. "parse_inputs" covers both the JUnit/coverage parse *and* the
# SARIF report parse, even though the latter runs later in main() -- it
# needs compute_patch_modified_lines()'s git diff first) -- _stage() adds
# to any existing value under the same key rather than overwriting it, so
# splitting a logical stage across multiple `with _stage(...)` blocks is
# safe and its total is still reported as one line.
_STAGE_LABELS = [
    ("parse_inputs", "Inputs & Parsing"),
    ("diff_patch_analysis", "Diff & Patch Coverage"),
    ("ast_inspection", "AST Assertion Walking"),
    ("github_rules_api", "GitHub Ruleset API"),
    ("rcs_scoring", "RCS Scoring Engine"),
    ("lockfile_dependencies", "Lockfile Dependency Detection"),
    ("predicate_assembly", "Predicate Serialization"),
    ("worm_upload", "WORM Upload Dispatch"),
]


@contextmanager
def _stage(stage_ns: Dict[str, int], name: str) -> Iterator[None]:
    """High-resolution (perf_counter_ns) timer for one profiling stage.
    Accumulates into stage_ns[name] (rather than overwriting) so a logical
    stage spread across multiple non-adjacent code blocks still reports as
    a single total -- see _STAGE_LABELS above."""
    t0 = time.perf_counter_ns()
    try:
        yield
    finally:
        stage_ns[name] = stage_ns.get(name, 0) + (time.perf_counter_ns() - t0)


def _fmt_ms(elapsed_ns: int) -> str:
    return f"{elapsed_ns / 1_000_000.0:,.1f} ms"


def _fmt_s(elapsed_ns: int) -> str:
    return f"{elapsed_ns / 1_000_000_000.0:.2f} s"


def _emit_stage_profile(
    stage_ns: Dict[str, int],
    sign_total_ns: Optional[int],
    sign_sub_ns: Dict[str, int],
    blocking_elapsed_ms: float,
    wall_elapsed_ns: int,
) -> None:
    """Prints the formatted per-stage timing breakdown to stderr (--debug
    only). Sigstore signing -- the dominant cost on a typical CI run, since
    it's a real network round-trip to Fulcio + Rekor -- is broken out into
    its own OIDC-fetch / Fulcio-Rekor sub-lines rather than folded into the
    single blocking-overhead figure the 50ms budget check already covers;
    see cli/oidc_signer.py::sign_statement's `timing` param."""
    label_w = 28
    print("=== Tenax Assay Stage Profiling ===", file=sys.stderr)
    for key, label in _STAGE_LABELS:
        print(f"- {label + ':':<{label_w}}{_fmt_ms(stage_ns.get(key, 0)):>12}", file=sys.stderr)
    if sign_total_ns is not None:
        print(f"- {'Sigstore Signing (Total):':<{label_w}}{_fmt_ms(sign_total_ns):>12}", file=sys.stderr)
        sub_rows = [
            ("OIDC Token Fetch:", sign_sub_ns.get("oidc_token_fetch_ns", 0)),
            ("Fulcio/Rekor Round-Trip:", sign_sub_ns.get("fulcio_rekor_ns", 0)),
        ]
        sub_w = max(len(sub_label) for sub_label, _ in sub_rows) + 1
        for sub_label, sub_ns in sub_rows:
            print(f"    ↳ {sub_label:<{sub_w}}{_fmt_ms(sub_ns):>12}", file=sys.stderr)
    print(
        f"Total Blocking Overhead: {blocking_elapsed_ms:>10,.1f} ms (excluding Sigstore network)",
        file=sys.stderr,
    )
    print(f"Total Wall-Clock Time:   {_fmt_s(wall_elapsed_ns):>13}", file=sys.stderr)
    print("====================================", file=sys.stderr)


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


def derive_slsa_provenance_path(out_path: str, explicit: Optional[str]) -> str:
    """Output path for --emit-slsa-provenance's second statement: honors
    --slsa-provenance-out verbatim when given, otherwise derives one from
    --out the same way derive_signed_path() derives the signed-envelope
    path, so the two outputs sit side by side (e.g.
    attestation.unsigned.json -> attestation.slsa-provenance.unsigned.json)
    without a caller having to spell out a second full path by hand."""
    if explicit:
        return explicit
    if out_path.endswith(".unsigned.json"):
        base_out = out_path[: -len(".unsigned.json")]
        return f"{base_out}.slsa-provenance.unsigned.json"
    if out_path.endswith(".json"):
        base_out = out_path[: -len(".json")]
        return f"{base_out}.slsa-provenance.json"
    return f"{out_path}.slsa-provenance.json"


def _maybe_emit_slsa_provenance(
    args: argparse.Namespace,
    *,
    image_digest: str,
    pipeline_started_at: str,
    resolved_dependencies: Optional[List[Dict[str, Any]]],
) -> Optional[str]:
    """Step 7b: builds and writes the --emit-slsa-provenance second
    statement (see cli/slsa_provenance.py), returning the path it was
    written to, or None when the flag wasn't passed. Extracted (same
    rationale as _detect_lockfile_dependencies/_maybe_sign above) so it's
    unit-testable directly with a tmp dir and a plain argparse.Namespace,
    rather than only reachable by driving main() end to end."""
    if not args.emit_slsa_provenance:
        return None

    slsa_statement = build_slsa_provenance_statement(
        subject_name=args.image_ref,
        subject_sha256=image_digest,
        started_at=pipeline_started_at,
        resolved_dependencies=resolved_dependencies,
    )
    slsa_provenance_out_path = safe_resolve_path(derive_slsa_provenance_path(args.out, args.slsa_provenance_out))
    with open(slsa_provenance_out_path, "w", encoding="utf-8") as f:
        json.dump(slsa_statement, f, indent=2)
    return slsa_provenance_out_path


def upload_to_worm_async(local_path: str, sha256_hex: str, bucket: str = "evidence"):
    """Fire-and-forget evidence storage dispatch."""
    def _upload():
        # Integration point for S3/MinIO Object Lock COMPLIANCE storage
        pass

    return _executor.submit(_upload)


def _merge_sonar_metrics(sonar_metrics_path: str, sarif_report: SarifSummaryReport) -> None:
    """--sonar-metrics enriches an existing SARIF tool's extensions; it
    never creates a new tool entry or a scoring input of its own, so a
    parse/merge failure here only ever warns (see main()'s step 3c)."""
    sonar_extension = parse_sonar_metrics_file(sonar_metrics_path)
    if sonar_extension is None:
        print(
            f"WARNING: --sonar-metrics '{sonar_metrics_path}' could not be read/parsed; "
            "skipping SonarQube metrics enrichment",
            file=sys.stderr,
        )
    elif not merge_sonar_metrics_into_tools(sarif_report.tools, sonar_extension):
        print(
            f"WARNING: --sonar-metrics '{sonar_metrics_path}' had no unambiguous SARIF tool to attach to "
            "(no tool named like 'sonar*' and more than one tool was scanned); skipping enrichment",
            file=sys.stderr,
        )


def _ingest_sarif(args: argparse.Namespace, stage_ns: Dict[str, int]) -> Optional[SarifSummaryReport]:
    """Step 3c: SARIF static-analysis ingestion (optional, --sarif may
    repeat). Returns None when --sarif wasn't passed at all -- scorer and
    builder both treat that as "not configured", not as a failure."""
    if not args.sarif:
        if args.sonar_metrics:
            print(
                "WARNING: --sonar-metrics was given without any --sarif input to attach it to; ignoring",
                file=sys.stderr,
            )
        return None

    with _stage(stage_ns, "diff_patch_analysis"):
        patch_modified_lines = compute_patch_modified_lines(args.base_sha, args.head_sha, args.repo_dir)
    with _stage(stage_ns, "parse_inputs"):
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
    elif args.sonar_metrics:
        _merge_sonar_metrics(args.sonar_metrics, sarif_report)

    return sarif_report


def _detect_lockfile_dependencies(args: argparse.Namespace, stage_ns: Dict[str, int]) -> List[Dict[str, Any]]:
    """Step 6b: auto-detects and parses lockfiles under args.repo_dir
    (uv.lock/package-lock.json/go.sum/Gradle/Maven -- see
    cli.parsers.lockfiles) into the predicate's resolved_dependencies.
    Scoring-independent -- feeds build_statement() only. Extracted (same
    rationale as _ingest_sarif above) so it's unit-testable directly
    rather than only reachable by driving main() end to end."""
    with _stage(stage_ns, "lockfile_dependencies"):
        return detect_and_parse_dependencies(args.repo_dir)


def _maybe_sign(args: argparse.Namespace, out_path) -> Tuple[Optional[int], Dict[str, int]]:
    """Step 9: keyless Sigstore signing, gated on --sign/--dry-run-sign.
    Returns (sign_total_ns, sign_sub_ns) for --debug's stage-profile
    report; sign_total_ns is None when neither flag was passed."""
    if not (args.sign or args.dry_run_sign):
        return None, {}

    from .oidc_signer import sign_statement

    with open(out_path, "rb") as f:
        envelope_bytes = f.read()

    sign_sub_ns: Dict[str, int] = {}
    t0 = time.perf_counter_ns()
    envelope = sign_statement(envelope_bytes, dry_run=args.dry_run_sign, timing=sign_sub_ns)
    sign_total_ns = time.perf_counter_ns() - t0

    signed_path = safe_resolve_path(derive_signed_path(str(out_path)))
    with open(signed_path, "w", encoding="utf-8") as f:
        f.write(envelope.to_json())
    print(f"signed envelope written to {signed_path}", file=sys.stderr)

    return sign_total_ns, sign_sub_ns


def _emit_run_warnings(
    rcs: RCSResult,
    branch_governance: BranchGovernanceReport,
    branch: str,
    blocking_elapsed_ms: float,
    skip_perf_budget_check: bool,
) -> None:
    """Post-run stderr summary: RCS/degraded status, branch-governance
    issues, and the 50ms blocking-overhead budget check
    (--skip-perf-budget-check)."""
    print(
        f"RCS={rcs.value} blocking_overhead_ms={blocking_elapsed_ms:.2f} degraded={rcs.degraded}",
        file=sys.stderr,
    )
    if rcs.degraded and rcs.degraded_reasons:
        print(f"degraded_reasons={rcs.degraded_reasons}", file=sys.stderr)

    if not branch_governance.available:
        print(
            f"WARNING: branch governance for '{branch}' could not be verified: {branch_governance.reason}",
            file=sys.stderr,
        )
    elif bypass_permits_unreviewed_change(branch_governance):
        print(f"WARNING: branch '{branch}' rules permit an unreviewed bypass", file=sys.stderr)
    for w in branch_governance.warnings:
        print(f"WARNING: branch governance: {w}", file=sys.stderr)

    if not skip_perf_budget_check and blocking_elapsed_ms > 50.0:
        print(
            f"WARNING: blocking overhead {blocking_elapsed_ms:.2f}ms exceeded the 50ms budget",
            file=sys.stderr,
        )


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="tenax-assay",
        description="tenax-assay: single-binary CI attestation & governance engine.",
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
        help="path to a SARIF 2.1.0 static-analysis report (repeatable; e.g. semgrep, trivy, SonarQube)",
    )
    p.add_argument(
        "--sonar-metrics",
        default=None,
        dest="sonar_metrics",
        help="path to a SonarQube 'api/measures/component' JSON export; merges quality-gate/cognitive-complexity/"
        "technical-debt metrics into the SonarQube tool's extensions when a --sarif input didn't already embed "
        "them (requires at least one --sarif input to attach to)",
    )
    p.add_argument("--patch-coverage-min", type=float, default=0.80)
    p.add_argument("--overall-coverage-min", type=float, default=0.60)
    p.add_argument("--min-rcs", type=int, default=0, help="Minimum acceptable RCS score threshold")
    p.add_argument("--out", default="attestation.unsigned.json")
    p.add_argument("--sign", action="store_true", help="perform keyless Sigstore signing")
    p.add_argument("--dry-run-sign", action="store_true", help="simulate DSSE envelope creation without OIDC")
    p.add_argument(
        "--emit-slsa-provenance",
        action="store_true",
        dest="emit_slsa_provenance",
        help="additionally emit a second, separate in-toto Statement shaped as real SLSA v1.0 provenance "
        "(predicateType https://slsa.dev/provenance/v1) alongside tenax-assay's own RCS predicate -- see "
        "cli/slsa_provenance.py. Populated only from real ambient GitHub Actions context (GITHUB_REPOSITORY/"
        "SHA/RUN_ID/WORKFLOW_REF, RUNNER_ENVIRONMENT); fields with no real value off-CI are simply omitted, "
        "never fabricated, so an off-CI run legitimately produces a less-complete statement.",
    )
    p.add_argument(
        "--slsa-provenance-out",
        default=None,
        dest="slsa_provenance_out",
        help="output path for the --emit-slsa-provenance statement (default: derived from --out, e.g. "
        "attestation.slsa-provenance.unsigned.json)",
    )
    p.add_argument("--skip-perf-budget-check", action="store_true")
    p.add_argument(
        "--debug",
        action="store_true",
        help="emit a high-resolution per-stage timing breakdown (parsing, diff/patch "
        "coverage, AST walk, GitHub ruleset API, scoring, predicate assembly, WORM "
        "dispatch, Sigstore signing) to stderr",
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    raw_argv = argv if argv is not None else sys.argv[1:]

    # `tenax`/`tenax-assay verify ...` dispatches to the standalone
    # admission gatekeeper instead of the attestation-building pipeline below.
    if raw_argv and raw_argv[0] == "verify":
        from .verify import main as verify_main

        return verify_main(raw_argv[1:])

    # `tenax-assay run ...` is an explicit alias for the attestation
    # pipeline below -- it's also what runs with no subcommand at all, so
    # `run` is stripped rather than required, keeping `tenax-assay --sarif
    # ...` (no subcommand) working exactly as before.
    if raw_argv and raw_argv[0] == "run":
        raw_argv = raw_argv[1:]

    args = parse_args(raw_argv)
    t_start = time.perf_counter()
    t_start_ns = time.perf_counter_ns()
    pipeline_started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stage_ns: Dict[str, int] = {}

    # 1. Parse test report
    with _stage(stage_ns, "parse_inputs"):
        test_totals = parse_junit_xml(args.junit_xml)

        # 2. Parse coverage report
        if args.coverage_format == "cobertura":
            coverage = parse_cobertura(args.coverage_report)
        else:
            coverage = parse_lcov(args.coverage_report)

    # 3. Patch coverage via git diff
    with _stage(stage_ns, "diff_patch_analysis"):
        patch_cov = compute_patch_coverage(args.base_sha, args.head_sha, args.repo_dir, coverage)

    # 3b. Branch governance / ruleset inspection (ambient GITHUB_TOKEN unless overridden)
    with _stage(stage_ns, "github_rules_api"):
        branch_governance = inspect_branch_governance(args.repository, args.branch, token=args.github_token)

    # 3c. SARIF static-analysis ingestion (optional, --sarif may repeat).
    # sarif_report stays None when --sarif wasn't passed at all -- scorer
    # and builder both treat that as "not configured", not as a failure.
    sarif_report = _ingest_sarif(args, stage_ns)

    # 4. Hash evidence artifacts
    test_report_sha = sha256_file(args.junit_xml)
    coverage_report_sha = sha256_file(args.coverage_report)
    image_digest = args.image_digest.strip().lower()
    if image_digest.startswith("sha256:"):
        image_digest = image_digest[7:]

    # 5. Assertion metrics (AST-walked test suite scoped to args.repo_dir)
    with _stage(stage_ns, "ast_inspection"):
        ast_metrics = inspect_test_suite(args.repo_dir)
        total_assertions = ast_metrics.total_assertions
        total_test_functions = ast_metrics.total_test_functions
        empty_bodies = ast_metrics.empty_test_bodies
        tautological = ast_metrics.tautological_assertions
        ast_skipped = ast_metrics.skipped_test_functions
        ast_languages = {lang: m.as_dict() for lang, m in ast_metrics.languages.items()}

    # 6. Deterministic scoring
    pr_approvers = [a.strip() for a in args.pr_approvers.split(",") if a.strip()]
    with _stage(stage_ns, "rcs_scoring"):
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
            ast_skipped_test_functions=ast_skipped,
        )

    # 6b. Lockfile dependency detection (see _detect_lockfile_dependencies)
    resolved_dependencies = _detect_lockfile_dependencies(args, stage_ns)

    # 7. Build unsigned in-toto Statement
    with _stage(stage_ns, "predicate_assembly"):
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
            ast_skipped_test_functions=ast_skipped,
            ast_languages=ast_languages,
            resolved_dependencies=resolved_dependencies,
        )

    blocking_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

    out_path = safe_resolve_path(args.out)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(statement, f, indent=2)

    # 7b. --emit-slsa-provenance: a second, separate in-toto Statement
    # shaped as real SLSA v1.0 provenance (see cli/slsa_provenance.py).
    # Independent of the RCS predicate above -- same subject digest, but
    # its own file and (if --sign/--dry-run-sign) its own DSSE envelope.
    slsa_provenance_out_path = _maybe_emit_slsa_provenance(
        args,
        image_digest=image_digest,
        pipeline_started_at=pipeline_started_at,
        resolved_dependencies=resolved_dependencies,
    )

    # 8. Async WORM uploads (fire-and-forget: the timed cost here is only
    # the dispatch/submission overhead, not the background upload itself)
    with _stage(stage_ns, "worm_upload"):
        upload_to_worm_async(args.junit_xml, test_report_sha)
        upload_to_worm_async(args.coverage_report, coverage_report_sha)

    # 9. Keyless signing
    sign_total_ns, sign_sub_ns = _maybe_sign(args, out_path)
    if slsa_provenance_out_path is not None:
        _maybe_sign(args, slsa_provenance_out_path)

    if args.debug:
        wall_elapsed_ns = time.perf_counter_ns() - t_start_ns
        _emit_stage_profile(stage_ns, sign_total_ns, sign_sub_ns, blocking_elapsed_ms, wall_elapsed_ns)

    _emit_run_warnings(rcs, branch_governance, args.branch, blocking_elapsed_ms, args.skip_perf_budget_check)

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
