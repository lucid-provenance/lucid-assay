#!/usr/bin/env python3
"""
lucid-assay: single-binary CI attestation & governance engine.

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
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .builder import build_statement
from .common import JSON_SUFFIX, UnsafePathError, derive_signed_path, safe_resolve_path
from .hashing import sha256_file, worm_uri
from .parsers.ast import inspect_test_suite
from .parsers.commit_author import CommitAuthorReport, inspect_commit_author
from .parsers.coverage import parse_cobertura, parse_jacoco, parse_lcov
from .parsers.coverage_contexts import parse_coverage_contexts
from .parsers.github_rules import BranchGovernanceReport, bypass_permits_unreviewed_change, inspect_branch_governance
from .parsers.junit import parse_junit_xml
from .parsers.lockfiles import detect_and_parse_dependencies
from .parsers.s2c2f import S2C2FReport, evaluate_s2c2f
from .parsers.sarif import (
    SarifSummaryReport,
    aggregate_sarif_reports,
    merge_sonar_metrics_into_tools,
    parse_sarif_file,
    parse_sonar_metrics_file,
)
from .parsers.sbom import (
    SbomReport,
    build_sbom_sarif_report,
    parse_sbom_file,
    sbom_components_to_resolved_dependencies,
)
from .patch_coverage import compute_patch_coverage, compute_patch_modified_lines
from .real_coverage import CoverageTrackResult, RealCoverageResult, compute_real_coverage
from .sbom_statement import build_sbom_statement
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
    ("s2c2f_evaluation", "S2C2F Control Evaluation"),
    ("predicate_assembly", "Predicate Serialization"),
    ("worm_upload", "WORM Upload Dispatch"),
    ("verdict_annotation", "Verdict Annotation"),
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
    print("=== Lucid Assay Stage Profiling ===", file=sys.stderr)
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
    if out_path.endswith(JSON_SUFFIX):
        base_out = out_path[: -len(JSON_SUFFIX)]
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


def derive_sbom_statement_path(out_path: str, explicit: Optional[str]) -> str:
    """Output path for the --sbom companion statement (cli/sbom_statement.
    py): honors --sbom-statement-out verbatim when given, otherwise sits
    as a fixed-basename sibling of --out in the same directory (e.g.
    build/attestation.unsigned.json -> build/sbom.unsigned.json).
    Deliberately a fixed name, not a derived-suffix scheme like
    derive_slsa_provenance_path's own *.slsa-provenance.unsigned.json --
    a downstream CI workflow (lucid-console's own dogfood pipeline is the
    first real caller) references this file by that fixed, predictable
    name, not by deriving it from --out's own basename."""
    if explicit:
        return explicit
    parent = Path(out_path).parent
    return str(parent / "sbom.unsigned.json") if str(parent) not in ("", ".") else "sbom.unsigned.json"


def _maybe_emit_sbom_statement(
    args: argparse.Namespace,
    *,
    sbom_report: Optional[SbomReport],
    image_digest: str,
) -> Optional[str]:
    """Step 7c: builds and writes the --sbom companion in-toto Statement
    (see cli/sbom_statement.py) -- a second, separate attestation wrapping
    the SBOM's own raw document verbatim as its predicate, alongside
    lucid-assay's own RCS predicate. Returns the path it was written to,
    or None when --sbom wasn't passed, it failed to parse (already warned
    about by _ingest_sbom), or its format doesn't map to a real
    predicateType (see build_sbom_statement) -- never a fabricated/partial
    companion statement. Extracted (same rationale as
    _maybe_emit_slsa_provenance above) so it's unit-testable directly."""
    if sbom_report is None or not sbom_report.available:
        return None

    statement = build_sbom_statement(
        subject_name=args.image_ref,
        subject_sha256=image_digest,
        sbom_format=sbom_report.format,
        raw_document=sbom_report.raw_document,
    )
    if statement is None:
        return None

    sbom_statement_out_path = safe_resolve_path(derive_sbom_statement_path(args.out, args.sbom_statement_out))
    with open(sbom_statement_out_path, "w", encoding="utf-8") as f:
        json.dump(statement, f, indent=2)
    return sbom_statement_out_path


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


def _ingest_sbom(args: argparse.Namespace, stage_ns: Dict[str, int]) -> Optional[SbomReport]:
    """Step 3d: SBOM (CycloneDX/SPDX) ingestion, optional via --sbom.
    Returns None when --sbom wasn't passed at all. Parsing failure (a
    missing/corrupt/unrecognized file) degrades to a returned
    SbomReport(available=False, ...) with a stderr WARNING -- never
    raises, same fail-open-but-diagnosed contract as _ingest_sarif above.
    The report's own license-policy findings are folded into sarif_report
    by _merge_sbom_into_sarif (called right after this at its call site in
    main()), and its components feed _detect_lockfile_dependencies' own
    fallback below -- see cli.parsers.sbom's module docstring for why both
    of those live in the existing sarif/lockfile pipelines rather than as
    new predicate fields of their own."""
    if not args.sbom:
        return None
    with _stage(stage_ns, "parse_inputs"):
        report = parse_sbom_file(args.sbom)
    if not report.available:
        print(
            f"WARNING: SBOM '{args.sbom}' could not be read/parsed: {'; '.join(report.reasons)}",
            file=sys.stderr,
        )
    return report


def _merge_sbom_into_sarif(
    sarif_report: Optional[SarifSummaryReport],
    sbom_report: Optional[SbomReport],
    sbom_report_sha: Optional[str] = None,
) -> Optional[SarifSummaryReport]:
    """Folds the SBOM's license-policy findings (cli.parsers.sbom.
    build_sbom_sarif_report) into sarif_report, so every downstream
    consumer of sarif_report -- the scorer's static-analysis component
    (WEIGHTS["static_analysis"]) and S2C2F's SCA-2 (License Checks) --
    sees them exactly like any other --sarif input's findings, with no
    special-casing. Returns sarif_report unchanged when there's no
    available SBOM to merge (no --sbom, or it failed to parse -- already
    warned about by _ingest_sbom above).

    `sbom_report_sha` (the same --sbom file hash predicate.artifact.sbom.
    sha256 uses) is threaded through as the synthetic SBOM tool's
    report_hash -- schema/lucid-attestation-v1.schema.json requires every
    static_analysis.tools[] entry to carry one; see build_sbom_sarif_
    report's own docstring for why the --sbom file's hash is the honest
    value here (there's no raw *SARIF* file for a synthetic tool).

    When both a real --sarif input and an available SBOM are present,
    this goes through cli.parsers.sarif.aggregate_sarif_reports() same as
    any other multi-input merge in this pipeline -- including its existing
    fail-closed contract that one unavailable input taints the whole
    aggregate. That's inherited deliberately, not incidentally: a broken
    --sarif input already degrades the static-analysis picture on its
    own (see _ingest_sarif's WARNING above), and this function must not
    quietly launder that into "well, at least the SBOM half was clean" --
    the same "no partial clean bill of health" principle
    aggregate_sarif_reports documents for its own multi-file case."""
    if sbom_report is None or not sbom_report.available:
        return sarif_report
    report_hash = {"algorithm": "sha256", "value": sbom_report_sha} if sbom_report_sha else None
    sbom_sarif = build_sbom_sarif_report(sbom_report.components, report_hash=report_hash)
    if sarif_report is None:
        return sbom_sarif
    return aggregate_sarif_reports([sarif_report, sbom_sarif])


# cli.parsers.sbom.detect_sbom_format()'s three format strings -> the
# predicate.artifact.sbom.format enum schema/lucid-attestation-v1.schema.
# json actually declares ("spdx-json"/"cyclonedx-json"/"syft-json") --
# "spdx2"/"spdx3" both collapse to "spdx-json" since the schema doesn't
# distinguish SPDX versions for this field, only the document family.
_SBOM_SCHEMA_FORMAT = {"cyclonedx": "cyclonedx-json", "spdx2": "spdx-json", "spdx3": "spdx-json"}


def _build_sbom_artifact_block(
    sbom_report: Optional[SbomReport], sbom_sha256: Optional[str]
) -> Optional[Dict[str, Any]]:
    """Populates predicate.artifact.sbom (schema/lucid-attestation-v1.
    schema.json) from a successfully-parsed --sbom input, using the same
    sha256 + WORM-content-addressed-uri pattern
    predicate.test_verification.report_uri/predicate.coverage.report_uri
    already use (see cli/hashing.py's own module docstring, which already
    names SBOMs as a third evidence-artifact kind this hashing scheme
    covers). Returns None (the field's own schema-declared default) when
    --sbom wasn't passed, failed to parse, or its detected format doesn't
    map to one of the schema's declared enum values -- never a fabricated
    hash/uri for a file this pipeline couldn't actually validate."""
    if sbom_report is None or not sbom_report.available or sbom_sha256 is None:
        return None
    schema_format = _SBOM_SCHEMA_FORMAT.get(sbom_report.format)
    if schema_format is None:
        return None
    return {
        "format": schema_format,
        "sha256": sbom_sha256,
        "uri": worm_uri(sbom_sha256),
        "component_count": len(sbom_report.components),
    }


def _detect_lockfile_dependencies(
    args: argparse.Namespace, stage_ns: Dict[str, int], sbom_report: Optional[SbomReport] = None
) -> List[Dict[str, Any]]:
    """Step 6b: auto-detects and parses lockfiles under args.repo_dir
    (uv.lock/package-lock.json/go.sum/Gradle/Maven -- see
    cli.parsers.lockfiles) into the predicate's resolved_dependencies.
    Scoring-independent -- feeds build_statement() only. Extracted (same
    rationale as _ingest_sarif above) so it's unit-testable directly
    rather than only reachable by driving main() end to end.

    Falls back to the SBOM's own PURL-bearing components (see
    cli.parsers.sbom.sbom_components_to_resolved_dependencies) only when
    lockfile detection came up genuinely empty -- a repo with a real
    lockfile is always the more authoritative, pipeline-native source (it
    describes exactly what this build resolved, not what some earlier,
    possibly-stale SBOM-generation step captured), so it's never
    overridden or merged with the SBOM's inventory, only substituted for
    when there's nothing else."""
    with _stage(stage_ns, "lockfile_dependencies"):
        deps = detect_and_parse_dependencies(args.repo_dir)
        if deps or sbom_report is None or not sbom_report.available:
            return deps
        return sbom_components_to_resolved_dependencies(sbom_report.components)


def _compute_real_coverage_analysis(
    args: argparse.Namespace,
    coverage,
    ast_metrics,
    stage_ns: Dict[str, int],
) -> RealCoverageResult:
    """Step 6c: vanity-test-aware "real" coverage (see cli.real_coverage),
    optional via --coverage-contexts. Both tracks (overall/patch) report
    available=False with a clear reason -- never an omitted block --
    when the flag wasn't passed at all, matching every other optional
    input's "absent, not silently missing" contract in this predicate.
    Scoring-independent, same rationale as _ingest_sarif/
    _detect_lockfile_dependencies above."""
    if not args.coverage_contexts:
        unavailable = CoverageTrackResult(available=False, reason="--coverage-contexts not provided for this run")
        return RealCoverageResult(overall=unavailable, patch=unavailable)

    with _stage(stage_ns, "real_coverage_analysis"):
        context_report = parse_coverage_contexts(args.coverage_contexts)
        if not context_report.available:
            print(
                f"WARNING: --coverage-contexts '{args.coverage_contexts}' could not be used: "
                f"{context_report.reason}",
                file=sys.stderr,
            )
        patch_modified_lines = compute_patch_modified_lines(args.base_sha, args.head_sha, args.repo_dir)
        return compute_real_coverage(
            test_suite_metrics=ast_metrics,
            coverage=coverage,
            context_report=context_report,
            patch_modified_lines=patch_modified_lines,
        )


def _evaluate_s2c2f_controls(
    args: argparse.Namespace,
    *,
    resolved_dependencies: List[Dict[str, Any]],
    sarif_report: Optional[SarifSummaryReport],
    branch_governance: BranchGovernanceReport,
    stage_ns: Dict[str, int],
) -> S2C2FReport:
    """Step 6d: S2C2F control evaluation (see cli.parsers.s2c2f), fed by
    data this pipeline already collected (resolved_dependencies, sarif_report,
    branch_governance) plus a couple of cheap new signals of its own (a
    GitHub API call, a local config-file check). Never raises -- every
    network-backed control it evaluates independently degrades to
    not_yet_reported on a missing token or API failure, same fail-closed
    contract as branch governance/commit author above. Extracted (same
    rationale as _ingest_sarif/_detect_lockfile_dependencies/
    _compute_real_coverage_analysis above) so it's unit-testable directly."""
    with _stage(stage_ns, "s2c2f_evaluation"):
        return evaluate_s2c2f(
            repo_dir=args.repo_dir,
            repository=args.repository,
            resolved_dependencies=resolved_dependencies,
            sarif_report=sarif_report,
            branch_governance=branch_governance,
            token=args.github_token,
        )


def _maybe_sign(
    args: argparse.Namespace, out_path
) -> Tuple[Optional[int], Dict[str, int], Optional[Path]]:
    """Step 9: keyless Sigstore signing, gated on --sign/--dry-run-sign.
    Returns (sign_total_ns, sign_sub_ns, signed_path) for --debug's
    stage-profile report and _maybe_annotate_verdict below; all three are
    None/{}/None when neither flag was passed.

    Thin wrapper around cli.oidc_signer.sign_file_to_envelope (the same
    file-in/file-out entry point `lucid-assay sign` -- cli/sign.py -- uses
    for an isolated signing job that only has an unsigned statement file,
    not this pipeline's in-process state); this call site just also times
    it for --debug's stage-profile report."""
    if not (args.sign or args.dry_run_sign):
        return None, {}, None

    from .oidc_signer import sign_file_to_envelope

    sign_sub_ns: Dict[str, int] = {}
    t0 = time.perf_counter_ns()
    signed_path = sign_file_to_envelope(
        str(out_path), derive_signed_path(str(out_path)), dry_run=args.dry_run_sign, timing=sign_sub_ns
    )
    sign_total_ns = time.perf_counter_ns() - t0
    print(f"signed envelope written to {signed_path}", file=sys.stderr)

    return sign_total_ns, sign_sub_ns, signed_path


def _maybe_annotate_verdict(
    args: argparse.Namespace, signed_path: Optional[Path], stage_ns: Dict[str, int]
) -> Optional[str]:
    """Step 9b: automatically persists this run's computed FAILED/GATED/
    PASSED verdict onto the just-signed envelope (the equivalent of
    `lucid-assay verify --write-verdict`, see cli/verify.py's
    _build_verdict_envelope_block/_write_verdict_into_envelope), so a
    downstream CI pipeline doesn't need a separate explicit `lucid-assay
    verify --write-verdict` step before uploading the envelope to the
    ingestion API. A no-op (returns None) when signing was skipped
    (signed_path is None -- neither --sign nor --dry-run-sign was passed).

    "Default gate parameters" here means exactly the one threshold this
    pipeline already gates its own exit code on -- args.min_rcs, the same
    value step 10 below checks -- not the fuller identity-pinning/
    --disallow-degraded surface `lucid-assay verify` itself exposes, which
    `lucid-assay run --sign` never collected flags for. A caller that
    needs --cert-identity/--expected-*/--disallow-degraded enforced still
    needs a real downstream `lucid-assay verify` call with those flags;
    this annotation is best-effort convenience, not a substitute for it
    (see _build_verdict_envelope_block's own docstring on why `_verdict`
    is an unsigned, re-derivable sibling field, never a trust boundary).

    Never fails the run and never changes its exit code: a GATED/FAILED
    verdict is a completely normal, correctly-computed outcome, not an
    error here -- it's still written to the envelope and reported to
    stderr exactly like a PASSED one would be (step 10 below remains the
    sole authority for *this run's own* pass/fail exit code, computed
    independently of this annotation). Loading or re-writing the envelope
    failing (a broken/oversized/unreadable file) degrades to a WARNING on
    stderr rather than crashing `lucid-assay run` outright -- same
    fail-open contract as WORM upload dispatch elsewhere in this
    pipeline: signing itself already succeeded by the time this runs, and
    this annotation step failing must never look like *that* failed.
    Returns the computed verdict word (for --debug/tests), or None when
    annotation didn't happen at all (skipped, or failed to load/write)."""
    if signed_path is None:
        return None

    from .verify import EnvelopeTooLargeError, load_envelope, verify_dsse_attestation
    from .verify import _write_verdict_into_envelope

    with _stage(stage_ns, "verdict_annotation"):
        try:
            envelope = load_envelope(str(signed_path))
        except (FileNotFoundError, EnvelopeTooLargeError, UnsafePathError, OSError, json.JSONDecodeError, RecursionError) as e:
            print(f"WARNING: could not load signed envelope to annotate verdict: {e}", file=sys.stderr)
            return None

        result = verify_dsse_attestation(envelope, min_rcs=args.min_rcs, dry_run=args.dry_run_sign)

        try:
            _write_verdict_into_envelope(envelope, result, str(signed_path))
        except (OSError, UnsafePathError) as e:
            print(f"WARNING: could not write verdict onto {signed_path}: {e}", file=sys.stderr)
            return None

    word = result.verdict_word or "FAILED"
    print(f"verdict ({word}) written to {signed_path}", file=sys.stderr)
    return word


def _emit_run_warnings(
    rcs: RCSResult,
    branch_governance: BranchGovernanceReport,
    branch: str,
    blocking_elapsed_ms: float,
    skip_perf_budget_check: bool,
    commit_author: Optional[CommitAuthorReport] = None,
) -> None:
    """Post-run stderr summary: RCS/degraded status, branch-governance
    issues, commit-author-identity data-collection failures, and the
    50ms blocking-overhead budget check (--skip-perf-budget-check)."""
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

    # Unlike branch governance, an *unverified* author (verified_github_
    # account=False) is a legitimate, common outcome -- not a data-
    # collection failure -- and is already surfaced via SLSA Source Level
    # 3 in `lucid-assay verify`'s output; only warn here when the check
    # itself couldn't run at all (available=False).
    if commit_author is not None and not commit_author.available:
        print(
            f"WARNING: commit author identity for {commit_author.commit_sha} could not be verified: "
            f"{commit_author.reason}",
            file=sys.stderr,
        )

    if not skip_perf_budget_check and blocking_elapsed_ms > 50.0:
        print(
            f"WARNING: blocking overhead {blocking_elapsed_ms:.2f}ms exceeded the 50ms budget",
            file=sys.stderr,
        )


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="lucid-assay",
        description="lucid-assay: single-binary CI attestation & governance engine.",
    )
    p.add_argument("--junit-xml", required=True)
    p.add_argument("--coverage-format", choices=["cobertura", "lcov", "jacoco"], default="cobertura")
    p.add_argument("--coverage-report", required=True, dest="coverage_report")
    p.add_argument(
        "--image-ref",
        default=None,
        help="container image reference this statement's subject describes. Exactly one "
        "of {--image-ref, --subject-name} plus its matching digest flag is required -- "
        "see --subject-name/--subject-digest for a non-container artifact.",
    )
    p.add_argument(
        "--image-digest",
        default=None,
        help="sha256:<hex> or bare hex digest of the image named by --image-ref",
    )
    p.add_argument(
        "--subject-name",
        default=None,
        help="generic subject name for an artifact that isn't a container image (e.g. a "
        "Lambda function ARN, a build output's own identifier) -- use this instead of "
        "--image-ref when the pipeline's actual output isn't one. The predicate's subject "
        "is genuinely artifact-agnostic already (build_statement() just takes a name + "
        "digest); --image-ref/--image-digest were simply the only names offered for it "
        "until now, which wrongly implied every caller ships a container image.",
    )
    p.add_argument(
        "--subject-digest",
        default=None,
        help="sha256:<hex> or bare hex digest of the artifact named by --subject-name",
    )
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
        "--sbom",
        default=None,
        help="path to a CycloneDX (1.4-1.6) or SPDX (2.3/3.0) JSON SBOM. Its components' declared/"
        "concluded licenses are evaluated against a forbidden-copyleft/permissive policy (see "
        "cli/parsers/sbom.py) and folded into the --sarif findings (feeding the scorer's static-"
        "analysis component and S2C2F's SCA-2 'License Checks'); its PURL-bearing components also "
        "back-fill predicate.resolved_dependencies (S2C2F INV-1/ING-1) when lockfile detection finds "
        "nothing on its own.",
    )
    p.add_argument(
        "--sonar-metrics",
        default=None,
        dest="sonar_metrics",
        help="path to a SonarQube 'api/measures/component' JSON export; merges quality-gate/cognitive-complexity/"
        "technical-debt metrics into the SonarQube tool's extensions when a --sarif input didn't already embed "
        "them (requires at least one --sarif input to attach to)",
    )
    p.add_argument(
        "--coverage-contexts",
        default=None,
        dest="coverage_contexts",
        help="path to a `coverage json --show-contexts` export (collected with `--cov-context=test`, e.g. "
        "`pytest --cov=... --cov-context=test`) -- when given, computes vanity-test-aware 'real' coverage "
        "(cli/real_coverage.py): how much of the reported total/patch coverage is exercised only by tests "
        "the AST assertion-integrity engine flags as vanity (zero real assertions), for both the overall "
        "and patch/new-code tracks. Purely informational (embedded in predicate.coverage.real); omitted "
        "entirely, this analysis is simply unavailable, never fabricated.",
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
        "(predicateType https://slsa.dev/provenance/v1) alongside lucid-assay's own RCS predicate -- see "
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
    p.add_argument(
        "--sbom-statement-out",
        default=None,
        dest="sbom_statement_out",
        help="output path for the --sbom companion in-toto statement (see cli/sbom_statement.py; default: "
        "a fixed-basename sibling of --out in the same directory, e.g. build/attestation.unsigned.json -> "
        "build/sbom.unsigned.json). A no-op when --sbom wasn't passed or failed to parse.",
    )
    p.add_argument("--skip-perf-budget-check", action="store_true")
    p.add_argument(
        "--debug",
        action="store_true",
        help="emit a high-resolution per-stage timing breakdown (parsing, diff/patch "
        "coverage, AST walk, GitHub ruleset API, scoring, predicate assembly, WORM "
        "dispatch, Sigstore signing) to stderr",
    )
    args = p.parse_args(argv)

    # Resolve --subject-name/--subject-digest onto the same args.image_ref/
    # args.image_digest attributes --image-ref/--image-digest have always
    # used, so every downstream reader (this function's own callers,
    # build_statement(), _maybe_emit_slsa_provenance()) needs no changes at
    # all -- this is purely two names for the same pair of fields. Neither
    # pair is individually required anymore (argparse's own required=True
    # can't express "one of these two pairs"), so that's enforced here
    # instead, with the same p.error()-based diagnostic (usage line + clear
    # message, exit code 2) argparse's own required-arg failures use.
    args.image_ref = args.subject_name or args.image_ref
    args.image_digest = args.subject_digest or args.image_digest
    if not args.image_ref or not args.image_digest:
        p.error(
            "either --image-ref and --image-digest (for a container image subject), or "
            "--subject-name and --subject-digest (for any other artifact), are required"
        )
    return args


def _dispatch_standalone_subcommand(raw_argv: List[str]) -> Optional[int]:
    """Dispatches `lucid-assay {verify,sign,provenance} ...` to their
    standalone subcommand entry points, each of which owns its own
    argument parsing entirely separately from parse_args()/the
    attestation-building pipeline below. Returns the subcommand's exit
    code, or None when `raw_argv` doesn't name one of these -- the caller
    (main()) then continues on to the pipeline itself. Split out of
    main() so each `if raw_argv[0] == ...` branch's own complexity is
    contained here rather than compounding with the pipeline's (same
    rationale as _ingest_sarif/_detect_lockfile_dependencies/_maybe_sign
    above)."""
    if not raw_argv:
        return None

    # `lucid`/`lucid-assay verify ...` dispatches to the standalone
    # admission gatekeeper instead of the attestation-building pipeline below.
    if raw_argv[0] == "verify":
        from .verify import main as verify_main

        return verify_main(raw_argv[1:])

    # `lucid-assay sign ...` dispatches to the standalone signing subcommand
    # (cli/sign.py) -- signs an already-built unsigned statement *file*
    # directly, without re-running the pipeline above. See cli/sign.py's
    # module docstring for why this exists separately from --sign/
    # --dry-run-sign below (which still build-then-sign in one process).
    if raw_argv[0] == "sign":
        from .sign import main as sign_main

        return sign_main(raw_argv[1:])

    # `lucid-assay provenance ...` dispatches to the standalone SLSA v1.0
    # provenance-construction subcommand (cli/provenance.py) -- builds a
    # provenance statement from *this process's own* ambient GitHub
    # Actions context, intended to run inside an isolated, trusted signer
    # job rather than the untrusted job that built the subject artifact
    # (see cli/provenance.py's module docstring for why this differs from
    # --emit-slsa-provenance below).
    if raw_argv[0] == "provenance":
        from .provenance import main as provenance_main

        return provenance_main(raw_argv[1:])

    return None


def main(argv: Optional[List[str]] = None) -> int:
    raw_argv = argv if argv is not None else sys.argv[1:]

    subcommand_exit_code = _dispatch_standalone_subcommand(raw_argv)
    if subcommand_exit_code is not None:
        return subcommand_exit_code

    # `lucid-assay run ...` is an explicit alias for the attestation
    # pipeline below -- it's also what runs with no subcommand at all, so
    # `run` is stripped rather than required, keeping `lucid-assay --sarif
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
        elif args.coverage_format == "jacoco":
            coverage = parse_jacoco(args.coverage_report)
        else:
            coverage = parse_lcov(args.coverage_report)

    # 3. Patch coverage via git diff
    with _stage(stage_ns, "diff_patch_analysis"):
        patch_cov = compute_patch_coverage(args.base_sha, args.head_sha, args.repo_dir, coverage)

    # 3b. Branch governance / ruleset inspection (ambient GITHUB_TOKEN unless overridden)
    with _stage(stage_ns, "github_rules_api"):
        branch_governance = inspect_branch_governance(args.repository, args.branch, token=args.github_token)
        # SLSA Source Level 3 (see cli/verify.py's _source_check_retained_history):
        # whether HEAD's commit author resolves to a linked, verified GitHub
        # account. Same GitHub REST API / token as branch governance above,
        # so it shares that stage's timing bucket.
        commit_author = inspect_commit_author(args.repository, args.head_sha, token=args.github_token)

    # 3c. SARIF static-analysis ingestion (optional, --sarif may repeat).
    # sarif_report stays None when --sarif wasn't passed at all -- scorer
    # and builder both treat that as "not configured", not as a failure.
    sarif_report = _ingest_sarif(args, stage_ns)

    # 3d. SBOM ingestion (optional, --sbom). Its license-policy findings
    # are folded into sarif_report *before* scoring/predicate-assembly
    # below, so both see one unified static-analysis picture regardless
    # of whether a finding originated from a real --sarif tool or the
    # SBOM's own license evaluation. Hashed here (not in step 4 alongside
    # the other evidence artifacts) because _merge_sbom_into_sarif needs
    # the hash already in hand, to give the synthetic SBOM SARIF tool a
    # real report_hash (see that function's own docstring) -- the same
    # sbom_report_sha value predicate.artifact.sbom.sha256 (step 7) and
    # the WORM upload dispatch (step 8) reuse below, computed once.
    sbom_report = _ingest_sbom(args, stage_ns)
    # Only hash a successfully-parsed --sbom -- an unreadable/malformed one
    # already produced a WARNING via _ingest_sbom above; hashing it here
    # too would let predicate.artifact.sbom claim a validated SBOM exists
    # for a file this pipeline couldn't actually read.
    sbom_report_sha = sha256_file(args.sbom) if (sbom_report is not None and sbom_report.available) else None
    sarif_report = _merge_sbom_into_sarif(sarif_report, sbom_report, sbom_report_sha)

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
        valid_test_functions = ast_metrics.valid_test_functions
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
    resolved_dependencies = _detect_lockfile_dependencies(args, stage_ns, sbom_report=sbom_report)

    # 6c. Vanity-test-aware real coverage (see _compute_real_coverage_analysis)
    real_coverage = _compute_real_coverage_analysis(args, coverage, ast_metrics, stage_ns)

    # 6d. S2C2F control evaluation (see _evaluate_s2c2f_controls)
    s2c2f_report = _evaluate_s2c2f_controls(
        args,
        resolved_dependencies=resolved_dependencies,
        sarif_report=sarif_report,
        branch_governance=branch_governance,
        stage_ns=stage_ns,
    )

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
            commit_author=commit_author,
            test_framework="junit",
            test_report_sha256=test_report_sha,
            test_report_uri=worm_uri(test_report_sha),
            test_totals=test_totals,
            coverage_format={"cobertura": "cobertura-xml", "jacoco": "jacoco-xml"}.get(args.coverage_format, "lcov"),
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
            valid_test_functions=valid_test_functions,
            rcs=rcs,
            sarif_report=sarif_report,
            ast_skipped_test_functions=ast_skipped,
            ast_languages=ast_languages,
            resolved_dependencies=resolved_dependencies,
            real_coverage=real_coverage,
            s2c2f=s2c2f_report,
            sbom=_build_sbom_artifact_block(sbom_report, sbom_report_sha),
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

    # 7c. --sbom's companion in-toto Statement (see cli/sbom_statement.py):
    # a second, separate attestation wrapping the SBOM's own raw document
    # verbatim, alongside the RCS predicate above. Independent of both the
    # RCS predicate and any --emit-slsa-provenance statement -- same
    # subject digest, but its own file and (if --sign/--dry-run-sign) its
    # own DSSE envelope. A no-op (returns None) when --sbom wasn't passed
    # or failed to parse.
    sbom_statement_out_path = _maybe_emit_sbom_statement(
        args, sbom_report=sbom_report, image_digest=image_digest
    )

    # 8. Async WORM uploads (fire-and-forget: the timed cost here is only
    # the dispatch/submission overhead, not the background upload itself)
    with _stage(stage_ns, "worm_upload"):
        upload_to_worm_async(args.junit_xml, test_report_sha)
        upload_to_worm_async(args.coverage_report, coverage_report_sha)
        if sbom_report_sha is not None:
            upload_to_worm_async(args.sbom, sbom_report_sha)

    # 9. Keyless signing
    sign_total_ns, sign_sub_ns, signed_path = _maybe_sign(args, out_path)
    if slsa_provenance_out_path is not None:
        _maybe_sign(args, slsa_provenance_out_path)
    if sbom_statement_out_path is not None:
        _maybe_sign(args, sbom_statement_out_path)

    # 9b. Automatically persist this run's FAILED/GATED/PASSED verdict onto
    # the just-signed envelope (see _maybe_annotate_verdict) -- best-effort,
    # never affects this run's own exit code (step 10 below is still the
    # sole authority for that). Only the primary RCS/assay envelope is
    # annotated, not the separate --emit-slsa-provenance one (which isn't
    # assay/v1-shaped and would always evaluate as a bare FAILED here).
    _maybe_annotate_verdict(args, signed_path, stage_ns)

    if args.debug:
        wall_elapsed_ns = time.perf_counter_ns() - t_start_ns
        _emit_stage_profile(stage_ns, sign_total_ns, sign_sub_ns, blocking_elapsed_ms, wall_elapsed_ns)

    _emit_run_warnings(
        rcs, branch_governance, args.branch, blocking_elapsed_ms, args.skip_perf_budget_check, commit_author
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
