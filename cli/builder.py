"""
Assembles the unsigned in-toto Statement (predicateType =
https://tenax.io/attestations/assay/v1) from parsed inputs.

Hardened against:
  - TypeError on boolean evaluation of NoneType line rates
  - Uncanonicalized SHA-256 hash formatting (case/prefix normalization)
  - Skipped/Total ratio zero-division edge cases
  - Immutable ISO 8601 UTC timestamp formatting
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .parsers.commit_author import CommitAuthorReport
from .parsers.coverage import CoverageReport
from .parsers.github_rules import BranchGovernanceReport
from .parsers.junit import TestTotals
from .parsers.sarif import SarifSummaryReport
from .patch_coverage import PatchCoverageResult
from .scorer import RCSResult

DEFAULT_PREDICATE_TYPE = "https://tenax.io/attestations/assay/v1"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# tenax-attestation-v1.schema.json requires pipeline.run_id/workflow_ref to
# be non-empty strings -- unlike cli/slsa_provenance.py's SLSA statement,
# which can omit an entire optional field when the ambient GitHub Actions
# context isn't present, this predicate's pipeline block can't simply leave
# them out. "not-run-in-ci" is an explicit, unambiguous sentinel for that
# case -- ground-truth-only (CLAUDE.md "Supply Chain Integrity &
# Attestation Invariants") means never asserting something that could be
# mistaken for a real run id/ref when this tool wasn't actually invoked
# inside CI.
_OFF_CI_SENTINEL = "not-run-in-ci"


def _ambient_run_id() -> str:
    """GITHUB_RUN_ID, when actually running inside a GitHub Actions job."""
    return os.environ.get("GITHUB_RUN_ID") or _OFF_CI_SENTINEL


def _ambient_run_attempt() -> int:
    """GITHUB_RUN_ATTEMPT, Actions-provided starting from "1" (genuinely
    unset, not a guess, on a workflow's first attempt -- same convention
    slsa_provenance.py's _invocation_metadata() already uses). Falls back
    to 1 both off-CI and on any unparseable value, rather than raising."""
    raw = os.environ.get("GITHUB_RUN_ATTEMPT")
    try:
        return int(raw) if raw else 1
    except ValueError:
        return 1


def _ambient_workflow_ref() -> str:
    """GITHUB_WORKFLOW_REF, Actions-provided already pre-assembled exactly
    in the shape the schema documents ("org/repo/.github/workflows/ci.yml@
    refs/heads/main") -- no parsing needed here, unlike slsa_provenance.py's
    builder, which further splits this same env var into path/ref for its
    own separate schema shape."""
    return os.environ.get("GITHUB_WORKFLOW_REF") or _OFF_CI_SENTINEL


def _ambient_runner_environment() -> str:
    """RUNNER_ENVIRONMENT, Actions-provided ("github-hosted"/"self-hosted"),
    matching the schema's own enum exactly -- "unknown" (the schema's own
    documented default) when genuinely absent, never fabricated as either
    specific value."""
    return os.environ.get("RUNNER_ENVIRONMENT") or "unknown"


def _clean_sha256(raw_sha: str) -> str:
    """Normalize hex digest to 64-char lowercase string."""
    s = raw_sha.strip().lower()
    if s.startswith("sha256:"):
        s = s[7:]
    return s


def build_statement(
    *,
    subject_name: str,
    subject_sha256: str,
    vcs_provider: str,
    repository: str,
    branch: str,
    commit_sha: str,
    base_commit_sha: Optional[str],
    pr_number: Optional[int],
    pr_target_branch: Optional[str],
    pr_approvers: List[str],
    pr_required_approvals: int,
    pr_review_state: str,
    branch_governance: BranchGovernanceReport,
    commit_author: Optional[CommitAuthorReport] = None,
    test_framework: str,
    test_report_sha256: str,
    test_report_uri: str,
    test_totals: TestTotals,
    coverage_format: str,
    coverage_report_sha256: str,
    coverage_report_uri: str,
    coverage: CoverageReport,
    patch_coverage: PatchCoverageResult,
    patch_coverage_min: float,
    overall_coverage_min: float,
    total_assertions: int,
    total_test_functions: int,
    empty_test_bodies: int,
    assertion_only_true: int,
    rcs: RCSResult,
    sbom: Optional[Dict[str, Any]] = None,
    sarif_report: Optional[SarifSummaryReport] = None,
    ast_skipped_test_functions: int = 0,
    ast_languages: Optional[Dict[str, Dict[str, int]]] = None,
    resolved_dependencies: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Returns a dict matching the lifecycle/v0.1 predicate schema, wrapped
    in a standard in-toto Statement envelope."""

    pull_request = None
    if pr_number is not None:
        pull_request = {
            "number": pr_number,
            "target_branch": pr_target_branch or branch,
            "approvers": sorted(set(pr_approvers)),
            "required_approvals": pr_required_approvals,
            "review_state": pr_review_state,
        }

    density_ratio = (
        round(total_assertions / total_test_functions, 3)
        if total_test_functions > 0
        else None
    )

    total_test_count = max(test_totals.tests, test_totals.skipped, 1)
    skipped_ratio = round(test_totals.skipped / total_test_count, 4)

    patch_met = False
    if patch_coverage.available and patch_coverage.line_rate is not None:
        patch_met = patch_coverage.line_rate >= patch_coverage_min

    clean_subj_sha = _clean_sha256(subject_sha256)

    if sarif_report is not None:
        static_analysis = {
            "available": sarif_report.available,
            "format": "sarif-2.1.0",
            "tools_scanned": sarif_report.tools_scanned,
            "total_findings": sarif_report.total_findings,
            "errors_count": sarif_report.errors_count,
            "warnings_count": sarif_report.warnings_count,
            "notes_count": sarif_report.notes_count,
            "none_count": sarif_report.none_count,
            "patch_errors_count": sarif_report.patch_errors_count,
            "patch_warnings_count": sarif_report.patch_warnings_count,
            "findings": [f.as_dict() for f in sarif_report.findings],
            "tools": [t.as_dict() for t in sarif_report.tools],
            "reasons": sarif_report.reasons,
        }
    else:
        # No --sarif flags were configured for this run at all -- an empty,
        # available=True block (nothing scanned, nothing to report), not a
        # failure state. Mirrors cli.scorer._score_sarif_findings(None).
        static_analysis = {
            "available": True,
            "format": "sarif-2.1.0",
            "tools_scanned": [],
            "total_findings": 0,
            "errors_count": 0,
            "warnings_count": 0,
            "notes_count": 0,
            "none_count": 0,
            "patch_errors_count": 0,
            "patch_warnings_count": 0,
            "findings": [],
            "tools": [],
            "reasons": [],
        }

    predicate = {
        "predicate_version": "0.1.0",
        "pipeline": {
            "ci_provider": "github-actions",
            "run_id": _ambient_run_id(),
            "run_attempt": _ambient_run_attempt(),
            "workflow_ref": _ambient_workflow_ref(),
            "runner_environment": _ambient_runner_environment(),
            "started_at": _now_iso(),
            "finished_at": _now_iso(),
        },
        "vcs": {
            "provider": vcs_provider,
            "repository": repository,
            "branch": branch,
            "commit_sha": commit_sha.strip().lower(),
            "base_commit_sha": (
                base_commit_sha.strip().lower() if base_commit_sha else None
            ),
            "pull_request": pull_request,
            # Live GitHub commit-author identity check
            # (cli/parsers/commit_author.py): whether HEAD's commit author
            # resolves to a linked, verified GitHub account, distinct from
            # the trivially-spoofable free-text git author name/email.
            # None on an attestation predating this field, or when the
            # caller didn't supply one at all (e.g. most existing tests) --
            # cli/verify.py's Source Level 3 check treats that identically
            # to an unverified author, never as "not applicable".
            "commit_author": commit_author.as_dict() if commit_author is not None else None,
        },
        "branch_governance": {
            "available": branch_governance.available,
            "branch": branch_governance.branch,
            "pull_request_required": branch_governance.pull_request_required,
            "approvals_required": branch_governance.approvals_required,
            "direct_push_prevented": branch_governance.direct_push_prevented,
            "bypass_actors_count": branch_governance.bypass_actors_count,
            "admin_enforced": branch_governance.admin_enforced,
            "warnings": branch_governance.warnings,
            "reason": branch_governance.reason,
            "reason_code": branch_governance.reason_code,
        },
        "artifact": {
            "subject": {
                "name": subject_name,
                "digest": {"sha256": clean_subj_sha},
            },
            "sbom": sbom,
        },
        "test_verification": {
            "framework": test_framework,
            "report_format": "junit-xml",
            "report_sha256": _clean_sha256(test_report_sha256),
            "report_uri": test_report_uri,
            "totals": {
                "tests": test_totals.tests,
                "passed": test_totals.passed,
                "failed": test_totals.failed,
                "errored": test_totals.errored,
                "skipped": test_totals.skipped,
            },
            "flaky_retries": test_totals.flaky_retries,
            "duration_ms": test_totals.duration_ms,
        },
        "coverage": {
            "format": coverage_format,
            "report_sha256": _clean_sha256(coverage_report_sha256),
            "report_uri": coverage_report_uri,
            "overall": {
                "line_rate": coverage.overall_line_rate,
                "branch_rate": coverage.overall_branch_rate,
            },
            "patch": {
                "available": patch_coverage.available,
                "line_rate": patch_coverage.line_rate,
                "lines_changed": patch_coverage.lines_changed,
                "lines_covered": patch_coverage.lines_covered,
                "reason": patch_coverage.reason,
                "reason_code": patch_coverage.reason_code,
            },
            "thresholds": {
                "overall_min": overall_coverage_min,
                "patch_min": patch_coverage_min,
                "overall_met": coverage.overall_line_rate >= overall_coverage_min,
                "patch_met": patch_met,
            },
        },
        "assertion_density": {
            "total_assertions": total_assertions,
            "total_test_functions": total_test_functions,
            "density_ratio": density_ratio,
            "heuristics": {
                "empty_test_bodies": empty_test_bodies,
                "assertion_only_true": assertion_only_true,
                "skipped_or_disabled_ratio": skipped_ratio,
                "ast_skipped_test_functions": ast_skipped_test_functions,
            },
            "languages": ast_languages or {},
        },
        "static_analysis": static_analysis,
        # Pinned/resolved dependencies detected from lockfiles under the
        # repo (cli/parsers/lockfiles.py: uv.lock, package-lock.json,
        # go.sum, Gradle/Maven locks), deduplicated by uri. This is
        # tenax-assay's own top-level predicate field, distinct from --
        # and never a substitute for -- SLSA v1.0 provenance's
        # buildDefinition.resolvedDependencies, which cli/verify.py's
        # SLSA Level 2 checklist reads from a differently-shaped
        # predicate entirely (see cli/verify.py's SLSA checklist
        # docstrings); populating this field does not change that
        # checklist's outcome. `[]` when detect_and_parse_dependencies()
        # found no recognized lockfile, or on attestations predating
        # this field.
        "resolved_dependencies": resolved_dependencies or [],
        "release_confidence_score": {
            "value": rcs.value,
            "algorithm_version": rcs.algorithm_version,
            "components": {k: v.as_dict() for k, v in rcs.components.items()},
            "degraded": rcs.degraded,
            "degraded_reasons": rcs.degraded_reasons,
            "computed_at": _now_iso(),
        },
    }

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": subject_name, "digest": {"sha256": clean_subj_sha}}],
        "predicateType": DEFAULT_PREDICATE_TYPE,
        "predicate": predicate,
    }
    return statement
