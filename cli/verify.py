#!/usr/bin/env python3
"""
lucid-assay verify: admission gatekeeper for signed DSSE in-toto attestations.

Decodes a DSSE envelope (`payloadType: application/vnd.in-toto+json`) produced
by `lucid-assay` (see cli.oidc_signer / cli.builder), best-effort verifies the
Sigstore keyless signing identity, and enforces admission policy gates against
the embedded Release Confidence Score (RCS) predicate.

Hardened against:
  - Missing/garbled DSSE fields (payloadType, payload, signatures) crashing
    the gate instead of failing it
  - Network-dependent Sigstore/TUF trust-root lookups crashing offline/CI
    runs (--dry-run or unreachable network degrades to a warning, not a crash)
  - Envelopes signed via --dry-run-sign being mistaken for cryptographically
    verified signatures
  - Ambiguous exit codes on file errors vs. policy breaches
  - A signature that verifies cryptographically but was minted for a
    different repository, workflow, ref, or OIDC issuer than expected
    (--expected-issuer/--expected-repository/--expected-workflow/
    --expected-ref strictly match the Fulcio certificate's SAN and its
    GitHub Actions OIDC extension claims; any mismatch is an explicit,
    gate-blocking failure, not a warning)
  - Silently falling back to signature-only (identity-unchecked)
    verification: when no identity assertion is provided at all, the
    UnsafeNoOp fallback is called out explicitly in identity_detail
    rather than being indistinguishable from a real identity check
  - Pathologically deep JSON nesting in the envelope file (well under
    MAX_ENVELOPE_SIZE by byte count -- 1,000 levels of `{"a":...}` is only
    a few KB, so the size guard alone doesn't catch this): `json.load`/
    `json.loads` are recursive descent, so a hostile envelope crafted to
    exceed `sys.getrecursionlimit()` raises `RecursionError`, not
    `json.JSONDecodeError` -- caught alongside it wherever the envelope or
    its decoded payload is parsed, same clean file-error exit code as any
    other malformed envelope, never an unhandled crash
"""
from __future__ import annotations

import argparse
import base64
import fnmatch
import json
import math
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .common import UnsafePathError, safe_resolve_path

# jsonschema is an optional dependency (pyproject.toml [dev] extra) -- this
# module is meant to work as a lightweight, dependency-minimal standalone
# admission gate, so formal schema validation degrades to "skipped" rather
# than making jsonschema a hard runtime requirement. See
# _validate_against_schema()'s docstring for the full fail-open contract.
try:
    import jsonschema

    _JSONSCHEMA_AVAILABLE = True
except ImportError:
    _JSONSCHEMA_AVAILABLE = False

EXPECTED_PAYLOAD_TYPE = "application/vnd.in-toto+json"
EXPECTED_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
EXPECTED_PREDICATE_TYPE = "https://lucidprovenance.io/attestations/assay/v1"

# The generic SLSA v1.0 provenance predicateType (distinct from
# EXPECTED_PREDICATE_TYPE above, which is lucid-assay's own RCS predicate).
# The SLSA Build Level 1/2 checklist below (_evaluate_slsa_l1/_l2) is a
# separate, purely informational assessment against the SLSA v1.0
# provenance schema (https://slsa.dev/spec/v1.0/provenance) -- it never
# gates `passed`/exit code, the same way static_analysis_tools doesn't --
# so it applies whether the decoded statement is lucid-assay's own
# predicate (which, not being SLSA provenance shaped, will legitimately
# fail most of this checklist today) or a real SLSA provenance statement
# handed to this same admission gate.
SLSA_PROVENANCE_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"

# Builder IDs trusted as SLSA Build Level 3 "isolated control-plane"
# identities -- i.e. the specific, isolated signer workflow that
# constructs *and* signs provenance atomically. Deliberately not encoding
# a ref/SHA: this identifies the split-signer *workflow* (repo+path),
# which is stable across TRUSTED_SIGNER_SHA bumps in that repo; the
# cryptographic pin to an exact trusted commit is separately enforced by
# Sigstore's --cert-identity check (see
# _slsa_check_isolated_provenance_generation), which does encode the ref.
#
# One entry: lucid-attest-service/sign-client.yml (constructs SLSA
# provenance from its own isolated context, then delegates the actual
# Sigstore operation to the shared lucid-attest-service Lambda).
# GitHub's OIDC job_workflow_ref claim (and hence the Fulcio certificate
# identity Sigstore issues) reflects the reusable workflow FILE's own
# path for a job that mints its own token inside a workflow_call
# invocation, regardless of which repo's `uses:` line invoked it --
# that's what makes this one, individually reviewed, sufficient to trust
# every future caller of that file -- see the Lucid vault's "Serverless
# signer needs a trustworthy provenance builder identity" note for the
# full reasoning this resolves. Deliberately still an explicit, narrow
# allowlist rather than a pattern/prefix match -- see
# TRUSTED_HOSTED_BUILDER_IDS's own comment below for why a claim this
# security-sensitive must fail closed on anything not individually
# reviewed, not be widened into a broader match.
#
# lucid-attest/sign.yml -- the original entry, same trust property via
# a pinned Docker image run locally in that job rather than delegating
# to a Lambda -- was removed 2026-09-03. lucid-attest is archived on
# GitHub; every real caller had already cut over to sign-client.yml
# before the archival, and an archived repo's workflow identity has no
# business staying in an active trust allowlist once nothing legitimate
# can still present it.
TRUSTED_CONTROL_PLANE_BUILDER_IDS = frozenset({
    "https://github.com/lucid-provenance/lucid-attest-service/.github/workflows/sign-client.yml",
})

# Builder IDs trusted as SLSA Build Level 2 "hosted"/tamper-resistant
# build platforms. Deliberately a narrow, explicit allowlist rather than
# a prefix/pattern match: a hosted-builder claim is exactly the kind of
# claim that must fail closed on anything not explicitly recognized.
# Includes TRUSTED_CONTROL_PLANE_BUILDER_IDS via a live computed union
# (unlike _ALLOWED_DEGRADED_REASONS's deliberately-duplicated literals --
# that rationale is about avoiding a *cross-module* import into cli/scorer.py
# et al.; both constants here are already defined in this same file, so a
# computed union carries no drift risk at all, and every future addition
# to TRUSTED_CONTROL_PLANE_BUILDER_IDS is automatically reflected here
# too, with nothing to remember to keep in sync): SLSA's levels are
# cumulative, so a builder identity specific and verifiable enough to
# satisfy Level 3's stricter check must, a fortiori, also satisfy Level
# 2's weaker "some trusted hosted platform" one -- otherwise Level 3
# could never actually be reached even once its own two checks pass,
# since Level 2 would independently block the cumulative Status line. A
# caller whose provenance wasn't constructed inside one of
# TRUSTED_CONTROL_PLANE_BUILDER_IDS's specific workflows still only
# reaches this generic hosted-runner tier, so Level 3 correctly stays out
# of reach for it regardless -- by design, not a stub.
TRUSTED_HOSTED_BUILDER_IDS = frozenset({
    "https://github.com/actions/runner",
} | TRUSTED_CONTROL_PLANE_BUILDER_IDS)

# GitHub Actions' well-known OIDC token issuer. GitHub-Actions-specific
# identity claims (repository/workflow/ref) are only meaningful -- and only
# safe to trust -- when they came from this issuer, so any of those claims
# being asserted pins the issuer here unless the caller explicitly overrides it.
GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

# Fulcio's GitHub Actions OIDC certificate extension OIDs used for ref
# matching (see https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md).
# The legacy (v1) extension's value is the raw UTF-8 bytes of the ref; the
# current (v2) extension DER-encodes it as an ASN.1 UTF8String. Which OID is
# present depends on the Fulcio/token version that minted the certificate.
_GITHUB_WORKFLOW_REF_OID = "1.3.6.1.4.1.57264.1.6"
_OIDC_SOURCE_REPOSITORY_REF_OID = "1.3.6.1.4.1.57264.1.14"

# Same v1/v2 split as above, for the other claims _describe_actual_cert_claims
# reports on failure: OIDC issuer, workflow repository, and workflow name.
# (Workflow name has no v2 successor extension -- it's carried by .4 alone.)
_OIDC_ISSUER_V1_OID = "1.3.6.1.4.1.57264.1.1"
_OIDC_ISSUER_V2_OID = "1.3.6.1.4.1.57264.1.8"
_GITHUB_WORKFLOW_NAME_OID = "1.3.6.1.4.1.57264.1.4"
_GITHUB_WORKFLOW_REPOSITORY_OID = "1.3.6.1.4.1.57264.1.5"
_OIDC_SOURCE_REPOSITORY_URI_OID = "1.3.6.1.4.1.57264.1.12"

EXIT_PASS = 0
EXIT_POLICY_VIOLATION = 2
EXIT_FILE_ERROR = 1

# Placeholder used throughout _describe_actual_cert_claims() for a
# certificate claim that's absent, unparseable, or hit an unexpected cert
# shape -- one constant instead of five duplicated literals so a caller
# comparing against it (or a future rename) has a single place to look.
UNPARSEABLE_LITERAL = "<unparseable>"

# A signed attestation envelope is a small JSON document by construction
# (a DSSE-wrapped RCS predicate); anything approaching this ceiling is
# either corrupt or hostile. Enforced via a stat() size check *before* any
# of the file's bytes are read into memory -- see load_envelope().
MAX_ENVELOPE_SIZE = 10 * 1024 * 1024  # 10MB

# Packaged predicate JSON Schema, resolved relative to this module rather
# than the process's CWD so `lucid-assay verify` works from any directory.
_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema" / "lucid-attestation-v1.schema.json"
_schema_cache: Optional[Dict[str, Any]] = None


class EnvelopeTooLargeError(Exception):
    """Raised by load_envelope() when the file exceeds MAX_ENVELOPE_SIZE.
    Deliberately not an OSError subclass, so callers that broadly catch
    OSError for file-system errors don't accidentally swallow this as one
    -- an oversized file is a distinct, policy-driven rejection, not an
    I/O failure."""

# degraded_reasons entries --disallow-degraded treats as non-blocking:
# known, unavoidable states that aren't a real governance/quality gap --
#   - a GitHub platform/plan-tier limitation on branch rulesets (private
#     repo, Free plan -- see
#     cli.parsers.github_rules.REASON_CODE_PLATFORM_UNSUPPORTED_TIER)
#   - a docs/config-only diff with zero coverable changed lines -- there's
#     no code in the diff for patch coverage to be missing over (see
#     cli.patch_coverage.REASON_CODE_NO_COVERABLE_LINES)
# Deliberately duplicated here as literals rather than imported from
# cli.scorer/cli.parsers.github_rules/cli.patch_coverage: this module
# verifies only the decoded JSON predicate, with no dependency on the
# pipeline's Python types, and these strings are a stable, versioned part
# of the attestation's own schema (predicate.release_confidence_score.
# degraded_reasons), not an implementation detail of those modules. If any
# of those modules' construction of these strings changes, this set must
# be updated to match. A degraded run is only exempted from
# --disallow-degraded when *every* entry in degraded_reasons is a member
# of this set -- any other cause present still blocks.
_ALLOWED_DEGRADED_REASONS = frozenset({
    "branch_governance:platform_unsupported_tier",
    "patch_coverage:no_coverable_lines",
})


@dataclass
class VerificationResult:
    __test__ = False
    passed: bool
    violations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    statement: Optional[Dict[str, Any]] = None
    rcs_value: Optional[int] = None
    # Always a concrete bool, never None -- see _validate_rcs_block's
    # docstring. Defaults to False (this field's own JSON-Schema-declared
    # default) when the predicate omits it entirely; that's a legitimate,
    # documented display interpretation, not a fabricated compliance claim.
    # degraded_field_present is the separate, honest "was this actually
    # asserted" signal -- --disallow-degraded (see _evaluate_policy_gates)
    # fails closed on degraded_field_present is False rather than silently
    # trusting the display default (CLAUDE.md "Fail-Closed Verification").
    degraded: bool = False
    degraded_field_present: bool = False
    degraded_reasons: Optional[List[str]] = None
    subject_digests: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    identity_status: str = "skipped"
    identity_detail: str = ""
    static_analysis_tools: List[Dict[str, Any]] = field(default_factory=list)
    # predicate.s2c2f.controls, verbatim (cli/parsers/s2c2f.py) -- purely
    # informational, same non-gating contract as static_analysis_tools.
    # [] when this predicate predates S2C2F evaluation or the run skipped
    # it, never fabricated as met/unmet.
    s2c2f_controls: List[Dict[str, Any]] = field(default_factory=list)
    # predicate.resolved_dependencies + predicate.artifact.sbom, evaluated
    # into a checklist (see _extract_dependency_evidence) -- lucid-assay's
    # own dependency evidence, deliberately never SLSA v1.0 provenance's
    # buildDefinition.resolvedDependencies (see CLAUDE.md's warning against
    # confusing the two). Used to have equivalent checks living inside
    # slsa_level2/slsa_level3 above; moved out into their own section since
    # SLSA v1.0's ratified Build Track doesn't define a dependency-
    # materialization level -- see _format_dependency_governance_report.
    # Purely informational, same non-gating contract as s2c2f_controls.
    dependency_governance_items: List[Dict[str, Any]] = field(default_factory=list)
    # predicate.repository_governance, evaluated into a checklist (see
    # _extract_repository_governance) -- solo-maintainer compensating
    # controls (cryptographic commit signing, branch-ruleset hygiene),
    # deliberately isolated from both the ratified SLSA Build Track and
    # the still-draft Source Track, same separation principle as
    # dependency_governance_items above. Purely informational except the
    # commit-signing item, which --require-commit-signing can opt into
    # gating (see verify_dsse_attestation).
    repository_governance_items: List[Dict[str, Any]] = field(default_factory=list)
    # The signed envelope's own _rekor.logIndex/logUrl (cli/oidc_signer.py)
    # -- not part of the signed predicate (see _extract_rekor_info's
    # docstring for why). Both None on --dry-run-sign or an envelope
    # predating this field.
    rekor_log_index: Optional[int] = None
    rekor_log_url: Optional[str] = None
    schema_validation_status: str = "skipped"
    slsa_level1: Optional[Dict[str, Any]] = None
    slsa_level2: Optional[Dict[str, Any]] = None
    # SLSA Build Level 3 -- see _evaluate_slsa_l3. Purely informational
    # like level1/level2 unless --require-slsa-build-l3 was set.
    slsa_level3: Optional[Dict[str, Any]] = None
    # SLSA Source Track Levels 1-4 -- see _evaluate_source_l1..l4. Always
    # populated (never None) once verify_dsse_attestation reaches the
    # point of evaluating them, since the Source checklist -- like the
    # Build one -- evaluates against whatever statement it's given and
    # honestly reports missing fields as failures, rather than a fourth
    # "unavailable" state (see _classify_statements).
    source_level1: Optional[Dict[str, Any]] = None
    source_level2: Optional[Dict[str, Any]] = None
    source_level3: Optional[Dict[str, Any]] = None
    source_level4: Optional[Dict[str, Any]] = None
    # predicate.release_confidence_score.components, verbatim -- feeds the
    # Assay Health & Governance Metrics report section (see
    # _format_assay_health_report). None when no RCS predicate was loaded.
    rcs_components: Optional[Dict[str, Any]] = None
    # The synthesized "FINAL VERDICT: ..." headline (see
    # _format_verdict_banner), without the surrounding "====" bars.
    # Empty string until verify_dsse_attestation computes it (e.g. the
    # top-level malformed-envelope guard returns before doing so).
    verdict: str = ""
    # The bare FAILED/GATED/PASSED word out of `verdict` above (see
    # _verdict_word) -- also the word _print_verify_result_human/
    # _render_step_summary_markdown use for the top-of-report heading, so
    # that heading and FINAL VERDICT always agree instead of the heading
    # computing its own separate PASS/FAIL binary under a word that
    # collides with FINAL VERDICT's own distinct "PASSED" state. Explicitly
    # "FAILED" (not "") on the malformed-envelope early return -- unlike
    # `verdict` above, this one is always safe to display even when
    # nothing else was computed, since result.passed=False there always
    # implies FAILED regardless of source/build level.
    verdict_word: str = ""
    # The highest SLSA Source/Build level each track cumulatively
    # satisfies (see _highest_passing_level) -- computed once, alongside
    # verdict/verdict_word, and stored here so a caller that wants them
    # (e.g. _build_verdict_envelope_block, for `--write-verdict`) doesn't
    # have to recompute _cumulative_track_status/_highest_passing_level
    # from source_level1../slsa_level1.. a second time. 0 on the
    # malformed-envelope early return, same as an all-failing track would
    # cumulatively produce.
    source_highest_level: int = 0
    build_highest_level: int = 0
    # The exact admission-gate parameters this call was invoked with
    # (min_rcs, disallow_degraded, cert_identity, expected_repository, ...)
    # -- verbatim, not re-derived -- so a report can be read on its own and
    # still answer "what threshold/flags produced this verdict", without
    # cross-referencing the CI job's command line separately. Always
    # populated (even on the malformed-envelope early return), since it
    # reflects what verify_dsse_attestation was called with, not anything
    # about the envelope itself. See _format_run_identity_report.
    gate_params: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "violations": self.violations,
            "warnings": self.warnings,
            "rcs_value": self.rcs_value,
            "degraded": self.degraded,
            "degraded_field_present": self.degraded_field_present,
            "degraded_reasons": self.degraded_reasons,
            "subject_digests": self.subject_digests,
            "metrics": self.metrics,
            "identity_status": self.identity_status,
            "identity_detail": self.identity_detail,
            "static_analysis_tools": self.static_analysis_tools,
            "s2c2f_controls": self.s2c2f_controls,
            "dependency_governance_items": self.dependency_governance_items,
            "repository_governance_items": self.repository_governance_items,
            "rekor_log_index": self.rekor_log_index,
            "rekor_log_url": self.rekor_log_url,
            "source_highest_level": self.source_highest_level,
            "build_highest_level": self.build_highest_level,
            "schema_validation_status": self.schema_validation_status,
            "slsa_level1": self.slsa_level1,
            "slsa_level2": self.slsa_level2,
            "slsa_level3": self.slsa_level3,
            "source_level1": self.source_level1,
            "source_level2": self.source_level2,
            "source_level3": self.source_level3,
            "source_level4": self.source_level4,
            "rcs_components": self.rcs_components,
            "verdict": self.verdict,
            "verdict_word": self.verdict_word,
            "gate_params": self.gate_params,
        }


def _extract_subject_digests(statement: Dict[str, Any]) -> List[str]:
    """Returns ["<alg>:<hex>", ...] for every digest of every subject."""
    digests: List[str] = []
    for subj in statement.get("subject") or []:
        if not isinstance(subj, dict):
            continue
        digest_map = subj.get("digest") or {}
        if not isinstance(digest_map, dict):
            continue
        for alg, hexval in digest_map.items():
            if isinstance(hexval, str):
                digests.append(f"{str(alg).strip().lower()}:{hexval.strip().lower()}")
    return digests


def _normalize_digest(raw: str) -> str:
    """Normalizes a --require-digest value to "<alg>:<hex>". Bare hex is
    assumed to be sha256, matching how --image-digest is handled elsewhere
    in this CLI (see cli.main)."""
    raw = raw.strip()
    if ":" in raw:
        alg, hexval = raw.split(":", 1)
    else:
        alg, hexval = "sha256", raw
    return f"{alg.strip().lower()}:{hexval.strip().lower()}"


def _extract_metrics(predicate: Dict[str, Any]) -> Dict[str, Any]:
    metrics: Dict[str, Any] = {}
    test_verification = predicate.get("test_verification")
    if isinstance(test_verification, dict):
        metrics["test_totals"] = test_verification.get("totals")
    coverage = predicate.get("coverage")
    if isinstance(coverage, dict):
        metrics["coverage_overall"] = coverage.get("overall")
        metrics["coverage_patch"] = coverage.get("patch")
        metrics["coverage_thresholds"] = coverage.get("thresholds")
        metrics["coverage_real"] = coverage.get("real")
    assertion_density = predicate.get("assertion_density")
    if isinstance(assertion_density, dict):
        metrics["assertion_density"] = assertion_density
    return metrics


def _extract_rcs_components(predicate: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Pulls release_confidence_score.components (test_health,
    patch_coverage, overall_coverage, assertion_integrity, governance,
    static_analysis -- see cli/scorer.py's RCSResult) out of the predicate
    for the Assay Health & Governance Metrics report section. Purely
    display data, same defensive contract as _extract_metrics: returns
    None (not a fabricated empty dict) when the field is missing or
    malformed, so the renderer can tell "no component breakdown was
    asserted" apart from "an empty one was"."""
    rcs_block = predicate.get("release_confidence_score")
    rcs_block = rcs_block if isinstance(rcs_block, dict) else {}
    components = rcs_block.get("components")
    return components if isinstance(components, dict) else None


def _extract_static_analysis_tools(predicate: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Defensively pulls the per-tool SARIF breakdown out of the predicate
    for display purposes only (never raises, never gates -- static_analysis
    is optional in the schema and this is purely informational). Malformed
    or missing entries are skipped individually rather than discarding the
    whole list."""
    static_analysis = predicate.get("static_analysis")
    if not isinstance(static_analysis, dict):
        return []

    tools = static_analysis.get("tools")
    if not isinstance(tools, list):
        return []

    return [t for t in tools if isinstance(t, dict)]


def _extract_s2c2f_controls(predicate: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Defensively pulls predicate.s2c2f.controls (cli/parsers/s2c2f.py) out
    of the predicate for display purposes only (never raises, never gates
    `passed` -- purely informational, same contract as
    _extract_static_analysis_tools). [] when the field is absent (an
    attestation predating S2C2F evaluation, or a run that skipped it) or
    malformed; individual malformed control entries are skipped rather
    than discarding the whole list."""
    s2c2f = predicate.get("s2c2f")
    if not isinstance(s2c2f, dict):
        return []
    controls = s2c2f.get("controls")
    if not isinstance(controls, list):
        return []
    return [c for c in controls if isinstance(c, dict)]


def _extract_repository_governance(predicate: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Builds the Repository & Workstation Governance checklist (see
    _format_repository_governance_report) from lucid-assay's own
    predicate.repository_governance (cli/parsers/github_rules.py +
    cli/parsers/commit_author.py) -- compensating controls for a
    solo-maintained repo that structurally can't satisfy SLSA Source
    Level 4's two-party review (see cli/verify.py's own module docstring
    on that limitation). Deliberately isolated from both the ratified
    SLSA Build Track and the still-draft Source Track: this project's own
    policy assessment, not a claim about either specification -- the same
    separation reasoning Rev. 8's dependency-materialization decoupling
    already established for a different section. Renders all four items
    (even a failing/unavailable one) once repository_governance is
    present at all, rather than silently dropping the section, matching
    branch_governance's own "always show why, never just disappear"
    convention. [] (no section at all) only when
    predicate.repository_governance is absent entirely -- an attestation
    predating this field, matching every other optional section here."""
    repo_gov = predicate.get("repository_governance")
    if not isinstance(repo_gov, dict):
        return []
    return [
        _repo_gov_check_commit_signing(repo_gov),
        _repo_gov_check_linear_history(repo_gov),
        _repo_gov_check_force_pushes_blocked(repo_gov),
        _repo_gov_check_deletions_blocked(repo_gov),
    ]


def _repo_gov_check_commit_signing(repo_gov: Dict[str, Any]) -> Dict[str, Any]:
    """Cryptographic proof the commit whose content this run actually
    describes wasn't altered after signing -- a materially different,
    stronger claim than SLSA Source Level 3's account-link check (see
    cli/parsers/commit_author.py's own docstring for why the two are
    kept apart). The only item in this section with an opt-in path into
    the hard gate -- see --require-commit-signing.

    `commit_signature.source_sha` (see cli/parsers/commit_author.py's
    GitHub-web-flow merge commit walk-back) is surfaced whenever it
    differs from the requested commit -- HEAD, on a push-triggered run
    after a PR merge, is usually GitHub's own auto-generated,
    auto-signed merge commit, not the human-authored content; silently
    crediting that signature would be a false positive this check
    exists specifically to avoid."""
    label = "Cryptographic Commit Signing"
    commit_sig = repo_gov.get("commit_signature")
    if not isinstance(commit_sig, dict):
        return _slsa_item(label, False, "commit author identity was not captured for this run -- no commit signature data available")
    if not commit_sig.get("available", False):
        return _slsa_item(label, False, "commit signature verification unavailable (see vcs.commit_author's own reason)")

    source_sha = commit_sig.get("source_sha")
    walked_back = isinstance(source_sha, str) and bool(source_sha)
    via_pr_head = f" on the PR's own head commit {source_sha[:12]}, not the merge commit" if walked_back else ""

    if commit_sig.get("verified") is True:
        sig_type = commit_sig.get("signature_type")
        via = f" via {sig_type.upper()}" if isinstance(sig_type, str) and sig_type else ""
        return _slsa_item(f"{label} (verified{via}{via_pr_head})", True)

    reason = commit_sig.get("reason")
    detail = f"commit is unsigned or unverified ({reason}){via_pr_head}" if reason else f"commit is unsigned or unverified{via_pr_head}"
    return _slsa_item(label, False, detail)


def _repo_gov_check_linear_history(repo_gov: Dict[str, Any]) -> Dict[str, Any]:
    label = "Linear History Enforced"
    if not repo_gov.get("available", False):
        return _slsa_item(label, False, "branch governance unavailable for this run (see branch_governance's own reason)")
    if repo_gov.get("linear_history_required") is True:
        return _slsa_item(f"{label} (merge commits disallowed)", True)
    return _slsa_item(label, False, "no 'required_linear_history' rule is active on this branch")


def _repo_gov_check_force_pushes_blocked(repo_gov: Dict[str, Any]) -> Dict[str, Any]:
    label = "Force Pushes Blocked"
    if not repo_gov.get("available", False):
        return _slsa_item(label, False, "branch governance unavailable for this run (see branch_governance's own reason)")
    if repo_gov.get("force_pushes_blocked") is True:
        return _slsa_item(f"{label} (history rewrite disabled)", True)
    return _slsa_item(
        label, False,
        "no 'non_fast_forward' rule is active on this branch -- history rewrite via force-push is not blocked",
    )


def _repo_gov_check_deletions_blocked(repo_gov: Dict[str, Any]) -> Dict[str, Any]:
    label = "Branch Deletion Blocked"
    if not repo_gov.get("available", False):
        return _slsa_item(label, False, "branch governance unavailable for this run (see branch_governance's own reason)")
    if repo_gov.get("deletions_blocked") is True:
        return _slsa_item(label, True)
    return _slsa_item(label, False, "no 'deletion' rule is active on this branch")


def _extract_dependency_evidence(predicate: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Builds the Dependency Materialization Evidence checklist (see
    _format_dependency_governance_report) from lucid-assay's own
    predicate.resolved_dependencies (cli/parsers/lockfiles.py-derived) and
    predicate.artifact.sbom -- deliberately never SLSA v1.0 provenance's
    buildDefinition.resolvedDependencies (see CLAUDE.md's warning against
    confusing the two; that field is a different predicate's, evaluated
    nowhere in this checklist). Purely informational, same never-raises/
    never-gates contract as _extract_s2c2f_controls. [] when
    resolved_dependencies is empty/absent AND no sbom is attached -- an
    attestation that never ran dependency detection at all, matching
    every other optional section's "nothing to show" convention here."""
    resolved = predicate.get("resolved_dependencies")
    resolved = [d for d in resolved if isinstance(d, dict)] if isinstance(resolved, list) else []

    artifact = predicate.get("artifact")
    artifact = artifact if isinstance(artifact, dict) else {}
    sbom = artifact.get("sbom")
    sbom = sbom if isinstance(sbom, dict) else None

    if not resolved and not sbom:
        return []

    items = [_dependency_check_resolved(resolved)]
    if resolved:
        items.append(_dependency_check_locked(resolved))
    items.append(_dependency_check_sbom(sbom))
    return items


def _dependency_check_resolved(resolved: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The lockfile-parsed dependency count, no rigor requirement beyond
    "has a non-empty uri" -- the same bar SLSA Build Level 2's dependency
    item used to apply (see _evaluate_slsa_l2's docstring)."""
    label = "Materialized Resolved Dependencies"
    valid = [d for d in resolved if isinstance(d.get("uri"), str) and d.get("uri").strip()]
    if not valid:
        return _slsa_item(
            label, False,
            "predicate.resolved_dependencies is missing or empty -- no lockfile was detected/parsed for this run",
        )
    return _slsa_item(f"{label} ({len(valid)} packages recorded)", True)


def _dependency_check_locked(resolved: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Stricter subset of _dependency_check_resolved: counts only entries
    hash-pinned to a real `pkg:` PURL with a sha256/sha512 digest (see
    _MATERIALIZED_DIGEST_ALGORITHMS) -- the same bar SLSA Build Level 3's
    dependency item used to apply. Any entry that doesn't clear it
    (Gradle/Maven lockfiles carry no digest at all -- see
    cli/parsers/lockfiles.py's parse_gradle_lockfile/parse_maven_pom_dependencies)
    is counted as floating and named in the passing label, so a real delta
    between the resolved and locked counts is never left unexplained."""
    label = "Materialized Locked Dependencies"

    def _is_locked(d: Dict[str, Any]) -> bool:
        uri = d.get("uri")
        if not isinstance(uri, str) or not uri.startswith("pkg:"):
            return False
        digest = d.get("digest")
        if not isinstance(digest, dict):
            return False
        return any(isinstance(digest.get(algo), str) and bool(digest.get(algo).strip()) for algo in _MATERIALIZED_DIGEST_ALGORITHMS)

    valid = [d for d in resolved if isinstance(d.get("uri"), str) and d.get("uri").strip()]
    locked = [d for d in valid if _is_locked(d)]
    floating = len(valid) - len(locked)

    if not locked:
        return _slsa_item(
            label, False,
            "no 'pkg:' PURL entries with a sha256 or sha512 digest found -- dependencies aren't hash-pinned "
            "to a lockfile",
        )
    detail_suffix = f", {floating} floating (no sha256/sha512 digest)" if floating else ""
    return _slsa_item(f"{label} ({len(locked)} packages locked to hash{detail_suffix})", True)


def _dependency_check_sbom(sbom: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """predicate.artifact.sbom (cli/main.py's _build_sbom_artifact_block)
    -- format is the schema's own enum value ("cyclonedx-json"/
    "spdx-json"), never a prettified display name, so this never claims a
    format lucid-assay didn't actually detect."""
    label = "Canonical SBOM Attached"
    if not sbom:
        return _slsa_item(label, False, "predicate.artifact.sbom is absent -- no --sbom was ingested for this run")
    sha256 = sbom.get("sha256")
    if not isinstance(sha256, str) or not sha256.strip():
        return _slsa_item(label, False, "predicate.artifact.sbom is present but missing a sha256 digest")

    fmt = sbom.get("format")
    detail = f"{fmt}, SHA-256 anchored" if isinstance(fmt, str) and fmt.strip() else "SHA-256 anchored"
    component_count = sbom.get("component_count")
    if isinstance(component_count, int) and not isinstance(component_count, bool):
        detail += f", {component_count} components"
    return _slsa_item(f"{label} ({detail})", True)


def _extract_rekor_info(envelope: Dict[str, Any]) -> Tuple[Optional[int], Optional[str]]:
    """Pulls (logIndex, logUrl) out of the DSSE envelope's own `_rekor`
    block (cli/oidc_signer.py's DSSEEnvelope.to_dict() -- a sibling of
    payload/signatures, not part of the signed predicate itself: Rekor
    coordinates only exist *after* signing, so they could never be
    embedded in the statement that got signed). Both None on a
    --dry-run-sign envelope (no real transparency-log entry was minted),
    an envelope predating this field, or a malformed `_rekor` block --
    never fabricated."""
    rekor = envelope.get("_rekor")
    if not isinstance(rekor, dict):
        return None, None
    log_index = rekor.get("logIndex")
    log_index = log_index if isinstance(log_index, int) and not isinstance(log_index, bool) else None
    log_url = rekor.get("logUrl")
    log_url = log_url if isinstance(log_url, str) and log_url.strip() else None
    return log_index, log_url


def _slsa_item(label: str, passed: bool, detail: str = "") -> Dict[str, Any]:
    """One SLSA checklist row: {label, passed, detail}. `detail` is a
    human-readable explanation of *why* a failed item failed; left "" for
    a passing item -- callers never need to distinguish "passed" from
    "passed with a caveat", only pass/fail plus a reason when it's not."""
    return {"label": label, "passed": passed, "detail": detail}


def _slsa_level_result(
    track: str, level: int, name: str, items: List[Dict[str, Any]], origin: Optional[str] = None
) -> Dict[str, Any]:
    """One level's worth of checklist items (see _slsa_item), for either
    the SLSA Source track or the SLSA Build track. `track` ("Source" or
    "Build") and `level` together drive both the rendered Status line
    (see _format_slsa_level_block) and the FINAL VERDICT banner's
    "(Source Lx / Build Ly)" summary (see _highest_passing_level) -- one
    shape shared by both tracks so the renderer and verdict logic don't
    need to special-case either one. `origin` (see _slsa_invocation_origin)
    is the CI run that produced the statement this level's items were
    evaluated from -- Build-track callers only, Source track has no
    runDetails to draw one from -- rendered by _format_slsa_level_block
    directly inside a failing level's own block."""
    return {
        "track": track,
        "level": level,
        "name": name,
        "items": items,
        "passed": all(i["passed"] for i in items),
        "origin": origin,
    }


def _slsa_check_statement_envelope(statement: Dict[str, Any]) -> Dict[str, Any]:
    statement_type = statement.get("_type")
    passed = statement_type == EXPECTED_STATEMENT_TYPE
    detail = "" if passed else f"unexpected _type: {statement_type!r} (expected {EXPECTED_STATEMENT_TYPE!r})"
    return _slsa_item("in-toto v1 Statement Envelope", passed, detail)


def _slsa_check_predicate_type(statement: Dict[str, Any]) -> Dict[str, Any]:
    predicate_type = statement.get("predicateType")
    passed = predicate_type == SLSA_PROVENANCE_PREDICATE_TYPE
    detail = (
        "" if passed
        else f"unexpected predicateType: {predicate_type!r} (expected {SLSA_PROVENANCE_PREDICATE_TYPE!r})"
    )
    return _slsa_item("SLSA v1.0 Provenance Predicate", passed, detail)


def _slsa_has_build_type(predicate: Dict[str, Any]) -> bool:
    build_definition = predicate.get("buildDefinition")
    build_definition = build_definition if isinstance(build_definition, dict) else {}
    build_type = build_definition.get("buildType")
    return isinstance(build_type, str) and bool(build_type.strip())


def _slsa_has_invocation_metadata(predicate: Dict[str, Any]) -> bool:
    """True if runDetails.metadata carries either an invocationId, or both
    a startedOn and finishedOn timestamp -- either is sufficient evidence
    the build's invocation was actually recorded, per SLSA's own
    BuildMetadata definition (all three fields are individually optional
    there)."""
    run_details = predicate.get("runDetails")
    run_details = run_details if isinstance(run_details, dict) else {}
    metadata = run_details.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}

    if metadata.get("invocationId"):
        return True
    return bool(metadata.get("startedOn")) and bool(metadata.get("finishedOn"))


def _slsa_invocation_origin(predicate: Dict[str, Any]) -> Optional[str]:
    """Extracts runDetails.metadata.invocationId -- when present, already a
    fully-formed https://github.com/<owner>/<repo>/actions/runs/<run_id>/
    attempts/<attempt> URL identifying the exact CI run that produced *this
    SLSA statement* (see slsa_provenance.py::_invocation_metadata, the only
    place that field is ever set). Deliberately not the same thing as
    _format_run_identity_report's "CI Run:" line -- that's sourced from the
    RCS/assay statement's predicate.pipeline, which can legitimately be a
    *different* run than the one that constructed the SLSA statement (e.g.
    the untrusted caller's build job vs. lucid-attest-service's isolated
    signer job). A failed Build Level checklist item needs a link to the run that
    actually produced *its own* predicate, so this is threaded through
    _slsa_level_result and rendered directly inside that level's block (see
    _format_slsa_level_block) instead. Returns None, not "", when absent --
    an off-CI or self-hosted-runner statement legitimately has no
    invocationId at all, same fail-closed contract as the rest of this
    module."""
    run_details = predicate.get("runDetails")
    run_details = run_details if isinstance(run_details, dict) else {}
    metadata = run_details.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    invocation_id = metadata.get("invocationId")
    return invocation_id if isinstance(invocation_id, str) and invocation_id.strip() else None


def _slsa_check_build_definition(predicate: Dict[str, Any]) -> Dict[str, Any]:
    """Combines two SLSA L1 requirements (a populated buildDefinition.
    buildType, and runDetails.metadata invocation evidence) into one
    checklist row -- both describe "the provenance actually records what
    build produced this", so a reader doesn't need two near-identical
    lines to see that's missing."""
    has_build_type = _slsa_has_build_type(predicate)
    has_metadata = _slsa_has_invocation_metadata(predicate)
    label = "Build Definition & Invocation Metadata"
    if has_build_type and has_metadata:
        return _slsa_item(label, True)

    missing = []
    if not has_build_type:
        missing.append("buildDefinition.buildType")
    if not has_metadata:
        missing.append("runDetails.metadata.invocationId (or startedOn/finishedOn)")
    return _slsa_item(label, False, f"missing {', '.join(missing)}")


def _slsa_check_subject_digest(statement: Dict[str, Any]) -> Dict[str, Any]:
    digests = _extract_subject_digests(statement)
    passed = bool(digests)
    detail = "" if passed else "no subject digests present under statement.subject[].digest"
    return _slsa_item("Subject Artifact Digest Verification", passed, detail)


def _evaluate_slsa_l1(statement: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluates the SLSA v1.0 Build Level 1 checklist -- in-toto Statement
    envelope, SLSA provenance predicateType, buildDefinition/runDetails
    invocation metadata, and a subject artifact digest -- against a
    decoded in-toto Statement dict. Purely informational: never raises,
    and its result never feeds into `passed`/exit code (see
    verify_dsse_attestation's docstring). Returns
    {level, name, items, passed} where `items` is a list of
    {label, passed, detail} rows (see _slsa_item) and `passed` is True iff
    every item passed."""
    predicate = statement.get("predicate")
    predicate = predicate if isinstance(predicate, dict) else {}
    items = [
        _slsa_check_statement_envelope(statement),
        _slsa_check_predicate_type(statement),
        _slsa_check_build_definition(predicate),
        _slsa_check_subject_digest(statement),
    ]
    return _slsa_level_result("Build", 1, "SLSA Build Level 1", items, origin=_slsa_invocation_origin(predicate))


def _slsa_check_hosted_builder(predicate: Dict[str, Any]) -> Dict[str, Any]:
    run_details = predicate.get("runDetails")
    run_details = run_details if isinstance(run_details, dict) else {}
    builder = run_details.get("builder")
    builder = builder if isinstance(builder, dict) else {}
    builder_id = builder.get("id")

    if not isinstance(builder_id, str) or not builder_id.strip():
        return _slsa_item("Hosted Builder Identity", False, "missing runDetails.builder.id")

    label = f"Hosted Builder Identity ({builder_id})"
    if builder_id not in TRUSTED_HOSTED_BUILDER_IDS:
        return _slsa_item(
            label, False,
            f"builder id is not in the trusted hosted-builder allowlist {sorted(TRUSTED_HOSTED_BUILDER_IDS)}",
        )
    return _slsa_item(label, True)


def _slsa_check_signature(identity_status: str, identity_detail: str) -> Dict[str, Any]:
    """Reuses the identity_status/identity_detail verify_dsse_attestation()
    already computed via _verify_sigstore_identity() -- this checklist
    item never re-verifies the signature itself, only reports on that
    result. Only the "verified" outcome counts: "skipped"/"unavailable"
    (network/offline conditions) and "failed" all fail this item, since a
    Level 2 tamper-resistance claim requires an actual verified
    signature, not merely the absence of an explicit rejection."""
    passed = identity_status == "verified"
    label = "Cryptographic Envelope Signature (Sigstore Keyless OIDC)"
    detail = "" if passed else f"Sigstore identity_status={identity_status!r}: {identity_detail}"
    return _slsa_item(label, passed, detail)


def _slsa_check_source_binding(predicate: Dict[str, Any], expected_repository: Optional[str]) -> Dict[str, Any]:
    """externalParameters lives under buildDefinition in the SLSA v1.0
    provenance schema (buildDefinition.{buildType, externalParameters,
    internalParameters, resolvedDependencies}), so this reads
    buildDefinition.externalParameters.workflow.repository, not a
    top-level predicate.externalParameters."""
    build_definition = predicate.get("buildDefinition")
    build_definition = build_definition if isinstance(build_definition, dict) else {}
    external_params = build_definition.get("externalParameters")
    external_params = external_params if isinstance(external_params, dict) else {}
    workflow = external_params.get("workflow")
    workflow = workflow if isinstance(workflow, dict) else {}
    repository = workflow.get("repository")
    label = "Authenticated Source Repository Binding"

    if not isinstance(repository, str) or not repository.strip():
        return _slsa_item(label, False, "missing buildDefinition.externalParameters.workflow.repository")

    if expected_repository and expected_repository not in repository:
        return _slsa_item(
            label, False,
            f"buildDefinition.externalParameters.workflow.repository {repository!r} does not match "
            f"expected repository {expected_repository!r}",
        )
    return _slsa_item(label, True)


def _evaluate_slsa_l2(
    statement: Dict[str, Any],
    *,
    identity_status: str,
    identity_detail: str,
    expected_repository: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluates the SLSA v1.0 Build Level 2 checklist -- a trusted hosted
    builder identity, a verified Sigstore keyless signature, and
    authenticated source-repository binding -- against a decoded in-toto
    Statement dict. Purely informational, same contract as
    _evaluate_slsa_l1 (never raises, never gates `passed`). Each item is
    evaluated independently here; see _format_slsa_report for where
    "Level 2 builds on Level 1" (SLSA's leveling is cumulative) is
    actually enforced in the combined Status line.

    Dependency-materialization evidence (buildDefinition.resolvedDependencies)
    used to be a fourth item here, but SLSA v1.0's ratified Build Track
    doesn't define a dependency-materialization level -- that's dependency
    governance (OpenSSF S2C2F ING-1/ING-2 territory), not a Build Level
    claim, so it now lives in its own section: see
    _extract_dependency_evidence/_format_dependency_governance_report."""
    predicate = statement.get("predicate")
    predicate = predicate if isinstance(predicate, dict) else {}
    items = [
        _slsa_check_hosted_builder(predicate),
        _slsa_check_signature(identity_status, identity_detail),
        _slsa_check_source_binding(predicate, expected_repository),
    ]
    return _slsa_level_result("Build", 2, "SLSA Build Level 2", items, origin=_slsa_invocation_origin(predicate))


def _slsa_check_control_plane_builder_identity(predicate: Dict[str, Any]) -> Dict[str, Any]:
    """SLSA Build Level 3's "unforgeable builder identity" requirement:
    runDetails.builder.id must name one of the isolated control-plane
    workflows themselves (TRUSTED_CONTROL_PLANE_BUILDER_IDS), not merely
    a generic hosted runner (TRUSTED_HOSTED_BUILDER_IDS, sufficient for
    Level 2). A caller whose provenance wasn't constructed inside one of
    those specific, individually-reviewed workflows -- e.g. builder.id is
    still the generic hosted-runner id, or names some other workflow
    entirely -- fails closed honestly here, not as a hardcoded stub."""
    run_details = predicate.get("runDetails")
    run_details = run_details if isinstance(run_details, dict) else {}
    builder = run_details.get("builder")
    builder = builder if isinstance(builder, dict) else {}
    builder_id = builder.get("id")
    label = "Unforgeable Control-Plane Builder Identity"

    if not isinstance(builder_id, str) or not builder_id.strip():
        return _slsa_item(label, False, "missing runDetails.builder.id")

    full_label = f"{label} ({builder_id})"
    if builder_id not in TRUSTED_CONTROL_PLANE_BUILDER_IDS:
        return _slsa_item(
            full_label, False,
            f"builder id is not in the trusted isolated-control-plane allowlist "
            f"{sorted(TRUSTED_CONTROL_PLANE_BUILDER_IDS)} -- provenance for this run was not "
            "constructed inside the isolated signer workflow",
        )
    return _slsa_item(full_label, True)


def _slsa_check_isolated_provenance_generation(
    predicate: Dict[str, Any], *, identity_status: str, cert_identity: Optional[str]
) -> Dict[str, Any]:
    """SLSA Build Level 3's other half of "unforgeable": the entity that
    *signed* this envelope must be provably the same entity the envelope
    claims *built* it (runDetails.builder.id) -- otherwise an untrusted
    build job could still construct a forged buildDefinition/runDetails
    even though it can't forge the signature. `cert_identity` is the
    caller-asserted --cert-identity value; identity_status=="verified"
    already proves (via Sigstore's Identity policy, see
    _build_identity_policy) that the *actual* signing certificate matches
    it exactly, so comparing it against builder.id here needs no further
    cryptographic material. The `@<ref>` suffix Fulcio's job_workflow_ref
    always carries is stripped before comparing, since builder.id is
    deliberately ref-independent (see TRUSTED_CONTROL_PLANE_BUILDER_IDS)."""
    label = "Isolated Provenance Generation (signer identity matches builder identity)"

    if identity_status != "verified":
        return _slsa_item(
            label, False,
            f"Sigstore identity_status={identity_status!r}: the signing identity was not "
            "cryptographically confirmed, so it cannot be compared against the claimed builder identity",
        )
    if not cert_identity:
        return _slsa_item(
            label, False,
            "no --cert-identity was asserted; cannot confirm the verified signer identity "
            "matches the provenance's claimed builder identity",
        )

    run_details = predicate.get("runDetails")
    run_details = run_details if isinstance(run_details, dict) else {}
    builder = run_details.get("builder")
    builder = builder if isinstance(builder, dict) else {}
    builder_id = builder.get("id")
    if not isinstance(builder_id, str) or not builder_id.strip():
        return _slsa_item(label, False, "missing runDetails.builder.id; cannot compare against the verified signer identity")

    signer_workflow = cert_identity.split("@", 1)[0]
    if signer_workflow != builder_id:
        return _slsa_item(
            label, False,
            f"verified signer identity ({signer_workflow!r}) does not match the provenance's "
            f"claimed builder identity ({builder_id!r})",
        )
    return _slsa_item(label, True)


# Both are real, currently-unbroken cryptographic hash algorithms suitable
# for a materialization/hermeticity proof -- sha1/md5 deliberately are not
# in this set. Not just a sha256-with-a-sha512-exception either: which one
# a lockfile carries is an ecosystem convention, not a strength signal
# worth gating on. uv.lock (Python) and go.sum emit sha256 natively; npm's
# package-lock.json v2/v3 `integrity` field is SRI, and
# cli/parsers/lockfiles.py's own _decode_sri_integrity already prefers
# sha512 over sha256 when an entry carries both, since sha512 is the
# stronger digest and virtually every real npm package ships only that one
# -- so requiring sha256 specifically meant no JS/TS repo's lockfile could
# ever satisfy this check, structurally, regardless of how well-pinned it
# was. Confirmed via a real run (lucid-provenance/lucid-console PR #1, 2026-08-27):
# a genuine, fully hash-pinned package-lock.json still failed this check
# with "no 'pkg:' PURL entries with a sha256 digest found" purely because
# every one of its ~569 resolved entries carried sha512, never sha256.
# Originally gated SLSA Build Level 3's hermeticity claim
# (_slsa_check_materialized_dependencies); now backs the Dependency
# Materialization Evidence section's locked-dependency check instead (see
# _dependency_check_locked) -- SLSA v1.0's ratified Build Track doesn't
# define a dependency-materialization level, so this stopped being a
# Build Level 3 item, not a stopped-mattering one.
_MATERIALIZED_DIGEST_ALGORITHMS = ("sha256", "sha512")


def _evaluate_slsa_l3(
    statement: Dict[str, Any], *, identity_status: str, cert_identity: Optional[str]
) -> Dict[str, Any]:
    """Evaluates the SLSA v1.0 Build Level 3 checklist -- an unforgeable
    control-plane builder identity and isolated provenance generation (the
    signer and the builder are provably the same entity) -- against a
    decoded in-toto Statement dict. Purely informational, same contract as
    _evaluate_slsa_l1/_l2 (never raises, never gates `passed` on its
    own -- see --require-slsa-build-l3 for the opt-in exception). Both
    items genuinely pass today, confirmed against real CI runs across
    every current caller (lucid-assay, lucid-console, lucid-dsse-collector,
    lucid-attest-service, 2026-09-03) -- lucid-attest-service's
    sign-client.yml constructs provenance from its own isolated context
    when a caller supplies --subject-name/--subject-digest, and its
    --builder-id matches TRUSTED_CONTROL_PLANE_BUILDER_IDS' sole entry.
    Not fail-closed-by-architecture-absence anymore; --require-slsa-build-l3
    stays opt-in because provenance construction is still conditional on a
    caller providing those two flags, not because the underlying mechanism
    doesn't exist.

    Materialized (locked) dependency evidence used to be a third item
    here; moved into its own section for the same reason described on
    _evaluate_slsa_l2 -- see _extract_dependency_evidence/
    _format_dependency_governance_report."""
    predicate = statement.get("predicate")
    predicate = predicate if isinstance(predicate, dict) else {}
    items = [
        _slsa_check_control_plane_builder_identity(predicate),
        _slsa_check_isolated_provenance_generation(predicate, identity_status=identity_status, cert_identity=cert_identity),
    ]
    return _slsa_level_result("Build", 3, "SLSA Build Level 3", items, origin=_slsa_invocation_origin(predicate))


def _source_check_version_controlled(vcs: Dict[str, Any]) -> Dict[str, Any]:
    """Source Level 1: the predicate names a VCS provider, repository, and
    branch -- the minimum "this came from somewhere identifiable" claim."""
    label = "Version Controlled Source (VCS provider & branch binding)"
    missing = [
        field_name
        for field_name, value in (("vcs.provider", vcs.get("provider")), ("vcs.repository", vcs.get("repository")), ("vcs.branch", vcs.get("branch")))
        if not isinstance(value, str) or not value.strip()
    ]
    if missing:
        return _slsa_item(label, False, f"missing {', '.join(missing)}")
    return _slsa_item(label, True)


def _is_hash_shaped(value: Any) -> bool:
    """True for a plausible git commit SHA: a non-empty hex string of at
    least 7 characters (git's historical minimum abbreviation length).
    Not a full 40/64-char format check -- this module treats commit_sha
    fields as opaque strings everywhere else too -- just enough to reject
    an empty/placeholder value."""
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    return len(stripped) >= 7 and all(c in "0123456789abcdefABCDEF" for c in stripped)


def _source_check_verified_history(vcs: Dict[str, Any]) -> Dict[str, Any]:
    """Source Level 2: an explicit commit SHA and base SHA are recorded
    (so the exact source revision, and what it was diffed against, is
    unambiguous), and when this run has PR context, that PR's number and
    target branch are recorded too (explicit lineage)."""
    label = "Verified History & Explicit Lineage (commit SHA, base SHA, PR lineage)"
    missing = []
    if not _is_hash_shaped(vcs.get("commit_sha")):
        missing.append("vcs.commit_sha")
    if not _is_hash_shaped(vcs.get("base_commit_sha")):
        missing.append("vcs.base_commit_sha")

    pull_request = vcs.get("pull_request")
    if isinstance(pull_request, dict):
        if not pull_request.get("number"):
            missing.append("vcs.pull_request.number")
        target_branch = pull_request.get("target_branch")
        if not isinstance(target_branch, str) or not target_branch.strip():
            missing.append("vcs.pull_request.target_branch")

    if missing:
        return _slsa_item(label, False, f"missing {', '.join(missing)}")
    return _slsa_item(label, True)


def _source_check_retained_history(vcs: Dict[str, Any]) -> Dict[str, Any]:
    """Source Level 3: SLSA's "retained history" requires verifiable
    commit-author identity -- not merely a free-text git author
    name/email, which is self-reported by whoever authored the commit
    object and trivially spoofable (`git commit --author=...`, or simply
    an unconfigured `git config user.*`). This check requires
    vcs.commit_author.verified_github_account (see
    cli/parsers/commit_author.py): the commit author's email resolved,
    via GitHub's own commits API, to a *linked, verified* GitHub account
    -- GitHub's `author.login`, populated only on a genuine email match,
    never inferred from the free-text name/email alone. Cryptographic
    commit signing would be a stronger binding still, but isn't required
    here -- a verified GitHub account is the bar this check enforces.
    Fails closed: absent, unavailable, or unverified all report [✗] with
    a distinct reason -- never silently treated as "not applicable"."""
    label = "Retained History & Author Identity (commit author resolves to a verified GitHub account)"
    commit_author = vcs.get("commit_author")
    if not isinstance(commit_author, dict):
        return _slsa_item(label, False, "vcs.commit_author is not captured in this predicate")
    if not commit_author.get("available"):
        reason = commit_author.get("reason") or "commit author identity could not be verified"
        return _slsa_item(label, False, str(reason))
    if not commit_author.get("verified_github_account"):
        email = commit_author.get("email") or "unknown"
        return _slsa_item(
            label, False, f"commit author email ({email}) does not resolve to a linked, verified GitHub account"
        )
    login = commit_author.get("github_login")
    return _slsa_item(f"{label} (author: @{login})", True)


def _source_check_two_party_review(branch_governance: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Source Level 4: branch_governance.approvals_required >= 1 -- the
    branch's own rule mandates at least a second reviewer, not merely
    that *this* PR happened to get one (see cli/builder.py's distinction
    between branch_governance.approvals_required, the branch rule itself,
    and vcs.pull_request.required_approvals, this PR's own state)."""
    label = "Two-Party Code Review & Branch Governance (branch_governance.approvals_required >= 1)"
    if not isinstance(branch_governance, dict):
        return _slsa_item(label, False, "branch_governance block is missing")

    if branch_governance.get("reason_code") == "platform_unsupported_tier":
        return _slsa_item(
            label, False,
            f"branch governance could not be evaluated: unsupported platform tier ({branch_governance.get('reason')})",
        )

    approvals_required = branch_governance.get("approvals_required")
    if not isinstance(approvals_required, int) or isinstance(approvals_required, bool):
        return _slsa_item(label, False, "branch_governance.approvals_required is missing or not an integer")
    if approvals_required < 1:
        return _slsa_item(label, False, f"branch_governance.approvals_required={approvals_required} (requires >= 1)")
    return _slsa_item(f"{label} ({approvals_required} approval(s) required)", True)


def _evaluate_source_l1(vcs: Dict[str, Any]) -> Dict[str, Any]:
    return _slsa_level_result(
        "Source", 1, "Source Policy Level 1: Version Controlled Source", [_source_check_version_controlled(vcs)]
    )


def _evaluate_source_l2(vcs: Dict[str, Any]) -> Dict[str, Any]:
    return _slsa_level_result(
        "Source", 2, "Source Policy Level 2: Verified History & Explicit Lineage", [_source_check_verified_history(vcs)]
    )


def _evaluate_source_l3(vcs: Dict[str, Any]) -> Dict[str, Any]:
    return _slsa_level_result(
        "Source", 3, "Source Policy Level 3: Retained History & Author Identity", [_source_check_retained_history(vcs)]
    )


def _evaluate_source_l4(branch_governance: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return _slsa_level_result(
        "Source", 4, "Source Policy Level 4: Two-Party Code Review & Branch Governance",
        [_source_check_two_party_review(branch_governance)],
    )


def _classify_statements(
    primary: Optional[Dict[str, Any]], secondary: Optional[Dict[str, Any]]
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Sorts up to two decoded in-toto Statements into (assay_statement,
    build_statement) by predicateType, regardless of which was passed as
    the primary envelope vs. the optional --slsa-envelope one -- so
    `lucid-assay verify a.dsse.json --slsa-envelope b.dsse.json` and the
    arguments reversed behave identically. Backward-compatible fallback:
    when a track's statement can't be identified by predicateType (most
    commonly: no --slsa-envelope was given at all), it falls back to
    `primary` -- the same "evaluate against whatever we were given,
    honestly reporting the fields that aren't there" behavior this
    checklist has always had for the Build track (see _evaluate_slsa_l1's
    docstring) is now shared by the Source track too."""
    primary = primary if isinstance(primary, dict) else {}
    secondary = secondary if isinstance(secondary, dict) else None

    assay_stmt: Optional[Dict[str, Any]] = None
    build_stmt: Optional[Dict[str, Any]] = None
    for stmt in (primary, secondary):
        if stmt is None:
            continue
        predicate_type = stmt.get("predicateType")
        if predicate_type == EXPECTED_PREDICATE_TYPE and assay_stmt is None:
            assay_stmt = stmt
        elif predicate_type == SLSA_PROVENANCE_PREDICATE_TYPE and build_stmt is None:
            build_stmt = stmt

    return (assay_stmt if assay_stmt is not None else primary), (build_stmt if build_stmt is not None else primary)


def _extract_vcs_and_governance(statement: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    predicate = statement.get("predicate")
    predicate = predicate if isinstance(predicate, dict) else {}
    vcs = predicate.get("vcs")
    vcs = vcs if isinstance(vcs, dict) else {}
    branch_governance = predicate.get("branch_governance")
    branch_governance = branch_governance if isinstance(branch_governance, dict) else None
    return vcs, branch_governance


def _evaluate_source_checklist(assay_statement: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """Computes all four SLSA Source Level assessments from an assay/v1
    predicate's vcs/branch_governance blocks."""
    vcs, branch_governance = _extract_vcs_and_governance(assay_statement)
    return (
        _evaluate_source_l1(vcs),
        _evaluate_source_l2(vcs),
        _evaluate_source_l3(vcs),
        _evaluate_source_l4(branch_governance),
    )


def _evaluate_slsa_checklists(
    statement: Optional[Dict[str, Any]],
    *,
    identity_status: str,
    identity_detail: str,
    cert_identity: Optional[str],
    expected_repository: Optional[str],
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """Computes all three SLSA Build checklists for verify_dsse_attestation():
    a thin wrapper whose only real job is applying the `statement or {}`
    fallback (a decode failure leaves `statement` as None) exactly once,
    so the _evaluate_slsa_l1/_l2/_l3 call sites in
    verify_dsse_attestation() don't each carry that branch's own
    complexity cost."""
    stmt = statement or {}
    l1 = _evaluate_slsa_l1(stmt)
    l2 = _evaluate_slsa_l2(
        stmt, identity_status=identity_status, identity_detail=identity_detail, expected_repository=expected_repository
    )
    l3 = _evaluate_slsa_l3(stmt, identity_status=identity_status, cert_identity=cert_identity)
    return l1, l2, l3


def _format_slsa_level_block(assessment: Dict[str, Any], overall_passed: bool) -> List[str]:
    """Renders one level's checklist -- header, one [✓]/[✗] row per item
    (with a trailing failure description on any [✗] row), an Origin CI Run
    line when this level failed and its statement carried one (see
    _slsa_invocation_origin -- the run that produced *this* statement, so a
    failing item can be traced back without cross-referencing the report's
    top-of-document "CI Run:" line, which reflects a possibly different
    run), and a Status line. `overall_passed` is taken from the caller
    rather than `assessment["passed"]` directly so _format_track_report can
    fold in each level's cumulative-on-lower-levels requirement without
    this function needing to know about that rule."""
    lines = [f"=== {assessment['name']} Assessment ==="]
    for item in assessment["items"]:
        mark = "✓" if item["passed"] else "✗"
        line = f"[{mark}] {item['label']}"
        if not item["passed"] and item["detail"]:
            line += f" -- {item['detail']}"
        lines.append(line)
    if not overall_passed and assessment.get("origin"):
        lines.append(f"Origin CI Run:  {assessment['origin']}")
    status = "PASSED" if overall_passed else "FAILED"
    # Source Track status is framed as "Source Policy Level N", not
    # "SLSA Source Level N" -- SLSA's Source Track is a draft
    # specification, unlike the ratified Build Track, so its levels are
    # reported as this project's own policy assessment against that draft
    # rather than implied compliance with a finalized SLSA standard.
    if assessment["track"] == "Source":
        lines.append(f"Status: {status} (Source Policy Level {assessment['level']})")
    else:
        lines.append(f"Status: {status} (SLSA {assessment['track']} Level {assessment['level']})")
    return lines


def _cumulative_track_status(levels: List[Dict[str, Any]]) -> List[bool]:
    """Given a track's level assessments in ascending order (e.g. SLSA
    Source Levels 1-4, or SLSA Build Levels 1-3), returns the cumulative
    pass/fail for each -- SLSA's own leveling is cumulative, so Level N is
    only truly "PASSED" when every level from 1..N passed its own checks,
    even though each level's items are still listed and marked
    independently (see _format_slsa_level_block)."""
    cumulative = True
    out = []
    for lvl in levels:
        cumulative = cumulative and bool(lvl["passed"])
        out.append(cumulative)
    return out


def _highest_passing_level(levels: List[Dict[str, Any]], cumulative_status: List[bool]) -> int:
    """The highest level number this track fully (cumulatively) satisfies,
    or 0 if not even Level 1 passes. Used by the FINAL VERDICT banner's
    "(Source Lx / Build Ly)" summary."""
    highest = 0
    for lvl, ok in zip(levels, cumulative_status):
        if not ok:
            break
        highest = lvl["level"]
    return highest


# Fixed-width closing rule shared by every plain-text report section
# below (S2C2F, CD/Signing, SLSA Source/Build tracks, Run Identity) --
# one constant rather than each section repeating the literal.
_SECTION_DIVIDER = "====================================="

_S2C2F_STATUS_MARK = {"met": "✓", "unmet": "✗", "not_yet_reported": "○"}


def _format_s2c2f_report(controls: List[Dict[str, Any]]) -> List[str]:
    """Renders predicate.s2c2f.controls (cli/parsers/s2c2f.py) as a
    checklist grouped by S2C2F level: [✓]/[✗]/[○] per control (met/unmet/
    not_yet_reported respectively -- a distinct third symbol, never folded
    into ✗, since a control that couldn't be evaluated must never look
    like one that was and failed). Purely informational, like the SARIF
    static-analysis table below -- no PASSED/FAILED Status line, since
    S2C2F controls aren't a cumulative leveling the way SLSA's Source/
    Build tracks are; just a coverage summary. [] (no section at all) when
    no controls were evaluated (an attestation predating S2C2F, or a run
    that skipped it) -- matching every other optional section here."""
    if not controls:
        return []

    met_count = sum(1 for c in controls if c.get("status") == "met")
    lines = [f"=== S2C2F Compliance Matrix ({met_count}/{len(controls)} controls met) ==="]

    by_level: Dict[int, List[Dict[str, Any]]] = {}
    for c in controls:
        by_level.setdefault(c.get("level") or 0, []).append(c)

    for level in sorted(by_level):
        lines.append(f"-- Level {level} --")
        for c in by_level[level]:
            mark = _S2C2F_STATUS_MARK.get(c.get("status"), "?")
            line = f"[{mark}] {c.get('id', '?')} {c.get('label', '')}"
            detail = c.get("detail")
            if detail:
                line += f" -- {detail}"
            lines.append(line)
    lines.append(_SECTION_DIVIDER)
    return lines


def _format_repository_governance_report(items: List[Dict[str, Any]]) -> List[str]:
    """Renders the Repository & Workstation Governance checklist (see
    _extract_repository_governance) -- solo-maintainer compensating
    controls (cryptographic commit signing, branch-ruleset hygiene), kept
    deliberately isolated from both the ratified SLSA Build Track and the
    still-draft Source Track: this project's own policy assessment, not
    a claim about either specification. Purely informational like the
    S2C2F/Dependency Materialization Evidence sections -- no cumulative
    Status line, since these are four independent controls, not a leveled
    track. One exception to "purely informational": the Cryptographic
    Commit Signing item specifically can be folded into the hard gate via
    --require-commit-signing (see verify_dsse_attestation) -- the other
    three have no such opt-in path today, so a caller must not assume
    setting that flag also requires branch-ruleset hygiene. [] (no
    section at all) when _extract_repository_governance found nothing,
    matching every other optional section here."""
    if not items:
        return []
    met_count = sum(1 for i in items if i["passed"])
    lines = [f"=== Repository & Workstation Governance (Policy Assessment) ({met_count}/{len(items)} controls met) ==="]
    for item in items:
        mark = "✓" if item["passed"] else "✗"
        line = f"[{mark}] {item['label']}"
        if not item["passed"] and item["detail"]:
            line += f" -- {item['detail']}"
        lines.append(line)
    lines.append(_SECTION_DIVIDER)
    return lines


def _format_dependency_governance_report(items: List[Dict[str, Any]]) -> List[str]:
    """Renders the Dependency Materialization Evidence checklist (see
    _extract_dependency_evidence) -- lucid-assay's own predicate.
    resolved_dependencies and predicate.artifact.sbom, deliberately never
    SLSA v1.0 provenance's buildDefinition.resolvedDependencies. This used
    to be two items folded into the SLSA Build Level 2/3 Assessment blocks
    (see _evaluate_slsa_l2/_evaluate_slsa_l3's docstrings); it moved here
    because SLSA v1.0's ratified Build Track doesn't define a dependency-
    materialization level -- dependency completeness/pinning is OpenSSF
    S2C2F territory (ING-1 "use a package manager", ING-2 "retain a local
    copy"), which this section's header names for context. It is *not*
    the same evaluation as the S2C2F Compliance Matrix's own ING-1/ING-2
    control rows (_format_s2c2f_report, driven by cli/parsers/s2c2f.py's
    separate met/unmet logic) -- the two sections can legitimately show
    different verdicts for the same run. Purely informational like
    _format_s2c2f_report: no PASSED/FAILED Status line, since nothing here
    is a cumulative SLSA-style leveling and nothing gates on it. []
    (no section at all) when _extract_dependency_evidence found nothing,
    matching every other optional section here."""
    if not items:
        return []
    present_count = sum(1 for i in items if i["passed"])
    lines = [f"=== Dependency Materialization Evidence ({present_count}/{len(items)} present; informs S2C2F ING-1/ING-2) ==="]
    for item in items:
        mark = "✓" if item["passed"] else "✗"
        line = f"[{mark}] {item['label']}"
        if not item["passed"] and item["detail"]:
            line += f" -- {item['detail']}"
        lines.append(line)
    lines.append(_SECTION_DIVIDER)
    return lines


def _format_signing_report(result: "VerificationResult") -> List[str]:
    """Renders the CD/signing summary: Sigstore identity verification
    (result.identity_status/identity_detail, already computed by
    _verify_sigstore_identity) and the Rekor transparency-log entry
    (result.rekor_log_index/rekor_log_url -- the envelope's own _rekor
    block, see _extract_rekor_info) as their own section shared by both
    renderers. Identity status previously only ever reached
    _print_verify_result_human's separate stderr "identity:" line -- never
    $GITHUB_STEP_SUMMARY, since that line lived outside
    _render_track_sections -- exactly the kind of drift that function's
    own docstring warns about; this folds both back into the one shared
    report."""
    lines = ["=== CD / Signing ==="]
    lines.append(f"Sigstore Identity: {result.identity_status} -- {result.identity_detail}")
    if result.rekor_log_index is not None:
        lines.append(f"Rekor Log Entry:   index {result.rekor_log_index}")
        if result.rekor_log_url:
            lines.append(f"Rekor Log URL:     {result.rekor_log_url}")
    else:
        lines.append("Rekor Log Entry:   none (--dry-run-sign, or this envelope predates Rekor log capture)")
    lines.append(_SECTION_DIVIDER)
    return lines


def _format_track_report(levels: List[Dict[str, Any]]) -> Tuple[List[str], List[bool]]:
    """Renders an ordered list of cumulative level assessments (SLSA
    Source Levels 1-4, or SLSA Build Levels 1-3) as plain-text lines --
    see the module README section "Verification (admission gate)" for a
    full example. Returns (lines, cumulative_status) so callers needing
    the highest fully-passing level (the FINAL VERDICT banner) don't have
    to recompute it."""
    cumulative_status = _cumulative_track_status(levels)
    lines: List[str] = []
    for i, (lvl, ok) in enumerate(zip(levels, cumulative_status)):
        if i > 0:
            lines.append("")
        lines.extend(_format_slsa_level_block(lvl, ok))
    lines.append(_SECTION_DIVIDER)
    return lines, cumulative_status


def _extract_run_identity(statement: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Pulls the "where did this predicate come from" fields -- source
    commit/PR (predicate.vcs), CI run (predicate.pipeline), and subject
    artifact -- out of an already-decoded statement, defensively. Shared by
    _format_run_identity_report (text/$GITHUB_STEP_SUMMARY) and
    _build_verify_json_payload so both renderings read the identical
    extraction rather than risk disagreeing about it."""
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    predicate = predicate if isinstance(predicate, dict) else {}
    vcs = predicate.get("vcs") if isinstance(predicate.get("vcs"), dict) else {}
    pipeline = predicate.get("pipeline") if isinstance(predicate.get("pipeline"), dict) else {}
    subjects = statement.get("subject") if isinstance(statement, dict) else None
    subjects = subjects if isinstance(subjects, list) else []
    return {"vcs": vcs, "pipeline": pipeline, "subjects": subjects}


def _format_vcs_lines(vcs: Dict[str, Any]) -> List[str]:
    """Renders the Repository/Branch/Commit/Base commit/Pull Request lines
    of _format_run_identity_report's vcs block -- split out purely to keep
    that function's cognitive complexity within budget, same rationale as
    _format_gate_params below."""
    if not vcs:
        return ["Repository:    unavailable (no predicate.vcs block in this statement)"]

    pr = vcs.get("pull_request") if isinstance(vcs.get("pull_request"), dict) else {}
    lines = [
        f"Repository:    {vcs.get('repository', '-')} ({vcs.get('provider', '-')})",
        f"Branch:        {vcs.get('branch', '-')}",
        f"Commit:        {vcs.get('commit_sha', '-')}",
    ]
    if vcs.get("base_commit_sha"):
        lines.append(f"Base commit:   {vcs['base_commit_sha']}")
    if pr.get("number") is not None:
        lines.append(f"Pull Request:  #{pr['number']} -> {pr.get('target_branch', '-')}")
    return lines


def _format_pipeline_lines(pipeline: Dict[str, Any]) -> List[str]:
    """Renders the CI Run/Workflow Ref lines of _format_run_identity_report's
    pipeline block -- same complexity-budget rationale as _format_vcs_lines."""
    if not pipeline:
        return []
    lines = [
        f"CI Run:        {pipeline.get('ci_provider', '-')} run {pipeline.get('run_id', '-')} "
        f"(attempt {pipeline.get('run_attempt', '-')})"
    ]
    if pipeline.get("workflow_ref"):
        lines.append(f"Workflow Ref:  {pipeline['workflow_ref']}")
    return lines


def _format_subject_lines(subjects: List[Any]) -> List[str]:
    """Renders one "Subject:" line per statement.subject entry of
    _format_run_identity_report -- same complexity-budget rationale as
    _format_vcs_lines."""
    lines = []
    for s in subjects:
        if not isinstance(s, dict):
            continue
        digest = s.get("digest") if isinstance(s.get("digest"), dict) else {}
        digest_str = ", ".join(f"{alg}:{val}" for alg, val in digest.items()) or "-"
        lines.append(f"Subject:       {s.get('name', '-')} @ {digest_str}")
    return lines


def _format_run_identity_report(result: "VerificationResult") -> List[str]:
    """Renders a "where did this come from" header: the source commit/PR/CI
    run this predicate was built from (predicate.vcs/pipeline, when
    present) and the exact admission-gate parameters this verify call was
    invoked with (result.gate_params). Exists so a report -- especially the
    $GITHUB_STEP_SUMMARY rendering, which is routinely read on its own,
    days later or copy-pasted out of context -- never leaves a reader
    guessing which push/PR produced it or which --min-rcs/--disallow-degraded
    values are actually enforcing the verdict below. The vcs/pipeline/
    subjects blocks are each rendered by their own _format_*_lines helper
    (see their docstrings) purely to keep this function's own cognitive
    complexity within budget -- this is just their assembly order."""
    identity = _extract_run_identity(result.statement)

    lines = ["=== Run Identity & Gate Parameters ==="]
    lines.extend(_format_vcs_lines(identity["vcs"]))
    lines.extend(_format_pipeline_lines(identity["pipeline"]))
    lines.extend(_format_subject_lines(identity["subjects"]))
    lines.extend(_format_gate_params(result.gate_params))
    lines.append(_SECTION_DIVIDER)
    return lines


def _format_gate_params(gate_params: Optional[Dict[str, Any]]) -> List[str]:
    """Renders the admission-gate parameters (--min-rcs/--disallow-degraded/
    --cert-identity/--expected-*) a verify call was invoked with -- split
    out of _format_run_identity_report purely to keep that function short.
    Identity-pinning and --expected-* lines are omitted entirely when unset
    (None/empty for every field in that group) rather than printed as a row
    of '-'s, since the vast majority of calls don't set them."""
    gp = gate_params or {}
    if not gp:
        return []

    lines = [
        "Gate:          "
        f"min_rcs={gp.get('min_rcs')} disallow_degraded={gp.get('disallow_degraded')} "
        f"require_digest={gp.get('require_digest')} require_slsa_build_l3={gp.get('require_slsa_build_l3')} "
        f"dry_run={gp.get('dry_run')}"
    ]
    if gp.get("cert_identity") or gp.get("cert_oidc_issuer"):
        lines.append(
            "Identity pin:  "
            f"cert_identity={gp.get('cert_identity') or '-'} cert_oidc_issuer={gp.get('cert_oidc_issuer') or '-'}"
        )
    if gp.get("expected_repository") or gp.get("expected_workflow") or gp.get("expected_ref"):
        lines.append(
            "Expected:      "
            f"repository={gp.get('expected_repository') or '-'} workflow={gp.get('expected_workflow') or '-'} "
            f"ref={gp.get('expected_ref') or '-'}"
        )
    return lines


def _format_pct(rate: Any) -> str:
    """Formats a 0.0-1.0 line-rate/ratio as a percentage string with one
    decimal place. Returns "n/a" for anything not a finite, non-bool
    number -- missing/malformed input degrades to a display placeholder,
    never a raised exception."""
    if not isinstance(rate, (int, float)) or isinstance(rate, bool):
        return "n/a"
    if math.isnan(rate) or math.isinf(rate):
        return "n/a"
    return f"{rate * 100:.1f}%"


def _format_coverage_line(metrics: Dict[str, Any]) -> str:
    """Total code coverage and new/patch code coverage, side by side --
    the two coverage.overall.line_rate / coverage.patch.line_rate values
    already embedded in the predicate (see cli.builder), just surfaced as
    a single scannable summary line instead of requiring a reader to dig
    them out of the per-component RCS breakdown below."""
    overall = metrics.get("coverage_overall")
    overall = overall if isinstance(overall, dict) else {}
    patch = metrics.get("coverage_patch")
    patch = patch if isinstance(patch, dict) else {}

    total_pct = _format_pct(overall.get("line_rate"))
    if patch.get("available") is False:
        patch_pct = f"n/a ({patch.get('reason') or 'unavailable'})"
    else:
        patch_pct = _format_pct(patch.get("line_rate"))

    return f"Coverage:       {total_pct} of total code covered, {patch_pct} of new/patch code covered"


def _format_test_validity_line(metrics: Dict[str, Any]) -> Optional[str]:
    """The fraction of test functions that are "valid" (>=1 real,
    non-tautological assertion) rather than "vanity" (an empty body, or
    every assertion in it tautological, e.g. `assert True`) -- see
    cli.parsers.ast._tally. Returns None (not a "0%" line) when
    valid_test_functions/total_test_functions are absent, which is
    expected on an attestation predating this field or a hand-built test
    fixture that never populated assertion_density at all -- silence is
    the honest answer there, not a fabricated zero."""
    assertion_density = metrics.get("assertion_density")
    assertion_density = assertion_density if isinstance(assertion_density, dict) else {}
    total = assertion_density.get("total_test_functions")
    valid = assertion_density.get("valid_test_functions")

    if not isinstance(total, int) or total <= 0 or not isinstance(valid, int):
        return None

    vanity = max(total - valid, 0)
    return f"Test Validity:  {_format_pct(valid / total)} valid ({valid}/{total} test functions; {vanity} vanity)"


# (display label, predicate.coverage.real key, predicate.coverage.thresholds key)
_REAL_COVERAGE_TRACKS = (("Total", "overall", "overall_min"), ("Patch", "patch", "patch_min"))


def _format_real_coverage_track_line(label: str, track: Any) -> Optional[str]:
    """One line for a single real-coverage track (overall or patch), or
    None if this track wasn't available -- --coverage-contexts wasn't
    provided at all, or (patch specifically) no patch-modified-lines data
    was available for this run. Never fabricates a percentage for an
    unavailable track."""
    if not isinstance(track, dict) or not track.get("available"):
        return None
    measured = _format_pct(track.get("measured_line_rate"))
    real = _format_pct(track.get("real_line_rate"))
    vanity_only = track.get("vanity_only_lines")
    line = f"Real {label} Coverage: {real} (measured {measured}"
    if isinstance(vanity_only, int) and vanity_only > 0:
        line += f", {vanity_only} vanity-only-covered line(s) of {track.get('total_lines')}"
    return line + ")"


def _format_real_coverage_threshold_warning(label: str, track: Any, threshold: Any) -> Optional[str]:
    """Flags the exact scenario this whole analysis exists to catch:
    measured coverage clears the configured --overall-coverage-min/
    --patch-coverage-min threshold, but real (vanity-discounted) coverage
    does not -- i.e. some of the coverage the gate is trusting is only
    exercised by tests that verify nothing. None when either rate is
    unavailable/non-numeric or no threshold is configured for this track,
    or when real coverage doesn't actually fall short."""
    if not isinstance(track, dict) or not track.get("available") or not isinstance(threshold, (int, float)):
        return None
    real_rate = track.get("real_line_rate")
    measured_rate = track.get("measured_line_rate")
    if not isinstance(real_rate, (int, float)) or not isinstance(measured_rate, (int, float)):
        return None
    if not (real_rate < threshold <= measured_rate):
        return None
    return (
        f"  ⚠ real {label.lower()} coverage {_format_pct(real_rate)} is BELOW the "
        f"{_format_pct(threshold)} threshold, even though measured {label.lower()} coverage "
        f"{_format_pct(measured_rate)} passes it"
    )


def _format_real_coverage_summary(metrics: Dict[str, Any]) -> List[str]:
    """Renders the "Real <Total|Patch> Coverage: ..." line (and, when it
    actually applies, the threshold-crossing warning right under it) for
    each track --coverage-contexts data is available for. A no-op ([])
    entirely when predicate.coverage.real is absent (--coverage-contexts
    wasn't used for this run) -- same "absent, not fabricated" contract
    as every other optional block in this report."""
    real = metrics.get("coverage_real")
    real = real if isinstance(real, dict) else {}
    thresholds = metrics.get("coverage_thresholds")
    thresholds = thresholds if isinstance(thresholds, dict) else {}

    lines: List[str] = []
    for label, track_key, threshold_key in _REAL_COVERAGE_TRACKS:
        track = real.get(track_key)
        track_line = _format_real_coverage_track_line(label, track)
        if not track_line:
            continue
        lines.append(track_line)
        warning = _format_real_coverage_threshold_warning(label, track, thresholds.get(threshold_key))
        if warning:
            lines.append(warning)
    return lines


def _format_test_coverage_summary(result: "VerificationResult") -> List[str]:
    """Renders the at-a-glance percentages every report/step-summary
    should lead with: total code coverage, new/patch code coverage, the
    valid-vs-vanity test ratio, and -- when --coverage-contexts was used
    for this run -- vanity-test-discounted "real" coverage for each
    track (see _format_real_coverage_summary), including a threshold-
    crossing warning when real coverage alone would fail a gate measured
    coverage currently passes. A no-op ([]) when result.metrics itself is
    empty (e.g. a VerificationResult built directly by a test, or a
    decode failure that never reached _extract_metrics) -- same
    "absent, not fabricated" contract as every other optional block in
    this report."""
    if not result.metrics:
        return []
    lines = [_format_coverage_line(result.metrics)]
    validity_line = _format_test_validity_line(result.metrics)
    if validity_line:
        lines.append(validity_line)
    lines.extend(_format_real_coverage_summary(result.metrics))
    return lines


def _format_assay_health_report(result: "VerificationResult") -> List[str]:
    """Renders the Assay Health & Governance Metrics block: total/patch
    code coverage and the valid-vs-vanity test ratio (see
    _format_test_coverage_summary) up front, then the Release Confidence
    Score, its per-component breakdown (test health, assertion density,
    coverage, governance, ...), and itemized degraded reasons. Reports
    "unavailable" rather than fabricating a score when no RCS predicate
    was loaded (e.g. --slsa-envelope was the only statement that decoded
    successfully) -- the coverage/validity summary is still attempted in
    that case, since it's independent of whether an RCS score exists."""
    lines = ["=== Assay Health & Governance Metrics ==="]
    if result.rcs_value is None:
        lines.append("Release Confidence Score: unavailable (no release_confidence_score predicate loaded)")
        lines.extend(_format_test_coverage_summary(result))
        return lines

    lines.append(f"Release Confidence Score (RCS): {result.rcs_value} (degraded={result.degraded})")
    lines.extend(_format_test_coverage_summary(result))
    if result.rcs_components:
        lines.append("Component breakdown:")
        for name in sorted(result.rcs_components):
            comp = result.rcs_components[name]
            if not isinstance(comp, dict):
                continue
            lines.append(
                f"  - {name}: raw={comp.get('raw_score')} weight={comp.get('weight')} "
                f"weighted={comp.get('weighted_score')}"
            )
            reason = comp.get("reason")
            if reason:
                lines.append(f"      {reason}")
    if result.degraded and result.degraded_reasons:
        lines.append("Degraded reasons:")
        for r in result.degraded_reasons:
            lines.append(f"  - {r}")
    return lines


def _verdict_word(result: "VerificationResult", source_highest: int, build_highest: int) -> str:
    """The bare FAILED/GATED/PASSED word (see _format_verdict_banner's own
    docstring for what each means) -- factored out so the top-of-report
    heading (_print_verify_result_human/_render_step_summary_markdown) can
    share the exact word FINAL VERDICT uses, rather than computing its own
    separate PASS/FAIL binary that only answers the narrower "did the hard
    admission gate reject this" question under a word ("PASS") that
    collides with FINAL VERDICT's own distinct "PASSED" state -- confusing
    to skim, especially for a reader (e.g. an auditor) who reads only the
    heading and never reaches FINAL VERDICT below it."""
    if not result.passed:
        return "FAILED"
    if source_highest >= 4 and build_highest >= 3:
        return "PASSED"
    return "GATED"


def _format_verdict_banner(result: "VerificationResult", source_highest: int, build_highest: int) -> List[str]:
    """Synthesizes the single FINAL VERDICT line summarizing the whole
    report. Three words, not two (see _verdict_word):
      FAILED - the hard admission gate itself rejected this run
               (result.passed is False: --min-rcs/--disallow-degraded/
               identity -- exactly as before; the SLSA checklists never
               affect this unless --require-slsa-build-l3 was set).
      GATED  - the hard gate passed (this run is admissible), but it
               hasn't yet reached full SLSA compliance on one or both
               tracks (Source Level 4 / Build Level 3) -- shippable, not
               yet fully certified.
      PASSED - the hard gate passed *and* both tracks are fully
               (cumulatively) compliant through their top level.
    The trailing clause names the first incomplete track/level standing
    between GATED and PASSED; omitted once both tracks are maxed."""
    verdict_word = _verdict_word(result, source_highest, build_highest)
    fully_compliant = source_highest >= 4 and build_highest >= 3

    incomplete = None
    if not fully_compliant:
        if build_highest < 3:
            incomplete = f"SLSA Build L{build_highest + 1} Incomplete"
        else:
            incomplete = f"Source Policy L{source_highest + 1} Incomplete"

    headline = f"FINAL VERDICT: {verdict_word} (Source L{source_highest} / Build L{build_highest})"
    if incomplete:
        headline += f" — {incomplete}"

    bar = "=" * 80
    return [bar, headline, bar]


def _load_schema() -> Optional[Dict[str, Any]]:
    """Best-effort load of the packaged predicate JSON Schema, cached after
    the first call. Returns None (never raises) if the file is missing,
    unreadable, or not valid JSON -- schema validation is an optional guard
    layered on top of everything else in this module, and a broken/absent
    schema file must degrade to "skipped", not crash the gate."""
    global _schema_cache
    if _schema_cache is not None:
        return _schema_cache
    try:
        with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
            _schema_cache = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    return _schema_cache


def _validate_against_schema(predicate: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Best-effort structural validation of the predicate against the
    packaged JSON Schema (schema/lucid-attestation-v1.schema.json).

    Returns (status, messages):
      - "passed": schema loaded, jsonschema ran, zero violations. messages=[].
      - "failed": schema loaded, jsonschema ran, real violations found.
        messages is one human-readable "<path>: <detail>" entry per
        violation. The caller surfaces these as non-blocking `warnings`,
        not `violations` -- this predicate schema evolves over time (see
        the call site's comment), so a mismatch is diagnostic signal, not
        proof of a hostile or corrupt payload on its own.
      - "skipped": jsonschema isn't installed, the schema file is
        unavailable, or validation itself raised unexpectedly (e.g. a
        corrupt packaged schema). messages is exactly one diagnostic
        entry explaining why. Either way (failed or skipped), a schema
        problem alone must never be able to fail an otherwise-valid
        attestation's admission gate.
    """
    if not _JSONSCHEMA_AVAILABLE:
        return "skipped", ["jsonschema package is not installed"]

    schema = _load_schema()
    if schema is None:
        return "skipped", [f"predicate schema file unavailable or unreadable at {_SCHEMA_PATH}"]

    try:
        validator = jsonschema.Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(predicate), key=str)
    except Exception as e:  # noqa: BLE001 -- a broken schema/validator must degrade, never crash the gate
        return "skipped", [f"schema validation raised unexpectedly ({e}); treating as unavailable"]

    if not errors:
        return "passed", []

    return "failed", [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in errors
    ]


def _static_analysis_tool_entry(t: Dict[str, Any]) -> Dict[str, Any]:
    """Builds one tool's {errors, warnings, quality_gate} entry for
    _static_analysis_tools_by_name -- split out purely to keep that
    function's cognitive complexity down (SonarCloud flagged it at 18 of
    an allowed 15); behavior is unchanged. A field that isn't the expected
    type is simply omitted from the entry rather than defaulting to a
    fabricated value."""
    entry: Dict[str, Any] = {}
    summary = t.get("summary") if isinstance(t.get("summary"), dict) else {}
    errors = summary.get("errors")
    warnings = summary.get("warnings")
    if isinstance(errors, int) and not isinstance(errors, bool):
        entry["errors"] = errors
    if isinstance(warnings, int) and not isinstance(warnings, bool):
        entry["warnings"] = warnings
    extensions = t.get("extensions") if isinstance(t.get("extensions"), dict) else {}
    sonarqube = extensions.get("sonarqube") if isinstance(extensions.get("sonarqube"), dict) else {}
    quality_gate = sonarqube.get("quality_gate")
    if isinstance(quality_gate, str):
        entry["quality_gate"] = quality_gate
    return entry


def _static_analysis_tools_by_name(tools: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Reshapes the internal per-tool SARIF list (see
    _extract_static_analysis_tools) into a {tool_name: {...}} mapping for
    --format json, merging each tool's error/warning summary and SonarQube
    quality-gate extension (when present) into one flat object per tool
    (see _static_analysis_tool_entry). Purely a display transform over
    already-validated data -- a tool with no usable name is skipped rather
    than raising."""
    out: Dict[str, Dict[str, Any]] = {}
    for t in tools:
        name = t.get("name")
        if not isinstance(name, str) or not name:
            continue
        out[name] = _static_analysis_tool_entry(t)
    return out


def _build_verify_json_payload(result: VerificationResult) -> Dict[str, Any]:
    """Assembles the --format json payload: the complete verification
    result (envelope shape, RCS score + component breakdown, static
    analysis, violations/warnings/identity) plus the same SLSA Source
    Level 1-4 and Build Level 1-3 checklists the text formatter renders
    via _format_track_report (result.source_level1../slsa_level1..,
    computed once by _evaluate_source_checklist()/_evaluate_slsa_checklists()
    inside verify_dsse_attestation() -- json and text output must never
    disagree about SLSA compliance, so this reads the identical
    already-computed result rather than recomputing its own assessment),
    plus the synthesized FINAL VERDICT headline (result.verdict) and its
    bare FAILED/GATED/PASSED word (result.verdict_word, see
    _verdict_word), plus run_identity/gate_params (see _extract_run_identity and
    VerificationResult.gate_params -- the same "where did this come from,
    what gate was enforced" fields _format_run_identity_report renders as
    text, kept here so a --format json consumer gets the identical
    traceability without having to parse the text report). Never raises --
    every field it reads off `result` is already defensively populated by
    verify_dsse_attestation()."""
    statement = result.statement or {}
    subjects = statement.get("subject")
    return {
        "version": "1.0.0",
        "verified": result.passed,
        "verdict": result.verdict,
        "verdict_word": result.verdict_word or "FAILED",
        "source_highest_level": result.source_highest_level,
        "build_highest_level": result.build_highest_level,
        "envelope": {
            "statement_type": statement.get("_type"),
            "predicate_type": statement.get("predicateType"),
            "subject": subjects if isinstance(subjects, list) else [],
        },
        "run_identity": _extract_run_identity(result.statement),
        "gate_params": result.gate_params,
        "source": {
            "level_1": result.source_level1,
            "level_2": result.source_level2,
            "level_3": result.source_level3,
            "level_4": result.source_level4,
        },
        "slsa": {"level_1": result.slsa_level1, "level_2": result.slsa_level2, "level_3": result.slsa_level3},
        "release_confidence_score": {
            "score": result.rcs_value,
            "degraded": result.degraded,
            "degraded_field_present": result.degraded_field_present,
            "degraded_reasons": result.degraded_reasons or [],
            "components": result.rcs_components,
        },
        "test_coverage": result.metrics,
        "static_analysis": {
            "tools": _static_analysis_tools_by_name(result.static_analysis_tools),
        },
        "s2c2f": {
            "controls": result.s2c2f_controls,
        },
        "dependency_governance": {
            "items": result.dependency_governance_items,
        },
        "repository_governance": {
            "items": result.repository_governance_items,
        },
        "identity": {
            "status": result.identity_status,
            "detail": result.identity_detail,
        },
        "signing": {
            "rekor_log_index": result.rekor_log_index,
            "rekor_log_url": result.rekor_log_url,
        },
        "violations": result.violations,
        "warnings": result.warnings,
    }


def _static_analysis_table_row(t: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """Builds one tool's (display_name, errors, warnings, quality_gate)
    display row for _format_static_analysis_table -- split out purely to
    keep that function's cyclomatic/cognitive complexity down (it hit 15
    of the allowed 15 once this row-labeling logic moved in; same
    rationale as _static_analysis_tool_entry above, split out of
    _static_analysis_tools_by_name for the identical reason). Missing/
    malformed fields degrade to '-' rather than raising.

    A tool's `extensions.sonarqube` block isn't necessarily *from* a
    SonarQube SARIF driver: SonarQube Cloud/Server doesn't emit a local
    SARIF file at all (see cli.parsers.sarif's module docstring), so its
    quality-gate/complexity/debt metrics are fed in externally via
    --sonar-metrics and `merge_sonar_metrics_into_tools()`, which attaches
    them to whichever SARIF tool matched by name -- or, when nothing
    matched "sonar*", to the sole scanned tool as an unambiguous fallback
    (e.g. a lone "CodeQL" row). Left unlabeled, that row shows a quality
    gate with no indication the data came from SonarQube at all -- which
    read as "SonarQube info is missing" even though it was merged in.
    So a tool whose own name doesn't already say "sonar" gets its display
    name suffixed with "(+ SonarQube)" whenever it carries that merged-in
    extension, making the source of the quality gate column explicit
    without inventing a separate, unbacked "SonarQube" row."""
    name = str(t.get("name") or "unknown")
    summary = t.get("summary") if isinstance(t.get("summary"), dict) else {}
    errors = summary.get("errors")
    warnings = summary.get("warnings")
    extensions = t.get("extensions") if isinstance(t.get("extensions"), dict) else {}
    sonarqube = extensions.get("sonarqube") if isinstance(extensions.get("sonarqube"), dict) else {}
    quality_gate = sonarqube.get("quality_gate")
    display_name = f"{name} (+ SonarQube)" if sonarqube and "sonar" not in name.lower() else name
    return (
        display_name,
        str(errors) if isinstance(errors, int) else "-",
        str(warnings) if isinstance(warnings, int) else "-",
        str(quality_gate) if isinstance(quality_gate, str) else "-",
    )


def _format_static_analysis_table(tools: List[Dict[str, Any]]) -> List[str]:
    """Renders a clean, fixed-width summary table (tool, error/warning
    counts, SonarQube quality gate status when present) for --verify's
    human-readable (non-JSON) output -- purely a layout/alignment pass over
    rows already built defensively by _static_analysis_table_row (which see
    for what each column means and where the data comes from)."""
    if not tools:
        return []

    rows = [_static_analysis_table_row(t) for t in tools]

    header = ("TOOL", "ERRORS", "WARNINGS", "QUALITY GATE")
    widths = [max(len(header[i]), *(len(r[i]) for r in rows)) for i in range(len(header))]

    def _fmt_row(cells: tuple) -> str:
        return "    " + "  ".join(c.ljust(w) for c, w in zip(cells, widths))

    return [_fmt_row(header)] + [_fmt_row(r) for r in rows]


def _pem_to_der_b64(pem: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    return base64.b64encode(cert.public_bytes(Encoding.DER)).decode("ascii")


def _envelope_to_bundle_json(envelope: Dict[str, Any]) -> str:
    """Returns the raw JSON of the Sigstore bundle to feed to
    `sigstore.models.Bundle.from_json()`.

    Preferred path: cli.oidc_signer embeds the complete, untouched bundle
    produced by `Signer.sign_dsse()` (via `Bundle.to_json()`) under
    `_sigstore_bundle` -- that object already satisfies Bundle's schema in full (mediaType,
    verificationMaterial.tlogEntries with kindVersion/inclusionProof/
    canonicalizedBody, dsseEnvelope, ...), so it's re-serialized and handed
    to Bundle.from_json() verbatim, with no field-by-field reconstruction.

    Fallback path: envelopes minted before `_sigstore_bundle` existed (or a
    --dry-run-sign envelope that never went through real signing) carry
    only sig/certificate/rekor log coordinates. That's necessarily
    incomplete relative to a full bundle -- notably it can never supply a
    tlogEntries entry's required kindVersion/inclusionProof/
    canonicalizedBody -- so Bundle.from_json() will reject it whenever a
    real transparency-log entry is present, and verification degrades to
    "unavailable" rather than crashing. This path exists only for
    backward-compatibility with those older envelopes; new envelopes always
    take the preferred path above."""
    sigstore_bundle = envelope.get("_sigstore_bundle")
    if isinstance(sigstore_bundle, dict) and sigstore_bundle:
        return json.dumps(sigstore_bundle)

    sig0 = envelope["signatures"][0]
    cert_der_b64 = _pem_to_der_b64(sig0.get("certificate", ""))

    rekor = envelope.get("_rekor") or {}
    log_index = rekor.get("logIndex")
    log_id = rekor.get("logId")

    bundle: Dict[str, Any] = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": cert_der_b64},
        },
        "dsseEnvelope": {
            "payload": envelope.get("payload", ""),
            "payloadType": envelope.get("payloadType", ""),
            "signatures": [{"sig": sig0.get("sig", "")}],
        },
    }
    if log_index is not None and log_id:
        bundle["verificationMaterial"]["tlogEntries"] = [
            {"logIndex": log_index, "logId": {"keyId": log_id}}
        ]
    return json.dumps(bundle)


def _der_decode_short_utf8_string(raw: bytes) -> Optional[str]:
    """Minimal DER decoder for a primitive UTF8String (tag 0x0C) with a
    short-form length (i.e. under 128 bytes -- true for every Fulcio v2
    claim value checked here: repo/ref names never approach that). Returns
    None if `raw` doesn't match that exact shape, rather than guessing at a
    more general (and unnecessary, for our purposes) ASN.1 decoder."""
    if len(raw) < 2 or raw[0] != 0x0C:
        return None
    length = raw[1]
    if length & 0x80 or len(raw) != 2 + length:
        return None
    try:
        return raw[2:].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _extract_cert_ext_v1_or_v2(cert: Any, v1_oid: str, v2_oid: str) -> Optional[str]:
    """Extracts a Fulcio GitHub Actions OIDC claim from `cert`, checking the
    legacy v1 extension (raw UTF-8 bytes) first and falling back to the
    current v2 extension (DER-encoded UTF8String) -- whichever version
    minted the cert. Returns None if neither extension is present or
    parseable."""
    from cryptography.x509 import ExtensionNotFound, ObjectIdentifier

    try:
        raw = cert.extensions.get_extension_for_oid(ObjectIdentifier(v1_oid)).value.value
        return raw.decode("utf-8")
    except ExtensionNotFound:
        pass
    except UnicodeDecodeError:
        return None

    try:
        raw = cert.extensions.get_extension_for_oid(ObjectIdentifier(v2_oid)).value.value
    except ExtensionNotFound:
        return None
    return _der_decode_short_utf8_string(raw)


def _extract_cert_ref(cert: Any) -> Optional[str]:
    """Extracts the GitHub Actions ref from a Fulcio certificate, checking
    both the legacy v1 extension (raw UTF-8 bytes) and the current v2
    extension (DER-encoded UTF8String) -- whichever version minted the
    cert. Returns None if neither extension is present."""
    return _extract_cert_ext_v1_or_v2(cert, _GITHUB_WORKFLOW_REF_OID, _OIDC_SOURCE_REPOSITORY_REF_OID)


def _describe_actual_cert_claims(cert: Any) -> str:
    """Best-effort, human-readable summary of a Fulcio certificate's SAN and
    GitHub Actions OIDC claims (issuer, repository, workflow name, ref), for
    logging alongside a failed identity policy's expected claims so a
    mismatch is immediately diagnoseable in CI logs. Never raises -- a claim
    that's absent, unparseable, or hits an unexpected cert shape is reported
    as None rather than aborting the whole summary."""
    from cryptography import x509
    from cryptography.x509 import ExtensionNotFound
    from cryptography.x509.oid import ExtensionOID

    san: Optional[str] = None
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        uris = san_ext.get_values_for_type(x509.UniformResourceIdentifier)
        san = uris[0] if uris else None
    except ExtensionNotFound:
        pass
    except Exception:  # noqa: BLE001 - diagnostics must never themselves crash the gate
        san = UNPARSEABLE_LITERAL

    try:
        issuer = _extract_cert_ext_v1_or_v2(cert, _OIDC_ISSUER_V1_OID, _OIDC_ISSUER_V2_OID)
    except Exception:  # noqa: BLE001
        issuer = UNPARSEABLE_LITERAL

    try:
        repository = _extract_cert_ext_v1_or_v2(
            cert, _GITHUB_WORKFLOW_REPOSITORY_OID, _OIDC_SOURCE_REPOSITORY_URI_OID
        )
    except Exception:  # noqa: BLE001
        repository = UNPARSEABLE_LITERAL

    try:
        # Workflow name has no v2 successor extension, so re-use the v1/v2
        # helper with the same OID twice -- it'll simply take the v1 branch.
        workflow = _extract_cert_ext_v1_or_v2(cert, _GITHUB_WORKFLOW_NAME_OID, _GITHUB_WORKFLOW_NAME_OID)
    except Exception:  # noqa: BLE001
        workflow = UNPARSEABLE_LITERAL

    try:
        ref = _extract_cert_ref(cert)
    except Exception:  # noqa: BLE001
        ref = UNPARSEABLE_LITERAL

    return f"SAN={san!r} issuer={issuer!r} repository={repository!r} workflow={workflow!r} ref={ref!r}"


class _RefPatternPolicy:
    """Sigstore VerificationPolicy: matches the certificate's GitHub Actions
    ref against a glob pattern (e.g. "refs/heads/main", "refs/tags/v*").
    Fails closed if neither the legacy nor current Fulcio ref extension is
    present on the certificate -- an absent claim is never treated as a
    match."""

    def __init__(self, pattern: str):
        self._pattern = pattern

    def verify(self, cert: Any) -> None:
        from sigstore.errors import VerificationError as SigstoreVerificationError

        ref = _extract_cert_ref(cert)
        if ref is None:
            raise SigstoreVerificationError(
                "certificate contains neither a GitHub Workflow Ref "
                f"({_GITHUB_WORKFLOW_REF_OID}) nor an OIDC Source Repository Ref "
                f"({_OIDC_SOURCE_REPOSITORY_REF_OID}) extension"
            )
        if not fnmatch.fnmatchcase(ref, self._pattern):
            raise SigstoreVerificationError(
                f"certificate's ref {ref!r} does not match expected ref pattern {self._pattern!r}"
            )


def _build_identity_policy(
    *,
    cert_identity: Optional[str],
    cert_oidc_issuer: Optional[str],
    expected_issuer: Optional[str],
    expected_repository: Optional[str],
    expected_workflow: Optional[str],
    expected_ref: Optional[str],
) -> Tuple[Any, bool, str]:
    """Composes a strict Sigstore identity-verification policy from the
    caller's assertion flags, requiring the sigstore package (raises
    ImportError if unavailable -- callers handle that the same way they
    already handle every other sigstore import).

    Every asserted claim is AND-ed together (sigstore.verify.policy.AllOf):
    a certificate must satisfy *all* of them, not merely one. Repository is
    checked against both the legacy GitHubWorkflowRepository extension and
    the current OIDCSourceRepositoryURI extension (AnyOf) since which one a
    given Fulcio certificate carries depends on its minting version.

    Returns (policy, unsafe, detail):
      policy - the composed VerificationPolicy to pass to Verifier.verify_dsse
      unsafe - True iff no identity assertion was requested at all, so
               `policy` is UnsafeNoOp: the signature is checked but the
               signer's identity is NOT
      detail - human-readable summary of what was (or wasn't) asserted, for
               identity_detail/logging
    """
    from sigstore.verify import policy as sp

    # A GitHub-Actions-specific claim is only meaningful -- and only safe to
    # trust -- coming from GitHub's own OIDC issuer. Pin it by default
    # whenever such a claim is asserted, unless the caller explicitly chose
    # a different issuer (e.g. verifying a non-GitHub-Actions attestation).
    resolved_issuer = expected_issuer or cert_oidc_issuer
    if resolved_issuer is None and (expected_repository or expected_workflow or expected_ref):
        resolved_issuer = GITHUB_ACTIONS_OIDC_ISSUER

    children: List[Any] = []
    asserted: List[str] = []

    if cert_identity:
        children.append(sp.Identity(identity=cert_identity, issuer=resolved_issuer))
        asserted.append(f"identity={cert_identity!r}" + (f" issuer={resolved_issuer!r}" if resolved_issuer else ""))
    elif resolved_issuer:
        children.append(sp.OIDCIssuer(resolved_issuer))
        asserted.append(f"issuer={resolved_issuer!r}")

    if expected_repository:
        children.append(
            sp.AnyOf(
                [
                    sp.GitHubWorkflowRepository(expected_repository),
                    sp.OIDCSourceRepositoryURI(f"https://github.com/{expected_repository}"),
                ]
            )
        )
        asserted.append(f"repository={expected_repository!r}")

    if expected_workflow:
        children.append(sp.GitHubWorkflowName(expected_workflow))
        asserted.append(f"workflow={expected_workflow!r}")

    if expected_ref:
        children.append(_RefPatternPolicy(expected_ref))
        asserted.append(f"ref={expected_ref!r}")

    if not children:
        return (
            sp.UnsafeNoOp(),
            True,
            "no identity assertions provided (--cert-identity / --expected-issuer / "
            "--expected-repository / --expected-workflow / --expected-ref); the signature "
            "was checked but the signer's identity was NOT",
        )

    composed = children[0] if len(children) == 1 else sp.AllOf(children)
    return composed, False, "asserted " + ", ".join(asserted)


def _verify_sigstore_identity(
    envelope: Dict[str, Any],
    *,
    dry_run: bool,
    cert_identity: Optional[str],
    cert_oidc_issuer: Optional[str],
    expected_issuer: Optional[str] = None,
    expected_repository: Optional[str] = None,
    expected_workflow: Optional[str] = None,
    expected_ref: Optional[str] = None,
) -> Tuple[str, str]:
    """Best-effort keyless Sigstore identity verification.

    Returns (status, detail):
      "verified"    - cryptographic + identity checks passed
      "skipped"     - intentionally not attempted (--dry-run, or the envelope
                       carries only a --dry-run-sign placeholder signature)
      "unavailable" - could not complete (offline/network, missing trust
                       root, or insufficient bundle material); non-blocking
      "failed"      - Sigstore explicitly rejected the signature/identity;
                       this is the only status that fails the gate
    """
    if dry_run:
        return "skipped", "--dry-run: Sigstore identity verification skipped (no network calls made)"

    signatures = envelope.get("signatures") or []
    if not signatures:
        return "skipped", "no signatures present; nothing to verify"

    sig0 = signatures[0] if isinstance(signatures[0], dict) else {}
    sig_val = sig0.get("sig") or ""
    cert_val = sig0.get("certificate") or ""

    if not sig_val or not cert_val or sig_val == "DRY_RUN_UNSIGNED" or cert_val == "DRY_RUN_NO_CERT":
        return (
            "skipped",
            "envelope carries an unsigned --dry-run-sign placeholder; "
            "re-sign with --sign (or pass --dry-run here) to accept it",
        )

    try:
        from sigstore.errors import MetadataError, NetworkError, TUFError
        from sigstore.errors import VerificationError as SigstoreVerificationError
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
    except ImportError as e:
        return "unavailable", f"sigstore package unavailable; skipping identity verification: {e}"

    try:
        policy, unsafe, policy_detail = _build_identity_policy(
            cert_identity=cert_identity,
            cert_oidc_issuer=cert_oidc_issuer,
            expected_issuer=expected_issuer,
            expected_repository=expected_repository,
            expected_workflow=expected_workflow,
            expected_ref=expected_ref,
        )
    except ImportError as e:
        return "unavailable", f"sigstore package unavailable; skipping identity verification: {e}"

    return _attempt_sigstore_verification(envelope, policy, unsafe, policy_detail)


def _attempt_sigstore_verification(envelope: Dict[str, Any], policy: Any, unsafe: bool, policy_detail: str) -> Tuple[str, str]:
    """Performs the actual Bundle.from_json() + Verifier.verify_dsse() call
    and classifies the outcome into (status, detail). Split out of
    _verify_sigstore_identity so that function's own complexity stays in
    its guard-clause/setup logic, not this exception fan-out. Requires the
    sigstore package (callers reach this only after _verify_sigstore_identity's
    own earlier import check already confirmed it's available)."""
    from sigstore.errors import MetadataError, NetworkError, TUFError
    from sigstore.errors import VerificationError as SigstoreVerificationError
    from sigstore.models import Bundle
    from sigstore.verify import Verifier

    try:
        bundle = Bundle.from_json(_envelope_to_bundle_json(envelope))
        verifier = Verifier.production(offline=False)
        verifier.verify_dsse(bundle, policy)
        if unsafe:
            return "verified", f"Sigstore signature verification succeeded, but {policy_detail}"
        return "verified", f"Sigstore identity verification succeeded ({policy_detail})"
    except SigstoreVerificationError as e:
        # `bundle` is guaranteed bound here: Bundle.from_json() above must
        # have already succeeded for verifier.verify_dsse() to have reached
        # a policy check that could raise this.
        try:
            actual_claims = _describe_actual_cert_claims(bundle.signing_certificate)
        except Exception:  # noqa: BLE001 - diagnostics must never mask the real failure
            actual_claims = "<unavailable: could not introspect signing certificate>"
        print(
            "Sigstore identity verification failed -- expected vs actual certificate claims:\n"
            f"  expected: {policy_detail}\n"
            f"  actual:   {actual_claims}\n"
            f"  error:    {e}",
            file=sys.stderr,
        )
        return "failed", f"Sigstore identity verification failed: {e}"
    except (NetworkError, TUFError, MetadataError) as e:
        return "unavailable", f"Sigstore verification unavailable (offline or trust-root fetch failed): {e}"
    except Exception as e:  # noqa: BLE001 - never let signing-material quirks crash the gate
        return "unavailable", f"Sigstore verification unavailable: {e}"


def _decode_envelope_statement(envelope: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], List[str], List[str]]:
    """Validates DSSE envelope structure (payloadType, signatures, payload)
    and decodes the base64+JSON payload into the in-toto Statement dict.
    Returns (statement_or_None, violations, warnings) -- never raises;
    every problem degrades to a violations entry with statement left None."""
    violations: List[str] = []
    warnings: List[str] = []

    payload_type = envelope.get("payloadType")
    if payload_type != EXPECTED_PAYLOAD_TYPE:
        violations.append(
            f"unsupported payloadType {payload_type!r} (expected {EXPECTED_PAYLOAD_TYPE!r})"
        )

    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) == 0:
        violations.append("DSSE envelope has no signatures (empty or missing 'signatures' list)")

    statement: Optional[Dict[str, Any]] = None
    payload_b64 = envelope.get("payload")
    if not payload_b64 or not isinstance(payload_b64, str):
        violations.append("DSSE envelope is missing a 'payload' field")
    else:
        try:
            raw = base64.b64decode(payload_b64, validate=True)
            decoded = json.loads(raw.decode("utf-8"))
        except Exception as e:
            violations.append(f"failed to decode DSSE payload as base64-encoded JSON: {e}")
        else:
            if not isinstance(decoded, dict):
                violations.append("decoded DSSE payload is not a JSON object")
            else:
                statement = decoded

    return statement, violations, warnings


def _validate_rcs_block(
    predicate: Dict[str, Any],
) -> Tuple[Optional[int], bool, bool, Optional[List[str]], List[str]]:
    """Extracts and type/range-validates release_confidence_score.{value,
    degraded,degraded_reasons} from the predicate. An invalid value resets
    to a safe default alongside a violation entry, never raised.

    Returns (rcs_value, degraded, degraded_field_present, degraded_reasons,
    violations).

    `degraded` is always a concrete bool, never None: when the predicate
    omits the field entirely (it's optional per schema/lucid-attestation-
    v1.schema.json, which documents "default": false), `degraded` resolves
    to that schema-declared default -- a legitimate, versioned display
    interpretation, not a fabricated compliance claim. `degraded_field_present`
    is the separate, honest signal of whether the predicate actually
    asserted a value (True) versus the field being absent or malformed
    (False) -- callers evaluating --disallow-degraded (see
    _evaluate_policy_gates) MUST fail closed on `degraded_field_present is
    False` rather than trusting the display default, since an absent field
    on anything but a genuine lucid-assay-signed predicate is an unknown
    state, not a confirmed non-degraded one (CLAUDE.md "Fail-Closed
    Verification"). A malformed (non-bool) value both reports
    degraded_field_present=False *and* raises its own `violations` entry,
    which already fails the whole gate regardless of --disallow-degraded.
    """
    violations: List[str] = []

    rcs_block = predicate.get("release_confidence_score")
    rcs_block = rcs_block if isinstance(rcs_block, dict) else {}
    rcs_value = rcs_block.get("value")

    # Check non-standard numeric scores for rcs_value
    if not isinstance(rcs_value, (int, float)) or isinstance(rcs_value, bool) or math.isnan(rcs_value) or math.isinf(rcs_value):
        violations.append(f"invalid release_confidence_score.value: {rcs_value!r}")
        rcs_value = None

    degraded_field_present = "degraded" in rcs_block
    degraded_raw = rcs_block.get("degraded")
    if degraded_field_present and not isinstance(degraded_raw, bool):
        violations.append(f"invalid release_confidence_score.degraded type, expected boolean: {degraded_raw!r}")
        degraded = False
        degraded_field_present = False
    elif degraded_field_present:
        degraded = degraded_raw
    else:
        degraded = False  # schema-documented display default; not itself a compliance claim

    degraded_reasons = rcs_block.get("degraded_reasons")
    if degraded_reasons is not None and not (
        isinstance(degraded_reasons, list) and all(isinstance(r, str) for r in degraded_reasons)
    ):
        violations.append(
            f"invalid release_confidence_score.degraded_reasons, expected a list of strings: {degraded_reasons!r}"
        )
        degraded_reasons = None

    return rcs_value, degraded, degraded_field_present, degraded_reasons, violations


def _evaluate_policy_gates(
    *,
    rcs_value: Optional[int],
    min_rcs: int,
    require_digest: Optional[str],
    subject_digests: List[str],
    disallow_degraded: bool,
    degraded: bool,
    degraded_field_present: bool,
    degraded_reasons: Optional[List[str]],
) -> Tuple[List[str], List[str]]:
    """Evaluates --min-rcs/--require-digest/--disallow-degraded against
    already-extracted+validated RCS fields (see _validate_rcs_block).
    Returns (violations, warnings) to fold into the overall result."""
    violations: List[str] = []
    warnings: List[str] = []

    if rcs_value is None:
        violations.append(
            "predicate.release_confidence_score.value is missing; cannot evaluate --min-rcs gate"
        )
    elif rcs_value < min_rcs:
        violations.append(f"RCS score {rcs_value} is below required threshold {min_rcs}")

    if require_digest:
        wanted = _normalize_digest(require_digest)
        if wanted not in subject_digests:
            violations.append(
                f"required subject digest {wanted!r} not found among attested digests {subject_digests}"
            )

    if disallow_degraded and not degraded_field_present:
        # Fail-closed on an unknown state (CLAUDE.md "Fail-Closed
        # Verification"): the field is either absent (no genuine
        # lucid-assay-signed predicate omits it -- scorer.py always sets
        # it explicitly) or malformed (already its own violation above).
        # Either way, --disallow-degraded exists specifically to block
        # degraded runs, so it must never silently trust an unconfirmed
        # "not degraded" -- that would be exactly the same null-treated-
        # as-pass loophole the degraded_reasons check below exists to
        # close for the *true* case.
        violations.append(
            "release_confidence_score.degraded is missing or malformed and --disallow-degraded was "
            "set; cannot confirm this run is not degraded, failing closed"
        )
    elif disallow_degraded and degraded is True:
        # Fail-closed by default: --disallow-degraded blocks unless
        # degraded_reasons proves every cause is a known, unavoidable
        # one (see _ALLOWED_DEGRADED_REASONS). A missing/malformed
        # degraded_reasons (older attestations predating this field,
        # or the type-violation case above) can't prove that, so it
        # blocks too -- silently trusting an absent explanation would
        # be exactly the kind of loophole this gate exists to prevent.
        non_exempt_reasons = (
            [r for r in degraded_reasons if r not in _ALLOWED_DEGRADED_REASONS]
            if degraded_reasons
            else None
        )
        if not degraded_reasons or non_exempt_reasons:
            violations.append(
                "release_confidence_score.degraded is true and --disallow-degraded was set "
                f"(degraded_reasons={degraded_reasons!r})"
            )
        else:
            warnings.append(
                "release_confidence_score.degraded is true, but --disallow-degraded allows it: "
                f"every cause ({degraded_reasons!r}) is a known, unavoidable one "
                "(a GitHub Free-plan branch-rulesets limitation and/or a docs/config-only diff "
                "with no coverable lines), not a real governance or quality gap"
            )

    return violations, warnings


def _evaluate_informational_tracks(
    statement: Optional[Dict[str, Any]],
    slsa_statement: Optional[Dict[str, Any]],
    *,
    identity_status: str,
    identity_detail: str,
    cert_identity: Optional[str],
    expected_repository: Optional[str],
    require_slsa_build_l3: bool,
) -> Tuple[
    Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any],
    Dict[str, Any], Dict[str, Any], Dict[str, Any], List[str],
]:
    """Computes the informational SLSA Source Level 1-4 and Build Level
    1-3 checklists (see _evaluate_source_checklist/_evaluate_slsa_checklists)
    and, only when `require_slsa_build_l3` opts in, the one additional
    violation that folds Build Level 3's cumulative outcome into the hard
    gate. Split out of verify_dsse_attestation() purely to keep that
    function's own cognitive complexity down -- every one of these calls
    is still made unconditionally on every verify run, in the same order,
    with the same non-gating contract as static_analysis_tools; nothing
    about *when* or *whether* this runs changed, only where the code
    lives. Returns (source_level1..4, slsa_level1..3, extra_violations)
    -- the caller extends its own `violations` list with the last one,
    matching the (violations, warnings) pattern _evaluate_policy_gates
    already uses rather than mutating a caller-owned list in place."""
    assay_stmt, build_stmt = _classify_statements(statement, slsa_statement)
    source_level1, source_level2, source_level3, source_level4 = _evaluate_source_checklist(assay_stmt)
    slsa_level1, slsa_level2, slsa_level3 = _evaluate_slsa_checklists(
        build_stmt,
        identity_status=identity_status,
        identity_detail=identity_detail,
        cert_identity=cert_identity,
        expected_repository=expected_repository,
    )

    extra_violations: List[str] = []
    if require_slsa_build_l3:
        build_cumulative = _cumulative_track_status([slsa_level1, slsa_level2, slsa_level3])
        if not build_cumulative[-1]:
            extra_violations.append(
                "--require-slsa-build-l3 was set, but this run does not fully satisfy SLSA Build "
                "Level 3 (see the SLSA Build Track section above for which check(s) failed)"
            )

    return (
        source_level1, source_level2, source_level3, source_level4,
        slsa_level1, slsa_level2, slsa_level3, extra_violations,
    )


def verify_dsse_attestation(
    envelope: Dict[str, Any],
    *,
    min_rcs: int = 0,
    require_digest: Optional[str] = None,
    disallow_degraded: bool = False,
    dry_run: bool = False,
    cert_identity: Optional[str] = None,
    cert_oidc_issuer: Optional[str] = None,
    expected_issuer: Optional[str] = None,
    expected_repository: Optional[str] = None,
    expected_workflow: Optional[str] = None,
    expected_ref: Optional[str] = None,
    slsa_statement: Optional[Dict[str, Any]] = None,
    require_slsa_build_l3: bool = False,
    require_commit_signing: bool = False,
) -> VerificationResult:
    """Validates a DSSE envelope's structure, decodes its in-toto Statement
    payload, best-effort verifies the Sigstore signing identity, and enforces
    the admission policy gates. Never raises for malformed/hostile input --
    problems are reported as `violations` on the returned result.

    `slsa_statement` is the already-decoded payload of an optional *second*
    envelope (the CLI's --slsa-envelope) -- when given alongside a primary
    envelope that's lucid-assay's own RCS predicate, the SLSA Source Track
    (sourced from the RCS predicate's vcs/branch_governance) and SLSA Build
    Track (sourced from this second, SLSA-shaped statement) are both fully
    evaluated together in one report (see _classify_statements). Omitted,
    behavior is unchanged from before this parameter existed: both tracks
    evaluate against whatever the single `envelope` decodes to, honestly
    reporting whichever fields aren't the right shape as failures.

    `require_slsa_build_l3`, when True, folds the (cumulative) SLSA Build
    Level 3 outcome into `passed`/exit code -- opt-in, off by default, so
    existing callers' admission gate is untouched until they choose to
    require it (see cli/verify.py's module-level SLSA Build Level 3
    section for why every caller legitimately fails it today).

    `require_commit_signing`, when True, folds the Repository &
    Workstation Governance section's Cryptographic Commit Signing item
    specifically into `passed`/exit code -- opt-in, off by default. The
    other three items in that section (branch-ruleset hygiene) have no
    such opt-in path today; setting this flag does not gate on them.

    Orchestrates (see each helper's own docstring for its contract):
      _decode_envelope_statement   -- structure + payload decode
      _validate_against_schema     -- optional/diagnostic JSON Schema check
      _validate_rcs_block          -- RCS field type/range validation
      _evaluate_policy_gates       -- --min-rcs/--require-digest/--disallow-degraded
      _verify_sigstore_identity      -- best-effort Sigstore identity check
      _evaluate_informational_tracks -- SLSA Source Level 1-4 + Build Level 1-3 checklists
    """
    # Captured verbatim from this call's own arguments, not re-derived --
    # see VerificationResult.gate_params. Built once, up front, so it's
    # identical on every return path (including the malformed-envelope
    # guard immediately below).
    gate_params: Dict[str, Any] = {
        "min_rcs": min_rcs,
        "require_digest": require_digest,
        "disallow_degraded": disallow_degraded,
        "dry_run": dry_run,
        "cert_identity": cert_identity,
        "cert_oidc_issuer": cert_oidc_issuer,
        "expected_issuer": expected_issuer,
        "expected_repository": expected_repository,
        "expected_workflow": expected_workflow,
        "expected_ref": expected_ref,
        "require_slsa_build_l3": require_slsa_build_l3,
        "require_commit_signing": require_commit_signing,
    }

    if not isinstance(envelope, dict):
        return VerificationResult(
            passed=False,
            violations=["DSSE envelope is not a JSON object"],
            identity_status="skipped",
            identity_detail="envelope malformed; identity verification not attempted",
            gate_params=gate_params,
            verdict_word="FAILED",
        )

    statement, violations, warnings = _decode_envelope_statement(envelope)

    rcs_value: Optional[int] = None
    degraded: bool = False
    degraded_field_present: bool = False
    degraded_reasons: Optional[List[str]] = None
    subject_digests: List[str] = []
    metrics: Dict[str, Any] = {}
    static_analysis_tools: List[Dict[str, Any]] = []
    s2c2f_controls: List[Dict[str, Any]] = []
    dependency_governance_items: List[Dict[str, Any]] = []
    repository_governance_items: List[Dict[str, Any]] = []
    schema_validation_status = "skipped"

    if statement is not None:
        statement_type = statement.get("_type")
        if statement_type != EXPECTED_STATEMENT_TYPE:
            warnings.append(f"unexpected in-toto _type: {statement_type!r}")

        predicate_type = statement.get("predicateType")
        if predicate_type != EXPECTED_PREDICATE_TYPE:
            violations.append(f"unexpected predicateType: {predicate_type!r} (expected {EXPECTED_PREDICATE_TYPE!r})")

        subject_digests = _extract_subject_digests(statement)

        predicate = statement.get("predicate")
        predicate = predicate if isinstance(predicate, dict) else {}

        # Formal schema validation, ahead of policy evaluation/score checks
        # per this guard's purpose: catch a structurally malformed predicate
        # before any of the checks below try to read fields out of it.
        # Fails open, never blocking: jsonschema not being installed, the
        # packaged schema file being unavailable/unreadable, or validation
        # itself raising unexpectedly all degrade to "skipped" with a
        # diagnostic warning -- only an actual, successfully-run schema
        # mismatch becomes a blocking violation.
        # Diagnostic, not a gate: this predicate schema has evolved (and
        # will keep evolving -- see e.g. static_analysis/degraded_reasons/
        # branch_governance, all added after the first attestations that
        # lacked them were already signed) and hand-built partial predicates
        # are a legitimate, deliberate testing pattern elsewhere in this
        # codebase. A schema mismatch surfaces as a `warnings` entry with
        # the precise violation, never as a blocking `violations` one --
        # otherwise every older real attestation predating a schema change,
        # and every test fixture that only populates the fields relevant to
        # what it's testing, would start failing --min-rcs runs outright.
        schema_validation_status, schema_messages = _validate_against_schema(predicate)
        if schema_validation_status == "failed":
            warnings.extend(f"predicate schema violation: {m}" for m in schema_messages)
        elif schema_validation_status == "skipped":
            warnings.extend(f"schema validation skipped: {m}" for m in schema_messages)

        rcs_value, degraded, degraded_field_present, degraded_reasons, rcs_violations = _validate_rcs_block(predicate)
        violations.extend(rcs_violations)

        metrics = _extract_metrics(predicate)
        static_analysis_tools = _extract_static_analysis_tools(predicate)
        s2c2f_controls = _extract_s2c2f_controls(predicate)
        dependency_governance_items = _extract_dependency_evidence(predicate)
        repository_governance_items = _extract_repository_governance(predicate)

        # --require-commit-signing: same opt-in-gate shape as
        # --require-slsa-build-l3 (see that flag's own handling), but
        # folding in only the one item this section has a confirmed gate
        # path for -- the other three (branch-ruleset hygiene) stay
        # purely informational regardless of this flag.
        if require_commit_signing:
            # _extract_repository_governance() always puts the commit-
            # signing item first when it returns anything at all (see its
            # own construction) -- an empty list means repository_governance
            # was never captured for this run, treated the same as "not
            # signed" rather than "check not applicable", same fail-closed
            # default every other opt-in gate here uses.
            commit_signing_passed = bool(repository_governance_items) and repository_governance_items[0]["passed"]
            if not commit_signing_passed:
                violations.append(
                    "--require-commit-signing was set, but HEAD's commit is not cryptographically signed/verified "
                    "(see the Repository & Workstation Governance section above for the exact reason)"
                )

        gate_violations, gate_warnings = _evaluate_policy_gates(
            rcs_value=rcs_value,
            min_rcs=min_rcs,
            require_digest=require_digest,
            subject_digests=subject_digests,
            disallow_degraded=disallow_degraded,
            degraded=degraded,
            degraded_field_present=degraded_field_present,
            degraded_reasons=degraded_reasons,
        )
        violations.extend(gate_violations)
        warnings.extend(gate_warnings)

    # Independent of statement decode success -- _rekor lives on the
    # envelope itself, not the signed payload (see _extract_rekor_info).
    rekor_log_index, rekor_log_url = _extract_rekor_info(envelope)

    identity_status, identity_detail = _verify_sigstore_identity(
        envelope,
        dry_run=dry_run,
        cert_identity=cert_identity,
        cert_oidc_issuer=cert_oidc_issuer,
        expected_issuer=expected_issuer,
        expected_repository=expected_repository,
        expected_workflow=expected_workflow,
        expected_ref=expected_ref,
    )
    if identity_status == "failed":
        violations.append(identity_detail)
    else:
        warnings.append(identity_detail)

    # Purely informational SLSA v1.0 Source Level 1-4 / Build Level 1-3
    # compliance checklists, never folded into violations/warnings/passed
    # above (unless require_slsa_build_l3 opts in) -- same non-gating
    # contract as static_analysis_tools. See _evaluate_informational_tracks'
    # own docstring for why this is its own helper rather than inlined here.
    (
        source_level1,
        source_level2,
        source_level3,
        source_level4,
        slsa_level1,
        slsa_level2,
        slsa_level3,
        track_violations,
    ) = _evaluate_informational_tracks(
        statement,
        slsa_statement,
        identity_status=identity_status,
        identity_detail=identity_detail,
        cert_identity=cert_identity,
        expected_repository=expected_repository,
        require_slsa_build_l3=require_slsa_build_l3,
    )
    violations.extend(track_violations)

    rcs_components = _extract_rcs_components(predicate) if statement is not None else None

    result = VerificationResult(
        passed=len(violations) == 0,
        violations=violations,
        warnings=warnings,
        statement=statement,
        rcs_value=rcs_value,
        degraded=degraded,
        degraded_field_present=degraded_field_present,
        degraded_reasons=degraded_reasons,
        subject_digests=subject_digests,
        metrics=metrics,
        identity_status=identity_status,
        identity_detail=identity_detail,
        static_analysis_tools=static_analysis_tools,
        s2c2f_controls=s2c2f_controls,
        dependency_governance_items=dependency_governance_items,
        repository_governance_items=repository_governance_items,
        rekor_log_index=rekor_log_index,
        rekor_log_url=rekor_log_url,
        schema_validation_status=schema_validation_status,
        slsa_level1=slsa_level1,
        slsa_level2=slsa_level2,
        slsa_level3=slsa_level3,
        source_level1=source_level1,
        source_level2=source_level2,
        source_level3=source_level3,
        source_level4=source_level4,
        rcs_components=rcs_components,
        gate_params=gate_params,
    )

    source_levels = [source_level1, source_level2, source_level3, source_level4]
    build_levels = [slsa_level1, slsa_level2, slsa_level3]
    source_highest = _highest_passing_level(source_levels, _cumulative_track_status(source_levels))
    build_highest = _highest_passing_level(build_levels, _cumulative_track_status(build_levels))
    result.source_highest_level = source_highest
    result.build_highest_level = build_highest
    result.verdict_word = _verdict_word(result, source_highest, build_highest)
    result.verdict = _format_verdict_banner(result, source_highest, build_highest)[1]

    return result


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="lucid-assay verify",
        description="Verify a lucid-assay DSSE in-toto attestation envelope against admission policy gates.",
    )
    p.add_argument("envelope", help="path to the signed DSSE envelope JSON file")
    p.add_argument("--min-rcs", type=int, default=0, help="minimum acceptable RCS score (default: 0)")
    p.add_argument(
        "--require-digest",
        default=None,
        help="require this subject digest to be present, e.g. sha256:<hex> (bare hex assumed sha256)",
    )
    p.add_argument(
        "--disallow-degraded",
        action="store_true",
        help="fail the gate if release_confidence_score.degraded is true",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="skip Sigstore identity verification entirely (offline mode, no network calls)",
    )
    p.add_argument("--cert-identity", default=None, help="expected Sigstore signing identity (certificate SAN)")
    p.add_argument("--cert-oidc-issuer", default=None, help="expected OIDC issuer for the signing identity")
    p.add_argument(
        "--expected-issuer",
        default=None,
        help=(
            "expected OIDC issuer for the signing identity; defaults to GitHub Actions' "
            f"issuer ({GITHUB_ACTIONS_OIDC_ISSUER!r}) automatically whenever --expected-repository, "
            "--expected-workflow, or --expected-ref is set and this flag isn't"
        ),
    )
    p.add_argument(
        "--expected-repository",
        default=None,
        help="require the certificate's GitHub Actions workflow/source repository to be this 'owner/repo'",
    )
    p.add_argument(
        "--expected-workflow",
        default=None,
        help="require the certificate's GitHub Actions workflow name (the workflow file's 'name:') to match",
    )
    p.add_argument(
        "--expected-ref",
        default=None,
        help="require the certificate's GitHub Actions ref to match this glob pattern, e.g. 'refs/heads/main'",
    )
    p.add_argument(
        "--slsa-envelope",
        default=None,
        dest="slsa_envelope",
        help="path to a second, SLSA v1.0 provenance-shaped DSSE envelope; when given alongside the "
        "primary envelope, the SLSA Source Track (from the primary envelope's vcs/branch_governance) "
        "and SLSA Build Track (from this one) are both evaluated together as one unified report",
    )
    p.add_argument(
        "--require-slsa-build-l3",
        action="store_true",
        dest="require_slsa_build_l3",
        help="fail the gate if this run does not fully (cumulatively) satisfy SLSA Build Level 3 -- "
        "off by default: it genuinely passes today when a caller supplies --subject-name/"
        "--subject-digest (confirmed against real CI runs, 2026-09-03), but that's still an opt-in "
        "caller choice, not universal (see cli/verify.py's SLSA Build Level 3 section)",
    )
    p.add_argument(
        "--require-commit-signing",
        action="store_true",
        dest="require_commit_signing",
        help="fail the gate if HEAD's commit is not cryptographically signed/verified (Repository & "
        "Workstation Governance section's Cryptographic Commit Signing item only -- the section's "
        "other three, branch-ruleset-hygiene items have no gate path yet) -- off by default",
    )
    p.add_argument(
        "--format",
        "-f",
        choices=["text", "json"],
        default="text",
        help=(
            "output format: 'text' (default) prints a human-readable summary to stderr; "
            "'json' suppresses all human-oriented output and emits ONLY the structured "
            "verification result (envelope, SLSA level 1/2 assessment, RCS score, static "
            "analysis) as JSON on stdout"
        ),
    )
    p.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="deprecated: equivalent to --format json (kept for backwards compatibility)",
    )
    p.add_argument(
        "--write-verdict",
        action="store_true",
        dest="write_verdict",
        help="persist this call's computed FAILED/GATED/PASSED verdict (plus rcs_value/degraded/SLSA "
        "highest-level/gate_params -- see _build_verdict_envelope_block) as an unsigned '_verdict' "
        "sibling field on the envelope -- same trust tier as the envelope's existing '_rekor'/"
        "'_sigstore_bundle' fields, never part of the signed DSSE payload (a verdict is a function of "
        "this call's own gate parameters, not an intrinsic fact about the artifact). Written to "
        "--verdict-out, or in place over the input envelope when --verdict-out isn't given.",
    )
    p.add_argument(
        "--verdict-out",
        default=None,
        dest="verdict_out",
        help="output path for --write-verdict (default: overwrite the input envelope file in place, "
        "so the same file can be re-uploaded to the ingestion API with its verdict attached)",
    )
    return p.parse_args(argv)


def load_envelope(path: str) -> Any:
    """Reads and JSON-decodes an envelope file, rejecting anything over
    MAX_ENVELOPE_SIZE *before* reading a single byte of it -- a size check
    done after loading the file into memory defeats the entire point of
    the guard (a hostile or corrupt multi-GB "envelope" must never be able
    to exhaust memory just by being pointed at). The path itself is
    resolved via safe_resolve_path() first (rejects null bytes/malformed
    paths, normalizes `../`/symlinks) so every downstream sink -- the
    size check and the read -- operates on the same validated, canonical
    Path; raises UnsafePathError (a ValueError) if that fails, which
    main() catches and reports the same way as any other file error."""
    resolved = safe_resolve_path(path)
    size = os.path.getsize(resolved)  # raises FileNotFoundError/OSError, same as open() would
    if size > MAX_ENVELOPE_SIZE:
        raise EnvelopeTooLargeError(
            f"attestation file exceeds maximum allowed size "
            f"({MAX_ENVELOPE_SIZE // (1024 * 1024)}MB): {size} bytes"
        )
    with open(resolved, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_envelope_for_cli(path: str) -> Tuple[Optional[Any], Optional[int]]:
    """Loads and validates the envelope file on main()'s behalf, collapsing
    every known failure mode (missing file, oversize, unsafe path,
    unreadable/malformed JSON, non-object JSON) into a single (None,
    exit_code) sentinel so main() itself only has to check for that,
    rather than repeat this dispatch inline."""
    try:
        envelope = load_envelope(path)
    except FileNotFoundError:
        print(f"ERROR: envelope file not found: {path}", file=sys.stderr)
        return None, EXIT_FILE_ERROR
    except EnvelopeTooLargeError as e:
        print(f"ERROR: Attestation file exceeds maximum allowed size (10MB): {e}", file=sys.stderr)
        return None, EXIT_FILE_ERROR
    except UnsafePathError as e:
        print(f"ERROR: unsafe envelope file path: {e}", file=sys.stderr)
        return None, EXIT_FILE_ERROR
    except (OSError, json.JSONDecodeError, RecursionError) as e:
        print(f"ERROR: failed to read/parse envelope file {path}: {e}", file=sys.stderr)
        return None, EXIT_FILE_ERROR

    if not isinstance(envelope, dict):
        print(f"ERROR: envelope file {path} does not contain a JSON object", file=sys.stderr)
        return None, EXIT_FILE_ERROR

    return envelope, None


def _render_track_sections(result: VerificationResult) -> List[str]:
    """Renders the full unified report -- Run Identity & Gate Parameters
    (see _format_run_identity_report; the source commit/PR/CI run this
    predicate traces back to, and the exact --min-rcs/--disallow-degraded/
    etc. this call enforced), Static Analysis (the per-tool SARIF/SonarQube
    breakdown from _format_static_analysis_table, when any tools were
    ingested), Repository & Workstation Governance
    (_format_repository_governance_report, when any was found -- solo-
    maintainer compensating controls, deliberately not part of either
    SLSA track), Source Track (SLSA Source, Levels 1-4), SLSA Build Track
    (Levels 1-3), Dependency Materialization Evidence
    (_format_dependency_governance_report, when any evidence was found),
    the S2C2F Compliance Matrix (_format_s2c2f_report, when any
    controls were evaluated), CD / Signing (_format_signing_report --
    Sigstore identity + Rekor log entry), Assay Health & Governance
    Metrics, and the synthesized FINAL VERDICT banner -- as plain-text
    lines, shared by both the stderr human
    renderer and the $GITHUB_STEP_SUMMARY markdown writer (the same
    [✓]/[✗] plain-text rows read fine as GFM markdown verbatim, wrapped in
    a fenced code block -- see _render_step_summary_markdown). Static
    Analysis lives here, not as a block either caller prints on its own,
    specifically so the two renderers can't drift apart on which sections
    they include -- they did, once: the SARIF table used to be printed
    directly by _print_verify_result_human and was silently absent from
    every $GITHUB_STEP_SUMMARY. A no-op section (empty list) for any track
    whose levels are absent (e.g. a VerificationResult built directly by a
    test without going through verify_dsse_attestation())."""
    lines: List[str] = _format_run_identity_report(result)
    if result.static_analysis_tools:
        lines.append("")
        lines.append("  static analysis:")
        lines.extend(_format_static_analysis_table(result.static_analysis_tools))

    # Repository & Workstation Governance renders immediately after Run
    # Identity & Gate Parameters, ahead of both SLSA tracks -- supply-
    # chain provenance flows from developer workstation/repo rules
    # outward to the build factory floor, so evaluating repo governance
    # first mirrors the code's actual physical lifecycle rather than the
    # order the two ratified/draft SLSA tracks happen to be defined in.
    repo_governance_lines = _format_repository_governance_report(result.repository_governance_items)
    if repo_governance_lines:
        lines.append("")
        lines.extend(repo_governance_lines)

    source_levels = [result.source_level1, result.source_level2, result.source_level3, result.source_level4]
    build_levels = [result.slsa_level1, result.slsa_level2, result.slsa_level3]

    if all(lvl is not None for lvl in source_levels):
        lines.append("")
        lines.append("Source Track (SLSA Source — Draft Specification)")
        track_lines, source_cumulative = _format_track_report(source_levels)
        lines.extend(track_lines)
    else:
        source_cumulative = []

    if all(lvl is not None for lvl in build_levels):
        lines.append("")
        lines.append("SLSA Build Track")
        track_lines, build_cumulative = _format_track_report(build_levels)
        lines.extend(track_lines)
    else:
        build_cumulative = []

    dependency_lines = _format_dependency_governance_report(result.dependency_governance_items)
    if dependency_lines:
        lines.append("")
        lines.extend(dependency_lines)

    s2c2f_lines = _format_s2c2f_report(result.s2c2f_controls)
    if s2c2f_lines:
        lines.append("")
        lines.extend(s2c2f_lines)

    lines.append("")
    lines.extend(_format_signing_report(result))

    lines.append("")
    lines.extend(_format_assay_health_report(result))

    if source_cumulative and build_cumulative:
        lines.append("")
        source_highest = _highest_passing_level(source_levels, source_cumulative)
        build_highest = _highest_passing_level(build_levels, build_cumulative)
        lines.extend(_format_verdict_banner(result, source_highest, build_highest))

    return lines


def _print_verify_result_human(result: VerificationResult) -> None:
    """Human-readable (non --json) stderr rendering of a completed
    VerificationResult -- main()'s else branch of --json. The heading uses
    result.verdict_word (FAILED/GATED/PASSED, see _verdict_word) rather
    than a separately-computed PASS/FAIL binary, so it always agrees with
    FINAL VERDICT below it."""
    print(f"lucid-assay verify: {result.verdict_word or 'FAILED'}", file=sys.stderr)
    if result.rcs_value is not None:
        print(f"  RCS={result.rcs_value} degraded={result.degraded}", file=sys.stderr)
        if result.degraded and result.degraded_reasons:
            print(f"  degraded_reasons={result.degraded_reasons}", file=sys.stderr)
    if result.subject_digests:
        print(f"  subject_digests={result.subject_digests}", file=sys.stderr)
    print(f"  identity: {result.identity_status} ({result.identity_detail})", file=sys.stderr)
    for line in _render_track_sections(result):
        print(line, file=sys.stderr)
    for v in result.violations:
        print(f"  VIOLATION: {v}", file=sys.stderr)
    for w in result.warnings:
        if w is not result.identity_detail:
            print(f"  warning: {w}", file=sys.stderr)


_VERDICT_EMOJI = {"PASSED": "✅", "GATED": "⚠️", "FAILED": "❌"}


def _render_step_summary_markdown(result: VerificationResult) -> str:
    """Renders the same unified report _print_verify_result_human prints
    to stderr as a $GITHUB_STEP_SUMMARY markdown document: a one-line
    FAILED/GATED/PASSED heading (result.verdict_word, same word and same
    meaning as FINAL VERDICT below it -- see _verdict_word's docstring for
    why this deliberately isn't its own PASS/FAIL binary), then the
    identical Source/Build/Assay-Health/verdict plain-text report wrapped
    in a fenced code block (its [✓]/[✗] rows and "====" banners are
    already fixed-width plain text, not meant to be reformatted as
    markdown headings/tables)."""
    word = result.verdict_word or "FAILED"
    heading = f"## lucid-assay verify: {_VERDICT_EMOJI.get(word, '❌')} {word}"
    body = "\n".join(_render_track_sections(result)).strip("\n")
    parts = [heading]
    if body:
        parts.append(f"```text\n{body}\n```")
    if result.violations:
        parts.append("**Violations:**\n" + "\n".join(f"- {v}" for v in result.violations))
    return "\n\n".join(parts) + "\n"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _checklist_envelope_rows(levels: List[Optional[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Reshapes a track's `_slsa_level_result()` dicts (see that function's
    own docstring for the real {track, level, name, items, passed,
    origin} shape -- items is a list of real {label, passed, detail} rows,
    see _slsa_item) into the list `_verdict.source_checklist`/
    `build_checklist` persist. Verbatim, not re-derived: every dict here
    already came out of _evaluate_source_l1..l4/_evaluate_slsa_l1..l3's
    real evaluation against this statement -- this function only drops
    the `None` entries a level can carry when its checklist genuinely
    wasn't evaluated (e.g. no assay/SLSA statement classified at all),
    never invents a row for one."""
    return [level for level in levels if level is not None]


def _build_verdict_envelope_block(result: VerificationResult) -> Dict[str, Any]:
    """Builds the `_verdict` block `--write-verdict` persists onto the
    envelope (see _write_verdict_into_envelope) -- the FAILED/GATED/PASSED
    verdict this exact `lucid-assay verify` invocation computed, plus
    enough of its own inputs (rcs_value, rcs_met, degraded, SLSA highest
    levels, the itemized Source/Build checklists, gate_params) that a
    reader isn't left trusting a bare word or a bare level number with no
    way to see what produced it.

    `rcs_met` is the real `rcs_value >= gate_params["min_rcs"]` comparison
    _evaluate_policy_gates already makes internally to decide the
    RCS-vs-threshold `violations` entry -- surfaced here so a downstream
    reader can color the RCS score card without re-deriving that
    comparison itself. `passed` above is a *different*, broader signal
    (every gate this call evaluated, not just this one), so it must not
    be reused as a stand-in for "did the score specifically clear its own
    bar".

    `source_checklist`/`build_checklist` are the same real, itemized
    per-criterion results `lucid-assay verify`'s own human-readable
    report and $GITHUB_STEP_SUMMARY output already show (see
    _format_track_report/_render_step_summary_markdown) -- persisted
    here for the first time so a downstream reader (lucid-dsse-collector,
    lucid-console) doesn't have to re-run `lucid-assay verify` or dig
    through a CI job's ephemeral step summary to see which specific
    criteria passed or failed. Like the checklist inputs are largely
    intrinsic facts about the artifact, but a handful of items
    (_slsa_check_signature, _slsa_check_source_binding, ...) do depend on
    this call's own --cert-identity/--expected-repository gate
    parameters -- exactly the same "function of this call's parameters"
    category `word`/`banner`/`source_level`/`build_level` already are, so
    this lives in the same unsigned `_verdict` block rather than a
    separate signed or unsigned field.

    `repository_governance_items` is the same real, flat {label, passed,
    detail} checklist _format_repository_governance_report renders --
    persisted here for the same reason source_checklist/build_checklist
    are, so lucid-console doesn't have to re-derive pass/fail from
    predicate.repository_governance's raw booleans itself.

    Deliberately NOT part of the signed DSSE payload: a verdict is a
    function of gate parameters (--min-rcs, --disallow-degraded,
    --cert-identity, ...) chosen per verify call, not an intrinsic fact
    about the artifact the way the RCS score or SLSA checklist inputs
    are -- baking it into the predicate at build time would freeze in one
    call's policy as if it were permanent. Instead this is an unsigned
    sibling field on the envelope, exactly the same trust tier as
    cli.oidc_signer's `_rekor`/`_sigstore_bundle`: informational,
    re-derivable by re-running `lucid-assay verify` with the same gate
    parameters, and never a substitute for doing so when the stakes
    actually require a fresh, trusted check rather than reading a cached
    one off the envelope."""
    min_rcs = result.gate_params.get("min_rcs")
    return {
        "word": result.verdict_word or "FAILED",
        "banner": result.verdict,
        "passed": result.passed,
        "rcs_value": result.rcs_value,
        # True only when both the score and this call's own --min-rcs are
        # real and the score clears it -- the exact same comparison
        # _evaluate_policy_gates already makes to decide the RCS-vs-
        # threshold `violations` entry, just also recorded here so a
        # reader doesn't have to reconstruct "did 89 clear 75" from a
        # free-text violation string. None (never fabricated true/false)
        # when either side is missing. A function of this call's own
        # gate parameter (--min-rcs), same category as word/banner/
        # source_level/build_level, hence unsigned here rather than
        # baked into the signed RCS predicate at build time.
        "rcs_met": None if result.rcs_value is None or min_rcs is None else result.rcs_value >= min_rcs,
        "degraded": result.degraded,
        "source_level": result.source_highest_level,
        "build_level": result.build_highest_level,
        "source_checklist": _checklist_envelope_rows(
            [result.source_level1, result.source_level2, result.source_level3, result.source_level4]
        ),
        "build_checklist": _checklist_envelope_rows([result.slsa_level1, result.slsa_level2, result.slsa_level3]),
        # The same real, flat {label, passed, detail} rows (_slsa_item)
        # _format_repository_governance_report already renders -- unlike
        # source_checklist/build_checklist, repository_governance_items
        # has no gate-parameter dependency at all (see
        # _extract_repository_governance/_repo_gov_check_*'s own
        # signatures: only the predicate's repository_governance block
        # in, nothing from this call's --cert-identity/--expected-* gate
        # parameters), so it's arguably an intrinsic artifact fact rather
        # than a function of this call -- persisted here anyway, in the
        # same unsigned _verdict block as source_checklist/build_checklist,
        # so a downstream reader (lucid-console) has one real, already-
        # computed place to read the checklist from rather than
        # re-deriving pass/fail from predicate.repository_governance's
        # raw booleans itself. [] when repository_governance_items is
        # empty (predicate.repository_governance was absent).
        "repository_governance_items": result.repository_governance_items,
        "gate_params": result.gate_params,
        "computed_at": _now_iso(),
    }


def _write_verdict_into_envelope(envelope: Dict[str, Any], result: VerificationResult, out_path: str) -> Path:
    """Merges `_build_verdict_envelope_block(result)` into `envelope` as a
    top-level `_verdict` key and writes the result to `out_path` (resolved
    via safe_resolve_path(), same convention as every other operator-
    supplied output path in cli/). Overwrites whatever `_verdict` may
    already be there -- each `--write-verdict` run reflects this call's
    own fresh gate parameters, never accumulates stale ones. Returns the
    resolved output Path. Raises on a write failure (OSError/
    UnsafePathError) -- unlike $GITHUB_STEP_SUMMARY's best-effort append,
    this is the one output --write-verdict callers explicitly asked for,
    so a failure to produce it must be visible, not silently swallowed."""
    envelope = dict(envelope)
    envelope["_verdict"] = _build_verdict_envelope_block(result)
    resolved_out = safe_resolve_path(out_path)
    with open(resolved_out, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)
    return resolved_out


def _write_github_step_summary(result: VerificationResult) -> None:
    """Appends the markdown rendering of `result` to $GITHUB_STEP_SUMMARY
    when that env var is set (i.e. running inside a GitHub Actions job
    step) -- a no-op everywhere else, and never raises: a broken/missing
    step-summary file must never fail the verification run itself.
    Appends rather than overwrites so multiple `lucid-assay verify`
    invocations within one job step accumulate rather than clobber each
    other's summary."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    try:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(_render_step_summary_markdown(result))
            f.write("\n")
    except OSError as e:  # noqa: BLE001 - a broken step-summary file must never fail the run
        print(f"warning: could not write $GITHUB_STEP_SUMMARY: {e}", file=sys.stderr)


def _resolve_slsa_statement(args: argparse.Namespace) -> Tuple[Optional[Dict[str, Any]], Optional[int]]:
    """Loads and decodes --slsa-envelope on main()'s behalf, when given --
    same (value, error_exit_code) sentinel convention as
    _load_envelope_for_cli, so main() only ever has one shape of check to
    make. Returns (None, None) when --slsa-envelope wasn't passed at all
    (verify_dsse_attestation then falls back to the primary envelope for
    both tracks, unchanged from before this flag existed). A decode
    failure on the SLSA envelope itself is a warning, not a hard failure
    -- the primary envelope's own Build Track fallback still applies."""
    if not args.slsa_envelope:
        return None, None

    slsa_envelope, error_exit_code = _load_envelope_for_cli(args.slsa_envelope)
    if error_exit_code is not None:
        return None, error_exit_code

    slsa_statement, decode_violations, _ = _decode_envelope_statement(slsa_envelope)
    if decode_violations:
        print(
            f"warning: --slsa-envelope {args.slsa_envelope!r} could not be decoded: "
            f"{'; '.join(decode_violations)}; SLSA Build Track will fall back to the primary envelope",
            file=sys.stderr,
        )
    return slsa_statement, None


def _resolve_output_format(args: argparse.Namespace) -> str:
    """Resolves --format, honoring the deprecated --json alias when
    --format was left at its default. The deprecation notice goes to
    stderr, never stdout, so it can never corrupt a --json consumer's
    "ONLY valid JSON on stdout" parsing."""
    if args.json_output and args.format == "text":
        print("warning: --json is deprecated; use --format json instead", file=sys.stderr)
        return "json"
    return args.format


def _maybe_write_verdict(args: argparse.Namespace, envelope: Dict[str, Any], result: VerificationResult) -> Optional[int]:
    """Handles --write-verdict on main()'s behalf: writes the envelope
    (annotated with `_verdict`) if requested, returning an error exit
    code on failure or None on success/no-op -- same sentinel convention
    as _load_envelope_for_cli, so main() only ever has one shape of check
    to make for this, too."""
    if not args.write_verdict:
        return None

    verdict_out_path = args.verdict_out or args.envelope
    try:
        written_path = _write_verdict_into_envelope(envelope, result, verdict_out_path)
    except (OSError, UnsafePathError) as e:
        print(f"ERROR: could not write --write-verdict envelope to {verdict_out_path!r}: {e}", file=sys.stderr)
        return EXIT_FILE_ERROR
    print(f"verdict ({result.verdict_word or 'FAILED'}) written to {written_path}", file=sys.stderr)
    return None


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    envelope, error_exit_code = _load_envelope_for_cli(args.envelope)
    if error_exit_code is not None:
        return error_exit_code

    slsa_statement, error_exit_code = _resolve_slsa_statement(args)
    if error_exit_code is not None:
        return error_exit_code

    result = verify_dsse_attestation(
        envelope,
        min_rcs=args.min_rcs,
        require_digest=args.require_digest,
        disallow_degraded=args.disallow_degraded,
        dry_run=args.dry_run,
        cert_identity=args.cert_identity,
        cert_oidc_issuer=args.cert_oidc_issuer,
        expected_issuer=args.expected_issuer,
        expected_repository=args.expected_repository,
        expected_workflow=args.expected_workflow,
        expected_ref=args.expected_ref,
        slsa_statement=slsa_statement,
        require_slsa_build_l3=args.require_slsa_build_l3,
        require_commit_signing=args.require_commit_signing,
    )

    if _resolve_output_format(args) == "json":
        print(json.dumps(_build_verify_json_payload(result), indent=2))
    else:
        _print_verify_result_human(result)
    _write_github_step_summary(result)

    error_exit_code = _maybe_write_verdict(args, envelope, result)
    if error_exit_code is not None:
        return error_exit_code

    return EXIT_PASS if result.passed else EXIT_POLICY_VIOLATION


if __name__ == "__main__":
    sys.exit(main())
def pr_patch_marker() -> str:
    """Helper to exercise patch coverage calculation."""
    return "patch-verified"
