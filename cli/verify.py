#!/usr/bin/env python3
"""
tenax-assay verify: admission gatekeeper for signed DSSE in-toto attestations.

Decodes a DSSE envelope (`payloadType: application/vnd.in-toto+json`) produced
by `tenax-assay` (see cli.oidc_signer / cli.builder), best-effort verifies the
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
EXPECTED_PREDICATE_TYPE = "https://tenax.io/attestations/assay/v1"

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
# than the process's CWD so `tenax-assay verify` works from any directory.
_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema" / "tenax-attestation-v1.schema.json"
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
    schema_validation_status: str = "skipped"

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
            "schema_validation_status": self.schema_validation_status,
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
    assertion_density = predicate.get("assertion_density")
    if isinstance(assertion_density, dict):
        metrics["assertion_density"] = assertion_density
    return metrics


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
    packaged JSON Schema (schema/tenax-attestation-v1.schema.json).

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


def _static_analysis_tools_by_name(tools: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Reshapes the internal per-tool SARIF list (see
    _extract_static_analysis_tools) into a {tool_name: {...}} mapping for
    --format json, merging each tool's error/warning summary and SonarQube
    quality-gate extension (when present) into one flat object per tool.
    Purely a display transform over already-validated data -- a tool with
    no usable name is skipped rather than raising, and a field that isn't
    the expected type is simply omitted from that tool's entry rather than
    defaulting to a fabricated value."""
    out: Dict[str, Dict[str, Any]] = {}
    for t in tools:
        name = t.get("name")
        if not isinstance(name, str) or not name:
            continue
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
        out[name] = entry
    return out


# Level 2 checks with no real underlying signal in this pipeline (see
# _compute_slsa_assessment) -- keyed by check name, valued by the reason
# it can't be evaluated. Per the "Fail-Closed Verification" invariant in
# CLAUDE.md ("Supply Chain Integrity & Attestation Invariants"), a check
# that can't be verified must resolve to `False`/non-compliant, never a
# `null`/unknown state that could be mistaken for "not yet checked" rather
# than "checked and can't be trusted" -- this dict exists purely to carry
# *why* alongside that `False`, not to soften it.
_SLSA_LEVEL_2_UNEVALUATED_CHECKS = {
    "resolved_dependencies": "not evaluated: tenax-assay does not track a build dependency graph",
}


def _compute_slsa_assessment(result: VerificationResult, args: argparse.Namespace) -> Dict[str, Any]:
    """Best-effort SLSA Level 1/2 self-assessment derived strictly from
    signals this pipeline actually verifies -- never a hardcoded/fabricated
    `true`. Each check maps to a concrete, already-computed fact on `result`
    (or a CLI flag the caller asserted). Fail-closed by construction (see
    CLAUDE.md "Supply Chain Integrity & Attestation Invariants"): a check
    with no real underlying signal (currently: resolved_dependencies --
    this pipeline doesn't build or track a dependency graph) is `False`,
    not `None`/skipped -- unverified must never be indistinguishable from
    "verified and non-compliant" by simply being excluded from the
    roll-up. `unevaluated_checks` carries the reason alongside that `False`
    so an auditor can still tell "checked, failed" apart from "can't check
    this at all yet" without the boolean itself pretending otherwise.

    Level 1 (provenance exists and is authentic to the artifact):
      - statement_envelope: the DSSE payload decoded into a well-formed
        in-toto Statement at all
      - provenance_predicate: the decoded Statement's _type/predicateType
        match what this tool actually produces (EXPECTED_STATEMENT_TYPE /
        EXPECTED_PREDICATE_TYPE)
      - build_definition: the predicate carries real build/test signal
        (result.metrics is non-empty -- test totals, coverage, or
        assertion density were actually extracted)
      - subject_digest_match: at least one subject digest was present to
        bind the provenance to an artifact

    Level 2 (provenance is authenticated by a hosted build platform):
      - hosted_builder / source_binding / cryptographic_signature: all
        require result.identity_status == "verified" -- i.e. Sigstore
        cryptographically verified the DSSE signature *and* the asserted
        identity policy, never merely that a signature block was present
      - hosted_builder additionally requires the caller asserted a CI-only
        identity claim (--expected-issuer/--expected-repository/
        --expected-workflow/--expected-ref/--cert-oidc-issuer): a bare
        --cert-identity alone (e.g. a human's email) doesn't establish the
        signer was a hosted CI runner
      - source_binding additionally requires --expected-repository was
        asserted and matched, binding the provenance to a specific source
        repo rather than just *some* verified identity
      - resolved_dependencies: always False -- see
        _SLSA_LEVEL_2_UNEVALUATED_CHECKS above
    """
    statement = result.statement or {}
    statement_type_ok = statement.get("_type") == EXPECTED_STATEMENT_TYPE
    predicate_type_ok = statement.get("predicateType") == EXPECTED_PREDICATE_TYPE

    level_1_checks: Dict[str, bool] = {
        "statement_envelope": result.statement is not None,
        "provenance_predicate": statement_type_ok and predicate_type_ok,
        "build_definition": bool(result.metrics),
        "subject_digest_match": bool(result.subject_digests),
    }
    level_1_compliant = all(level_1_checks.values())

    identity_verified = result.identity_status == "verified"
    ci_identity_asserted = bool(
        args.expected_issuer
        or args.expected_repository
        or args.expected_workflow
        or args.expected_ref
        or args.cert_oidc_issuer
    )
    level_2_checks: Dict[str, bool] = {
        "hosted_builder": identity_verified and ci_identity_asserted,
        "cryptographic_signature": identity_verified,
        "source_binding": identity_verified and bool(args.expected_repository),
        "resolved_dependencies": False,
    }
    level_2_compliant = all(level_2_checks.values())

    return {
        "level_1": {"compliant": level_1_compliant, "checks": level_1_checks},
        "level_2": {
            "compliant": level_2_compliant,
            "checks": level_2_checks,
            "unevaluated_checks": dict(_SLSA_LEVEL_2_UNEVALUATED_CHECKS),
        },
    }


def _build_verify_json_payload(result: VerificationResult, args: argparse.Namespace) -> Dict[str, Any]:
    """Assembles the --format json payload: the complete verification
    result (envelope shape, RCS score, static analysis, violations/
    warnings/identity) plus a best-effort SLSA Level 1/2 self-assessment
    (see _compute_slsa_assessment). Never raises -- every field it reads
    off `result`/`args` is already defensively populated by
    verify_dsse_attestation()/parse_args()."""
    statement = result.statement or {}
    subjects = statement.get("subject")
    return {
        "version": "1.0.0",
        "verified": result.passed,
        "envelope": {
            "statement_type": statement.get("_type"),
            "predicate_type": statement.get("predicateType"),
            "subject": subjects if isinstance(subjects, list) else [],
        },
        "slsa": _compute_slsa_assessment(result, args),
        "release_confidence_score": {
            "score": result.rcs_value,
            "degraded": result.degraded,
            "degraded_field_present": result.degraded_field_present,
            "degraded_reasons": result.degraded_reasons or [],
        },
        "static_analysis": {
            "tools": _static_analysis_tools_by_name(result.static_analysis_tools),
        },
        "identity": {
            "status": result.identity_status,
            "detail": result.identity_detail,
        },
        "violations": result.violations,
        "warnings": result.warnings,
    }


def _format_static_analysis_table(tools: List[Dict[str, Any]]) -> List[str]:
    """Renders a clean, fixed-width summary table (tool, error/warning
    counts, SonarQube quality gate status when present) for --verify's
    human-readable (non-JSON) output. Missing/malformed fields degrade to
    '-' rather than raising -- this is a display helper over data that
    `_extract_static_analysis_tools` already validated defensively."""
    if not tools:
        return []

    rows = []
    for t in tools:
        name = str(t.get("name") or "unknown")
        summary = t.get("summary") if isinstance(t.get("summary"), dict) else {}
        errors = summary.get("errors")
        warnings = summary.get("warnings")
        extensions = t.get("extensions") if isinstance(t.get("extensions"), dict) else {}
        sonarqube = extensions.get("sonarqube") if isinstance(extensions.get("sonarqube"), dict) else {}
        quality_gate = sonarqube.get("quality_gate")
        rows.append((
            name,
            str(errors) if isinstance(errors, int) else "-",
            str(warnings) if isinstance(warnings, int) else "-",
            str(quality_gate) if isinstance(quality_gate, str) else "-",
        ))

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
    omits the field entirely (it's optional per schema/tenax-attestation-
    v1.schema.json, which documents "default": false), `degraded` resolves
    to that schema-declared default -- a legitimate, versioned display
    interpretation, not a fabricated compliance claim. `degraded_field_present`
    is the separate, honest signal of whether the predicate actually
    asserted a value (True) versus the field being absent or malformed
    (False) -- callers evaluating --disallow-degraded (see
    _evaluate_policy_gates) MUST fail closed on `degraded_field_present is
    False` rather than trusting the display default, since an absent field
    on anything but a genuine tenax-assay-signed predicate is an unknown
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
        # tenax-assay-signed predicate omits it -- scorer.py always sets
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
) -> VerificationResult:
    """Validates a DSSE envelope's structure, decodes its in-toto Statement
    payload, best-effort verifies the Sigstore signing identity, and enforces
    the admission policy gates. Never raises for malformed/hostile input --
    problems are reported as `violations` on the returned result.

    Orchestrates (see each helper's own docstring for its contract):
      _decode_envelope_statement -- structure + payload decode
      _validate_against_schema   -- optional/diagnostic JSON Schema check
      _validate_rcs_block        -- RCS field type/range validation
      _evaluate_policy_gates     -- --min-rcs/--require-digest/--disallow-degraded
      _verify_sigstore_identity  -- best-effort Sigstore identity check
    """
    if not isinstance(envelope, dict):
        return VerificationResult(
            passed=False,
            violations=["DSSE envelope is not a JSON object"],
            identity_status="skipped",
            identity_detail="envelope malformed; identity verification not attempted",
        )

    statement, violations, warnings = _decode_envelope_statement(envelope)

    rcs_value: Optional[int] = None
    degraded: bool = False
    degraded_field_present: bool = False
    degraded_reasons: Optional[List[str]] = None
    subject_digests: List[str] = []
    metrics: Dict[str, Any] = {}
    static_analysis_tools: List[Dict[str, Any]] = []
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

    return VerificationResult(
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
        schema_validation_status=schema_validation_status,
    )


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="tenax-assay verify",
        description="Verify a tenax-assay DSSE in-toto attestation envelope against admission policy gates.",
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
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: failed to read/parse envelope file {path}: {e}", file=sys.stderr)
        return None, EXIT_FILE_ERROR

    if not isinstance(envelope, dict):
        print(f"ERROR: envelope file {path} does not contain a JSON object", file=sys.stderr)
        return None, EXIT_FILE_ERROR

    return envelope, None


def _print_verify_result_human(result: VerificationResult) -> None:
    """Human-readable (non --json) stderr rendering of a completed
    VerificationResult -- main()'s else branch of --json."""
    print(f"tenax-assay verify: {'PASS' if result.passed else 'FAIL'}", file=sys.stderr)
    if result.rcs_value is not None:
        print(f"  RCS={result.rcs_value} degraded={result.degraded}", file=sys.stderr)
        if result.degraded and result.degraded_reasons:
            print(f"  degraded_reasons={result.degraded_reasons}", file=sys.stderr)
    if result.subject_digests:
        print(f"  subject_digests={result.subject_digests}", file=sys.stderr)
    print(f"  identity: {result.identity_status} ({result.identity_detail})", file=sys.stderr)
    if result.static_analysis_tools:
        print("  static analysis:", file=sys.stderr)
        for line in _format_static_analysis_table(result.static_analysis_tools):
            print(line, file=sys.stderr)
    for v in result.violations:
        print(f"  VIOLATION: {v}", file=sys.stderr)
    for w in result.warnings:
        if w is not result.identity_detail:
            print(f"  warning: {w}", file=sys.stderr)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    envelope, error_exit_code = _load_envelope_for_cli(args.envelope)
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
    )

    output_format = args.format
    if args.json_output and output_format == "text":
        # --json predates --format and is kept only as an alias; the
        # deprecation notice goes to stderr, never stdout, so it can never
        # corrupt a --json consumer's "ONLY valid JSON on stdout" parsing.
        print("warning: --json is deprecated; use --format json instead", file=sys.stderr)
        output_format = "json"

    if output_format == "json":
        print(json.dumps(_build_verify_json_payload(result, args), indent=2))
    else:
        _print_verify_result_human(result)

    return EXIT_PASS if result.passed else EXIT_POLICY_VIOLATION


if __name__ == "__main__":
    sys.exit(main())
def pr_patch_marker() -> str:
    """Helper to exercise patch coverage calculation."""
    return "patch-verified"
