#!/usr/bin/env python3
"""
plinth-assay verify: admission gatekeeper for signed DSSE in-toto attestations.

Decodes a DSSE envelope (`payloadType: application/vnd.in-toto+json`) produced
by `plinth-assay` (see cli.oidc_signer / cli.builder), best-effort verifies the
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
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

EXPECTED_PAYLOAD_TYPE = "application/vnd.in-toto+json"
EXPECTED_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
EXPECTED_PREDICATE_TYPE = "https://plinth.dev/attestation/v1"

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
    degraded: Optional[bool] = None
    degraded_reasons: Optional[List[str]] = None
    subject_digests: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    identity_status: str = "skipped"
    identity_detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "violations": self.violations,
            "warnings": self.warnings,
            "rcs_value": self.rcs_value,
            "degraded": self.degraded,
            "degraded_reasons": self.degraded_reasons,
            "subject_digests": self.subject_digests,
            "metrics": self.metrics,
            "identity_status": self.identity_status,
            "identity_detail": self.identity_detail,
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
        san = "<unparseable>"

    try:
        issuer = _extract_cert_ext_v1_or_v2(cert, _OIDC_ISSUER_V1_OID, _OIDC_ISSUER_V2_OID)
    except Exception:  # noqa: BLE001
        issuer = "<unparseable>"

    try:
        repository = _extract_cert_ext_v1_or_v2(
            cert, _GITHUB_WORKFLOW_REPOSITORY_OID, _OIDC_SOURCE_REPOSITORY_URI_OID
        )
    except Exception:  # noqa: BLE001
        repository = "<unparseable>"

    try:
        # Workflow name has no v2 successor extension, so re-use the v1/v2
        # helper with the same OID twice -- it'll simply take the v1 branch.
        workflow = _extract_cert_ext_v1_or_v2(cert, _GITHUB_WORKFLOW_NAME_OID, _GITHUB_WORKFLOW_NAME_OID)
    except Exception:  # noqa: BLE001
        workflow = "<unparseable>"

    try:
        ref = _extract_cert_ref(cert)
    except Exception:  # noqa: BLE001
        ref = "<unparseable>"

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
    problems are reported as `violations` on the returned result."""
    violations: List[str] = []
    warnings: List[str] = []

    if not isinstance(envelope, dict):
        return VerificationResult(
            passed=False,
            violations=["DSSE envelope is not a JSON object"],
            identity_status="skipped",
            identity_detail="envelope malformed; identity verification not attempted",
        )

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

    rcs_value: Optional[int] = None
    degraded: Optional[bool] = None
    degraded_reasons: Optional[List[str]] = None
    subject_digests: List[str] = []
    metrics: Dict[str, Any] = {}

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

        rcs_block = predicate.get("release_confidence_score")
        rcs_block = rcs_block if isinstance(rcs_block, dict) else {}
        rcs_value = rcs_block.get("value")
        
        # Check non-standard numeric scores for rcs_value
        if not isinstance(rcs_value, (int, float)) or isinstance(rcs_value, bool) or math.isnan(rcs_value) or math.isinf(rcs_value):
            violations.append(f"invalid release_confidence_score.value: {rcs_value!r}")
            rcs_value = None
        
        degraded = rcs_block.get("degraded")
        if degraded is not None and not isinstance(degraded, bool):
            violations.append(f"invalid release_confidence_score.degraded type, expected boolean: {degraded!r}")
            degraded = False

        degraded_reasons = rcs_block.get("degraded_reasons")
        if degraded_reasons is not None and not (
            isinstance(degraded_reasons, list) and all(isinstance(r, str) for r in degraded_reasons)
        ):
            violations.append(
                f"invalid release_confidence_score.degraded_reasons, expected a list of strings: {degraded_reasons!r}"
            )
            degraded_reasons = None

        metrics = _extract_metrics(predicate)

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

        if disallow_degraded and degraded is True:
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
        degraded_reasons=degraded_reasons,
        subject_digests=subject_digests,
        metrics=metrics,
        identity_status=identity_status,
        identity_detail=identity_detail,
    )


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="plinth-assay verify",
        description="Verify a plinth-assay DSSE in-toto attestation envelope against admission policy gates.",
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
        "--json", action="store_true", dest="json_output", help="emit the machine-readable result as JSON on stdout"
    )
    return p.parse_args(argv)


def load_envelope(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    try:
        envelope = load_envelope(args.envelope)
    except FileNotFoundError:
        print(f"ERROR: envelope file not found: {args.envelope}", file=sys.stderr)
        return EXIT_FILE_ERROR
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: failed to read/parse envelope file {args.envelope}: {e}", file=sys.stderr)
        return EXIT_FILE_ERROR

    if not isinstance(envelope, dict):
        print(f"ERROR: envelope file {args.envelope} does not contain a JSON object", file=sys.stderr)
        return EXIT_FILE_ERROR

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

    if args.json_output:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(f"plinth-assay verify: {'PASS' if result.passed else 'FAIL'}", file=sys.stderr)
        if result.rcs_value is not None:
            print(f"  RCS={result.rcs_value} degraded={result.degraded}", file=sys.stderr)
            if result.degraded and result.degraded_reasons:
                print(f"  degraded_reasons={result.degraded_reasons}", file=sys.stderr)
        if result.subject_digests:
            print(f"  subject_digests={result.subject_digests}", file=sys.stderr)
        print(f"  identity: {result.identity_status} ({result.identity_detail})", file=sys.stderr)
        for v in result.violations:
            print(f"  VIOLATION: {v}", file=sys.stderr)
        for w in result.warnings:
            if w is not result.identity_detail:
                print(f"  warning: {w}", file=sys.stderr)

    return EXIT_PASS if result.passed else EXIT_POLICY_VIOLATION


if __name__ == "__main__":
    sys.exit(main())
def pr_patch_marker() -> str:
    """Helper to exercise patch coverage calculation."""
    return "patch-verified"
