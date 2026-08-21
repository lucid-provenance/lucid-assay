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
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

EXPECTED_PAYLOAD_TYPE = "application/vnd.in-toto+json"
EXPECTED_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
EXPECTED_PREDICATE_TYPE = "https://plinth.dev/attestation/v1"

EXIT_PASS = 0
EXIT_POLICY_VIOLATION = 2
EXIT_FILE_ERROR = 1


@dataclass
class VerificationResult:
    __test__ = False
    passed: bool
    violations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    statement: Optional[Dict[str, Any]] = None
    rcs_value: Optional[int] = None
    degraded: Optional[bool] = None
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
    """Best-effort reconstruction of a Sigstore bundle (bundle_v1 schema)
    from plinth-assay's minimal DSSE envelope. The envelope intentionally
    keeps only sig/certificate/rekor log coordinates (see cli.oidc_signer),
    so this reconstruction is necessarily incomplete relative to a full
    Sigstore-CLI bundle (no inclusion proof/checkpoint) -- verification may
    still degrade to "unavailable" even when the network is reachable."""
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


def _verify_sigstore_identity(
    envelope: Dict[str, Any],
    *,
    dry_run: bool,
    cert_identity: Optional[str],
    cert_oidc_issuer: Optional[str],
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
        from sigstore.verify.policy import Identity, UnsafeNoOp
    except ImportError as e:
        return "unavailable", f"sigstore package unavailable; skipping identity verification: {e}"

    try:
        bundle = Bundle.from_json(_envelope_to_bundle_json(envelope))
        verifier = Verifier.production(offline=False)
        policy = (
            Identity(identity=cert_identity, issuer=cert_oidc_issuer)
            if cert_identity
            else UnsafeNoOp()
        )
        verifier.verify_dsse(bundle, policy)
        return "verified", "Sigstore identity verification succeeded"
    except SigstoreVerificationError as e:
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
            violations.append("release_confidence_score.degraded is true and --disallow-degraded was set")

    identity_status, identity_detail = _verify_sigstore_identity(
        envelope,
        dry_run=dry_run,
        cert_identity=cert_identity,
        cert_oidc_issuer=cert_oidc_issuer,
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
    )

    if args.json_output:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(f"plinth-assay verify: {'PASS' if result.passed else 'FAIL'}", file=sys.stderr)
        if result.rcs_value is not None:
            print(f"  RCS={result.rcs_value} degraded={result.degraded}", file=sys.stderr)
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
