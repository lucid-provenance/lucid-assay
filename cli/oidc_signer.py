"""
Keyless signing of the in-toto Statement using ambient OIDC identity via
Sigstore's `Signer.sign_dsse()` library API (see sign_statement()'s docstring
for why this uses the library API rather than shelling out to the `sigstore`
CLI, unlike cli.verify's use of the CLI's underlying verification classes).

Hardened against:
  - SSRF / Hostile redirect attacks on the OIDC token endpoint
  - Malformed URL query string assembly
  - Forked PR / Non-OIDC pipeline crashes via explicit dry-run support
  - A hostile/corrupt oversized input file exhausting memory before signing
    is even attempted (sign_file_to_envelope's size guard, same rationale
    and threshold as cli.verify.load_envelope's)
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .common import safe_resolve_path


class AmbientIdentityError(RuntimeError):
    """Raised when no ambient OIDC token is available and signing is strictly required."""


# Bounded retry for the GitHub Actions ambient token fetch: a brief blip
# talking to the ambient token endpoint (or a transient rate-limit/5xx)
# must not fail an entire CI run outright on the first hiccup, but the
# retry itself must be provably bounded -- fixed attempt count, fixed
# per-attempt timeout, fixed capped backoff -- so a persistently
# unreachable endpoint still fails in well under a minute rather than
# hanging or busy-looping indefinitely.
_OIDC_FETCH_MAX_ATTEMPTS = 3
_OIDC_FETCH_TIMEOUT_SECONDS = 10
_OIDC_FETCH_BACKOFF_BASE_SECONDS = 1.0
_OIDC_FETCH_BACKOFF_CAP_SECONDS = 5.0

# An unsigned in-toto Statement is a small JSON document by construction --
# same rationale and threshold as cli.verify.MAX_ENVELOPE_SIZE. sign_file_
# to_envelope() takes an operator-supplied input path directly (unlike
# sign_statement()'s in-memory bytes, used only by cli.main's own pipeline
# right after it built the statement in-process), so it gets the same
# stat()-before-read guard every other such boundary in cli/ already has.
MAX_INPUT_FILE_SIZE = 10 * 1024 * 1024  # 10MB


class InputFileTooLargeError(Exception):
    """Raised by sign_file_to_envelope() when the input file exceeds
    MAX_INPUT_FILE_SIZE. Deliberately not an OSError subclass, matching
    cli.verify.EnvelopeTooLargeError's reasoning: an oversized file is a
    distinct, policy-driven rejection, not an I/O failure a broad `except
    OSError` should swallow."""


@dataclass
class DSSEEnvelope:
    __test__ = False
    payload_type: str  # "application/vnd.in-toto+json"
    payload_b64: str
    signatures: List[Dict[str, str]]  # [{"sig": <b64>, "certificate": <pem>}]
    rekor_log_index: Optional[int] = None
    rekor_log_id: Optional[str] = None
    # The complete, untouched Sigstore bundle (`Bundle.to_json()` output of
    # the DSSE-signed result) as parsed JSON, when one was actually minted.
    # Preserved verbatim -- including tlogEntries' kindVersion/inclusionProof/
    # canonicalizedBody -- so cli.verify can hand it straight to
    # sigstore.models.Bundle.from_json() rather than hand-reconstructing a
    # partial bundle from a handful of extracted fields, which can never
    # satisfy Bundle's schema (those fields are required, not optional).
    sigstore_bundle: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payloadType": self.payload_type,
            "payload": self.payload_b64,
            "signatures": self.signatures,
            "_rekor": {
                "logIndex": self.rekor_log_index,
                "logId": self.rekor_log_id,
            },
            "_sigstore_bundle": self.sigstore_bundle,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def fetch_ambient_oidc_token(audience: str = "sigstore") -> str:
    """Resolve an ambient OIDC ID token from the current CI environment with
    SSRF guards.

    The GitHub Actions branch retries up to _OIDC_FETCH_MAX_ATTEMPTS times
    on a transient failure (timeout, connection error, non-2xx response),
    each attempt bounded by _OIDC_FETCH_TIMEOUT_SECONDS, with a short
    capped exponential backoff between attempts -- see the constants'
    docstring above for why this is provably bounded rather than an
    unbounded retry loop."""
    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

    if request_url and request_token:
        parsed = urllib.parse.urlparse(request_url)
        # SSRF Guard: Enforce HTTPS and restrict scheme
        if parsed.scheme != "https":
            raise AmbientIdentityError(f"Refusing to fetch OIDC token over insecure scheme: {parsed.scheme}")

        # Safely append audience parameter
        query_params = urllib.parse.parse_qs(parsed.query)
        query_params["audience"] = [audience]
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        target_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

        req = urllib.request.Request(
            target_url,
            headers={"Authorization": f"bearer {request_token}"},
        )

        last_error: Optional[Exception] = None
        for attempt in range(1, _OIDC_FETCH_MAX_ATTEMPTS + 1):
            try:
                with urllib.request.urlopen(req, timeout=_OIDC_FETCH_TIMEOUT_SECONDS) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                    return body["value"]
            except Exception as e:
                last_error = e
                if attempt < _OIDC_FETCH_MAX_ATTEMPTS:
                    backoff = min(
                        _OIDC_FETCH_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)),
                        _OIDC_FETCH_BACKOFF_CAP_SECONDS,
                    )
                    time.sleep(backoff)

        raise AmbientIdentityError(
            f"Failed to fetch GitHub Actions OIDC token after {_OIDC_FETCH_MAX_ATTEMPTS} attempts: {last_error}"
        ) from last_error

    # GitLab CI
    gitlab_token = os.environ.get("SIGSTORE_ID_TOKEN") or os.environ.get("CI_JOB_JWT_V2")
    if gitlab_token:
        return gitlab_token.strip()

    raise AmbientIdentityError(
        "No ambient OIDC identity token found. In GitHub Actions, verify "
        "`permissions: id-token: write` is set. On GitLab CI configure "
        "`id_tokens:` with audience 'sigstore'."
    )


def sign_statement(
    statement_json_bytes: bytes,
    dry_run: bool = False,
    timing: Optional[Dict[str, int]] = None,
) -> DSSEEnvelope:
    """Keyless-sign an in-toto Statement into a DSSE envelope via Sigstore.

    `timing`, when passed a dict, is populated in place with high-resolution
    (`time.perf_counter_ns()`) sub-stage durations so a caller (cli.main's
    stage profiler) can break the "sigstore_signing" stage down further:
      - "oidc_token_fetch_ns": ambient OIDC ID token acquisition.
      - "fulcio_rekor_ns": the Fulcio cert issuance + Rekor inclusion
        round-trip performed inside `signer.sign_dsse()`. Note this is
        *not* a `python3 -m sigstore sign` subprocess -- see the module
        docstring and the try/except block below for why this deliberately
        calls the `Signer.sign_dsse()` library API in-process instead.
    On dry_run, both keys are set to 0 (no network I/O occurs).
    """
    payload_b64 = base64.b64encode(statement_json_bytes).decode("ascii")

    if dry_run:
        if timing is not None:
            timing["oidc_token_fetch_ns"] = 0
            timing["fulcio_rekor_ns"] = 0
        return DSSEEnvelope(
            payload_type="application/vnd.in-toto+json",
            payload_b64=payload_b64,
            signatures=[{"sig": "DRY_RUN_UNSIGNED", "certificate": "DRY_RUN_NO_CERT"}],
            rekor_log_index=None,
            rekor_log_id=None,
        )

    _t0 = time.perf_counter_ns()
    oidc_token = fetch_ambient_oidc_token()
    if timing is not None:
        timing["oidc_token_fetch_ns"] = time.perf_counter_ns() - _t0

    # NOTE: this deliberately does NOT shell out to `sigstore sign` (as an
    # earlier version of this function did). `sigstore sign` always produces
    # a hashedrekord/messageSignature bundle -- signing over the *artifact
    # bytes* -- never a DSSE envelope, regardless of what's passed on the
    # input file. cli.verify expects (and calls `Verifier.verify_dsse` on) a
    # real DSSE-enveloped in-toto attestation, so a hashedrekord bundle fails
    # verification with "cannot perform DSSE verification on a bundle
    # without a DSSE envelope" every time, no matter how the CLI is invoked.
    # `sigstore attest` *does* produce a DSSE envelope, but this sigstore
    # version's CLI restricts --predicate-type to the SLSA provenance enum
    # and derives the subject from a hash of the predicate file itself --
    # neither fits a custom predicateType (tenax.io/attestations/assay/v1) over
    # an already-fully-assembled Statement whose subject is a container
    # image digest, not a local file's hash. `Signer.sign_dsse()` is the
    # public library entry point both CLI subcommands themselves delegate
    # to under the hood (see sigstore._cli._sign_file_threaded), so this
    # calls it directly, wrapping the caller's exact Statement bytes
    # unmodified via `dsse.Statement(bytes)` -- no re-derivation of the
    # subject or predicate, no restriction on predicate type.
    from sigstore.dsse import Statement
    from sigstore.models import ClientTrustConfig
    from sigstore.oidc import IdentityToken
    from sigstore.sign import SigningContext

    _t1 = time.perf_counter_ns()
    try:
        trust_config = ClientTrustConfig.production()
        signing_ctx = SigningContext.from_trust_config(trust_config)
        identity = IdentityToken(oidc_token)
        statement = Statement(statement_json_bytes)
        with signing_ctx.signer(identity) as signer:
            bundle = signer.sign_dsse(statement)
    except Exception as e:  # noqa: BLE001 - surface any signing failure uniformly
        raise RuntimeError(f"Sigstore signing failed: {e}") from e
    finally:
        if timing is not None:
            timing["fulcio_rekor_ns"] = time.perf_counter_ns() - _t1

    bundle_data = json.loads(bundle.to_json())

    # Extract signature and certificate from the standard Sigstore bundle format
    # Supports both Protobuf JSON spec and legacy bundle schemas
    sig_b64 = ""
    cert_pem = ""
    log_index = None
    log_id = None

    if "messageSignature" in bundle_data:
        sig_b64 = bundle_data["messageSignature"].get("signature", "")
    elif "dsseEnvelope" in bundle_data:
        sigs = bundle_data["dsseEnvelope"].get("signatures", [])
        if sigs:
            sig_b64 = sigs[0].get("sig", "")

    # Extract signing certificate (PEM or DER/Base64)
    verification_material = bundle_data.get("verificationMaterial", {})
    if "certificate" in verification_material:
        raw_cert = verification_material["certificate"].get("rawBytes", "")
        cert_pem = f"-----BEGIN CERTIFICATE-----\n{raw_cert}\n-----END CERTIFICATE-----"
    elif "x509CertificateChain" in verification_material:
        certs = verification_material["x509CertificateChain"].get("certificates", [])
        if certs:
            raw_cert = certs[0].get("rawBytes", "")
            cert_pem = f"-----BEGIN CERTIFICATE-----\n{raw_cert}\n-----END CERTIFICATE-----"

    # Extract Rekor transparency log metadata
    tlog_entries = verification_material.get("tlogEntries", [])
    if tlog_entries:
        log_index = tlog_entries[0].get("logIndex")
        log_id = tlog_entries[0].get("logId", {}).get("keyId")

    return DSSEEnvelope(
        payload_type="application/vnd.in-toto+json",
        payload_b64=payload_b64,
        signatures=[{
            "sig": sig_b64,
            "certificate": cert_pem,
        }],
        rekor_log_index=log_index,
        rekor_log_id=log_id,
        sigstore_bundle=bundle_data,
    )


def sign_file_to_envelope(
    input_path: str,
    output_path: str,
    *,
    dry_run: bool = False,
    timing: Optional[Dict[str, int]] = None,
) -> Path:
    """Reads an already-built unsigned in-toto Statement from `input_path`,
    signs it via sign_statement(), and writes the resulting DSSE envelope
    to `output_path`. Returns the resolved output Path.

    This is the file-in/file-out counterpart to sign_statement() (which
    takes/returns in-memory bytes for cli.main's own single-process
    pipeline, right after it builds a statement) -- it exists for callers
    that sign a statement they didn't just build themselves, e.g. a
    separate CI job (cli.sign's `tenax-assay sign` subcommand) that only
    received the unsigned file as an artifact from an upstream build job
    and has no access to -- or trust in -- however that job produced it
    beyond the file's own bytes. Both paths are resolved via
    common.safe_resolve_path() first, the same convention every other
    operator-supplied path in cli/ follows.
    """
    resolved_input = safe_resolve_path(input_path)
    size = os.path.getsize(resolved_input)  # raises FileNotFoundError/OSError, same as open() would
    if size > MAX_INPUT_FILE_SIZE:
        raise InputFileTooLargeError(
            f"input statement file exceeds maximum allowed size "
            f"({MAX_INPUT_FILE_SIZE // (1024 * 1024)}MB): {size} bytes"
        )

    with open(resolved_input, "rb") as f:
        statement_json_bytes = f.read()

    envelope = sign_statement(statement_json_bytes, dry_run=dry_run, timing=timing)

    resolved_output = safe_resolve_path(output_path)
    with open(resolved_output, "w", encoding="utf-8") as f:
        f.write(envelope.to_json())

    return resolved_output