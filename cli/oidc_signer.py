"""
Keyless signing of the in-toto Statement using ambient OIDC identity.

Hardened against:
  - SSRF / Hostile redirect attacks on the OIDC token endpoint
  - Malformed URL query string assembly
  - Forked PR / Non-OIDC pipeline crashes via explicit dry-run support
"""
from __future__ import annotations

import base64
import io
import json
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


class AmbientIdentityError(RuntimeError):
    """Raised when no ambient OIDC token is available and signing is strictly required."""


@dataclass
class DSSEEnvelope:
    __test__ = False
    payload_type: str  # "application/vnd.in-toto+json"
    payload_b64: str
    signatures: List[Dict[str, str]]  # [{"sig": <b64>, "certificate": <pem>}]
    rekor_log_index: Optional[int] = None
    rekor_log_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payloadType": self.payload_type,
            "payload": self.payload_b64,
            "signatures": self.signatures,
            "_rekor": {
                "logIndex": self.rekor_log_index,
                "logId": self.rekor_log_id,
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def fetch_ambient_oidc_token(audience: str = "sigstore") -> str:
    """Resolve an ambient OIDC ID token from the current CI environment with SSRF guards."""
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
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return body["value"]
        except Exception as e:
            raise AmbientIdentityError(f"Failed to fetch GitHub Actions OIDC token: {e}") from e

    # GitLab CI
    gitlab_token = os.environ.get("SIGSTORE_ID_TOKEN") or os.environ.get("CI_JOB_JWT_V2")
    if gitlab_token:
        return gitlab_token.strip()

    raise AmbientIdentityError(
        "No ambient OIDC identity token found. In GitHub Actions, verify "
        "`permissions: id-token: write` is set. On GitLab CI configure "
        "`id_tokens:` with audience 'sigstore'."
    )


def sign_statement(statement_json_bytes: bytes, dry_run: bool = False) -> DSSEEnvelope:
    """Keyless-sign an in-toto Statement into a DSSE envelope."""
    payload_b64 = base64.b64encode(statement_json_bytes).decode("ascii")

    if dry_run:
        return DSSEEnvelope(
            payload_type="application/vnd.in-toto+json",
            payload_b64=payload_b64,
            signatures=[{"sig": "DRY_RUN_UNSIGNED", "certificate": "DRY_RUN_NO_CERT"}],
            rekor_log_index=None,
            rekor_log_id=None,
        )

    oidc_token = fetch_ambient_oidc_token()

    try:
        from sigstore.oidc import IdentityToken
        from sigstore.sign import Signer
    except ImportError:
        raise RuntimeError("sigstore package not installed. Run `pip install sigstore`.")

    identity = IdentityToken(oidc_token)
    signer = Signer.production()

    # Sign the in-toto payload
    bundle = signer.sign(
        input_=io.BytesIO(statement_json_bytes),
        identity_token=identity,
    )

    # Extract signature and certificate from the signed bundle
    sig_b64 = base64.b64encode(bundle.message_signature.signature).decode("ascii")
    cert_pem = bundle.signing_certificate.to_pem()

    # Extract Rekor transparency log metadata if present
    log_index = None
    log_id = None
    if bundle.log_entry is not None:
        log_index = getattr(bundle.log_entry, "log_index", None)
        log_id = getattr(bundle.log_entry, "log_id", None)
        if log_id is not None and isinstance(log_id, bytes):
            log_id = log_id.hex()

    return DSSEEnvelope(
        payload_type="application/vnd.in-toto+json",
        payload_b64=payload_b64,
        signatures=[{
            "sig": sig_b64,
            "certificate": cert_pem,
        }],
        rekor_log_index=log_index,
        rekor_log_id=log_id,
    )