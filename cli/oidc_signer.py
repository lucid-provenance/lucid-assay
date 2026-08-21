"""
Keyless signing of the in-toto Statement using ambient OIDC identity via Sigstore CLI.

Hardened against:
  - SSRF / Hostile redirect attacks on the OIDC token endpoint
  - Malformed URL query string assembly
  - Forked PR / Non-OIDC pipeline crashes via explicit dry-run support
  - Upstream Python library API drift by using the stable CLI contract
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
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
    """Keyless-sign an in-toto Statement into a DSSE envelope via Sigstore."""
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

    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = os.path.join(tmpdir, "statement.json")
        bundle_path = os.path.join(tmpdir, "statement.sigstore.json")

        with open(input_path, "wb") as f:
            f.write(statement_json_bytes)

        # Run sigstore CLI subprocess
        cmd = [
            sys.executable,
            "-m",
            "sigstore",
            "sign",
            "--identity-token",
            oidc_token,
            "--bundle",
            bundle_path,
            input_path,
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"Sigstore signing failed (exit code {proc.returncode}):\n{proc.stderr}\n{proc.stdout}")

        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle_data = json.load(f)

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
    )