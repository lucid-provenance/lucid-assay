"""
Shared test helper: builds a self-signed X.509 certificate carrying the
same GitHub Actions OIDC extensions (and SAN) a real Fulcio-issued
certificate would carry, so cli.verify's policy-composition logic
(_build_identity_policy / the sigstore.verify.policy.* objects it
composes) can be unit tested directly against `.verify(cert)`, without a
live Sigstore/Fulcio round-trip (which needs network access and a trusted
root).

Extracted out of tests/test_verify.py so other adversarial/boundary test
modules (tests/test_security_boundaries.py) can build the same
Fulcio-shaped certs without duplicating this ~60-line X.509 builder.
Not itself a test module (no `test_` prefix, so pytest never collects it).
"""
from __future__ import annotations

import datetime


def _der_utf8_string(value: str) -> bytes:
    """DER-encodes `value` as a primitive ASN.1 UTF8String with a short-form
    length, matching how Fulcio v2 certificate extensions are encoded (and
    how cli.verify._der_decode_short_utf8_string expects to read them)."""
    encoded = value.encode("utf-8")
    assert len(encoded) < 128, "test helper only supports short-form DER lengths"
    return bytes([0x0C, len(encoded)]) + encoded


def _make_fulcio_style_cert(
    *,
    san_uri=None,
    issuer=None,
    repository=None,
    source_repository_uri=None,
    workflow_name=None,
    ref=None,
    ref_is_v2=False,
):
    """Builds a self-signed X.509 certificate carrying the same GitHub
    Actions OIDC extensions (and SAN) that a real Fulcio-issued certificate
    would carry, so cli.verify's policy-composition logic can be unit
    tested directly against `.verify(cert)` without a live Sigstore/Fulcio
    round-trip (which needs network access and a trusted root)."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tenax-assay-test")])
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(minutes=10))
    )

    if san_uri:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san_uri)]), critical=False
        )

    def _v1(oid: str, value: str) -> x509.UnrecognizedExtension:
        return x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value.encode("utf-8"))

    if issuer:
        builder = builder.add_extension(_v1("1.3.6.1.4.1.57264.1.1", issuer), critical=False)
    if repository:
        builder = builder.add_extension(_v1("1.3.6.1.4.1.57264.1.5", repository), critical=False)
    if workflow_name:
        builder = builder.add_extension(_v1("1.3.6.1.4.1.57264.1.4", workflow_name), critical=False)
    if source_repository_uri:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.12"), _der_utf8_string(source_repository_uri)
            ),
            critical=False,
        )
    if ref:
        if ref_is_v2:
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.14"), _der_utf8_string(ref)
                ),
                critical=False,
            )
        else:
            builder = builder.add_extension(_v1("1.3.6.1.4.1.57264.1.6", ref), critical=False)

    return builder.sign(key, None)
