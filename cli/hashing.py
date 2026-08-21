"""
SHA-256 content hashing for evidence artifacts (test reports, coverage
reports, SBOMs). The resulting digest doubles as:
  1. the value embedded in the in-toto predicate (report_sha256), and
  2. the content-addressed object key in WORM storage (S3 Object Lock /
     MinIO with retention), i.e. s3://evidence/sha256/<hex digest>.

Hashing streams in fixed-size chunks so multi-hundred-MB coverage reports
don't spike memory, and is intentionally synchronous+cheap (a few ms even
for large files) — the *upload* of the artifact to WORM storage is what
must be async/parallel per the <50ms blocking-overhead budget; hashing
itself happens once, locally, before the async upload is kicked off.
"""
from __future__ import annotations

import hashlib

_CHUNK_SIZE = 1024 * 1024  # 1MB


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def worm_uri(sha256_hex: str, bucket: str = "evidence") -> str:
    """Deterministic content-addressed key. Same content -> same key ->
    idempotent uploads and free dedup across pipeline runs re-attesting
    the same artifact."""
    return f"s3://{bucket}/sha256/{sha256_hex}"
