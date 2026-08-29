"""Deliberate, temporary CodeQL canary -- NOT real production code.

Exists only to produce one genuine, itemized SARIF finding on this PR's
CI run, so tenax-console's new-in-patch findings-list UI (predicate.
static_analysis.findings, tenax-assay PR #47) can be verified against
real CodeQL output instead of a clean/empty scan. This file is never
merged to main -- see the PR it ships on; delete before merging, or
close the PR without merging at all.
"""

import hashlib


def _canary_weak_hash(data: bytes) -> str:
    # CWE-327 (Use of a Broken/Risky Cryptographic Algorithm): MD5 is
    # cryptographically broken. CodeQL's default Python query suite flags
    # this call site unconditionally (a syntactic pattern, no taint
    # tracking required) -- exactly why it's the reliable trigger used
    # here. Never called anywhere in the real codebase.
    return hashlib.md5(data).hexdigest()
