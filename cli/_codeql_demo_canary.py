"""Deliberate, temporary CodeQL canary -- NOT real production code.

Exists only to produce one genuine, itemized SARIF finding on this PR's
CI run, so tenax-console's new-in-patch findings-list UI (predicate.
static_analysis.findings, tenax-assay PR #47) can be verified against
real CodeQL output instead of a clean/empty scan. This file is never
merged to main -- see the PR it ships on; delete before merging, or
close the PR without merging at all.
"""

import hashlib


def _canary_hash_password(password: str) -> str:
    # CWE-327 (Use of a Broken/Risky Cryptographic Algorithm), specifically
    # py/weak-sensitive-data-hashing: CodeQL's query here is taint-tracked,
    # not purely syntactic -- it only fires when a value flowing into a
    # broken hash (MD5/SHA1) is recognized as sensitive by its naming
    # heuristic (password/secret/token/credential/...). A first attempt
    # using a generically-named `data: bytes` parameter produced zero
    # results for exactly this reason; naming it `password` is what
    # actually triggers the query. Never called anywhere in the real
    # codebase.
    return hashlib.md5(password.encode()).hexdigest()
