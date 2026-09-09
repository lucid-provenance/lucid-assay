"""
CI-level evidence/telemetry scaffolding, deliberately kept outside the
`cli` package.

Everything under `scripts/` is pre-production scaffolding for S2C2F
controls the real attestation pipeline (`cli/parsers/s2c2f.py`) doesn't
evaluate yet -- see `scripts/_ingestion_lib.py`'s module docstring for the
specific controls and the honesty caveats attached to each. Nothing here
is wired into `cli/main.py`'s pipeline or the signed predicate; promote a
control into `cli/parsers/s2c2f.py` only once its signal has been run for
real and judged trustworthy, the same bar every control already there met
(see that module's own docstring).

This file exists (not just a bare directory) for the same reason
`schema/__init__.py` had to be added -- see lucid-assay's CLAUDE.md
"Packaging: schema/ needs __init__.py" note -- so `python3 -m
scripts.verify_ingestion` / `python3 -m scripts.emit_s2c2f_evidence`
resolve as real package modules run from the repo root, not a bare script
whose sibling imports (`from . import _ingestion_lib`) would fail.
"""
