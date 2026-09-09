#!/usr/bin/env bash
# Thin wrapper around `python3 -m scripts.verify_ingestion`, kept so CI
# steps and local invocations can name a fixed, memorable entry point
# without spelling out the module invocation each time. All real logic
# lives in scripts/verify_ingestion.py + scripts/_ingestion_lib.py -- see
# their docstrings.
#
# Never invoke scripts/verify_ingestion.py directly with a bare `python3
# scripts/verify_ingestion.py` from an arbitrary cwd: its sibling imports
# (`from scripts._ingestion_lib import ...`) only resolve when the repo
# root is on sys.path, which requires either running as `python3 -m
# scripts.verify_ingestion` from the repo root (what this wrapper does) or
# the sys.path shim verify_ingestion.py itself carries as a fallback.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"
exec python3 -m scripts.verify_ingestion "$@"
