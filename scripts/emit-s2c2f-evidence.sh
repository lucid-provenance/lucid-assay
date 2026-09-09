#!/usr/bin/env bash
# Thin wrapper around `python3 -m scripts.emit_s2c2f_evidence` -- see
# scripts/verify-ingestion.sh's own comment for why this indirection
# (sibling-import resolution) exists. All real logic lives in
# scripts/emit_s2c2f_evidence.py + scripts/_ingestion_lib.py.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"
exec python3 -m scripts.emit_s2c2f_evidence "$@"
