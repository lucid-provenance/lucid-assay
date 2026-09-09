"""
CLI entry point: `python3 -m scripts.verify_ingestion [options]`
(or `scripts/verify-ingestion.sh [options]`, a thin wrapper around this).

Enforceable gate over three S2C2F controls -- ING-3 (Denylists, L3), ING-2
(Local Copies, L2 -- a second, independent measurement alongside
cli/parsers/s2c2f.py's own; see scripts/_ingestion_lib.py's module
docstring), and ENF-2 (Curated Feeds, L3). Prints a
JSON result to stdout (and optionally --out) and exits non-zero if any
control comes back FAIL, unless --dry-run/--audit-only is passed -- see
_ingestion_lib.py's module docstring for the PASS/FAIL/AUDIT status
contract (mirrors cli.parsers.s2c2f's met/unmet/not_yet_reported).

This is deliberately NOT wired into cli/main.py's attestation pipeline --
see scripts/__init__.py for why. It's pre-production scaffolding meant to
be run as its own non-blocking CI job first (see
.github/workflows/s2c2f-evidence-telemetry.yml) so real violation data can
accumulate before any of these three controls is flipped into a hard gate.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# Repo root must be on sys.path for `from cli...` imports below to resolve
# when this file is invoked directly (`python3 scripts/verify_ingestion.py`)
# rather than via `python3 -m scripts.verify_ingestion` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cli.parsers.lockfiles import detect_and_parse_dependencies  # noqa: E402

from scripts._ingestion_lib import (  # noqa: E402
    STATUS_FAIL,
    compute_denylist_digest,
    run_ingestion_checks,
)


def _resolve_internal_hosts(cli_value: Optional[str]) -> List[str]:
    raw = cli_value if cli_value is not None else os.environ.get("LUCID_INTERNAL_REGISTRY_HOSTS", "")
    return [h.strip().lower() for h in raw.split(",") if h.strip()]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cmd_write_denylist_digest(path: Path) -> int:
    """Maintenance utility: recomputes digest_sha256 over an edited
    denylist's `entries` and rewrites the file with the corrected value.
    Does not run any control checks. Exits 1 (never raises) if the file
    doesn't already parse as a denylist document shaped correctly enough
    to have an `entries` list, even if its digest is currently wrong --
    that's exactly the case this command exists to fix."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: could not read/parse {path}: {e}", file=sys.stderr)
        return 1
    entries = doc.get("entries")
    if not isinstance(entries, list):
        print(f"error: {path} has no 'entries' list to digest", file=sys.stderr)
        return 1
    doc["digest_sha256"] = compute_denylist_digest(entries)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote digest_sha256={doc['digest_sha256']} for {len(entries)} entries to {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-dir", default=".", help="Repo checkout to evaluate (default: .)")
    parser.add_argument("--denylist", default=".lucid/denylist.json", help="Path to the ING-3 denylist policy artifact (default: .lucid/denylist.json)")
    parser.add_argument("--internal-registry", default=None, help="Comma-separated internal/curated registry host substrings; falls back to $LUCID_INTERNAL_REGISTRY_HOSTS")
    parser.add_argument("--dry-run", "--audit-only", dest="audit_only", action="store_true", help="Report findings but always exit 0")
    parser.add_argument("--out", default=None, help="Also write the JSON result to this path")
    parser.add_argument("--write-denylist-digest", metavar="PATH", default=None, help="Utility mode: recompute and rewrite PATH's digest_sha256, then exit (runs no checks)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.write_denylist_digest:
        return _cmd_write_denylist_digest(Path(args.write_denylist_digest))

    repo_dir = Path(args.repo_dir)
    internal_hosts = _resolve_internal_hosts(args.internal_registry)
    resolved_dependencies = detect_and_parse_dependencies(str(repo_dir))
    results = run_ingestion_checks(
        repo_dir=repo_dir, internal_hosts=internal_hosts, denylist_path=Path(args.denylist), resolved_dependencies=resolved_dependencies,
    )

    payload = {
        "schema_version": "s2c2f-ingestion-verify/v1",
        "generated_at": _utc_now_iso(),
        "mode": "audit" if args.audit_only else "enforce",
        "internal_registry_hosts": internal_hosts,
        "controls": {cid: r.as_dict() for cid, r in results.items()},
    }
    text = json.dumps(payload, indent=2, sort_keys=True)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")

    any_fail = any(r.status == STATUS_FAIL for r in results.values())
    if any_fail and not args.audit_only:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
