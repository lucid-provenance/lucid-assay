#!/usr/bin/env python3
"""
lucid-assay sign: standalone keyless-signing subcommand for an already-built
unsigned in-toto Statement file (`cli.oidc_signer.sign_file_to_envelope`).

Why this exists as its own subcommand, separate from `cli.main`'s `--sign`/
`--dry-run-sign` flags (which still work exactly as before, for anyone
running the pipeline as one local command): a CI setup that wants real
isolation between "the job that runs untrusted build/test code" and "the
job that mints the Sigstore signing identity" needs to sign a statement it
didn't just build itself -- a separate job downloaded it as an artifact from
an upstream build job and has no access to, or trust in, anything about how
that job produced it beyond the file's own bytes. `lucid-assay sign` is that
narrow surface: it takes exactly one already-built unsigned statement file
and signs it, nothing else -- it never re-runs scoring, coverage, SARIF
ingestion, or branch governance, so a job invoking only this subcommand
never needs read access to any of that.

This module's own import graph is held to the same narrow standard as its
read-access surface: it depends only on cli.common and cli.oidc_signer,
deliberately never cli.main -- importing cli.main would pull in the entire
scoring/parsing pipeline (cli.scorer, cli.parsers.*, cli.builder) at module
load time regardless of which subcommand actually runs, which is exactly
the code footprint lucid-attest's immutable signer container (Milestone
#18) packages this module specifically to avoid carrying.

Hardened against:
  - A missing/oversized/unreadable input file crashing instead of failing
    closed with a clear diagnostic (mirrors cli.verify's load_envelope
    size-guard-before-read discipline)
  - An unsafe input/output path (null bytes, malformed) reaching open()
    unresolved (cli.common.safe_resolve_path(), same as every other
    operator-supplied path in cli/)
  - Ambiguous exit codes on file errors vs. a successful (possibly
    --dry-run-sign placeholder) signing
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .common import UnsafePathError, derive_signed_path
from .oidc_signer import AmbientIdentityError, InputFileTooLargeError, sign_file_to_envelope

EXIT_PASS = 0
EXIT_FILE_ERROR = 1
EXIT_SIGNING_ERROR = 2


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="lucid-assay sign",
        description="Keyless-sign an already-built unsigned in-toto Statement file into a DSSE envelope.",
    )
    p.add_argument("statement", help="path to the unsigned in-toto Statement JSON file")
    p.add_argument(
        "--out",
        default=None,
        help="output path for the signed DSSE envelope (default: derived from the input path, "
        "the same way cli.main --out's signed envelope path is derived)",
    )
    p.add_argument(
        "--dry-run-sign",
        action="store_true",
        dest="dry_run_sign",
        help="simulate DSSE envelope creation without a real OIDC/Sigstore round-trip",
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    out_path = args.out or derive_signed_path(args.statement)

    try:
        signed_path = sign_file_to_envelope(args.statement, out_path, dry_run=args.dry_run_sign)
    except FileNotFoundError:
        print(f"ERROR: statement file not found: {args.statement}", file=sys.stderr)
        return EXIT_FILE_ERROR
    except InputFileTooLargeError as e:
        print(f"ERROR: statement file exceeds maximum allowed size (10MB): {e}", file=sys.stderr)
        return EXIT_FILE_ERROR
    except UnsafePathError as e:
        print(f"ERROR: unsafe path: {e}", file=sys.stderr)
        return EXIT_FILE_ERROR
    except AmbientIdentityError as e:
        print(f"ERROR: no ambient OIDC identity available for signing: {e}", file=sys.stderr)
        return EXIT_SIGNING_ERROR
    except (OSError, RuntimeError) as e:
        print(f"ERROR: signing failed: {e}", file=sys.stderr)
        return EXIT_SIGNING_ERROR

    print(f"signed envelope written to {signed_path}", file=sys.stderr)
    return EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
