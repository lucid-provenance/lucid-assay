"""
CLI entry point: `python3 -m scripts.emit_s2c2f_evidence [options]`
(or `scripts/emit-s2c2f-evidence.sh [options]`, a thin wrapper around this).

Non-blocking telemetry emitter, distinct from scripts.verify_ingestion:
always exits 0 (never gates a build) and emits a fuller predicate --
the same ING-3/ING-2/ENF-2 control results plus captured environment data
(active registry config, git/CI identity) -- wrapped as the predicate of a
real in-toto v1 Statement (predicateType
https://lucidprovenance.io/attestations/s2c2f-evidence/v1, matching the
predicate-type-minting convention cli/sbom_statement.py and
cli/sarif_statement.py already established for a companion attestation
with no shared external schema to reuse). See
.github/workflows/s2c2f-evidence-telemetry.yml for how this is meant to be
wired in.

Subject: two real, addressable git object identities for the exact
checkout this evidence was collected against -- the commit SHA and the
git tree SHA of that commit (a real "repo root digest": the content
identity of the entire checked-out tree at HEAD, not an invented ad hoc
hash of a directory listing). Neither is fabricated when unavailable (a
non-git checkout, or `git` missing) -- see build_statement()'s own
docstring for what happens then.

Signing: `--sign`/`--dry-run-sign` reuse cli.oidc_signer.sign_file_to_envelope
directly -- the same file-in/file-out entry point cli.sign's own
`lucid-assay sign` subcommand uses for a signing job with no access to how
its input file was produced beyond the file's own bytes -- rather than
shelling out to `cosign sign-blob`. That was an earlier draft's plan;
deliberately dropped: `cosign sign-blob` (like `sigstore sign`, called out
in cli/oidc_signer.py's own module docstring) signs over raw artifact
bytes into a hashedrekord bundle, never a DSSE envelope, no matter what's
handed to it -- the exact anti-pattern this codebase already hit and fixed
once for its main signing path. `cosign attest-blob` does produce DSSE,
but introduces a second, independent signing implementation/dependency for
a job that doesn't need one when cli.oidc_signer already has a real,
tested one. If ambient OIDC credentials aren't available when --sign is
requested (an AmbientIdentityError from cli.oidc_signer.fetch_ambient_oidc_token
-- e.g. a local run, or a fork PR with no OIDC token forwarded), this
degrades to writing only the unsigned Statement and warns on stderr,
rather than failing the whole (non-blocking) job.

Emits the unsigned Statement to --out (default: s2c2f-evidence.unsigned.json)
and, when signed, the DSSE envelope to cli.common.derive_signed_path(--out)
(default: s2c2f-evidence.dsse.json). The predicate itself matches
schema/s2c2f-evidence-v1.schema.json.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cli.common import derive_signed_path, safe_resolve_path  # noqa: E402
from cli.parsers.lockfiles import detect_and_parse_dependencies  # noqa: E402
from cli.slsa_provenance import _github_repository_uri  # noqa: E402

from scripts._ingestion_lib import STATUS_FAIL, run_ingestion_checks  # noqa: E402
from scripts.verify_ingestion import _resolve_internal_hosts  # noqa: E402

_EVIDENCE_SCHEMA_VERSION = "s2c2f-evidence/v1"
_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_PREDICATE_TYPE = "https://lucidprovenance.io/attestations/s2c2f-evidence/v1"
_GIT_TIMEOUT_SECONDS = 5


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git_rev_parse(repo_dir: Path, rev: str) -> Optional[str]:
    """Best-effort `git rev-parse <rev>` in repo_dir. Never raises -- a
    missing git binary, a non-repo directory, or a hung/failing process
    (bounded by _GIT_TIMEOUT_SECONDS) all degrade to None, same "checked,
    not available" contract as every other environment-capture field
    here."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", rev],
            capture_output=True, text=True, timeout=_GIT_TIMEOUT_SECONDS, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None if result.returncode == 0 else None


def _repository_uri(repo_dir: Path) -> Optional[str]:
    """Prefers the ambient GITHUB_REPOSITORY (cli.slsa_provenance's own
    _github_repository_uri, reused here for the identical convention a
    real SLSA provenance statement's own git-subject already uses),
    falling back to `git remote get-url origin` for a local/off-CI run.
    None -- never a fabricated placeholder -- when neither resolves."""
    uri = _github_repository_uri()
    if uri:
        return uri
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=_GIT_TIMEOUT_SECONDS, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None if result.returncode == 0 else None


def _read_npm_registry_config(repo_dir: Path) -> Optional[str]:
    """Reads the `registry=` line out of a repo-root .npmrc, if any --
    the same file scripts._ingestion_lib's pip/maven config-presence
    checks look at, but read here for its raw value rather than a
    presence boolean, since emit_s2c2f_evidence's job is to *capture*
    environment data, not classify it."""
    npmrc = repo_dir / ".npmrc"
    if not npmrc.is_file():
        return None
    try:
        for line in npmrc.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if stripped.startswith("registry="):
                return stripped.split("=", 1)[1].strip()
    except OSError:
        return None
    return None


def _capture_environment(repo_dir: Path, commit_sha: Optional[str]) -> Dict[str, Any]:
    return {
        "npm_registry_config": _read_npm_registry_config(repo_dir),
        "pip_index_url_env": os.environ.get("PIP_INDEX_URL"),
        "git_commit_sha": commit_sha,
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "ref": os.environ.get("GITHUB_REF"),
    }


def build_predicate(repo_dir: Path, denylist_path: Path, internal_hosts: List[str]) -> Dict[str, Any]:
    resolved_dependencies = detect_and_parse_dependencies(str(repo_dir))
    results = run_ingestion_checks(
        repo_dir=repo_dir, internal_hosts=internal_hosts, denylist_path=denylist_path, resolved_dependencies=resolved_dependencies,
    )
    would_enforce_exit_code = 1 if any(r.status == STATUS_FAIL for r in results.values()) else 0
    commit_sha = os.environ.get("GITHUB_SHA") or _git_rev_parse(repo_dir, "HEAD")
    return {
        "schema_version": _EVIDENCE_SCHEMA_VERSION,
        "generated_at": _utc_now_iso(),
        "environment": _capture_environment(repo_dir, commit_sha),
        "controls": {cid: r.as_dict() for cid, r in results.items()},
        "would_enforce_exit_code": would_enforce_exit_code,
    }


def build_statement(repo_dir: Path, predicate: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Wraps `predicate` as an in-toto v1 Statement. Returns None -- never
    a statement with an empty/fabricated subject -- when repo_dir has no
    resolvable git commit at all (not a git repo, or `git` isn't on PATH);
    same "nothing honest to wrap, emit nothing" contract
    cli.sbom_statement.build_sbom_statement's own docstring documents.

    Deliberately resolves its own commit_sha via `git -C repo_dir
    rev-parse HEAD` rather than reusing predicate["environment"]
    ["git_commit_sha"] (which prefers the ambient $GITHUB_SHA -- ground
    truth about what the *runner's own checkout step* fetched, matching
    cli.slsa_provenance._source_resolved_dependency's identical
    preference, but not necessarily about `repo_dir` specifically if a
    caller ever points --repo-dir somewhere other than the workflow's own
    checkout). A Statement's subject digests must always describe the
    exact same tree: computing gitCommit and gitTree from two different
    sources (ambient env vs. repo_dir's own git state) could silently
    produce a self-inconsistent subject if the two ever diverged. Caught
    by tests/test_scripts_ingestion.py's build_statement tests, which run
    against a repo_dir carrying no ambient $GITHUB_SHA relationship at
    all."""
    commit_sha = _git_rev_parse(repo_dir, "HEAD")
    if not commit_sha:
        return None
    repository_uri = _repository_uri(repo_dir)
    name = f"git+{repository_uri}" if repository_uri else str(repo_dir)
    subjects = [{"name": name, "digest": {"gitCommit": commit_sha}}]
    tree_sha = _git_rev_parse(repo_dir, "HEAD^{tree}")
    if tree_sha:
        subjects.append({"name": f"{name}#tree", "digest": {"gitTree": tree_sha}})
    return {"_type": _STATEMENT_TYPE, "subject": subjects, "predicateType": _PREDICATE_TYPE, "predicate": predicate}


def _maybe_sign(unsigned_path: Path, *, sign: bool, dry_run_sign: bool) -> Optional[Path]:
    """Mirrors cli.main._maybe_sign's --sign/--dry-run-sign contract
    exactly (see module docstring for why cli.oidc_signer.sign_file_to_envelope
    is reused directly rather than shelling out to `cosign sign-blob`), with
    one addition: since this job is telemetry-only and must never block a
    build, a missing-ambient-credentials failure degrades to "no signed
    file written, warn on stderr" instead of raising -- the "fall back to
    an unsigned statement" cli.oidc_signer's own module docstring
    deliberately refuses to do for the real attestation pipeline is exactly
    right here, where there's no --min-rcs/--disallow-degraded gate reading
    a signature at all."""
    if not (sign or dry_run_sign):
        return None

    from cli.oidc_signer import AmbientIdentityError, sign_file_to_envelope

    signed_path = derive_signed_path(str(unsigned_path))
    try:
        result_path = sign_file_to_envelope(str(unsigned_path), signed_path, dry_run=dry_run_sign)
    except AmbientIdentityError as e:
        print(f"warning: no ambient OIDC credentials available ({e}); writing unsigned S2C2F evidence statement only", file=sys.stderr)
        return None
    except Exception as e:  # noqa: BLE001 - telemetry must never fail the build on a signing error
        print(f"warning: S2C2F evidence signing failed ({e}); writing unsigned statement only", file=sys.stderr)
        return None
    print(f"signed S2C2F evidence envelope written to {result_path}", file=sys.stderr)
    return result_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-dir", default=".", help="Repo checkout to evaluate (default: .)")
    parser.add_argument("--denylist", default=".lucid/denylist.json", help="Path to the ING-3 denylist policy artifact (default: .lucid/denylist.json)")
    parser.add_argument("--internal-registry", default=None, help="Comma-separated internal/curated registry host substrings; falls back to $LUCID_INTERNAL_REGISTRY_HOSTS")
    parser.add_argument("--out", default="s2c2f-evidence.unsigned.json", help="Path for the unsigned in-toto Statement (default: s2c2f-evidence.unsigned.json)")
    parser.add_argument("--sign", action="store_true", help="Sign the statement into a real DSSE envelope via ambient Sigstore OIDC (falls back to unsigned if credentials aren't available)")
    parser.add_argument("--dry-run-sign", action="store_true", help="Write a placeholder (unsigned) DSSE envelope, same semantics as cli.main's --dry-run-sign")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    repo_dir = Path(args.repo_dir)
    internal_hosts = _resolve_internal_hosts(args.internal_registry)

    predicate = build_predicate(repo_dir, Path(args.denylist), internal_hosts)
    statement = build_statement(repo_dir, predicate)

    if statement is None:
        print("warning: no git commit SHA could be resolved for this checkout; emitting the bare predicate with no in-toto Statement wrapper", file=sys.stderr)
        text = json.dumps(predicate, indent=2, sort_keys=True)
        print(text)
        if args.out:
            safe_resolve_path(args.out).write_text(text + "\n", encoding="utf-8")
        return 0

    text = json.dumps(statement, indent=2, sort_keys=True)
    print(text)
    out_path = safe_resolve_path(args.out)
    out_path.write_text(text + "\n", encoding="utf-8")

    _maybe_sign(out_path, sign=args.sign, dry_run_sign=args.dry_run_sign)

    # Telemetry-only: this command always succeeds regardless of findings.
    # predicate["would_enforce_exit_code"] is what scripts.verify_ingestion
    # would return in enforce mode -- surfaced for visibility, not acted on
    # here.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
