"""
Assembles a genuine SLSA v1.0 provenance Statement (predicateType =
https://slsa.dev/provenance/v1) as a *second*, separate attestation
alongside lucid-assay's own RCS predicate (cli/builder.py, predicateType
https://lucidprovenance.io/attestations/assay/v1).

The two are deliberately kept apart rather than merged into one predicate
shape -- see README.md's "SLSA v1.0 provenance attestation" section and
cli/verify.py's SLSA checklist docstrings for why. This module exists so
that checklist (`_evaluate_slsa_l1`/`_evaluate_slsa_l2` in cli/verify.py,
informational and non-gating there) has a real SLSA-shaped statement to
legitimately evaluate, instead of always failing against a predicate that
was never SLSA-shaped to begin with.

Ground-truth-only (CLAUDE.md "Supply Chain Integrity & Attestation
Invariants"): every field here is populated strictly from data that
actually describes this run -- ambient GITHUB_* environment variables set
by Actions itself, the caller-supplied subject/commit/repository, and
lucid-assay's own already-parsed lockfile dependency list
(parsers/lockfiles.py). Nothing is inferred, guessed, or defaulted to a
"probably true" value. A field whose real value isn't available is simply
omitted rather than filled with a plausible fake -- an off-CI or
self-hosted-runner invocation legitimately produces a provenance statement
that doesn't satisfy every SLSA checklist item, the same fail-closed
contract as the rest of cli/.

Hardened against:
  - Fabricating builder identity, invocation IDs, or timestamps when the
    ambient GitHub Actions environment isn't actually present
  - Claiming SLSA Build Level 2 "hosted builder" trust for a self-hosted
    runner (RUNNER_ENVIRONMENT != "github-hosted") or an off-CI run
  - Silently mis-parsing GITHUB_WORKFLOW_REF into a wrong path/ref instead
    of leaving the workflow object out entirely
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"

# The real, published buildType for a GitHub Actions workflow build, as
# defined by the slsa-github-generator project -- not a value invented for
# this tool. See https://github.com/slsa-framework/github-actions-buildtypes
GITHUB_ACTIONS_WORKFLOW_BUILD_TYPE = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"

# Matches cli/verify.py's TRUSTED_HOSTED_BUILDER_IDS allowlist -- the only
# builder id that checklist accepts as "hosted", so it's only ever emitted
# below when the runner genuinely reports itself as GitHub-hosted.
GITHUB_HOSTED_BUILDER_ID = "https://github.com/actions/runner"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _github_repository_uri() -> Optional[str]:
    """https://github.com/<owner>/<repo>, from the ambient GITHUB_REPOSITORY
    Actions sets on every run (GITHUB_SERVER_URL covers GitHub Enterprise
    Server too). None off-CI or when unset."""
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        return None
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    return f"{server}/{repo}"


def _workflow_external_parameters() -> Dict[str, Any]:
    """Builds buildDefinition.externalParameters.workflow {repository, path,
    ref} from ambient GITHUB_* Actions env vars. GITHUB_WORKFLOW_REF is
    Actions-provided pre-assembled as
    'owner/repo/.github/workflows/assay.yml@refs/heads/main' -- path and
    ref are parsed out of that single source of truth rather than
    reconstructed from pieces, so there's nothing here to get out of sync.
    Returns {} (not a partially-filled dict) when the ambient context isn't
    present, so callers can treat "no workflow object" and "off CI" as the
    same case rather than emitting a half-populated one."""
    repository = _github_repository_uri()
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF")
    repo_slug = os.environ.get("GITHUB_REPOSITORY")
    if not repository or not workflow_ref or not repo_slug or "@" not in workflow_ref:
        return {}

    path, ref = workflow_ref.rsplit("@", 1)
    prefix = f"{repo_slug}/"
    if path.startswith(prefix):
        path = path[len(prefix):]

    if not path or not ref:
        return {}
    return {"workflow": {"repository": repository, "path": path, "ref": ref}}


def _source_resolved_dependency() -> Optional[Dict[str, Any]]:
    """The checked-out source commit itself as a SLSA resolvedDependencies
    entry -- an unambiguous, always-real build input when the commit sha
    and repository are both known. Uses GITHUB_SHA (the commit Actions
    actually checked out for this run) rather than any caller-supplied
    --head-sha, since GITHUB_SHA is what the ambient environment itself
    attests to."""
    repository = _github_repository_uri()
    commit_sha = os.environ.get("GITHUB_SHA")
    if not repository or not commit_sha:
        return None
    return {"uri": f"git+{repository}", "digest": {"gitCommit": commit_sha}}


def _lockfile_resolved_dependencies(resolved_dependencies: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Reshapes lucid-assay's own lockfile-derived dependency list
    (cli/parsers/lockfiles.py: pkg: PURL + digest per entry, already
    computed by _detect_lockfile_dependencies() in cli/main.py) into
    SLSA's {uri, digest} resolvedDependencies shape. Same underlying real
    data as the top-level predicate.resolved_dependencies field on
    lucid-assay's own predicate -- reformatted here, never re-derived or
    fabricated. Entries missing a usable 'uri' are skipped individually
    rather than discarding the whole list."""
    out: List[Dict[str, Any]] = []
    for dep in resolved_dependencies or []:
        if not isinstance(dep, dict):
            continue
        uri = dep.get("uri")
        if not isinstance(uri, str) or not uri.strip():
            continue
        entry: Dict[str, Any] = {"uri": uri}
        digest = dep.get("digest")
        if isinstance(digest, dict) and digest:
            entry["digest"] = digest
        out.append(entry)
    return out


def _hosted_builder(builder_id: Optional[str] = None) -> Dict[str, Any]:
    """Only claims a trusted hosted-builder id when the runner actually
    reports itself as GitHub-hosted (RUNNER_ENVIRONMENT=github-hosted,
    ambient and unspoofable by workflow YAML). A self-hosted runner, or a
    local/off-CI invocation, gets an empty builder object rather than a
    false "hosted" claim -- that's exactly the tamper-resistance signal
    SLSA Build Level 2 is meant to gate on, so it fails closed the same
    way the rest of this module does.

    `builder_id`, when given, overrides the default generic
    GITHUB_HOSTED_BUILDER_ID with a more specific identity -- used by
    `cli/provenance.py` (run from inside an isolated, trusted signer job)
    to assert *that job's own* workflow identity instead of the generic
    "some hosted runner ran this" claim, which is what SLSA Build Level 3's
    unforgeable-builder-identity check needs (see cli/verify.py's
    TRUSTED_CONTROL_PLANE_BUILDER_IDS). Every other, existing caller (the
    untrusted build job's own --emit-slsa-provenance path) omits it and
    gets exactly the same GITHUB_HOSTED_BUILDER_ID behavior as before this
    parameter existed."""
    if os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted":
        return {"id": builder_id or GITHUB_HOSTED_BUILDER_ID}
    return {}


def _invocation_metadata(started_at: str, finished_at: Optional[str]) -> Dict[str, Any]:
    """startedOn/finishedOn are always real, caller-supplied wall-clock
    timestamps of this pipeline run -- finished_at defaults to "now" only
    because this function is necessarily called once the run is already
    finishing. invocationId is only added when GITHUB_RUN_ID is actually
    present; GITHUB_RUN_ATTEMPT defaults to "1" per Actions' own
    documented behavior for the first attempt (it's genuinely unset then,
    not a guess)."""
    metadata: Dict[str, Any] = {"startedOn": started_at, "finishedOn": finished_at or _now_iso()}
    run_id = os.environ.get("GITHUB_RUN_ID")
    repository = _github_repository_uri()
    if run_id and repository:
        attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
        metadata["invocationId"] = f"{repository}/actions/runs/{run_id}/attempts/{attempt}"
    return metadata


def build_slsa_provenance_statement(
    *,
    subject_name: str,
    subject_sha256: str,
    started_at: str,
    finished_at: Optional[str] = None,
    resolved_dependencies: Optional[List[Dict[str, Any]]] = None,
    builder_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Assembles a real, spec-shaped SLSA v1.0 provenance in-toto Statement
    for the same subject artifact lucid-assay's own RCS predicate attests
    to. Every buildDefinition/runDetails field is sourced from real ambient
    GitHub Actions context (see module docstring); fields whose real value
    isn't available are simply absent rather than guessed. `subject_sha256`
    should already be a clean lowercase hex digest (cli/main.py normalizes
    --image-digest before calling this, same as it does for
    cli.builder.build_statement). `builder_id` overrides the default
    generic hosted-runner builder identity -- see _hosted_builder()'s
    docstring; omitted, behavior is unchanged from before this parameter
    existed."""
    resolved: List[Dict[str, Any]] = []
    source_dep = _source_resolved_dependency()
    if source_dep is not None:
        resolved.append(source_dep)
    resolved.extend(_lockfile_resolved_dependencies(resolved_dependencies))

    build_definition: Dict[str, Any] = {
        "buildType": GITHUB_ACTIONS_WORKFLOW_BUILD_TYPE,
        "externalParameters": _workflow_external_parameters(),
        "internalParameters": {},
        "resolvedDependencies": resolved,
    }

    run_details: Dict[str, Any] = {
        "builder": _hosted_builder(builder_id),
        "metadata": _invocation_metadata(started_at, finished_at),
    }

    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": subject_name, "digest": {"sha256": subject_sha256}}],
        "predicateType": SLSA_PROVENANCE_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": build_definition,
            "runDetails": run_details,
        },
    }
