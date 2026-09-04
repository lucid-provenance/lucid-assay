"""
Assembles a companion in-toto Statement wrapping every `--sarif` input's own
raw document as its predicate, keyed by the tool name each document's own
SARIF `runs[].tool.driver.name` reports -- the same identifier
cli.parsers.sarif already treats as canonical (`SarifToolSummary.name`,
S2C2F's own tool-name matching in cli/parsers/s2c2f.py). A second, separate
attestation alongside lucid-assay's own RCS predicate and the `--sbom`
companion statement (cli/sbom_statement.py) -- same "external document
family, kept apart" rationale that module's own docstring gives, applied
here to a third, different document family.

Ground-truth-only (CLAUDE.md "Supply Chain Integrity & Attestation
Invariants"): each entry is the exact raw SARIF document lucid-assay itself
read via `--sarif`, verbatim -- never re-derived from `SarifSummaryReport`/
`SarifFinding`, which are a lossy, scoring-oriented projection (see
cli.parsers.sarif's own module docstring), not a faithful copy of the
original document(s). The synthetic `lucid-assay-sbom-license-policy`
"tool" (cli.parsers.sbom.build_sbom_sarif_report) has no raw document at
all -- its findings are synthesized in-memory from the SBOM's own component
list, never round-tripped through an actual SARIF file on disk -- so it
never appears here; only real `--sarif` inputs do.

One statement per run, not one per `--sarif` input: lucid-dsse-collector's
ingest pipeline only ever keeps a single decoded statement per
predicateType out of one bundle (see its workers/ingest_worker.py --
"duplicate statement for predicateType X; keeping the first"), so N raw
`--sarif` inputs are bundled into ONE statement whose predicate maps
`{tool_name: raw_document}`, rather than requiring the collector to support
multiple statements sharing a predicateType. A raw SARIF document with
multiple `runs[]` (multiple tools in one file -- spec-legal, uncommon)
contributes its same raw document under each of its own tool names.

Hardened against the same failure modes cli.parsers.sarif.parse_sarif_file
already guards (unsafe paths, oversized files, unreadable/malformed JSON,
pathological nesting) -- degrades a single unreadable input to "not
represented in this statement" rather than raising or tainting the others,
deliberately looser than cli.parsers.sarif.aggregate_sarif_reports' own
fail-closed-on-any-bad-input contract: this statement's only job is to
preserve whatever raw bytes genuinely were read successfully, not to make
a scoring judgment about the run as a whole (that judgment already happened
in the scorer, off SarifSummaryReport, independently of this module).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .common import UnsafePathError, safe_resolve_path
from .parsers.sarif import MAX_SARIF_FILE_SIZE

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
# lucid-assay's own predicateType, minted the same way assay/v1 and
# episteme/v1 were (cli/builder.py, lucid-episteme). SARIF has no
# established in-toto predicateType of its own to reuse -- unlike
# CycloneDX/SPDX, which do (see cli.sbom_statement's own constants) --
# so this is a project-owned identifier, not a fabricated claim about an
# external spec.
SARIF_REPORTS_PREDICATE_TYPE = "https://lucidprovenance.io/attestations/sarif-reports/v1"


def _load_raw_sarif_document(path: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """Same hardening as cli.parsers.sbom._load_sbom_document, applied to a
    `--sarif` path instead: unsafe path, oversized file, unreadable file,
    malformed/non-UTF-8/pathologically-nested JSON, or a non-object
    top-level value all degrade to None -- never raise, never taint a
    sibling `--sarif` input's own document."""
    try:
        resolved = safe_resolve_path(path)
        if resolved.stat().st_size > MAX_SARIF_FILE_SIZE:
            return None
        with open(resolved, "rb") as f:
            raw = f.read()
        doc = json.loads(raw.decode("utf-8"))
    except (UnsafePathError, OSError, json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return None
    return doc if isinstance(doc, dict) else None


def _run_tool_names(document: Dict[str, Any]) -> List[str]:
    """Every distinct tool name a raw SARIF document's own runs[] report,
    via the identical driver.name lookup cli.parsers.sarif's own
    _extract_driver_metadata uses (name.strip(), falling back to
    "unknown") -- so a report served from this statement is always
    addressable by the exact same tool name string the rest of this
    pipeline (SarifToolSummary.name, S2C2F's tool-name matching) already
    uses for it. Never raises on a malformed document -- returns []."""
    runs = document.get("runs")
    if not isinstance(runs, list):
        return []
    names: List[str] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        name = driver.get("name") if isinstance(driver, dict) else None
        name = name.strip() if isinstance(name, str) and name.strip() else "unknown"
        if name not in names:
            names.append(name)
    return names


def build_sarif_reports_statement(
    *,
    subject_name: str,
    subject_sha256: str,
    sarif_paths: List[str],
) -> Optional[Dict[str, Any]]:
    """Loads and wraps every raw SARIF document at `sarif_paths` (verbatim
    `args.sarif` from cli.main) into one in-toto Statement, predicate
    `{"reports": {tool_name: document, ...}}`, for the same subject
    artifact lucid-assay's own RCS predicate attests to.

    Returns None -- never a fabricated/partial statement -- when
    `sarif_paths` is empty (no `--sarif` was passed), every input failed
    to load, or none yielded an addressable tool name at all."""
    reports: Dict[str, Any] = {}
    for path in sarif_paths:
        doc = _load_raw_sarif_document(path)
        if doc is None:
            continue
        for name in _run_tool_names(doc):
            # First document to claim a given tool name wins -- mirrors
            # cli.parsers.sarif.aggregate_sarif_reports' own "duplicate
            # statement... keeping the first" convention elsewhere in this
            # pipeline, applied here to the same identifier space.
            reports.setdefault(name, doc)

    if not reports:
        return None

    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": subject_name, "digest": {"sha256": subject_sha256}}],
        "predicateType": SARIF_REPORTS_PREDICATE_TYPE,
        "predicate": {"reports": reports},
    }
