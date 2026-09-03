"""
Assembles a companion in-toto Statement wrapping a --sbom input's own raw
document as its predicate -- predicateType https://cyclonedx.org/bom for a
CycloneDX SBOM, https://spdx.dev/Document for an SPDX one (2.3 or 3.0) --
as a *second*, separate attestation alongside lucid-assay's own RCS
predicate (cli/builder.py, predicateType
https://lucidprovenance.io/attestations/assay/v1) and any
--emit-slsa-provenance statement (cli/slsa_provenance.py).

The three are deliberately kept apart rather than merged into one
predicate shape -- same rationale as cli/slsa_provenance.py's own module
docstring, applied here to a second, different external schema: this
predicate's shape is CycloneDX's/SPDX's own, not lucid-assay's. Folding it
into assay/v1 would mean lucid-assay owns and must track two external
schemas' evolution inside its own predicate, and the resulting document
would validate cleanly against neither shape on its own.

Ground-truth-only (CLAUDE.md "Supply Chain Integrity & Attestation
Invariants"): the predicate is the SBOM's *own* raw parsed document,
verbatim (cli.parsers.sbom.SbomReport.raw_document) -- never re-derived,
summarized, or re-serialized from cli.parsers.sbom's own SbomComponent
extraction, which is a lossy, license-policy-oriented projection meant for
SARIF-finding/resolved_dependencies purposes, not a faithful copy of the
original document.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
CYCLONEDX_PREDICATE_TYPE = "https://cyclonedx.org/bom"
SPDX_PREDICATE_TYPE = "https://spdx.dev/Document"

# cli.parsers.sbom.detect_sbom_format()'s three format strings ("cyclonedx",
# "spdx2", "spdx3") map to a real, spec-published predicateType each --
# "spdx2" and "spdx3" share one, since SPDX publishes a single Document
# predicateType across its own versions; lucid-assay doesn't mint a
# version-specific one of its own. A format this module doesn't recognize
# maps to nothing (see build_sbom_statement's own None-return contract)
# rather than guessing a predicateType for it.
_PREDICATE_TYPE_BY_FORMAT: Dict[str, str] = {
    "cyclonedx": CYCLONEDX_PREDICATE_TYPE,
    "spdx2": SPDX_PREDICATE_TYPE,
    "spdx3": SPDX_PREDICATE_TYPE,
}


def predicate_type_for_format(sbom_format: Optional[str]) -> Optional[str]:
    """Maps a cli.parsers.sbom.detect_sbom_format() format string to its
    real, published in-toto predicateType. None for an unrecognized/absent
    format -- never a fabricated URI."""
    if not isinstance(sbom_format, str):
        return None
    return _PREDICATE_TYPE_BY_FORMAT.get(sbom_format)


def build_sbom_statement(
    *,
    subject_name: str,
    subject_sha256: str,
    sbom_format: Optional[str],
    raw_document: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Wraps `raw_document` (a --sbom input's own parsed JSON, verbatim) as
    an in-toto Statement predicate, for the same subject artifact
    lucid-assay's own RCS predicate attests to. `subject_sha256` should
    already be a clean lowercase hex digest, same convention
    cli.slsa_provenance.build_slsa_provenance_statement's own
    `subject_sha256` param documents (cli.main normalizes --image-digest
    once, before calling either builder).

    Returns None -- never a best-effort/partial statement -- when there's
    nothing honest to wrap: `raw_document` is None (the SBOM never parsed
    successfully) or `sbom_format` doesn't map to a real predicateType
    (see predicate_type_for_format). Both are "don't emit a companion
    statement at all" conditions, not "emit one with a guessed predicate
    type" or "emit one with an empty predicate" -- a caller should treat
    None the same way cli.main's --emit-slsa-provenance treats "the flag
    wasn't passed": simply no second statement this run.
    """
    if raw_document is None:
        return None
    predicate_type = predicate_type_for_format(sbom_format)
    if predicate_type is None:
        return None

    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": subject_name, "digest": {"sha256": subject_sha256}}],
        "predicateType": predicate_type,
        "predicate": raw_document,
    }
