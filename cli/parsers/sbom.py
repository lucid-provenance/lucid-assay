"""
SBOM (Software Bill of Materials) ingestion: detects and parses CycloneDX
JSON (1.4-1.6) and SPDX JSON (2.3, plus a best-effort subset of 3.0) into a
normalized component inventory, evaluates each component's declared/
concluded license against a license policy (forbidden copyleft/source-
available vs. permissive), and converts the result into SARIF-compatible
findings (cli.parsers.sarif.SarifFinding/SarifToolSummary/SarifSummaryReport
-- the exact same shapes parse_sarif_file() produces from a real SARIF
file). That's a deliberate design choice, not an implementation shortcut:
a caller (cli.main) folds the returned SarifSummaryReport into whatever
--sarif input it already has via cli.parsers.sarif.aggregate_sarif_reports,
so this module's findings flow through the scorer's existing static-
analysis component (WEIGHTS["static_analysis"]) and S2C2F's SCA-2
("License Checks") control with zero special-casing anywhere downstream --
scorer.py and cli.parsers.s2c2f both already treat "a SARIF tool with
findings" generically, regardless of where those findings came from.

Also produces resolved_dependencies-shaped entries (see
cli.parsers.lockfiles.ResolvedDependency's {"uri": "pkg:...", "digest": {}}
shape) from each component's PURL -- for S2C2F's INV-1 (Inventory)/ING-1
(Package Managers), which already key off resolved_dependencies being
non-empty, format-agnostically. cli.main uses this as a fallback only when
lockfile detection came up empty (a vendored/third-party artifact with no
lockfile of its own, or an ecosystem cli.parsers.lockfiles doesn't cover).

SbomReport also carries the SBOM's own raw parsed document verbatim
(`.raw_document`) alongside `.components` -- cli.sbom_statement's companion
in-toto Statement (predicateType https://cyclonedx.org/bom or
https://spdx.dev/Document) wraps that raw document as its predicate,
deliberately never a re-derivation from `.components` (a lossy,
license-policy-oriented projection, not a faithful copy of the original).

Hardened against:
  - Every file path is resolved through cli.common.safe_resolve_path()
    before being opened/read, same as every other parser in this package.
  - Oversized input (MAX_SBOM_FILE_SIZE, matching cli.parsers.sarif's own
    10MB cap) is rejected by a stat() size check before the file is ever
    read into memory.
  - Missing/unreadable files and malformed/non-object JSON all degrade to
    SbomReport(available=False) -- never raise, never silently report an
    empty-but-"available" inventory.
  - Pathologically deep JSON nesting (CPython's json.loads is recursive-
    descent) raises RecursionError before json.JSONDecodeError would fire;
    caught alongside it, same as cli.parsers.sarif.parse_sarif_file.
  - CycloneDX's nested `components[].components[]` (a library bundling its
    own vendored sub-components) is walked via an explicit stack, not
    recursion -- an arbitrarily deep nesting can't blow the call stack.
  - A single malformed component/package entry (missing name, an
    unrecognized hash algorithm, an unresolvable SPDX 3.0 license
    cross-reference) is skipped/degraded individually, never discarding
    the whole document's worth of components.
  - A missing/NOASSERTION/NONE license (SPDX's own "no assertion made"
    tokens) classifies as "unclassified", never silently folded into
    "permissive"/clean -- an unknown license is a real, distinct signal a
    compliance report must not hide.
  - A CycloneDX component with `type: "file"` (Syft's file cataloger --
    dist-info metadata files, workflow YAMLs, anything with no license
    concept of its own) is excluded before license evaluation ever runs,
    never counted as a real dependency with an "unclassified" license --
    see _cdx_component_to_sbom_component's own comment for why this is an
    exclude-"file" rule, not a "library"-only allowlist. SPDX's own
    packages[]/files[] split means this only applies to CycloneDX; SPDX
    parsing already reads packages[] exclusively.
  - classify_license_expression() is a deliberately shallow, best-effort
    SPDX-license-expression evaluator (flattened AND/OR/WITH splitting,
    no operator-precedence/nesting awareness) -- see its own docstring for
    exactly what boolean structure it does and doesn't honor. It is never
    guessed at beyond that documented contract.
  - SPDX 3.0's full JSON-LD form can reference a license via a separate
    graph node's @id rather than inlining the expression string; resolving
    that cross-reference is out of scope, and such a component's
    license_expression is simply None (unclassified), never guessed at
    from the unresolved reference.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterator, List, Optional, Set, Tuple, Union

from ..common import UnsafePathError, safe_resolve_path
from .sarif import SarifFinding, SarifRuleGroup, SarifSummaryReport, SarifToolSummary

MAX_SBOM_FILE_SIZE = 10 * 1024 * 1024  # matches cli.parsers.sarif.MAX_SARIF_FILE_SIZE

# The synthetic SARIF tool name this module's findings are reported under.
# Deliberately unambiguous (unlike a real multi-purpose scanner, e.g.
# Trivy, whose SARIF output shares one driver name across vulnerability/
# license/secret/misconfig scan classes) -- this module only ever emits
# license findings, so a plain tool-name substring match in
# cli.parsers.s2c2f._LICENSE_TOOL_NAME_PATTERNS is sufficient and correct,
# no tag-based corroboration needed.
SBOM_LICENSE_TOOL_NAME = "lucid-assay-sbom-license-policy"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class SbomComponent:
    __test__ = False
    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    license_expression: Optional[str] = None
    license_source: str = "unspecified"  # "declared" | "concluded" | "unspecified"
    digest: Dict[str, str] = field(default_factory=dict)


@dataclass
class SbomReport:
    __test__ = False
    available: bool
    format: Optional[str] = None  # "cyclonedx" | "spdx2" | "spdx3"
    components: List[SbomComponent] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    # The SBOM's own parsed JSON document, verbatim -- carried alongside
    # `components` (lucid-assay's own lossy, license-policy-oriented
    # projection of it) so a caller that needs the faithful original (e.g.
    # cli.sbom_statement's companion in-toto Statement, whose predicate is
    # explicitly the SBOM's own document, not a re-derived summary of it)
    # doesn't have to re-read and re-parse the file a second time. None
    # only when available=False.
    raw_document: Optional[Dict[str, Any]] = None


@dataclass
class LicensePolicy:
    """A license policy is two matching rulesets: `forbidden_prefixes`
    (an SPDX id starting with any of these, case-insensitively, is
    forbidden -- e.g. "GPL-" matches "GPL-3.0-only") and `permissive_exact`
    / `permissive_prefixes` (an exact id, or one starting with any of
    these prefixes, is permissive). Anything matching neither is
    "unclassified" -- never silently treated as either clean or a
    violation."""
    __test__ = False
    forbidden_prefixes: Tuple[str, ...]
    permissive_prefixes: Tuple[str, ...]
    permissive_exact: FrozenSet[str]


# Sensible defaults per this module's own product requirements: strong
# copyleft / source-available families are forbidden; the common permissive
# families are clean. Everything else (LGPL-*, MPL-2.0, EPL-*, a custom/
# proprietary license name, NOASSERTION/NONE, ...) is "unclassified" --
# present in the report, not silently absorbed into either bucket.
DEFAULT_FORBIDDEN_PREFIXES: Tuple[str, ...] = ("AGPL-", "GPL-", "SSPL-", "CC-BY-NC-")
DEFAULT_PERMISSIVE_PREFIXES: Tuple[str, ...] = ("APACHE-", "BSD-")
DEFAULT_PERMISSIVE_EXACT: FrozenSet[str] = frozenset(
    {"MIT", "MIT-0", "ISC", "0BSD", "UNLICENSE", "ZLIB", "POSTGRESQL", "BSL-1.0", "PYTHON-2.0"}
)

DEFAULT_LICENSE_POLICY = LicensePolicy(
    forbidden_prefixes=DEFAULT_FORBIDDEN_PREFIXES,
    permissive_prefixes=DEFAULT_PERMISSIVE_PREFIXES,
    permissive_exact=DEFAULT_PERMISSIVE_EXACT,
)


# ---------------------------------------------------------------------------
# License expression classification
# ---------------------------------------------------------------------------

_OPERATOR_TOKENS = {"AND", "OR", "WITH"}
_UNSPECIFIED_TOKENS = {"NOASSERTION", "NONE"}


def _tokenize(expression: str) -> List[str]:
    """Splits a license expression into whitespace-delimited tokens, after
    stripping parentheses. Real SPDX expressions are always
    whitespace-tokenized -- an AND/OR/WITH operator is never glued
    directly onto an identifier -- so this correctly leaves a hyphenated
    SPDX id containing the *substring* "or" (e.g. the extremely common
    "-or-later" suffix: "GPL-2.0-or-later", "LGPL-2.1-or-later", ...) as
    one single term. An earlier version of this function used a regex
    `\\bOR\\b` word-boundary match instead, which -- since "-" counts as a
    non-word character -- incorrectly matched the "or" inside "-or-later"
    as the boolean OR operator, corrupting every "-or-later"-suffixed
    identifier's classification. Caught by this module's own test suite
    (test_forbidden_single_term against "GPL-2.0-or-later"), not by
    inspection -- worth keeping in mind before "simplifying" this back to
    a regex."""
    return expression.replace("(", " ").replace(")", " ").split()


def _split_terms(tokens: List[str]) -> List[str]:
    return [t for t in tokens if t.upper() not in _OPERATOR_TOKENS]


def _is_or_expression(tokens: List[str]) -> bool:
    return any(t.upper() == "OR" for t in tokens)


def _classify_term(term: str, policy: LicensePolicy) -> str:
    # No empty-string guard: `term` always comes from _split_terms(), whose
    # tokens are produced by str.split() with no arguments -- which never
    # yields an empty string -- so an empty `term` can't reach here.
    upper = term.strip().upper()
    if any(upper.startswith(p.upper()) for p in policy.forbidden_prefixes):
        return "forbidden"
    if upper in policy.permissive_exact or any(upper.startswith(p.upper()) for p in policy.permissive_prefixes):
        return "permissive"
    return "unclassified"


def classify_license_expression(
    expression: Optional[str], policy: Optional[LicensePolicy] = None
) -> Tuple[str, List[str]]:
    """Classifies a raw SPDX-style license expression (a single id, or an
    AND/OR/WITH compound) as "forbidden", "permissive", or "unclassified"
    against `policy` (default DEFAULT_LICENSE_POLICY). Returns
    (classification, matched_forbidden_terms).

    Deliberately a shallow, best-effort evaluator -- not a full SPDX
    license-expression parser: it flattens the expression into individual
    identifier terms (stripping parentheses and the AND/OR/WITH operators)
    without tracking operator precedence or nesting. The one piece of
    boolean structure it does honor: if the expression contains "OR"
    anywhere, it's treated as satisfiable by whichever term a consumer
    would actually pick, so it classifies "forbidden" only when *every*
    term is forbidden (a "GPL-3.0-only OR Apache-2.0" dual license is not
    itself a violation -- the permissive branch is a legal choice) and
    "permissive" only when every term is permissive; anything else (a
    single term, or an AND/WITH-joined expression, where every term's
    obligation applies simultaneously) is "forbidden" if *any* term is
    forbidden. A deeply nested mixed expression (e.g. "(A AND B) OR C") is
    evaluated on this same flattened, un-nested basis -- a known,
    documented limitation, not silently miscounted as exact.

    Missing/empty/NOASSERTION/NONE expressions (SPDX's own "no license
    information available" tokens) classify as "unclassified" -- an
    unknown license is a real, distinct signal, never silently folded
    into "permissive"/clean.
    """
    policy = policy or DEFAULT_LICENSE_POLICY
    if not expression or not expression.strip():
        return "unclassified", []
    normalized = expression.strip()
    if normalized.upper() in _UNSPECIFIED_TOKENS:
        return "unclassified", []

    tokens = _tokenize(normalized)
    terms = _split_terms(tokens)
    if not terms:
        return "unclassified", []

    classifications = [(_classify_term(t, policy), t) for t in terms]
    forbidden_terms = [t for cls, t in classifications if cls == "forbidden"]

    if _is_or_expression(tokens):
        if forbidden_terms and len(forbidden_terms) == len(terms):
            return "forbidden", forbidden_terms
        if all(cls == "permissive" for cls, _ in classifications):
            return "permissive", []
        return "unclassified", []

    if forbidden_terms:
        return "forbidden", forbidden_terms
    if all(cls == "permissive" for cls, _ in classifications):
        return "permissive", []
    return "unclassified", []


# ---------------------------------------------------------------------------
# Shared hash-algorithm normalization (CycloneDX/SPDX each spell these
# differently; normalized to the lowercase, hyphen-free form
# cli.parsers.s2c2f._MATERIALIZED_DIGEST_ALGORITHMS/cli.parsers.lockfiles
# already use elsewhere in this predicate).
# ---------------------------------------------------------------------------

_HASH_ALG_ALIASES = {
    "SHA-256": "sha256", "SHA256": "sha256",
    "SHA-512": "sha512", "SHA512": "sha512",
    "SHA-1": "sha1", "SHA1": "sha1",
    "MD5": "md5",
}


def _normalize_hash_alg(raw: Any) -> Optional[str]:
    if not isinstance(raw, str):
        return None
    return _HASH_ALG_ALIASES.get(raw.strip().upper())


def _digest_from_hash_list(entries: Any, alg_key: str, value_key: str) -> Dict[str, str]:
    """Shared extractor for CycloneDX's `hashes: [{"alg", "content"}]` and
    SPDX 2.x's `checksums: [{"algorithm", "checksumValue"}]` -- same shape,
    different key names. An unrecognized algorithm or empty value is
    skipped individually, never discarding the other entries."""
    if not isinstance(entries, list):
        return {}
    digest: Dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        alg = _normalize_hash_alg(entry.get(alg_key))
        value = entry.get(value_key)
        if alg and isinstance(value, str) and value.strip():
            digest[alg] = value.strip().lower()
    return digest


# ---------------------------------------------------------------------------
# CycloneDX JSON (1.4-1.6)
# ---------------------------------------------------------------------------


def _cdx_license_expression(licenses_field: Any) -> Optional[str]:
    """CycloneDX's component.licenses is a list of {"license": {"id"|
    "name": ...}} or {"expression": "..."} entries. Multiple entries are
    joined with " AND " -- CycloneDX's own convention for the array
    meaning "all of these apply simultaneously", unlike SPDX's single
    expression string where OR/AND structure is explicit inline. A
    {"license": {"name": "Custom License"}} entry (a free-text name, not
    an SPDX id) contributes its name unchanged; it won't match any
    forbidden/permissive rule and correctly classifies "unclassified"
    rather than being silently dropped."""
    if not isinstance(licenses_field, list) or not licenses_field:
        return None
    parts: List[str] = []
    for entry in licenses_field:
        if not isinstance(entry, dict):
            continue
        expression = entry.get("expression")
        if isinstance(expression, str) and expression.strip():
            parts.append(expression.strip())
            continue
        lic = entry.get("license")
        if isinstance(lic, dict):
            ident = lic.get("id") or lic.get("name")
            if isinstance(ident, str) and ident.strip():
                parts.append(ident.strip())
    if not parts:
        return None
    return parts[0] if len(parts) == 1 else " AND ".join(parts)


def _cdx_component_digest(comp: Dict[str, Any]) -> Dict[str, str]:
    return _digest_from_hash_list(comp.get("hashes"), "alg", "content")


def _cdx_component_to_sbom_component(comp: Dict[str, Any]) -> Optional[SbomComponent]:
    # CycloneDX's own "type" enum includes "file" -- Syft's file cataloger
    # emits one of these for every loose file it walks past (a dist-info
    # METADATA/RECORD/top_level.txt, a .github/workflows/*.yml, ...), none
    # of which is a third-party dependency with a license concept of its
    # own. Left unfiltered, these correctly (and unhelpfully) classify as
    # "unclassified" every time -- confirmed empirically against a real
    # Syft-generated SBOM: 128 of that run's 256 total components were
    # type=="file", zero of which ever carry a purl or licenses field.
    # Every other CycloneDX component type ("library", "application",
    # "framework", "container", "operating-system", ...) can be a real,
    # license-bearing shipped component depending on what generated the
    # SBOM, so this is deliberately an exclude-"file" rule, not an
    # allowlist of "library" alone -- narrowing to one type would silently
    # drop real components a different ecosystem's Syft/CycloneDX output
    # legitimately reports under a different type.
    if comp.get("type") == "file":
        return None
    name = comp.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    version = comp.get("version")
    version = version.strip() if isinstance(version, str) and version.strip() else None
    purl = comp.get("purl")
    purl = purl.strip() if isinstance(purl, str) and purl.strip() else None
    return SbomComponent(
        name=name.strip(),
        version=version,
        purl=purl,
        license_expression=_cdx_license_expression(comp.get("licenses")),
        license_source="declared",
        digest=_cdx_component_digest(comp),
    )


def _iter_cdx_components(components: Any) -> Iterator[Dict[str, Any]]:
    """Walks CycloneDX's `components[]` array, including nested
    `components[].components[]` sub-components (a library bundling its own
    vendored dependencies), via an explicit stack rather than recursion --
    an arbitrarily deep nesting can't blow the call stack."""
    stack = list(components) if isinstance(components, list) else []
    while stack:
        comp = stack.pop()
        if not isinstance(comp, dict):
            continue
        yield comp
        nested = comp.get("components")
        if isinstance(nested, list):
            stack.extend(nested)


def parse_cyclonedx_sbom(doc: Dict[str, Any]) -> List[SbomComponent]:
    """Parses a CycloneDX JSON document's `components[]` (including nested
    sub-components) into SbomComponent. Returns [] when `components` is
    missing/malformed -- a CycloneDX BOM describing zero components is a
    legitimate, if unusual, document, not a parse failure."""
    components = doc.get("components")
    if not isinstance(components, list):
        return []
    result: List[SbomComponent] = []
    for comp in _iter_cdx_components(components):
        parsed = _cdx_component_to_sbom_component(comp)
        if parsed:
            result.append(parsed)
    return result


# ---------------------------------------------------------------------------
# SPDX JSON 2.3
# ---------------------------------------------------------------------------


def _spdx2_license_expression(pkg: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """Prefers licenseConcluded (an auditor/tool's own determination) over
    licenseDeclared (what the package's own metadata claims), the same
    preference order SPDX itself documents; falls back to whichever raw
    value is present (for diagnostics) when both are absent/NOASSERTION/
    NONE, rather than reporting nothing at all."""
    concluded = pkg.get("licenseConcluded")
    if isinstance(concluded, str) and concluded.strip() and concluded.strip().upper() not in _UNSPECIFIED_TOKENS:
        return concluded.strip(), "concluded"
    declared = pkg.get("licenseDeclared")
    if isinstance(declared, str) and declared.strip() and declared.strip().upper() not in _UNSPECIFIED_TOKENS:
        return declared.strip(), "declared"
    fallback = concluded if isinstance(concluded, str) and concluded.strip() else declared
    return (fallback.strip() if isinstance(fallback, str) and fallback.strip() else None), "unspecified"


def _spdx2_purl(pkg: Dict[str, Any]) -> Optional[str]:
    refs = pkg.get("externalRefs")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if ref.get("referenceType") == "purl" and isinstance(ref.get("referenceLocator"), str):
            locator = ref["referenceLocator"].strip()
            if locator:
                return locator
    return None


def _spdx2_package_digest(pkg: Dict[str, Any]) -> Dict[str, str]:
    return _digest_from_hash_list(pkg.get("checksums"), "algorithm", "checksumValue")


def _spdx2_package_to_sbom_component(pkg: Dict[str, Any]) -> Optional[SbomComponent]:
    name = pkg.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    version = pkg.get("versionInfo")
    version = version.strip() if isinstance(version, str) and version.strip() else None
    license_expression, license_source = _spdx2_license_expression(pkg)
    return SbomComponent(
        name=name.strip(),
        version=version,
        purl=_spdx2_purl(pkg),
        license_expression=license_expression,
        license_source=license_source,
        digest=_spdx2_package_digest(pkg),
    )


def parse_spdx_2_sbom(doc: Dict[str, Any]) -> List[SbomComponent]:
    """Parses an SPDX 2.x JSON document's `packages[]` into SbomComponent.
    Returns [] when `packages` is missing/malformed."""
    packages = doc.get("packages")
    if not isinstance(packages, list):
        return []
    result: List[SbomComponent] = []
    for pkg in packages:
        if isinstance(pkg, dict):
            parsed = _spdx2_package_to_sbom_component(pkg)
            if parsed:
                result.append(parsed)
    return result


# ---------------------------------------------------------------------------
# SPDX JSON 3.0 (best-effort subset -- see module docstring)
# ---------------------------------------------------------------------------

_SPDX3_PACKAGE_TYPES = {"software_package", "package"}


def _spdx3_local_type(elem: Dict[str, Any]) -> Optional[str]:
    """SPDX 3.0 JSON-LD nodes carry their type as "type" (the flattened
    "software_Package" convention its own JSON-LD context defines) or the
    raw JSON-LD "@type" (occasionally a full IRI). Normalizes either to a
    lowercased local name."""
    raw = elem.get("type") or elem.get("@type")
    if not isinstance(raw, str) or not raw.strip():
        return None
    local = raw.rsplit("#", 1)[-1].rsplit("/", 1)[-1]
    return local.strip().lower()


def _spdx3_purl(elem: Dict[str, Any]) -> Optional[str]:
    idents = elem.get("externalIdentifier")
    if not isinstance(idents, list):
        return None
    for ident in idents:
        if not isinstance(ident, dict):
            continue
        ident_type = ident.get("externalIdentifierType")
        if isinstance(ident_type, str) and ident_type.strip().lower() == "purl":
            value = ident.get("identifier")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _spdx3_license_expression(elem: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """Best-effort only (see module docstring): handles the common case
    where a tool inlines the license as a plain SPDX-expression string
    directly on the package element. SPDX 3.0's full JSON-LD form can
    instead reference a separate license node elsewhere in the graph by
    @id -- resolving that cross-reference is out of scope; such a
    component's license_expression is simply None (unclassified), never
    guessed at from the unresolved reference string."""
    for key, source in (("software_concludedLicense", "concluded"), ("software_declaredLicense", "declared")):
        value = elem.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip(), source
    return None, "unspecified"


def _spdx3_element_digest(elem: Dict[str, Any]) -> Dict[str, str]:
    return _digest_from_hash_list(elem.get("verifiedUsing"), "algorithm", "hashValue")


def _spdx3_element_to_sbom_component(elem: Dict[str, Any]) -> Optional[SbomComponent]:
    name = elem.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    version = elem.get("software_packageVersion") or elem.get("packageVersion")
    version = version.strip() if isinstance(version, str) and version.strip() else None
    license_expression, license_source = _spdx3_license_expression(elem)
    return SbomComponent(
        name=name.strip(),
        version=version,
        purl=_spdx3_purl(elem),
        license_expression=license_expression,
        license_source=license_source,
        digest=_spdx3_element_digest(elem),
    )


def parse_spdx3_sbom(doc: Dict[str, Any]) -> List[SbomComponent]:
    """Parses an SPDX 3.0 JSON-LD document's `@graph[]` package-type
    elements into SbomComponent (see module docstring for this parser's
    documented scope limits). Returns [] when `@graph` is missing/
    malformed."""
    graph = doc.get("@graph")
    if not isinstance(graph, list):
        return []
    result: List[SbomComponent] = []
    for elem in graph:
        if not isinstance(elem, dict):
            continue
        if _spdx3_local_type(elem) not in _SPDX3_PACKAGE_TYPES:
            continue
        parsed = _spdx3_element_to_sbom_component(elem)
        if parsed:
            result.append(parsed)
    return result


# ---------------------------------------------------------------------------
# Format detection + top-level orchestration
# ---------------------------------------------------------------------------

_SBOM_PARSERS = {
    "cyclonedx": parse_cyclonedx_sbom,
    "spdx2": parse_spdx_2_sbom,
    "spdx3": parse_spdx3_sbom,
}


def detect_sbom_format(doc: Dict[str, Any]) -> Optional[str]:
    """Detects which of CycloneDX / SPDX 2.x / SPDX 3.0 `doc` is shaped
    as, returning "cyclonedx" / "spdx2" / "spdx3", or None if it matches
    none of them. Never raises on a malformed/partial document -- an
    absent/wrong-typed field simply fails that format's own check."""
    if not isinstance(doc, dict):
        return None

    bom_format = doc.get("bomFormat")
    if isinstance(bom_format, str) and bom_format.strip().lower() == "cyclonedx":
        return "cyclonedx"
    # Some CycloneDX exporters omit the "bomFormat" field entirely; a
    # specVersion + components/metadata pairing is CycloneDX-specific
    # enough (SPDX has no "specVersion" key at all) to detect the same way.
    if isinstance(doc.get("specVersion"), str) and ("components" in doc or "metadata" in doc):
        return "cyclonedx"

    spdx_version = doc.get("spdxVersion")
    if isinstance(spdx_version, str):
        v = spdx_version.strip().upper()
        if v.startswith("SPDX-3"):
            return "spdx3"
        if v.startswith("SPDX-"):
            return "spdx2"
    # SPDX 3.0's JSON-LD form doesn't necessarily carry a top-level
    # "spdxVersion" string the way 2.x always does -- its own "@graph"
    # array is the reliable tell instead.
    if isinstance(doc.get("@graph"), list):
        return "spdx3"

    return None


def _load_sbom_document(path: Union[str, Path]) -> Optional[Dict[str, Any]]:
    try:
        resolved = safe_resolve_path(path)
        if resolved.stat().st_size > MAX_SBOM_FILE_SIZE:
            return None
        with open(resolved, "rb") as f:
            raw = f.read()
        doc = json.loads(raw.decode("utf-8"))
    except (UnsafePathError, OSError, json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return None
    return doc if isinstance(doc, dict) else None


def parse_sbom_file(path: Union[str, Path]) -> SbomReport:
    """Detects and parses an SBOM file (CycloneDX JSON 1.4-1.6, SPDX JSON
    2.3, or a best-effort subset of SPDX JSON 3.0) into an SbomReport.
    Never raises: a missing/oversized/unreadable/malformed-JSON file, or
    one that doesn't match any recognized SBOM format, degrades to
    SbomReport(available=False, reasons=[...])."""
    doc = _load_sbom_document(path)
    if doc is None:
        return SbomReport(available=False, reasons=[f"SBOM file '{path}' could not be read/parsed as JSON"])

    fmt = detect_sbom_format(doc)
    if fmt is None:
        return SbomReport(
            available=False,
            reasons=[f"SBOM file '{path}' is not recognized CycloneDX (1.4-1.6) or SPDX (2.3/3.0) JSON"],
        )

    return SbomReport(available=True, format=fmt, components=_SBOM_PARSERS[fmt](doc), raw_document=doc)


# ---------------------------------------------------------------------------
# resolved_dependencies (INV-1/ING-1) projection
# ---------------------------------------------------------------------------


def sbom_components_to_resolved_dependencies(components: List[SbomComponent]) -> List[Dict[str, Any]]:
    """Projects every component that carries a real `pkg:` PURL into the
    same {"uri": ..., "digest": {...}} shape
    cli.parsers.lockfiles.ResolvedDependency.to_dict() produces, deduped by
    URI (first component to produce a given URI wins) -- the same
    dedup convention cli.parsers.lockfiles.detect_and_parse_dependencies
    uses. A component with no PURL (an SBOM can legitimately describe
    files/services with no package-manager identity) is simply omitted,
    never fabricated."""
    seen: Set[str] = set()
    deps: List[Dict[str, Any]] = []
    for comp in components:
        if not comp.purl or not comp.purl.startswith("pkg:") or comp.purl in seen:
            continue
        seen.add(comp.purl)
        deps.append({"uri": comp.purl, "digest": dict(comp.digest)})
    return deps


# ---------------------------------------------------------------------------
# License-policy evaluation -> SARIF-compatible findings
# ---------------------------------------------------------------------------

_CLASSIFICATION_TO_LEVEL = {"forbidden": "error", "unclassified": "warning"}


def _finding_message(comp: SbomComponent, classification: str, matched_terms: List[str]) -> str:
    label = comp.license_expression or "(no license information)"
    identity = f"{comp.name}@{comp.version}" if comp.version else comp.name
    if classification == "forbidden":
        return (
            f"{identity} declares a forbidden license ({label}); "
            f"matched forbidden term(s): {', '.join(matched_terms)}"
        )
    return f"{identity} declares an unclassified license ({label}) -- not recognized as permissive or forbidden by policy"


def build_license_findings(
    components: List[SbomComponent], policy: Optional[LicensePolicy] = None
) -> Tuple[List[SarifFinding], Dict[str, int]]:
    """Evaluates every component's license_expression against `policy`
    (default DEFAULT_LICENSE_POLICY) and returns
    (findings, {classification: count}). A "permissive" classification
    produces no finding at all -- a clean dependency isn't itself a
    differential signal, the same way a passing SARIF rule never emits a
    results[] entry for code with no problem. "forbidden" findings are
    level "error"; "unclassified" ones are level "warning" -- present in
    the report so an unreviewed/custom license is visible, but weighed
    less severely than a confirmed policy violation."""
    policy = policy or DEFAULT_LICENSE_POLICY
    findings: List[SarifFinding] = []
    tally: Dict[str, int] = {"forbidden": 0, "unclassified": 0, "permissive": 0}

    for comp in components:
        classification, matched_terms = classify_license_expression(comp.license_expression, policy)
        tally[classification] = tally.get(classification, 0) + 1
        if classification == "permissive":
            continue

        findings.append(
            SarifFinding(
                tool_name=SBOM_LICENSE_TOOL_NAME,
                rule_id=f"sbom-license/{classification}",
                level=_CLASSIFICATION_TO_LEVEL[classification],
                message=_finding_message(comp, classification, matched_terms),
                file_path=comp.purl or comp.name,
                start_line=0,
                category="license",
                tags=["license", classification],
            )
        )
    return findings, tally


def build_sbom_sarif_report(
    components: List[SbomComponent],
    policy: Optional[LicensePolicy] = None,
    report_hash: Optional[Dict[str, str]] = None,
) -> SarifSummaryReport:
    """Evaluates `components`' licenses against `policy` and packages the
    result as a SarifSummaryReport carrying one synthetic tool run
    (SBOM_LICENSE_TOOL_NAME) -- the same shape parse_sarif_file() produces
    from a real SARIF file, so a caller can merge it via
    cli.parsers.sarif.aggregate_sarif_reports() alongside any real --sarif
    input, with no special-casing needed downstream.

    `report_hash` -- schema/lucid-attestation-v1.schema.json requires
    every static_analysis.tools[] entry to carry one, documented there as
    "SHA-256 of the raw SARIF file this tool's results were parsed from".
    This tool has no such file (its findings are synthesized in-memory,
    never round-tripped through an actual SARIF document on disk) -- the
    honest equivalent a caller should pass is the SHA-256 of the --sbom
    file itself, the real raw input these findings actually were derived
    from (see cli.main._merge_sbom_into_sarif, which threads through the
    same hash predicate.artifact.sbom.sha256 also uses). None (the
    dataclass default) when the caller has no hash to offer -- never a
    fabricated one."""
    findings, tally = build_license_findings(components, policy)

    rule_groups: Dict[str, SarifRuleGroup] = {}
    for f in findings:
        group = rule_groups.setdefault(
            f.rule_id, SarifRuleGroup(rule_id=f.rule_id, count=0, category=f.category, tags=list(f.tags))
        )
        group.count += 1

    errors_count = sum(1 for f in findings if f.level == "error")
    warnings_count = sum(1 for f in findings if f.level == "warning")

    tool = SarifToolSummary(
        name=SBOM_LICENSE_TOOL_NAME,
        errors_count=errors_count,
        warnings_count=warnings_count,
        total_findings=len(findings),
        report_hash=dict(report_hash) if report_hash else None,
        rules=list(rule_groups.values()),
        extensions={"sbom_license_policy": dict(tally)},
    )

    return SarifSummaryReport(
        available=True,
        total_findings=len(findings),
        errors_count=errors_count,
        warnings_count=warnings_count,
        findings=findings,
        tools_scanned=[SBOM_LICENSE_TOOL_NAME],
        tools=[tool],
    )
