"""
Multi-ecosystem lockfile parsing: extracts pinned/resolved dependencies from
Python (uv.lock), JavaScript/TypeScript (package-lock.json), Go (go.sum),
and Java (Gradle dependency locks, Maven pom.xml) lockfiles into normalized
`pkg:` PURL identifiers with cryptographic digests -- shaped for a SLSA v1.0
provenance predicate's `resolvedDependencies` array
(https://slsa.dev/spec/v1.0/provenance#resolveddependencies).

Hardened against:
  - Every file path is resolved through cli.common.safe_resolve_path()
    before being opened/read, the same way every other parser in this
    package handles operator- or repo-supplied paths.
  - Missing files, unreadable files, and malformed TOML/JSON/XML/text all
    fail closed to [] (never raise) -- a corrupt or absent lockfile must
    never crash the pipeline, only omit that ecosystem's dependencies.
  - Malformed SRI integrity strings (npm), unparseable go.sum `h1:`
    hashes, and missing wheel hashes in uv.lock all degrade to an entry
    with an empty `digest` dict rather than raising or dropping the
    dependency entirely -- an unresolved digest is still a resolved
    dependency, just one the signed predicate can't cryptographically
    pin.
  - A single malformed entry (bad hash, missing version, an unresolved
    Maven property placeholder in any of groupId/artifactId/version) is
    skipped individually rather than discarding the whole file's worth of
    dependencies -- one bad record in a 2,000-line go.sum must not blank
    out the other 1,999.
  - A Maven `<dependency>`-named element that isn't inside a real
    `<dependencies>` collection (e.g. a plugin configuration parameter
    that happens to reuse the tag name, like japicmp-maven-plugin's
    `<oldVersion><dependency>` baseline-version pointer) is never
    mistaken for an actual project dependency -- see
    parse_maven_pom_dependencies()'s own docstring for the confirmed
    real-world case this guards against.
  - detect_and_parse_dependencies() walks repo_dir defensively, skipping
    vendored/build directory subtrees (node_modules, .git, vendor,
    build, dist, target, .venv) and tolerating unreadable directories, so
    a huge or symlink-heavy tree doesn't turn detection into an
    unbounded/slow/crashing walk.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple, Union

from ..common import UnsafePathError, safe_resolve_path

_SKIP_DIR_NAMES = {"node_modules", ".git", "vendor", "build", "dist", "target", ".venv"}


@dataclass
class ResolvedDependency:
    __test__ = False
    uri: str
    digest: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"uri": self.uri, "digest": dict(self.digest)}


def _read_text_safe(path: Union[str, Path]) -> Optional[str]:
    """Resolves `path` via safe_resolve_path() and reads it as UTF-8 text.
    Returns None (never raises) on an unsafe path, missing file, or any
    other read error -- every text-based parser below treats that
    identically to "no dependencies found"."""
    try:
        resolved = safe_resolve_path(path)
        return resolved.read_text(encoding="utf-8")
    except (UnsafePathError, OSError, UnicodeDecodeError):
        return None


# --------------------------------------------------------------------------
# Python: uv.lock
# --------------------------------------------------------------------------

def _normalize_pypi_name(name: str) -> str:
    """PEP 503 normalization for a PyPI purl name: lowercase, runs of
    -_. collapsed to a single '-'."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _split_hash_string(raw: Any) -> Dict[str, str]:
    """Splits an 'algo:hexvalue' hash string (a uv.lock wheel/sdist
    `hash` field) into a {algo: hex} dict. Returns {} for anything that
    isn't a string with exactly one colon separating two non-empty
    parts."""
    if not isinstance(raw, str) or raw.count(":") != 1:
        return {}
    algo, _, value = raw.partition(":")
    algo, value = algo.strip(), value.strip()
    return {algo: value} if algo and value else {}


def _uv_wheel_digest(pkg: Dict[str, Any]) -> Dict[str, str]:
    wheels = pkg.get("wheels")
    if isinstance(wheels, list) and wheels and isinstance(wheels[0], dict):
        return _split_hash_string(wheels[0].get("hash"))
    return {}


def _uv_sdist_digest(pkg: Dict[str, Any]) -> Dict[str, str]:
    sdist = pkg.get("sdist")
    return _split_hash_string(sdist.get("hash")) if isinstance(sdist, dict) else {}


def _uv_git_commit_digest(pkg: Dict[str, Any]) -> Dict[str, str]:
    """Falls back to a source git commit (the fragment of a `source.git`
    URL, e.g. "...?rev=x#<full-sha>") for a git-sourced dependency, which
    carries no wheel/sdist hash at all."""
    source = pkg.get("source")
    git_url = source.get("git") if isinstance(source, dict) else None
    if not isinstance(git_url, str) or "#" not in git_url:
        return {}
    commit = git_url.rsplit("#", 1)[-1].strip()
    return {"gitCommit": commit} if commit else {}


def _uv_package_digest(pkg: Dict[str, Any]) -> Dict[str, str]:
    """A uv.lock [[package]] entry's digest: prefers wheels[0].hash, falls
    back to sdist.hash, falls back to a source git commit -- the first
    of these three extractors to produce a non-empty digest wins."""
    for extractor in (_uv_wheel_digest, _uv_sdist_digest, _uv_git_commit_digest):
        digest = extractor(pkg)
        if digest:
            return digest
    return {}


def _uv_package_to_dependency(pkg: Dict[str, Any]) -> Optional[ResolvedDependency]:
    name = pkg.get("name")
    version = pkg.get("version")
    if not isinstance(name, str) or not name.strip():
        return None
    if not isinstance(version, str) or not version.strip():
        return None

    uri = f"pkg:pypi/{_normalize_pypi_name(name)}@{version.strip()}"
    return ResolvedDependency(uri=uri, digest=_uv_package_digest(pkg))


def parse_uv_lock(path: Union[str, Path]) -> List[ResolvedDependency]:
    """Parses a uv.lock (Python) file's [[package]] entries into
    ResolvedDependency, one per package, using wheels[0].hash (falling
    back to sdist.hash, then a source git commit) as the digest. Returns
    [] on any missing/unreadable/malformed input."""
    text = _read_text_safe(path)
    if text is None:
        return []

    try:
        doc = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []

    packages = doc.get("package") if isinstance(doc, dict) else None
    if not isinstance(packages, list):
        return []

    deps: List[ResolvedDependency] = []
    for pkg in packages:
        if isinstance(pkg, dict):
            dep = _uv_package_to_dependency(pkg)
            if dep:
                deps.append(dep)
    return deps


# --------------------------------------------------------------------------
# JavaScript/TypeScript: package-lock.json (npm v2/v3)
# --------------------------------------------------------------------------

# SRI algorithm preference when an integrity string carries more than one
# (npm commonly emits sha512 alone, but a hand-edited/older lockfile can
# carry weaker algorithms alongside or instead of it).
_SRI_STRENGTH = {"sha512": 3, "sha256": 2, "sha1": 1}


def _decode_sri_entry(entry: str) -> Optional[Tuple[str, int, str]]:
    """Decodes one space-delimited SRI entry ("algo-base64digest") into
    (algo, strength, hex). Returns None if the algorithm isn't
    recognized or the base64 payload doesn't decode cleanly."""
    algo, _, b64_digest = entry.partition("-")
    if algo not in _SRI_STRENGTH or not b64_digest:
        return None
    try:
        raw = base64.b64decode(b64_digest, validate=True)
    except (binascii.Error, ValueError):
        return None
    return algo, _SRI_STRENGTH[algo], raw.hex()


def _decode_sri_integrity(integrity: Any) -> Dict[str, str]:
    """Decodes an npm `integrity` SRI string (one or more space-separated
    `algo-base64digest` entries, e.g. "sha512-Xy...==") to {algo: hex}.
    When multiple algorithms are present the strongest one
    (sha512 > sha256 > sha1) wins. Malformed/unrecognized entries are
    skipped individually; returns {} if none decode cleanly."""
    if not isinstance(integrity, str) or not integrity.strip():
        return {}

    best: Optional[Tuple[str, int, str]] = None
    for entry in integrity.strip().split():
        decoded = _decode_sri_entry(entry)
        if decoded and (best is None or decoded[1] > best[1]):
            best = decoded

    return {best[0]: best[2]} if best else {}


def _npm_package_name(pkg_path: str) -> Optional[str]:
    """Extracts a package name from a package-lock.json v2/v3 `packages`
    key -- e.g. "node_modules/lodash" -> "lodash",
    "node_modules/@scope/pkg" -> "@scope/pkg", and a nested
    "node_modules/foo/node_modules/@scope/pkg" -> "@scope/pkg" (the
    segment(s) after the *last* "node_modules/"). Returns None for keys
    with no "node_modules/" segment at all (the root "" entry, or a
    non-npm workspace path)."""
    marker = "node_modules/"
    idx = pkg_path.rfind(marker)
    if idx == -1:
        return None
    name = pkg_path[idx + len(marker):].strip("/")
    return name or None


def _npm_purl(name: str) -> str:
    if name.startswith("@") and "/" in name:
        scope, _, rest = name.partition("/")
        return f"pkg:npm/%40{scope[1:]}/{rest}"
    return f"pkg:npm/{name}"


def _npm_entry_to_dependency(pkg_path: str, entry: Dict[str, Any]) -> Optional[ResolvedDependency]:
    if entry.get("link") is True:
        return None  # a symlinked local workspace member, not a resolved external dependency

    name = _npm_package_name(pkg_path)
    version = entry.get("version")
    if not name or not isinstance(version, str) or not version.strip():
        return None

    uri = f"{_npm_purl(name)}@{version.strip()}"
    return ResolvedDependency(uri=uri, digest=_decode_sri_integrity(entry.get("integrity")))


def parse_package_lock_json(path: Union[str, Path]) -> List[ResolvedDependency]:
    """Parses an npm v2/v3 package-lock.json's flat `packages` map into
    ResolvedDependency, decoding each entry's SRI `integrity` string to a
    hex digest. The root package (the "" key) and linked/workspace
    entries are skipped. Returns [] on any missing/unreadable/malformed
    input, or on a v1-only lockfile (no `packages` key at all)."""
    text = _read_text_safe(path)
    if text is None:
        return []

    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return []

    packages = doc.get("packages") if isinstance(doc, dict) else None
    if not isinstance(packages, dict):
        return []

    deps: List[ResolvedDependency] = []
    for pkg_path, entry in packages.items():
        if pkg_path and isinstance(entry, dict):
            dep = _npm_entry_to_dependency(pkg_path, entry)
            if dep:
                deps.append(dep)
    return deps


# --------------------------------------------------------------------------
# Go: go.sum
# --------------------------------------------------------------------------

_GO_SUM_LINE = re.compile(r"^(\S+)\s+(\S+)\s+h1:(\S+)$")


def _decode_go_h1_hash(b64_hash: str) -> Dict[str, str]:
    """Decodes a go.sum `h1:` base64 module dirhash to hex sha256 (that's
    the hash algorithm `h1` actually is). Returns {} on any decode
    failure."""
    try:
        raw = base64.b64decode(b64_hash, validate=True)
    except (binascii.Error, ValueError):
        return {}
    return {"sha256": raw.hex()}


def _go_sum_line_to_dependency(line: str) -> Optional[ResolvedDependency]:
    match = _GO_SUM_LINE.match(line)
    if not match:
        return None

    module, version, b64_hash = match.groups()
    if version.endswith("/go.mod"):
        # This line hashes only the go.mod file, not the module's actual
        # content -- go.sum carries a paired entry like this for every
        # real module line; we want the content hash, not this one.
        return None

    return ResolvedDependency(uri=f"pkg:golang/{module}@{version}", digest=_decode_go_h1_hash(b64_hash))


def parse_go_sum(path: Union[str, Path]) -> List[ResolvedDependency]:
    """Parses a go.sum file's `<module> <version> h1:<base64>` lines into
    ResolvedDependency, decoding the h1: dirhash to hex sha256 and
    skipping the paired `<version>/go.mod` lines (they hash just the
    go.mod file, not the module's content). Returns [] on any missing/
    unreadable input."""
    text = _read_text_safe(path)
    if text is None:
        return []

    deps: List[ResolvedDependency] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        dep = _go_sum_line_to_dependency(line)
        if dep:
            deps.append(dep)
    return deps


# --------------------------------------------------------------------------
# Java: Gradle dependency locks
# --------------------------------------------------------------------------

_GRADLE_LOCK_LINE = re.compile(r"^([^:#\s]+):([^:#\s]+):([^=\s]+)=\S*$")


def _gradle_line_to_dependency(line: str) -> Optional[ResolvedDependency]:
    if not line or line.startswith("#") or line.startswith("empty="):
        return None
    match = _GRADLE_LOCK_LINE.match(line)
    if not match:
        return None
    group, artifact, version = match.groups()
    return ResolvedDependency(uri=f"pkg:maven/{group}/{artifact}@{version}")


def parse_gradle_lockfile(path: Union[str, Path]) -> List[ResolvedDependency]:
    """Parses a Gradle dependency-lock file (`group:artifact:version=
    <configurations>` lines, per Gradle's own gradle.lockfile format)
    into ResolvedDependency. Gradle's lock format doesn't carry a
    digest, so every entry's `digest` is {}. Comment lines (`#...`) and
    the `empty=` sentinel line (an configuration with no locked
    dependencies) are skipped. Returns [] on any missing/unreadable
    input."""
    text = _read_text_safe(path)
    if text is None:
        return []

    deps: List[ResolvedDependency] = []
    for raw_line in text.splitlines():
        dep = _gradle_line_to_dependency(raw_line.strip())
        if dep:
            deps.append(dep)
    return deps


# --------------------------------------------------------------------------
# Java: Maven (pom.xml / dependency-tree XML export)
# --------------------------------------------------------------------------

def _local_name(tag: str) -> str:
    """Strips a `{namespace}` prefix off an ElementTree tag, so pom.xml's
    default `http://maven.apache.org/POM/4.0.0` namespace doesn't have
    to be threaded through every lookup below."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _child_text(elem: ET.Element, name: str) -> Optional[str]:
    for child in elem:
        if _local_name(child.tag) == name and child.text and child.text.strip():
            return child.text.strip()
    return None


def _dependency_element_to_dependency(elem: ET.Element) -> Optional[ResolvedDependency]:
    group_id = _child_text(elem, "groupId")
    artifact_id = _child_text(elem, "artifactId")
    version = _child_text(elem, "version")
    if not group_id or not artifact_id or not version:
        return None
    if "${" in group_id or "${" in artifact_id or "${" in version:
        return None  # an unresolved property placeholder, not a literal resolved coordinate
    return ResolvedDependency(uri=f"pkg:maven/{group_id}/{artifact_id}@{version}")


def parse_maven_pom_dependencies(path: Union[str, Path]) -> List[ResolvedDependency]:
    """Parses `<dependency>` elements (groupId/artifactId/version, each
    with a literal resolved coordinate -- not a `${...}` property
    placeholder or range in any of the three fields) out of a pom.xml or a
    Maven dependency-tree-style XML export, namespace-agnostically.
    Maven's own file formats don't carry a digest, so every entry's
    `digest` is {}. Returns [] on any missing/unreadable/malformed-XML
    input.

    Only `<dependency>` elements whose immediate parent is a
    `<dependencies>` collection are treated as real dependencies --
    covers `<project><dependencies>`, `<dependencyManagement>
    <dependencies>`, `<profile><dependencies>`, and plugin-level
    `<plugin><dependencies>`, every real Maven dependency-declaration
    shape. This deliberately excludes `<dependency>`-named elements that
    appear elsewhere in a plugin's own `<configuration>` block for an
    unrelated purpose -- e.g. japicmp-maven-plugin's
    `<oldVersion><dependency>`, a comparison-baseline coordinate pointer,
    not a project dependency -- which an earlier, unscoped
    `tree.getroot().iter()` walk mistook for one, landing a synthesized-
    looking placeholder coordinate (`${project.groupId}/${project.
    artifactId}`) straight into a signed predicate's
    `resolved_dependencies`. ElementTree has no parent pointers, so one is
    built explicitly rather than reached for via an lxml-only API.
    """
    try:
        resolved = safe_resolve_path(path)
        tree = ET.parse(resolved)
    except (UnsafePathError, OSError, ET.ParseError):
        return []

    root = tree.getroot()
    parent_of: Dict[ET.Element, ET.Element] = {child: parent for parent in root.iter() for child in parent}

    deps: List[ResolvedDependency] = []
    for elem in root.iter():
        if _local_name(elem.tag) != "dependency":
            continue
        parent = parent_of.get(elem)
        if parent is None or _local_name(parent.tag) != "dependencies":
            continue
        dep = _dependency_element_to_dependency(elem)
        if dep:
            deps.append(dep)
    return deps


# --------------------------------------------------------------------------
# Orchestrator: auto-detection across ecosystems
# --------------------------------------------------------------------------

_LOCKFILE_PARSERS: Dict[str, Callable[[Union[str, Path]], List[ResolvedDependency]]] = {
    "uv.lock": parse_uv_lock,
    "package-lock.json": parse_package_lock_json,
    "go.sum": parse_go_sum,
    "gradle.lockfile": parse_gradle_lockfile,
    "pom.xml": parse_maven_pom_dependencies,
}


def _iter_lockfiles(repo_dir: Path) -> Iterator[Tuple[str, Path]]:
    """Walks repo_dir depth-first, yielding (filename, path) for every
    file whose name matches one of _LOCKFILE_PARSERS' keys, skipping
    vendored/build directory subtrees (_SKIP_DIR_NAMES) so detection
    can't turn into an unbounded walk over node_modules/.git/etc, and
    tolerating a directory that can't be listed (permissions, a broken
    symlink) rather than raising."""
    stack = [repo_dir]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name not in _SKIP_DIR_NAMES:
                    stack.append(entry)
            elif entry.name in _LOCKFILE_PARSERS:
                yield entry.name, entry


def detect_and_parse_dependencies(repo_dir: Union[str, Path]) -> List[Dict[str, Any]]:
    """Auto-detects lockfiles under repo_dir (uv.lock, package-lock.json,
    go.sum, gradle.lockfile, pom.xml -- any number/combination, at any
    depth outside vendored/build directories), parses each with its
    matching ecosystem parser, and aggregates the results into a flat
    list of ResolvedDependency dicts (see `ResolvedDependency.to_dict`),
    deduplicated by `uri` (first lockfile to produce a given URI wins).
    Returns [] if repo_dir doesn't exist/isn't a readable directory, or
    no known lockfiles are found under it -- never raises."""
    try:
        resolved_dir = safe_resolve_path(repo_dir)
    except UnsafePathError:
        return []

    if not resolved_dir.is_dir():
        return []

    seen_uris: Set[str] = set()
    deps: List[Dict[str, Any]] = []
    for filename, file_path in _iter_lockfiles(resolved_dir):
        parser = _LOCKFILE_PARSERS[filename]
        for dep in parser(file_path):
            if dep.uri not in seen_uris:
                seen_uris.add(dep.uri)
                deps.append(dep.to_dict())
    return deps
