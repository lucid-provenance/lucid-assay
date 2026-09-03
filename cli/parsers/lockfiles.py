"""
Multi-ecosystem lockfile parsing: extracts pinned/resolved dependencies from
Python (uv.lock, poetry.lock, Pipfile.lock, pip-compile-generated
requirements.txt), JavaScript/TypeScript (package-lock.json, pnpm-lock.yaml,
yarn.lock -- both Classic v1 and Berry v2+), Go (go.sum), and Java (Gradle
dependency locks, a build.gradle/build.gradle.kts fallback for repos without
one, Maven pom.xml) lockfiles into normalized `pkg:` PURL identifiers with
cryptographic digests -- shaped for a SLSA v1.0 provenance predicate's
`resolvedDependencies` array
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
  - A plain, hand-written requirements.txt (unhashed version pins, or no
    pins at all) is never mistaken for a real pip-compile lockfile: only
    lines carrying at least one real `--hash=<algo>:<hex>` are treated as
    resolved, and the file as a whole is rejected (-> []) if it contains
    none at all -- see parse_pip_compile_requirements()'s own docstring.
  - pnpm-lock.yaml and yarn.lock (both generations) are parsed with a
    minimal, purpose-built line scanner each (see parse_pnpm_lock()'s and
    parse_yarn_lock()'s own docstrings for why, not a general YAML
    library) scoped exactly to the block(s) this module needs -- a
    malformed or truncated file degrades individual entries the same way
    every other parser here does, never raises.
  - A Gradle build script's dynamic version (`31.+`) or Ivy-style range
    (`[1.0,2.0)`) is never mistaken for a pinned coordinate -- see
    parse_gradle_build_file()'s own docstring, the same
    fails-closed-per-field discipline pom.xml's `${...}` placeholder
    check already applies.
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
# Python: poetry.lock
# --------------------------------------------------------------------------

def _poetry_package_digest(pkg: Dict[str, Any]) -> Dict[str, str]:
    """Picks one file's hash out of a poetry.lock [[package]] entry's own
    `files = [{file = "...", hash = "sha256:..."}, ...]` array -- one
    entry per distributed artifact (a wheel per platform, plus the
    sdist), all real sha256 hashes of genuinely different files, the
    same "digest: Dict[str, str] has no room for N hashes of one
    algorithm" situation _pip_compile_entries() already documents.
    Prefers a `.whl` file's hash over a `.tar.gz`/sdist's, mirroring
    uv.lock's own wheel-before-sdist preference (_uv_package_digest) --
    same rationale, a wheel is what actually gets installed on the
    common path. Malformed entries (a non-dict, a hash without its own
    'sha256:' prefix) are skipped individually; returns {} if no file
    entry decodes cleanly."""
    files = pkg.get("files")
    if not isinstance(files, list):
        return {}

    def _entry_digest(entry: Any) -> Optional[Tuple[bool, Dict[str, str]]]:
        if not isinstance(entry, dict):
            return None
        filename = entry.get("file")
        raw_hash = entry.get("hash")
        if not isinstance(raw_hash, str) or ":" not in raw_hash:
            return None
        algo, _, hex_value = raw_hash.partition(":")
        algo, hex_value = algo.strip(), hex_value.strip()
        if not algo or not hex_value:
            return None
        is_wheel = isinstance(filename, str) and filename.endswith(".whl")
        return is_wheel, {algo: hex_value}

    best: Optional[Tuple[bool, Dict[str, str]]] = None
    for entry in files:
        candidate = _entry_digest(entry)
        if candidate and (best is None or (candidate[0] and not best[0])):
            best = candidate
    return best[1] if best else {}


def _poetry_package_to_dependency(pkg: Dict[str, Any]) -> Optional[ResolvedDependency]:
    name = pkg.get("name")
    version = pkg.get("version")
    if not isinstance(name, str) or not name.strip():
        return None
    if not isinstance(version, str) or not version.strip():
        return None
    return ResolvedDependency(
        uri=f"pkg:pypi/{_normalize_pypi_name(name)}@{version.strip()}", digest=_poetry_package_digest(pkg)
    )


def parse_poetry_lock(path: Union[str, Path]) -> List[ResolvedDependency]:
    """Parses a poetry.lock (Python) file's [[package]] entries into
    ResolvedDependency, same TOML shape as uv.lock (a sibling Python
    lockfile format, both parsed with the stdlib tomllib) but with real
    per-file sha256 hashes under each entry's own `files` array rather
    than a single wheels[0]/sdist.hash pair. Returns [] on any missing/
    unreadable/malformed input."""
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
            dep = _poetry_package_to_dependency(pkg)
            if dep:
                deps.append(dep)
    return deps


# --------------------------------------------------------------------------
# Python: Pipfile.lock (Pipenv)
# --------------------------------------------------------------------------

def _pipfile_lock_entry_to_dependency(name: str, entry: Dict[str, Any]) -> Optional[ResolvedDependency]:
    version = entry.get("version")
    if not isinstance(version, str) or not version.strip():
        return None
    # Pipfile.lock's own version strings carry a PEP 440 operator prefix
    # ("==1.3.1", always "==" in practice -- Pipenv only ever locks to an
    # exact pin) that a purl version has no business including.
    version = version.strip().lstrip("=").strip()
    if not version:
        return None

    digest: Dict[str, str] = {}
    hashes = entry.get("hashes")
    if isinstance(hashes, list):
        for raw_hash in hashes:
            if isinstance(raw_hash, str) and ":" in raw_hash:
                algo, _, hex_value = raw_hash.partition(":")
                algo, hex_value = algo.strip(), hex_value.strip()
                if algo and hex_value:
                    digest[algo] = hex_value
                    break  # first well-formed hash wins -- see poetry's own digest picker for why "one of several real per-file hashes" is an inherent digest: Dict[str, str] limitation, not special-cased differently here

    return ResolvedDependency(uri=f"pkg:pypi/{_normalize_pypi_name(name)}@{version}", digest=digest)


def parse_pipfile_lock(path: Union[str, Path]) -> List[ResolvedDependency]:
    """Parses a Pipfile.lock (Pipenv) file's `default` and `develop`
    dependency maps into ResolvedDependency, decoding each entry's own
    `hashes` array (real sha256 hashes, one per distributed file --
    picks the first well-formed one; see _pipfile_lock_entry_to_dependency).
    Both sections are included -- Pipenv's own distinction between
    "runtime" and "dev" dependencies doesn't map onto anything this
    module's callers use resolved_dependencies for, and every other
    ecosystem parser here includes dev/test dependencies too (uv.lock's
    [[package]] array has no runtime/dev split at all to even exclude
    from). Returns [] on any missing/unreadable/malformed input, or a
    file with neither section present."""
    text = _read_text_safe(path)
    if text is None:
        return []

    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return []

    if not isinstance(doc, dict):
        return []

    deps: List[ResolvedDependency] = []
    for section in ("default", "develop"):
        entries = doc.get(section)
        if not isinstance(entries, dict):
            continue
        for name, entry in entries.items():
            if isinstance(name, str) and isinstance(entry, dict):
                dep = _pipfile_lock_entry_to_dependency(name, entry)
                if dep:
                    deps.append(dep)
    return deps


# --------------------------------------------------------------------------
# Python: pip-compile-generated requirements.txt
# --------------------------------------------------------------------------

# A top-level pinned requirement line: "name==version", optionally followed
# by a line-continuation backslash if --hash lines follow. Deliberately
# anchored to "==" (an exact pin) -- pip-compile always emits exact pins,
# and this is also what excludes a hand-written "name>=1.0" range pin from
# ever being mistaken for one.
_PIP_COMPILE_REQUIREMENT_LINE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9._!+-]*)\s*(?:\\\s*)?$"
)
# A --hash continuation line (pip's own --require-hashes format), e.g.
#     --hash=sha256:1f28b4522cdc2fb4256ac1a020c78acf9cba2c6b461ccd2c126f3aa8e8335d1
# possibly followed by a line-continuation backslash if more --hash lines
# follow for the same requirement.
_PIP_COMPILE_HASH_LINE = re.compile(r"^--hash=([A-Za-z0-9]+):([A-Za-z0-9]+)\s*(?:\\\s*)?$")


def _pip_compile_entries(lines: List[str]) -> List[ResolvedDependency]:
    """Groups a pip-compile-style requirements.txt's lines into one
    ResolvedDependency per top-level `name==version` line, folding in
    every `--hash=algo:hex` continuation line that follows it (each on
    its own line, indented, per pip's own --require-hashes output --
    never inline on the requirement line itself) until the next
    non-continuation line. A `# via ...` trace-comment line or a blank
    line ends the current requirement's hash block without starting a
    new one. Requirements with zero --hash lines are skipped entirely --
    see parse_pip_compile_requirements()'s own docstring for why.

    A real pip-compile entry commonly carries several --hash lines for
    the *same* algorithm (sha256) -- one per platform-specific wheel plus
    the sdist, all genuinely different files' hashes, not the
    same-file-multiple-algorithms case package-lock.json's SRI decoding
    handles. digest: Dict[str, str] has no room to represent "N hashes
    for the same algorithm" any more than any other parser in this module
    does, so the last --hash=sha256:... line for a given algorithm simply
    wins over earlier ones -- an arbitrary but deterministic choice, not a
    claim that the discarded hashes matter less."""
    deps: List[ResolvedDependency] = []
    name: Optional[str] = None
    version: Optional[str] = None
    digest: Dict[str, str] = {}

    def _flush() -> None:
        if name and digest:
            deps.append(ResolvedDependency(uri=f"pkg:pypi/{_normalize_pypi_name(name)}@{version}", digest=dict(digest)))

    for raw_line in lines:
        line = raw_line.strip()
        req_match = _PIP_COMPILE_REQUIREMENT_LINE.match(line)
        if req_match:
            _flush()
            name, version = req_match.groups()
            digest = {}
            continue

        hash_match = _PIP_COMPILE_HASH_LINE.match(line) if name else None
        if hash_match:
            algo, hex_value = hash_match.groups()
            digest[algo] = hex_value
            continue

        if not line.startswith("--hash="):
            # Anything else (a blank line, a "# via ..." trace comment, a
            # header comment) ends the current requirement's hash block --
            # the next --hash= line, if any, belongs to a different
            # requirement and must not be folded into this one.
            _flush()
            name = version = None
            digest = {}

    _flush()
    return deps


def parse_pip_compile_requirements(path: Union[str, Path]) -> List[ResolvedDependency]:
    """Parses a pip-compile-generated (pip-tools, `--generate-hashes`)
    requirements.txt into ResolvedDependency, one per `name==version`
    entry with at least one real `--hash=<algo>:<hex>` line folded in as
    its digest.

    Deliberately rejects a plain, hand-written requirements.txt rather
    than treat an unhashed version pin as "resolved": a requirement line
    with no --hash= lines following it is skipped individually (same
    per-entry fail-closed contract as every other parser here), and if
    the file contains *no* real --hash= lines at all, this returns []
    for the whole file -- a bare `name==1.0.0`/`name>=1.0` pin is a
    version constraint, not a cryptographically pinned dependency, and
    this module's whole point is the latter. This is also what tells a
    genuine pip-compile lockfile apart from a hand-edited requirements.txt
    that happens to share the same filename -- there's no other reliable
    signal to detect by (pip-compile's own header comment is conventional,
    not guaranteed present after manual edits).

    Returns [] on any missing/unreadable input."""
    text = _read_text_safe(path)
    if text is None:
        return []

    # _pip_compile_entries() only ever appends an entry once it has at
    # least one real digest, so an all-unhashed file naturally comes back
    # as [] here too -- no separate "did we find anything real" check
    # needed.
    return _pip_compile_entries(text.splitlines())


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
# JavaScript/TypeScript: pnpm-lock.yaml
# --------------------------------------------------------------------------

# A "packages:" block's own package-key line: 2-space indented, single
# quoted or bare key, nothing else on the line (the entry's own fields
# follow on more-indented lines below it). Real pnpm output always quotes
# these (the key contains "@", and a scoped name embeds "/" too), but the
# quotes aren't load-bearing for us either way.
_PNPM_PACKAGE_KEY_LINE = re.compile(r"^  ['\"]?([^'\"]+?)['\"]?:\s*$")
# The resolution line nested under a package key, e.g.
#     resolution: {integrity: sha512-BcYH1CVJ...==}
# Deliberately reuses the flow-mapping shape wholesale rather than a real
# YAML flow-mapping parse -- pnpm always emits `integrity` as the first
# key inside `resolution: {...}`, and this is the only field this module
# needs out of it.
_PNPM_RESOLUTION_LINE = re.compile(r"^\s+resolution:\s*\{.*?integrity:\s*([^\s,}]+)")


def _pnpm_split_key(key: str) -> Optional[Tuple[str, str]]:
    """Splits one pnpm `packages:` block key into (name, version).
    Handles both the current (lockfileVersion 9.0+) bare key shape,
    'name@version' / '@scope/name@version', and the older (pre-9,
    e.g. 6.0) registry-relative shape, '/name@version' -- pnpm's own
    lockfile spec calls the latter a "dependency path"
    (https://github.com/pnpm/spec/blob/master/lockfile/6.0.md); the
    leading '/' is stripped before applying the same split either way.
    A scoped name's own '/' is not the separator -- the version starts
    at the *second* '@' when the key begins with '@', the first
    otherwise. Any trailing peer-dependency suffix in parens (only ever
    seen directly in a *snapshots:*-style key, never confirmed inside a
    real packages: one, but stripped defensively all the same, since a
    purl version has no business carrying one) is dropped. Returns None
    if the key doesn't contain an '@' to split on at all."""
    key = key.strip()
    if key.startswith("/"):
        key = key[1:]

    at_index = key.find("@", 1) if key.startswith("@") else key.find("@")
    if at_index <= 0:
        return None

    name, version = key[:at_index], key[at_index + 1:]
    version = version.split("(", 1)[0].strip()
    return (name, version) if name and version else None


def _pnpm_package_lines_to_dependency(key: str, entry_lines: List[str]) -> Optional[ResolvedDependency]:
    split = _pnpm_split_key(key)
    if split is None:
        return None
    name, version = split

    digest: Dict[str, str] = {}
    for line in entry_lines:
        match = _PNPM_RESOLUTION_LINE.match(line)
        if match:
            digest = _decode_sri_integrity(match.group(1))
            break

    return ResolvedDependency(uri=f"{_npm_purl(name)}@{version}", digest=digest)


def parse_pnpm_lock(path: Union[str, Path]) -> List[ResolvedDependency]:
    """Parses a pnpm-lock.yaml's `packages:` block into ResolvedDependency,
    decoding each entry's `resolution.integrity` SRI string the same way
    parse_package_lock_json() does (pnpm uses the identical SRI format npm
    does). Covers both the current split `packages:`/`snapshots:` schema
    (lockfileVersion 9.0+, where `packages:` carries the immutable
    resolution/integrity metadata and `snapshots:` carries the
    peer-resolved dependency graph -- only the former has what this module
    needs) and the older, unsplit `packages:`-only schema (lockfileVersion
    6.0 and earlier) transparently, since both shapes carry the same
    `resolution: {integrity: ...}` field per entry.

    Deliberately a minimal, purpose-built line scanner rather than a real
    YAML parse: this project has no YAML dependency today (every other
    parser in this module is stdlib-only -- tomllib/json/xml.etree), and
    pulling one in just for this single, narrow, always-machine-generated
    block would cut against that. Confirmed against a real, current
    lockfileVersion 9.0 file (github.com/pnpm/logger's own pnpm-lock.yaml)
    before writing this, not assumed from memory. Scoped exactly to what's
    needed: find the top-level `packages:` block, split it into per-entry
    line groups by the 2-space-indented key line, and pull `resolution.
    integrity` out of each. A key this scanner can't split (see
    _pnpm_split_key) or an entry with no resolution/integrity line at all
    degrades to being skipped (unparseable key) or an empty digest
    (missing integrity) individually -- never raises, never drops the
    whole file. Returns [] on any missing/unreadable input, or when the
    file has no top-level `packages:` block at all."""
    text = _read_text_safe(path)
    if text is None:
        return []

    in_packages = False
    current_key: Optional[str] = None
    current_lines: List[str] = []
    deps: List[ResolvedDependency] = []

    def _flush() -> None:
        if current_key is not None:
            dep = _pnpm_package_lines_to_dependency(current_key, current_lines)
            if dep:
                deps.append(dep)

    for line in text.splitlines():
        if line.rstrip("\n") == "packages:":
            in_packages = True
            continue
        if not in_packages:
            continue
        if line and not line[0].isspace():
            # An unindented line (snapshots:, importers:, overrides:, ...,
            # or a later env-lockfile document's own top-level key) ends
            # the packages: block.
            _flush()
            current_key = None
            in_packages = False
            continue

        key_match = _PNPM_PACKAGE_KEY_LINE.match(line)
        if key_match:
            _flush()
            current_key = key_match.group(1)
            current_lines = []
        elif current_key is not None:
            current_lines.append(line)

    _flush()
    return deps


# --------------------------------------------------------------------------
# JavaScript/TypeScript: yarn.lock (Classic v1 and Berry v2+)
# --------------------------------------------------------------------------

_YARN_CLASSIC_VERSION_LINE = re.compile(r'^\s+version\s+"([^"]+)"\s*$')
# Deliberately unquoted in real Yarn Classic output (unlike npm's own SRI
# string, which is always JSON-quoted) -- see parse_yarn_lock()'s own
# docstring; the payload itself is the identical SRI shape either way.
_YARN_CLASSIC_INTEGRITY_LINE = re.compile(r"^\s+integrity\s+(\S+)\s*$")

# Yarn Berry's own block-header line -- single or comma-separated
# "name@npm:range" specifiers, quoted, e.g.
# '"@babel/code-frame@npm:^7.0.0":' -- needs no dedicated regex of its
# own: structurally it's the same "non-indented line" shape Classic's
# header is, so both generations' scanners detect one identically
# (`not line[0].isspace()`) and hand it to the same
# _yarn_first_specifier_name() either way.
_YARN_BERRY_VERSION_LINE = re.compile(r"^\s+version:\s*(\S+)\s*$")
_YARN_BERRY_CHECKSUM_LINE = re.compile(r"^\s+checksum:\s*(\S+)\s*$")


def _yarn_first_specifier_name(key_line: str) -> Optional[str]:
    """Extracts just the package name out of a yarn.lock block-header
    line's *first* specifier -- 'foo@^1.0.0, foo@^1.1.0:' and
    '\"@scope/foo@npm:^1.0.0\":' both -> the name before the range. Every
    comma-separated specifier on one block names the same package (that's
    the whole reason yarn merged them into one block), so only the first
    is needed. Reuses the same "second '@' for a scoped name, first '@'
    otherwise" rule pnpm's own key-splitting uses (_pnpm_split_key) --
    same underlying npm package-naming convention."""
    first = key_line.split(",", 1)[0].strip().rstrip(":").strip()
    if first.startswith('"') and first.endswith('"'):
        first = first[1:-1]
    if not first:
        return None
    at_index = first.find("@", 1) if first.startswith("@") else first.find("@")
    if at_index <= 0:
        return None
    return first[:at_index]


def _is_yarn_berry(text: str) -> bool:
    """Yarn Berry (v2+) lockfiles always open with a top-level
    `__metadata:` block; Classic (v1) ones never have one -- the same
    real, documented signal Yarn's own tooling uses to reject a Classic
    lockfile as unreadable by Berry and vice versa (see e.g.
    yarnpkg/berry#6042, "'__metadata' key not found in yarn.lock, must be
    a Yarn classic lockfile"). Checked as an unindented line match, not a
    bare substring search, so a dependency literally named
    "__metadata" (were that ever legal) couldn't false-positive this."""
    return any(line.rstrip("\n") == "__metadata:" for line in text.splitlines())


def _parse_yarn_classic(text: str) -> List[ResolvedDependency]:
    deps: List[ResolvedDependency] = []
    name: Optional[str] = None
    version: Optional[str] = None
    integrity: Optional[str] = None

    def _flush() -> None:
        if name and version:
            digest = _decode_sri_integrity(integrity) if integrity else {}
            deps.append(ResolvedDependency(uri=f"{_npm_purl(name)}@{version}", digest=digest))

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        if not line[0].isspace():
            _flush()
            name = _yarn_first_specifier_name(line)
            version = None
            integrity = None
            continue

        if name is None:
            continue  # a stray indented line before any real block header

        version_match = _YARN_CLASSIC_VERSION_LINE.match(line)
        if version_match:
            version = version_match.group(1)
            continue
        integrity_match = _YARN_CLASSIC_INTEGRITY_LINE.match(line)
        if integrity_match:
            integrity = integrity_match.group(1)

    _flush()
    return deps


def _parse_yarn_berry(text: str) -> List[ResolvedDependency]:
    deps: List[ResolvedDependency] = []
    name: Optional[str] = None
    version: Optional[str] = None
    checksum: Optional[str] = None

    def _flush() -> None:
        if name and version:
            deps.append(ResolvedDependency(uri=f"{_npm_purl(name)}@{version}", digest=_decode_yarn_berry_checksum(checksum)))

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        if not line[0].isspace():
            if line != "__metadata:":
                _flush()
                name = _yarn_first_specifier_name(line)
                version = None
                checksum = None
            else:
                _flush()
                name = None
            continue

        if name is None:
            continue

        version_match = _YARN_BERRY_VERSION_LINE.match(line)
        if version_match:
            version = version_match.group(1).strip('"')
            continue
        checksum_match = _YARN_BERRY_CHECKSUM_LINE.match(line)
        if checksum_match:
            checksum = checksum_match.group(1)

    _flush()
    return deps


def _decode_yarn_berry_checksum(checksum: Optional[str]) -> Dict[str, str]:
    """Decodes a Yarn Berry `checksum:` field -- '<cache-key-version>/
    <hex>', e.g. '10/6eebd12a5cd...9d6c0a' -- to {algo: hex}. The hex
    portion is consistently 128 characters in every real lockfile
    confirmed while writing this (github.com/yarnpkg/berry's own
    yarn.lock), which is exactly a raw (unencoded) SHA-512 digest's
    length -- Berry's own checksum is documented as a SHA-512 of the
    package archive, prefixed with a cache-format version for
    invalidation, not SRI or base64 like every other digest this module
    decodes. A checksum that doesn't split into exactly two '/'-separated
    parts, or whose hex portion isn't 128 hex characters, degrades to {}
    rather than guessed at -- a future Berry cache-format bump changing
    the hash algorithm would show up here as a length mismatch, not a
    silently wrong algorithm label."""
    if not checksum or "/" not in checksum:
        return {}
    _, _, hex_value = checksum.rpartition("/")
    hex_value = hex_value.strip()
    if len(hex_value) == 128 and re.fullmatch(r"[0-9a-fA-F]+", hex_value):
        return {"sha512": hex_value.lower()}
    return {}


def parse_yarn_lock(path: Union[str, Path]) -> List[ResolvedDependency]:
    """Parses a yarn.lock (Yarn Classic v1, or Yarn Berry v2+) file into
    ResolvedDependency, dispatching on which generation it is
    (_is_yarn_berry) since the two are structurally different formats
    that happen to share a filename -- Classic is a bespoke text format
    (unquoted `integrity <sri-string>`), Berry is real YAML-shaped
    (`checksum: <n>/<hex>`, no SRI at all). Both are parsed with the same
    minimal line-scanner approach pnpm-lock.yaml's parser uses, for the
    same reason (see parse_pnpm_lock()'s own docstring) -- Berry's format
    happens to be YAML, but this module has no YAML dependency to lean on
    for it either. Confirmed against real, current lockfiles for both
    generations (github.com/yarnpkg/yarn and github.com/yarnpkg/berry's
    own yarn.lock files) before writing this, not assumed from memory.
    Returns [] on any missing/unreadable input, or a file with no
    resolvable package blocks at all."""
    text = _read_text_safe(path)
    if text is None:
        return []
    return _parse_yarn_berry(text) if _is_yarn_berry(text) else _parse_yarn_classic(text)


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
# Java: Gradle build script fallback (build.gradle / build.gradle.kts)
# --------------------------------------------------------------------------

# A dependency-configuration call carrying a literal "group:artifact:version"
# GAV string, in either DSL: Groovy's `implementation 'g:a:v'` (parens
# optional) or Kotlin's `implementation("g:a:v")` (parens required, but
# this doesn't need to tell the two apart -- both use identical
# configuration-name and quoted-GAV-string shapes). Deliberately not
# anchored to end-of-line: a real declaration is often followed by a
# `{ exclude ... }` configuration block or a trailing comment, which this
# has no need to parse, only to stop before.
#
# The gap between the configuration keyword and the opening quote is
# `[\s(]*` -- one quantifier over one character class -- rather than the
# more obvious-looking `\s*\(?\s*` (whitespace, optional paren,
# whitespace): two adjacent `\s*`s straddling an optional group is
# exactly the "how many ways can N spaces split across two independent
# quantifiers" shape that makes a regex engine's backtracking blow up on
# a long non-matching run -- confirmed empirically (SonarQube flagged it,
# then a real timing test: 8+ seconds against 50K trailing spaces with
# the two-\s* version, versus this version staying linear) before fixing
# it this way rather than just taking the linter's word for it. Matches
# the identical real inputs either way -- Gradle source never has more
# than one paren here -- just without the ambiguous partitioning.
_GRADLE_BUILD_DEPENDENCY = re.compile(
    r"""^\s*(?:implementation|api|compile|testImplementation|testCompile|compileOnly|
        testCompileOnly|runtimeOnly|testRuntimeOnly|annotationProcessor|
        testAnnotationProcessor|kapt|testKapt|providedCompile|feature)
        [\s(]*['"]([^:'"]+):([^:'"]+):([^:'"]+)['"]""",
    re.VERBOSE,
)


def _is_pinned_gradle_version(version: str) -> bool:
    """A literal GAV string's version segment is only treated as
    "resolved" the same way this module treats every other ecosystem's
    pin -- excludes Gradle's own dynamic-version syntax (`31.+`, `+`) and
    Ivy-style version ranges (`[1.0,2.0)`, `(,2.0]`) exactly the way
    parse_maven_pom_dependencies() already excludes an unresolved
    `${...}` property placeholder: a range or a floating "whatever's
    newest" marker isn't a pinned coordinate, even though it's a literal
    string sitting right there in the build file."""
    version = version.strip()
    return bool(version) and not any(c in version for c in "+[](),$")


def _gradle_build_line_to_dependency(match: "re.Match[str]") -> Optional[ResolvedDependency]:
    group, artifact, version = (s.strip() for s in match.groups())
    if not group or not artifact or not _is_pinned_gradle_version(version):
        return None
    return ResolvedDependency(uri=f"pkg:maven/{group}/{artifact}@{version}")


def parse_gradle_build_file(path: Union[str, Path]) -> List[ResolvedDependency]:
    """Fallback for a Gradle project with no gradle.lockfile at all --
    the common case, since `dependencyLocking` is opt-in and most real
    Gradle projects never enable it (unlike Maven, where
    parse_maven_pom_dependencies() reads pom.xml's always-present
    declared dependencies directly, with no separate lock-file
    requirement -- this closes that same asymmetry for Gradle). Regex-
    matches literal `<configuration> 'group:artifact:version'` /
    `<configuration>(\"group:artifact:version\")` declarations across
    both Gradle DSLs (build.gradle / build.gradle.kts) -- deliberately
    does NOT attempt map-notation (`group: 'x', name: 'y', version: 'z'`),
    version-catalog references (`libs.guava`), or variable interpolation
    (`\"$group:$artifact:$version\"`); a build script is a real
    programming language (Groovy/Kotlin), and matching the common,
    literal-string-coordinate case is the realistic scope for a regex
    scanner, the same tradeoff parse_gradle_lockfile's own regex already
    makes for its simpler, fully-structured input. A dynamic-version
    coordinate (`31.+`) or an Ivy-style range (`[1.0,2.0)`) is excluded
    the same way an unresolved `${...}` Maven property is -- see
    _is_pinned_gradle_version. Digests are always {} (a build script
    carries no hash, same as gradle.lockfile itself). When a real
    gradle.lockfile also exists in the same repo, this fallback still
    runs -- harmless: both sources produce the same `pkg:maven/...` URI
    for a genuinely matching coordinate, deduplicated downstream by
    detect_and_parse_dependencies() the same way any two lockfiles
    naming the same dependency already are. Returns [] on any missing/
    unreadable input."""
    text = _read_text_safe(path)
    if text is None:
        return []

    deps: List[ResolvedDependency] = []
    for line in text.splitlines():
        if line.lstrip().startswith("//"):
            continue
        match = _GRADLE_BUILD_DEPENDENCY.match(line)
        if match:
            dep = _gradle_build_line_to_dependency(match)
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
    "poetry.lock": parse_poetry_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "requirements.txt": parse_pip_compile_requirements,
    "package-lock.json": parse_package_lock_json,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "yarn.lock": parse_yarn_lock,
    "go.sum": parse_go_sum,
    "gradle.lockfile": parse_gradle_lockfile,
    "build.gradle": parse_gradle_build_file,
    "build.gradle.kts": parse_gradle_build_file,
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
    """Auto-detects lockfiles under repo_dir (uv.lock, poetry.lock,
    Pipfile.lock, requirements.txt, package-lock.json, pnpm-lock.yaml,
    yarn.lock, go.sum, gradle.lockfile, build.gradle/build.gradle.kts,
    pom.xml -- any number/combination, at any depth outside vendored/
    build directories), parses each with its matching ecosystem parser,
    and aggregates the results into a flat
    list of ResolvedDependency dicts (see `ResolvedDependency.to_dict`),
    deduplicated by `uri` (first lockfile to produce a given URI wins --
    when both a real gradle.lockfile and a build.gradle fallback are
    present and name the same coordinate, which one's entry survives
    depends on directory-walk order; harmless, since neither carries a
    digest to lose over the other -- see parse_gradle_build_file()'s own
    docstring). A `requirements.txt` that turns out not to be real
    pip-compile output (no `--hash=` lines at all) contributes nothing
    here, same as if it didn't exist -- see
    parse_pip_compile_requirements()'s own docstring; filename-based
    auto-detection alone can't tell it apart from a hand-written one, so
    the parser itself is what fails closed. Returns [] if repo_dir
    doesn't exist/isn't a readable directory, or no known lockfiles are
    found under it -- never raises."""
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
