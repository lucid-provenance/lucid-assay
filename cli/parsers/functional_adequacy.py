"""
Functional test adequacy evaluation: end-to-end/live-testing coverage
assessed against a repo-declared contract of critical user journeys
(CUJs), rather than scraped or guessed from raw terminal logs.

Ground-truth only (see CLAUDE.md's Supply Chain Integrity & Attestation
invariants): adequacy is a checked contract -- Declared Operational
Surface (`.lucid/functional-verification.json`'s `declared_journeys`,
the denominator) vs. Executed Scenarios (a real, structured test-report
file this pipeline actually parses, the numerator) -- the same
"evaluated contract, not a guess" posture cli.parsers.s2c2f's UPD-1
control already established for a different signal. This module never
reads raw stdout/stderr CI logs.

Journey tagging is one convention across every supported framework: a
`@cuj:<journey-id>` token (journey-id: `[A-Za-z0-9_-]+`) embedded in a
test's own identifying text -- Playwright's full spec title (suite path
+ spec title) or a JUnit `<testcase>`'s classname/name/`<properties>`
values. `generic_json` (this project's own report shape, since there's
no third-party convention to piggyback on) instead carries an explicit
`journeys` array per test, though `@cuj:` tags in its `name` field are
still honored for consistency.

A declared journey counts as covered only when at least one associated
test passed AND none associated with it failed -- a real failure
anywhere on a declared journey is never masked by a coincidental pass
elsewhere in the same run.

Hardened against:
  - Missing/unreadable/malformed `--functional-report` input (fails
    closed to available=False, never a crash or a silent full-credit
    pass)
  - An unsupported/misspelled `framework` value in
    .lucid/functional-verification.json (fails closed with an explicit
    reason_code, never silently falls back to a different parser)
  - Malformed/empty .lucid/functional-verification.json, or one with an
    empty/absent declared_journeys list (never raises -- same
    "unreadable config -> None" contract as
    cli.parsers.s2c2f._load_manual_updates_process_ref; reported as
    adequacy.status == "not_configured", not a failure)
  - An unrecognized per-test status string in a generic_json report
    (treated as failed, never silently dropped or credited as a pass)
  - An invalid v2 `journeys` contract (bad/duplicate id, missing or
    unknown `tier`, wrong types) -- reported as an explicit, amber
    `config_invalid` result, never silently dropped from the denominator
    or defaulted to a tier (a typo must not shrink what is required)
  - A missing post-deploy report file at the `cd` tier -- reported as
    `execution_aborted` (met=false), never as a silent pass, and never
    allowed to vanish: the caller submits the result so an operational
    failure is visible rather than indistinguishable from "not run yet"

Tiers (contract v2): a journey declares where it must be proven -- `ci`
(before the artifact is attested), `cd` (after deployment, against a real
environment), or `both`. `evaluate_functional_adequacy(..., tier=...)`
scores only the journeys responsible at that tier (`ci` = ci + both,
`cd` = cd + both) and lists the rest as `deferred`, so a 100% at one tier
can never hide work still owed at the other. The legacy flat
`declared_journeys` list reads as all-`ci`, and a legacy contract
evaluated at `ci` produces byte-identical output to before tiers existed
(the new `tier`/`deferred`/`journeys` fields are emitted only for a v2
contract or a non-default tier) -- existing pipelines and stored
attestations are unaffected.
"""
from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

FRAMEWORK_PLAYWRIGHT = "playwright"
FRAMEWORK_PYTEST = "pytest"
FRAMEWORK_GENERIC_JSON = "generic_json"

_CONFIG_PATH = ".lucid/functional-verification.json"
_CUJ_TAG_RE = re.compile(r"@cuj:([A-Za-z0-9_-]+)")
_DEFAULT_MIN_ADEQUACY_PCT = 100.0

METRIC_TYPE_CUJ_COVERAGE = "cuj_coverage"

ADEQUACY_STATUS_EVALUATED = "evaluated"
ADEQUACY_STATUS_NOT_CONFIGURED = "not_configured"
ADEQUACY_STATUS_UNAVAILABLE = "unavailable"

REASON_CODE_NOT_CONFIGURED = "not_configured"
REASON_CODE_REPORT_MISSING = "report_missing"
REASON_CODE_REPORT_MALFORMED = "report_malformed"
REASON_CODE_UNSUPPORTED_FRAMEWORK = "unsupported_framework"
REASON_CODE_NO_TESTS_EXECUTED = "no_tests_executed"
REASON_CODE_TEST_FAILURES = "test_failures"
REASON_CODE_PARTIAL_ADEQUACY = "partial_adequacy"
REASON_CODE_CONFIG_INVALID = "config_invalid"
REASON_CODE_EXECUTION_ABORTED = "execution_aborted"

TIER_CI = "ci"
TIER_CD = "cd"
TIER_BOTH = "both"
# The tiers a run can be evaluated *at* (`both` is a declaration, not a stage).
EVALUATION_TIERS = (TIER_CI, TIER_CD)
DECLARED_TIERS = (TIER_CI, TIER_CD, TIER_BOTH)

JOURNEY_STATUS_COVERED = "covered"
JOURNEY_STATUS_MISSING = "missing"
JOURNEY_STATUS_DEFERRED = "deferred"

_JOURNEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
# Display-only free text authored in the repo; capped so a hostile or
# careless contract can't bloat the signed predicate or a UI built on it.
_JOURNEY_NAME_MAX_LEN = 120
_JOURNEY_DESCRIPTION_MAX_LEN = 500


@dataclass
class JourneyDeclaration:
    """One declared Critical User Journey. `name`/`description` are
    display-only metadata -- never scored, never used for matching."""
    id: str
    tier: str
    name: Optional[str] = None
    description: Optional[str] = None


@dataclass
class FunctionalVerificationConfig:
    """The declared contract read from .lucid/functional-verification.json.
    `framework` is carried through verbatim (even if not one this module
    recognizes) so evaluate_functional_adequacy() can report an honest
    "unsupported framework" outcome rather than the loader silently
    normalizing/guessing at it. `tiered` is True only when the contract
    used the v2 `journeys` object form -- a legacy flat `declared_journeys`
    list reads as all-`ci` journeys with `tiered=False`."""
    framework: str
    min_adequacy_pct: float
    journeys: List[JourneyDeclaration]
    tiered: bool = False

    @property
    def declared_journeys(self) -> List[str]:
        """Every declared journey id, all tiers (the legacy flat view)."""
        return [j.id for j in self.journeys]


# Per-test results carried in the signed predicate (`functional_verification.tests`),
# so a consumer can render *which* tests ran and why one failed without the raw
# report. Bounded on every axis: the predicate is signed and stored, so a huge
# suite or a huge failure message must not balloon it. `metrics` always carries
# the true totals, and `tests_truncated` says when the list is a subset.
MAX_REPORTED_TESTS = 1000
_TEST_NAME_MAX_LEN = 300
_TEST_CLASSNAME_MAX_LEN = 200
_TEST_MESSAGE_MAX_LEN = 500
_TEST_TRUNCATION_MARK = "..."
# C0 controls (bar tab), DEL, and C1 controls: never useful in a test name or
# message and a nuisance for anything that renders it (or a terminal).
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_TEST_STATUS_ORDER = {"failed": 0, "skipped": 1, "passed": 2}


def _clean_test_text(value: Any, max_len: int) -> Optional[str]:
    """A short, printable, single-line rendering of a test name/message, or
    None for anything that isn't non-empty text. Newlines and other control
    characters become spaces (a multi-line assertion message stays readable
    on one line), and an over-long value is cut and marked -- never silently
    dropped, so a reader can tell it was shortened.

    Only ever fed an *attribute* (a failure's own `message`), never element
    text: the text body of a JUnit <failure> is the full traceback, and
    captured stdout/stderr live in <system-out>/<system-err>, either of which
    can carry secrets from the run's environment."""
    if not isinstance(value, str):
        return None
    text = " ".join(_CONTROL_CHARS_RE.sub(" ", value).split())
    if not text:
        return None
    if len(text) > max_len:
        text = text[: max_len - len(_TEST_TRUNCATION_MARK)].rstrip() + _TEST_TRUNCATION_MARK
    return text


def _clean_duration(value: Any) -> Optional[float]:
    """Seconds as a finite, non-negative float rounded to milliseconds, or None."""
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if seconds != seconds or seconds in (float("inf"), float("-inf")) or seconds < 0:
        return None
    return round(seconds, 3)


@dataclass
class _NormalizedCase:
    status: str  # "passed" | "failed" | "skipped"
    journeys: Tuple[str, ...]
    # Display-only fields for the per-test list. Optional so a parser that can't
    # supply one (or a hand-built case in a test) keeps working unchanged.
    name: str = ""
    classname: Optional[str] = None
    duration_s: Optional[float] = None
    message: Optional[str] = None


def _test_rows(cases: List[_NormalizedCase]) -> Tuple[List[Dict[str, Any]], bool]:
    """The bounded per-test list for the predicate, and whether it is a subset.
    Failed tests come first, then skipped, then passed (report order within
    each), so a cap can only ever drop passing tests, never the failures a
    reader most needs to see."""
    ordered = sorted(cases, key=lambda c: _TEST_STATUS_ORDER.get(c.status, 0))  # stable
    rows: List[Dict[str, Any]] = []
    for case in ordered[:MAX_REPORTED_TESTS]:
        row: Dict[str, Any] = {
            "name": _clean_test_text(case.name, _TEST_NAME_MAX_LEN) or "(unnamed test)",
            "status": case.status,
        }
        classname = _clean_test_text(case.classname, _TEST_CLASSNAME_MAX_LEN)
        if classname:
            row["classname"] = classname
        duration = _clean_duration(case.duration_s)
        if duration is not None:
            row["duration_s"] = duration
        message = _clean_test_text(case.message, _TEST_MESSAGE_MAX_LEN)
        if message:
            row["message"] = message
        row["journeys"] = list(case.journeys)
        rows.append(row)
    return rows, len(cases) > MAX_REPORTED_TESTS


@dataclass
class FunctionalVerificationReport:
    __test__ = False
    available: bool
    met: bool
    framework: Optional[str]
    target_env: Optional[str]
    total: int
    passed: int
    failed: int
    skipped: int
    adequacy_status: str
    score_pct: float
    reason: str
    reason_code: Optional[str] = None
    declared: List[str] = field(default_factory=list)
    covered: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    report_uri: Optional[str] = None
    # Set together, and only for a v2 contract or a non-default tier -- None
    # keeps a legacy contract's output byte-identical to pre-tier releases.
    tier: Optional[str] = None
    deferred: Optional[List[str]] = None
    journeys: Optional[List[Dict[str, Any]]] = None
    # Per-test rows (see _test_rows). None -- and so absent from the output --
    # unless the tier fields are also emitted, keeping a legacy flat-contract
    # attestation byte-identical to earlier releases.
    tests: Optional[List[Dict[str, Any]]] = None
    tests_truncated: bool = False

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "available": self.available,
            "met": self.met,
            "framework": self.framework,
            "target_env": self.target_env,
            "metrics": {
                "total": self.total,
                "passed": self.passed,
                "failed": self.failed,
                "skipped": self.skipped,
            },
            "adequacy": {
                "status": self.adequacy_status,
                "metric_type": METRIC_TYPE_CUJ_COVERAGE,
                "score_pct": self.score_pct,
                "declared": self.declared,
                "covered": self.covered,
                "missing": self.missing,
            },
            "report_uri": self.report_uri,
            "reason": self.reason,
            "reason_code": self.reason_code,
        }
        if self.journeys is not None:
            out["adequacy"]["tier"] = self.tier
            out["adequacy"]["deferred"] = list(self.deferred or [])
            out["adequacy"]["journeys"] = self.journeys
        if self.tests is not None:
            out["tests"] = self.tests
            out["tests_truncated"] = self.tests_truncated
        return out


def _optional_text(value: Any, max_len: int) -> Optional[str]:
    """Display-only free text from the contract: a stripped, length-capped
    string, or None when absent/blank/not a string. Never an error -- this
    metadata is never scored, so a bad value must not invalidate a contract
    whose scoring fields are fine."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped[:max_len] if stripped else None


def _parse_journey_objects(raw: Any) -> Tuple[Optional[List[JourneyDeclaration]], Optional[str]]:
    """Parses the v2 `journeys` array. Returns (journeys, None) on success,
    (None, None) for an explicitly empty array (nothing declared -- the same
    "not configured" the legacy empty list already means), or
    (None, <specific reason>) for an invalid declaration. Invalid is never
    silently repaired or dropped: skipping an entry would shrink the
    denominator, and defaulting a missing/typo'd `tier` would quietly move a
    journey to a tier its author never chose."""
    if not isinstance(raw, list):
        return None, "`journeys` must be a JSON array of journey objects"
    if not raw:
        return None, None
    journeys: List[JourneyDeclaration] = []
    seen: set = set()
    for index, item in enumerate(raw):
        where = f"journeys[{index}]"
        if not isinstance(item, dict):
            return None, f"{where} must be an object with an id and a tier"
        raw_id = item.get("id")
        journey_id = raw_id.strip() if isinstance(raw_id, str) else ""
        if not _JOURNEY_ID_RE.match(journey_id):
            return None, f"{where}.id must be a non-empty string of letters, digits, '_' or '-'"
        if journey_id in seen:
            return None, f"{where}.id {journey_id!r} is declared more than once"
        seen.add(journey_id)
        tier = item.get("tier")
        if tier not in DECLARED_TIERS:
            return None, f"{where}.tier must be one of {list(DECLARED_TIERS)}, got {tier!r}"
        journeys.append(
            JourneyDeclaration(
                id=journey_id,
                tier=tier,
                name=_optional_text(item.get("name"), _JOURNEY_NAME_MAX_LEN),
                description=_optional_text(item.get("description"), _JOURNEY_DESCRIPTION_MAX_LEN),
            )
        )
    return journeys, None


def _load_contract(repo_dir: str) -> Tuple[Optional[FunctionalVerificationConfig], Optional[str]]:
    """Reads .lucid/functional-verification.json. Returns (config, None) for
    a usable contract, (None, None) when genuinely unconfigured (missing
    file, unreadable, malformed JSON, not an object, or nothing declared --
    reported as adequacy.status == "not_configured"), or (None, reason) when
    the v2 `journeys` form is present but invalid (reported as
    `config_invalid`). When both `journeys` and the legacy `declared_journeys`
    are present, `journeys` wins. Never raises."""
    try:
        text = (Path(repo_dir) / _CONFIG_PATH).read_text(encoding="utf-8")
    except OSError:
        return None, None
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return None, None
    if not isinstance(doc, dict):
        return None, None

    if "journeys" in doc:
        journeys, invalid_reason = _parse_journey_objects(doc["journeys"])
        if invalid_reason is not None:
            return None, invalid_reason
        if not journeys:
            return None, None
        tiered = True
    else:
        raw_journeys = doc.get("declared_journeys")
        if not isinstance(raw_journeys, list):
            return None, None
        ids = [j.strip() for j in raw_journeys if isinstance(j, str) and j.strip()]
        if not ids:
            return None, None
        journeys = [JourneyDeclaration(id=journey_id, tier=TIER_CI) for journey_id in ids]
        tiered = False

    framework_raw = doc.get("framework")
    framework = framework_raw.strip() if isinstance(framework_raw, str) and framework_raw.strip() else ""

    min_adequacy_pct_raw = doc.get("min_adequacy_pct", _DEFAULT_MIN_ADEQUACY_PCT)
    if isinstance(min_adequacy_pct_raw, bool) or not isinstance(min_adequacy_pct_raw, (int, float)):
        min_adequacy_pct = _DEFAULT_MIN_ADEQUACY_PCT
    else:
        min_adequacy_pct = float(min_adequacy_pct_raw)

    return (
        FunctionalVerificationConfig(
            framework=framework,
            min_adequacy_pct=min_adequacy_pct,
            journeys=journeys,
            tiered=tiered,
        ),
        None,
    )


def load_functional_verification_config(repo_dir: str) -> Optional[FunctionalVerificationConfig]:
    """Returns the declared contract, or None when unconfigured *or*
    invalid -- the caller that needs to tell those apart (and report
    `config_invalid`) uses _load_contract() directly. Never raises."""
    return _load_contract(repo_dir)[0]


def _extract_cuj_tags(*texts: str) -> Tuple[str, ...]:
    found: set = set()
    for text in texts:
        if text:
            found.update(_CUJ_TAG_RE.findall(text))
    return tuple(sorted(found))


# Matches one *whole* tag-array entry, tolerant of Playwright's own
# leading "@" convention (`test.tags` / `{ tag: [...] }`, e.g. "@cuj:auth-
# flow") and a bare, unprefixed "cuj:auth-flow". Deliberately anchored
# (^...$), unlike _CUJ_TAG_RE above -- a tag-array entry is one discrete
# token, not free-text prose to scan for an embedded marker.
_TAG_ENTRY_CUJ_RE = re.compile(r"^@?cuj:([A-Za-z0-9_-]+)$")
# A tag entry with no "cuj:" marker at all is still accepted directly as
# a bare journey id (e.g. tag: ['auth-flow'] or tag: ['@auth-flow']) --
# Playwright's native tag feature doesn't mandate any particular
# vocabulary, so a repo may simply tag a test with the journey id itself.
_BARE_TAG_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _journey_from_tag_entry(tag: Any) -> Optional[str]:
    """Normalizes one native Playwright tag-array entry to a journey id,
    or None when it doesn't look like one at all (an unrelated tag, e.g.
    "@smoke", is still accepted per the bare-id fallback above -- callers
    only ever intersect the result against config.declared_journeys, so
    an unrelated tag can only ever coincidentally match a real declared
    journey id, never fabricate one)."""
    if not isinstance(tag, str):
        return None
    stripped = tag.strip()
    if not stripped:
        return None
    m = _TAG_ENTRY_CUJ_RE.match(stripped)
    if m:
        return m.group(1)
    bare = stripped[1:] if stripped.startswith("@") else stripped
    return bare if _BARE_TAG_RE.match(bare) else None


def _journeys_from_tag_array(tags: Any) -> set:
    if not isinstance(tags, list):
        return set()
    return {j for j in (_journey_from_tag_entry(t) for t in tags) if j is not None}


# ---------------------------------------------------------------------------
# Playwright JSON reporter ingestion
# ---------------------------------------------------------------------------

_PLAYWRIGHT_PASS_STATUSES = {"passed"}
_PLAYWRIGHT_SKIP_STATUSES = {"skipped"}
# Everything else (failed, timedOut, interrupted, or an unrecognized/
# missing status) folds into "failed" -- fail closed, never a silent pass.


def _playwright_final_status(results: List[Dict[str, Any]]) -> str:
    """A Playwright spec can carry multiple retry attempts under
    results[]; the *last* attempt is the one that determines the spec's
    real outcome (same "final attempt wins" convention
    cli.parsers.junit's flaky-retry handling already uses)."""
    if not results:
        return "skipped"
    final_status = results[-1].get("status", "")
    if final_status in _PLAYWRIGHT_PASS_STATUSES:
        return "passed"
    if final_status in _PLAYWRIGHT_SKIP_STATUSES:
        return "skipped"
    return "failed"


def _walk_playwright_suite(suite: Dict[str, Any], title_prefix: str, out: List[_NormalizedCase]) -> None:
    if not isinstance(suite, dict):
        return
    title = f"{title_prefix} {suite.get('title', '')}".strip()

    for spec in suite.get("specs", []) or []:
        if not isinstance(spec, dict):
            continue
        spec_title = f"{title} {spec.get('title', '')}".strip()
        # Two independent sources, unioned: the title-embedded @cuj: tag
        # convention (free-text scan), and Playwright's own native
        # tag/tags array -- confirmed against Playwright's JSON reporter
        # shape, which can carry `tags` on the spec object, the test
        # object (per-project), or both. A spec-level tag applies to
        # every test under it; a test-level tag is additionally unioned
        # in per-test, since projects can in principle carry different
        # tags for the same spec.
        spec_journeys = set(_extract_cuj_tags(spec_title)) | _journeys_from_tag_array(spec.get("tags"))
        for test in spec.get("tests", []) or []:
            if not isinstance(test, dict):
                continue
            test_journeys = spec_journeys | _journeys_from_tag_array(test.get("tags"))
            status = _playwright_final_status(test.get("results", []) or [])
            out.append(_NormalizedCase(status=status, journeys=tuple(sorted(test_journeys)), name=spec_title))

    for nested_suite in suite.get("suites", []) or []:
        _walk_playwright_suite(nested_suite, title, out)


def _parse_playwright_report(path: str) -> List[_NormalizedCase]:
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict):
        raise ValueError("playwright report root is not a JSON object")

    cases: List[_NormalizedCase] = []
    for suite in doc.get("suites", []) or []:
        _walk_playwright_suite(suite, "", cases)
    return cases


# ---------------------------------------------------------------------------
# JUnit XML (pytest) ingestion, tagged via classname/name or <properties>
# ---------------------------------------------------------------------------


def _junit_case_status(elem: ET.Element) -> str:
    if elem.find("failure") is not None or elem.find("error") is not None:
        return "failed"
    if elem.find("skipped") is not None:
        return "skipped"
    return "passed"


def _junit_case_journeys(elem: ET.Element) -> Tuple[str, ...]:
    haystack_parts = [elem.get("classname", ""), elem.get("name", "")]
    for prop in elem.findall("./properties/property"):
        haystack_parts.append(prop.get("name", "") or "")
        haystack_parts.append(prop.get("value", "") or "")
    return _extract_cuj_tags(*haystack_parts)


def _junit_case_message(elem: ET.Element) -> Optional[str]:
    """The failure/error/skip reason: the outcome element's own `message`
    attribute (or `type`), never its text body -- see _clean_test_text."""
    for tag in ("failure", "error", "skipped"):
        child = elem.find(tag)
        if child is not None:
            return child.get("message") or child.get("type")
    return None


def _parse_junit_functional_report(path: str) -> List[_NormalizedCase]:
    cases: List[_NormalizedCase] = []
    context = ET.iterparse(path, events=("end",))
    for _, elem in context:
        if elem.tag != "testcase":
            continue
        cases.append(
            _NormalizedCase(
                status=_junit_case_status(elem),
                journeys=_junit_case_journeys(elem),
                name=elem.get("name", ""),
                classname=elem.get("classname"),
                duration_s=_clean_duration(elem.get("time")),
                message=_junit_case_message(elem),
            )
        )
        elem.clear()  # safe: already read; bounds memory the same way cli.parsers.junit does
    return cases


# ---------------------------------------------------------------------------
# generic_json ingestion (this project's own minimal report shape):
#   {"tests": [{"name": "...", "status": "passed"|"failed"|"skipped", "journeys": ["auth-flow"]}]}
# ---------------------------------------------------------------------------

_GENERIC_JSON_PASS_STATUSES = {"passed", "pass"}
_GENERIC_JSON_SKIP_STATUSES = {"skipped", "skip"}


def _parse_generic_json_report(path: str) -> List[_NormalizedCase]:
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict):
        raise ValueError("generic_json report root is not a JSON object")
    tests = doc.get("tests")
    if not isinstance(tests, list):
        raise ValueError("generic_json report is missing a 'tests' array")

    cases: List[_NormalizedCase] = []
    for test in tests:
        if not isinstance(test, dict):
            continue
        status_raw = str(test.get("status", "")).strip().lower()
        if status_raw in _GENERIC_JSON_PASS_STATUSES:
            status = "passed"
        elif status_raw in _GENERIC_JSON_SKIP_STATUSES:
            status = "skipped"
        else:
            # Covers "failed"/"error"/"errored"/"timedOut" and any
            # unrecognized value -- fail closed, never silently a pass.
            status = "failed"

        # Normalized through the same tag-entry rules as Playwright's native
        # tags array above -- a "@cuj:auth-flow" or "@auth-flow" entry here
        # normalizes to "auth-flow" too, not just a bare "auth-flow" string.
        explicit_journeys = _journeys_from_tag_array(test.get("journeys"))
        tagged_journeys = set(_extract_cuj_tags(str(test.get("name", ""))))
        journeys = tuple(sorted(explicit_journeys | tagged_journeys))

        cases.append(
            _NormalizedCase(
                status=status,
                journeys=journeys,
                name=str(test.get("name", "")),
                message=test.get("message") if isinstance(test.get("message"), str) else None,
            )
        )
    return cases


_PARSERS = {
    FRAMEWORK_PLAYWRIGHT: _parse_playwright_report,
    FRAMEWORK_PYTEST: _parse_junit_functional_report,
    FRAMEWORK_GENERIC_JSON: _parse_generic_json_report,
}


def _compute_adequacy(
    cases: List[_NormalizedCase], declared_journeys: List[str]
) -> Tuple[int, int, int, int, List[str], List[str]]:
    total = len(cases)
    passed = sum(1 for c in cases if c.status == "passed")
    failed = sum(1 for c in cases if c.status == "failed")
    skipped = sum(1 for c in cases if c.status == "skipped")

    passed_journeys: set = set()
    failed_journeys: set = set()
    for case in cases:
        for journey in case.journeys:
            if case.status == "passed":
                passed_journeys.add(journey)
            elif case.status == "failed":
                failed_journeys.add(journey)

    # A journey with even one failing test anywhere is never counted
    # covered, regardless of a coincidental pass elsewhere in the run.
    covered = [j for j in declared_journeys if j in passed_journeys and j not in failed_journeys]
    missing = [j for j in declared_journeys if j not in covered]
    return total, passed, failed, skipped, covered, missing


@dataclass
class _ReportFailure:
    path: str
    missing: bool  # the file does not exist (vs. exists but can't be parsed)
    message: str


def _normalize_report_paths(report_path: Any) -> List[str]:
    """`--functional-report` is one path at CI and repeatable at CD (one
    JUnit file per live stage). Accepts None, one path, or a sequence."""
    if not report_path:
        return []
    if isinstance(report_path, (str, os.PathLike)):
        return [os.fspath(report_path)]
    return [os.fspath(p) for p in report_path if p]


def _parse_reports(parse: Any, paths: List[str]) -> Tuple[List[_NormalizedCase], List[_ReportFailure]]:
    cases: List[_NormalizedCase] = []
    failures: List[_ReportFailure] = []
    for path in paths:
        try:
            cases.extend(parse(path))
        except FileNotFoundError as e:
            failures.append(_ReportFailure(path=path, missing=True, message=str(e)))
        except (OSError, ValueError, TypeError, json.JSONDecodeError, ET.ParseError) as e:
            failures.append(_ReportFailure(path=path, missing=False, message=str(e)))
    return cases, failures


def _tier_fields(config: FunctionalVerificationConfig, tier: str, covered: List[str]) -> Dict[str, Any]:
    """The v2-only output fields, or {} for a legacy contract at the default
    tier (keeping its output byte-identical to pre-tier releases)."""
    if not config.tiered and tier == TIER_CI:
        return {}
    covered_set = set(covered)
    rows: List[Dict[str, Any]] = []
    deferred: List[str] = []
    for journey in config.journeys:
        if journey.tier in (tier, TIER_BOTH):
            status = JOURNEY_STATUS_COVERED if journey.id in covered_set else JOURNEY_STATUS_MISSING
        else:
            status = JOURNEY_STATUS_DEFERRED
            deferred.append(journey.id)
        row: Dict[str, Any] = {"id": journey.id, "tier": journey.tier, "status": status}
        if journey.name:
            row["name"] = journey.name
        if journey.description:
            row["description"] = journey.description
        rows.append(row)
    return {"tier": tier, "deferred": deferred, "journeys": rows}


def _unavailable_report(
    *,
    framework: Optional[str],
    target_env: Optional[str],
    declared_journeys: List[str],
    report_uri: Optional[str],
    reason: str,
    reason_code: str,
    tier_fields: Optional[Dict[str, Any]] = None,
) -> FunctionalVerificationReport:
    return FunctionalVerificationReport(
        available=False,
        met=False,
        framework=framework,
        target_env=target_env,
        total=0,
        passed=0,
        failed=0,
        skipped=0,
        adequacy_status=ADEQUACY_STATUS_UNAVAILABLE,
        score_pct=0.0,
        declared=list(declared_journeys),
        covered=[],
        missing=list(declared_journeys),
        report_uri=report_uri,
        reason=reason,
        reason_code=reason_code,
        **(tier_fields or {}),
    )


def _not_configured_report(
    *, target_env: Optional[str], report_uri: Optional[str], framework: Optional[str], reason: str,
    tier_fields: Optional[Dict[str, Any]] = None,
) -> FunctionalVerificationReport:
    return FunctionalVerificationReport(
        available=False,
        met=False,
        framework=framework,
        target_env=target_env,
        total=0,
        passed=0,
        failed=0,
        skipped=0,
        adequacy_status=ADEQUACY_STATUS_NOT_CONFIGURED,
        score_pct=0.0,
        declared=[],
        covered=[],
        missing=[],
        report_uri=report_uri,
        reason=reason,
        reason_code=REASON_CODE_NOT_CONFIGURED,
        **(tier_fields or {}),
    )


def _all_reports_failed(
    *, framework: str, tier: str, paths: List[str], failures: List[_ReportFailure],
) -> Tuple[str, str]:
    """(reason, reason_code) when not one --functional-report file could be
    used. At the `cd` tier, files that simply don't exist mean the live
    suite never ran far enough to write a report: `execution_aborted`.
    Everything else -- including any missing file at `ci`, unchanged from
    before tiers -- stays `report_malformed`."""
    if tier == TIER_CD and all(f.missing for f in failures):
        names = ", ".join(repr(f.path) for f in failures)
        return (
            f"execution aborted: none of the {len(paths)} --functional-report file(s) exist ({names}) -- "
            "the suite did not run far enough to write a report",
            REASON_CODE_EXECUTION_ABORTED,
        )
    if len(paths) == 1:
        return (
            f"--functional-report {paths[0]!r} could not be read as a {framework!r} report: {failures[0].message}",
            REASON_CODE_REPORT_MALFORMED,
        )
    detail = "; ".join(f"{f.path!r}: {f.message}" for f in failures)
    return (
        f"none of the {len(paths)} --functional-report files could be read as a {framework!r} report: {detail}",
        REASON_CODE_REPORT_MALFORMED,
    )


def evaluate_functional_adequacy(
    repo_dir: str,
    report_path: Any,
    *,
    target_env: Optional[str] = None,
    report_uri: Optional[str] = None,
    tier: str = TIER_CI,
) -> FunctionalVerificationReport:
    """Evaluates functional test adequacy for this run: Declared
    Operational Surface (.lucid/functional-verification.json's journeys)
    vs. Executed Scenarios (--functional-report, parsed per the config's
    declared `framework`), scoped to the journeys responsible at `tier`.

    `report_path` is one path, or several (the `cd` tier's post-deploy
    suite writes one JUnit file per stage); their cases are aggregated.
    `tier` is the stage being evaluated (`ci` or `cd`) -- an unknown value
    is a caller bug and raises ValueError, the one exception to "never
    raises" below (the CLI restricts it with argparse choices).

    Never raises otherwise. Every failure mode -- no config, an invalid
    contract, no report path, an unsupported framework, or a report that
    can't be read/parsed -- degrades to an honest, explicit outcome rather
    than crashing the pipeline or silently granting full credit for an
    unmet contract.

    `met` is a concrete, non-nullable bool in every outcome, "not
    configured" included -- it is never true unless a real, passing
    evaluation actually ran (CLAUDE.md's Fail-Closed Verification
    invariant: missing/unevaluated metadata must never default to a
    passing state). A naive downstream consumer that reads only `met`
    must see false for an unconfigured contract, not an emerald "passed"
    it never earned; `available`/`adequacy.status`/`reason_code` are the
    fields that distinguish "evaluated and failed" from "never
    configured" -- the same "unconfirmed is never treated as confirmed
    non-degraded" contract cli.verify.VerificationResult.degraded already
    holds for a structurally similar tri-state situation. This is
    deliberately not the same relief cli.mutation's `not_applicable`
    grade gives an un-configured/no-op mutation-testing run: that grade
    only ever feeds an internal scoring *multiplier* (never surfaced as a
    bare pass/fail claim a console could render directly), whereas `met`
    here is exactly the kind of direct boolean gate signal a console or a
    future --require-functional-adequacy flag would read at face value."""
    if tier not in EVALUATION_TIERS:
        raise ValueError(f"tier must be one of {list(EVALUATION_TIERS)}, got {tier!r}")

    config, invalid_reason = _load_contract(repo_dir)
    if invalid_reason is not None:
        return _unavailable_report(
            framework=None,
            target_env=target_env,
            declared_journeys=[],
            report_uri=report_uri,
            reason=f"{_CONFIG_PATH} is invalid and was not evaluated: {invalid_reason}",
            reason_code=REASON_CODE_CONFIG_INVALID,
        )
    if config is None:
        return _not_configured_report(
            target_env=target_env,
            report_uri=report_uri,
            framework=None,
            reason=(
                f"no declared_journeys configured at {_CONFIG_PATH} -- functional test adequacy is "
                "not evaluated for this run (reported as unmet, not a silent pass, to avoid a false "
                "'evaluated and passed' signal for a control that never actually ran)"
            ),
        )

    framework = config.framework
    declared = [j.id for j in config.journeys if j.tier in (tier, TIER_BOTH)]

    if not declared:
        return _not_configured_report(
            target_env=target_env,
            report_uri=report_uri,
            framework=framework,
            reason=(
                f"{_CONFIG_PATH} declares no journeys for tier {tier!r} -- functional test adequacy is "
                f"not evaluated at this tier (reported as unmet, not a silent pass)"
            ),
            tier_fields=_tier_fields(config, tier, []),
        )

    paths = _normalize_report_paths(report_path)
    if not paths:
        return _unavailable_report(
            framework=framework,
            target_env=target_env,
            declared_journeys=declared,
            report_uri=report_uri,
            reason=(
                f"{_CONFIG_PATH} declares {len(declared)} journey(s), but "
                "--functional-report was not provided for this run"
            ),
            reason_code=REASON_CODE_REPORT_MISSING,
            tier_fields=_tier_fields(config, tier, []),
        )

    parse = _PARSERS.get(framework)
    if parse is None:
        return _unavailable_report(
            framework=framework,
            target_env=target_env,
            declared_journeys=declared,
            report_uri=report_uri,
            reason=(
                f"{_CONFIG_PATH} declares an unsupported framework {framework!r} "
                f"(expected one of {sorted(_PARSERS)})"
            ),
            reason_code=REASON_CODE_UNSUPPORTED_FRAMEWORK,
            tier_fields=_tier_fields(config, tier, []),
        )

    cases, failures = _parse_reports(parse, paths)
    if len(failures) == len(paths):
        reason, reason_code = _all_reports_failed(framework=framework, tier=tier, paths=paths, failures=failures)
        return _unavailable_report(
            framework=framework,
            target_env=target_env,
            declared_journeys=declared,
            report_uri=report_uri,
            reason=reason,
            reason_code=reason_code,
            tier_fields=_tier_fields(config, tier, []),
        )

    total, passed, failed, skipped, covered, missing = _compute_adequacy(cases, declared)
    score_pct = round((len(covered) / len(declared)) * 100.0, 2)

    met = total > 0 and failed == 0 and score_pct >= config.min_adequacy_pct

    if met:
        reason = (
            f"{len(covered)}/{len(declared)} declared journey(s) covered "
            f"({score_pct:.1f}% >= {config.min_adequacy_pct:.1f}% required), 0 failed test(s)"
        )
        reason_code = None
    elif total == 0:
        reason = f"{framework!r} report at {paths[0]!r} parsed but contained zero executed tests"
        reason_code = REASON_CODE_NO_TESTS_EXECUTED
    elif failed > 0:
        reason = (
            f"{failed} executed test(s) failed -- functional adequacy cannot be met regardless of "
            f"{score_pct:.1f}% journey coverage"
        )
        reason_code = REASON_CODE_TEST_FAILURES
    else:
        reason = (
            f"only {len(covered)}/{len(declared)} declared journey(s) covered "
            f"({score_pct:.1f}% < {config.min_adequacy_pct:.1f}% required); missing: {missing}"
        )
        reason_code = REASON_CODE_PARTIAL_ADEQUACY

    if failures:
        # Some report files were unusable: whatever the readable ones say,
        # the run is incomplete, so it can never be `met`. Coverage above
        # still reflects only real, readable evidence.
        aborted = tier == TIER_CD and any(f.missing for f in failures)
        unreadable = "; ".join(f"{f.path!r}: {f.message}" for f in failures)
        reason = (
            f"{'execution aborted: ' if aborted else ''}{len(failures)} of {len(paths)} --functional-report "
            f"file(s) could not be read ({unreadable}) -- coverage reflects only the readable report(s): "
            f"{len(covered)}/{len(declared)} declared journey(s) covered, {failed} failed test(s)"
        )
        reason_code = REASON_CODE_EXECUTION_ABORTED if aborted else REASON_CODE_REPORT_MALFORMED
        met = False

    tier_fields = _tier_fields(config, tier, covered)
    test_fields: Dict[str, Any] = {}
    if tier_fields:  # only where the tier fields are emitted too -- see FunctionalVerificationReport.tests
        rows, truncated = _test_rows(cases)
        test_fields = {"tests": rows, "tests_truncated": truncated}

    return FunctionalVerificationReport(
        available=True,
        met=met,
        framework=framework,
        target_env=target_env,
        total=total,
        passed=passed,
        failed=failed,
        skipped=skipped,
        adequacy_status=ADEQUACY_STATUS_EVALUATED,
        score_pct=score_pct,
        declared=declared,
        covered=covered,
        missing=missing,
        report_uri=report_uri,
        reason=reason,
        reason_code=reason_code,
        **tier_fields,
        **test_fields,
    )
