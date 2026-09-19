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
"""
from __future__ import annotations

import json
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


@dataclass
class FunctionalVerificationConfig:
    """The declared contract read from .lucid/functional-verification.json.
    `framework` is carried through verbatim (even if not one this module
    recognizes) so evaluate_functional_adequacy() can report an honest
    "unsupported framework" outcome rather than the loader silently
    normalizing/guessing at it."""
    framework: str
    min_adequacy_pct: float
    declared_journeys: List[str]


@dataclass
class _NormalizedCase:
    status: str  # "passed" | "failed" | "skipped"
    journeys: Tuple[str, ...]


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

    def as_dict(self) -> Dict[str, Any]:
        return {
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


def load_functional_verification_config(repo_dir: str) -> Optional[FunctionalVerificationConfig]:
    """Returns the declared functional-verification contract from
    .lucid/functional-verification.json, or None when genuinely
    unconfigured (missing file, unreadable, malformed JSON, not a JSON
    object, or no non-empty declared_journeys list) -- the caller
    reports this as adequacy.status == "not_configured", never a
    failure. Never raises."""
    try:
        text = (Path(repo_dir) / _CONFIG_PATH).read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict):
        return None

    raw_journeys = doc.get("declared_journeys")
    if not isinstance(raw_journeys, list):
        return None
    declared_journeys = [j.strip() for j in raw_journeys if isinstance(j, str) and j.strip()]
    if not declared_journeys:
        return None

    framework_raw = doc.get("framework")
    framework = framework_raw.strip() if isinstance(framework_raw, str) and framework_raw.strip() else ""

    min_adequacy_pct_raw = doc.get("min_adequacy_pct", _DEFAULT_MIN_ADEQUACY_PCT)
    if isinstance(min_adequacy_pct_raw, bool) or not isinstance(min_adequacy_pct_raw, (int, float)):
        min_adequacy_pct = _DEFAULT_MIN_ADEQUACY_PCT
    else:
        min_adequacy_pct = float(min_adequacy_pct_raw)

    return FunctionalVerificationConfig(
        framework=framework,
        min_adequacy_pct=min_adequacy_pct,
        declared_journeys=declared_journeys,
    )


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
            out.append(_NormalizedCase(status=status, journeys=tuple(sorted(test_journeys))))

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


def _parse_junit_functional_report(path: str) -> List[_NormalizedCase]:
    cases: List[_NormalizedCase] = []
    context = ET.iterparse(path, events=("end",))
    for _, elem in context:
        if elem.tag != "testcase":
            continue
        cases.append(_NormalizedCase(status=_junit_case_status(elem), journeys=_junit_case_journeys(elem)))
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

        cases.append(_NormalizedCase(status=status, journeys=journeys))
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


def _unavailable_report(
    *,
    framework: Optional[str],
    target_env: Optional[str],
    declared_journeys: List[str],
    report_uri: Optional[str],
    reason: str,
    reason_code: str,
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
    )


def evaluate_functional_adequacy(
    repo_dir: str,
    report_path: Optional[str],
    *,
    target_env: Optional[str] = None,
    report_uri: Optional[str] = None,
) -> FunctionalVerificationReport:
    """Evaluates functional test adequacy for this run: Declared
    Operational Surface (.lucid/functional-verification.json's
    declared_journeys) vs. Executed Scenarios (--functional-report,
    parsed per the config's declared `framework`).

    Never raises. Every failure mode -- no config, no report path, an
    unsupported framework, or a report that can't be read/parsed --
    degrades to an honest, explicit outcome rather than crashing the
    pipeline or silently granting full credit for an unmet contract.

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
    config = load_functional_verification_config(repo_dir)
    if config is None:
        return FunctionalVerificationReport(
            available=False,
            met=False,
            framework=None,
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
            reason=(
                f"no declared_journeys configured at {_CONFIG_PATH} -- functional test adequacy is "
                "not evaluated for this run (reported as unmet, not a silent pass, to avoid a false "
                "'evaluated and passed' signal for a control that never actually ran)"
            ),
            reason_code=REASON_CODE_NOT_CONFIGURED,
        )

    framework = config.framework

    if not report_path:
        return _unavailable_report(
            framework=framework,
            target_env=target_env,
            declared_journeys=config.declared_journeys,
            report_uri=report_uri,
            reason=(
                f"{_CONFIG_PATH} declares {len(config.declared_journeys)} journey(s), but "
                "--functional-report was not provided for this run"
            ),
            reason_code=REASON_CODE_REPORT_MISSING,
        )

    parse = _PARSERS.get(framework)
    if parse is None:
        return _unavailable_report(
            framework=framework,
            target_env=target_env,
            declared_journeys=config.declared_journeys,
            report_uri=report_uri,
            reason=(
                f"{_CONFIG_PATH} declares an unsupported framework {framework!r} "
                f"(expected one of {sorted(_PARSERS)})"
            ),
            reason_code=REASON_CODE_UNSUPPORTED_FRAMEWORK,
        )

    try:
        cases = parse(report_path)
    except (OSError, ValueError, TypeError, json.JSONDecodeError, ET.ParseError) as e:
        return _unavailable_report(
            framework=framework,
            target_env=target_env,
            declared_journeys=config.declared_journeys,
            report_uri=report_uri,
            reason=f"--functional-report {report_path!r} could not be read as a {framework!r} report: {e}",
            reason_code=REASON_CODE_REPORT_MALFORMED,
        )

    total, passed, failed, skipped, covered, missing = _compute_adequacy(cases, config.declared_journeys)
    score_pct = round((len(covered) / len(config.declared_journeys)) * 100.0, 2)

    met = total > 0 and failed == 0 and score_pct >= config.min_adequacy_pct

    if met:
        reason = (
            f"{len(covered)}/{len(config.declared_journeys)} declared journey(s) covered "
            f"({score_pct:.1f}% >= {config.min_adequacy_pct:.1f}% required), 0 failed test(s)"
        )
        reason_code = None
    elif total == 0:
        reason = f"{framework!r} report at {report_path!r} parsed but contained zero executed tests"
        reason_code = REASON_CODE_NO_TESTS_EXECUTED
    elif failed > 0:
        reason = (
            f"{failed} executed test(s) failed -- functional adequacy cannot be met regardless of "
            f"{score_pct:.1f}% journey coverage"
        )
        reason_code = REASON_CODE_TEST_FAILURES
    else:
        reason = (
            f"only {len(covered)}/{len(config.declared_journeys)} declared journey(s) covered "
            f"({score_pct:.1f}% < {config.min_adequacy_pct:.1f}% required); missing: {missing}"
        )
        reason_code = REASON_CODE_PARTIAL_ADEQUACY

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
        declared=list(config.declared_journeys),
        covered=covered,
        missing=missing,
        report_uri=report_uri,
        reason=reason,
        reason_code=reason_code,
    )
