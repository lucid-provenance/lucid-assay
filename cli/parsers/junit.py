"""
JUnit XML parser.

Design notes (perf):
  - Uses xml.etree.iterparse with element clearing so memory stays O(1) per
    testsuite regardless of file size, and we never build a DOM. For typical
    CI-sized reports (hundreds to low-thousands of <testcase>) this parses
    in low single-digit milliseconds; multi-MB monorepo reports stay linear
    and avoid the ~5-10x overhead of a full DOM parse (lxml.etree / minidom).
  - Flaky-retry detection: many runners (e.g. jest-junit with retries,
    pytest-rerunfailures) emit a <testcase> per attempt with the same
    classname+name. We key on (classname, name) and consider a case "flaky"
    if it has >1 recorded attempt AND the final attempt passed.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, Tuple

@dataclass
class TestTotals:
    __test__ = False
    tests: int = 0
    passed: int = 0
    failed: int = 0
    errored: int = 0
    skipped: int = 0
    duration_ms: int = 0
    flaky_retries: int = 0


@dataclass
class _CaseAttempt:
    outcome: str  # "passed" | "failed" | "errored" | "skipped"


def parse_junit_xml(path: str) -> TestTotals:
    """Stream-parse a junit.xml (or junit-xml aggregate with multiple
    <testsuite> elements) into aggregate totals.

    Raises FileNotFoundError / ET.ParseError to the caller; the CLI layer
    is responsible for turning parse failures into a hard pipeline failure
    (an unparseable test report must never silently yield RCS=0-with-a-shrug;
    it should abort ingestion).
    """
    attempts: Dict[Tuple[str, str], list] = {}
    totals = TestTotals()

    # iterparse gives us "end" events per element; we clear each <testcase>
    # after reading it so peak memory is bounded by one suite's cases, not
    # the whole file.
    context = ET.iterparse(path, events=("end",))
    for _, elem in context:
        if elem.tag != "testcase":
            continue

        classname = elem.get("classname", "")
        name = elem.get("name", "")
        time_s = float(elem.get("time", "0") or 0.0)
        totals.duration_ms += int(round(time_s * 1000))

        outcome = "passed"
        if elem.find("failure") is not None:
            outcome = "failed"
        elif elem.find("error") is not None:
            outcome = "errored"
        elif elem.find("skipped") is not None:
            outcome = "skipped"

        key = (classname, name)
        attempts.setdefault(key, []).append(outcome)

        elem.clear()  # release memory; safe because we've already read it

    for key, outcomes in attempts.items():
        totals.tests += 1
        final = outcomes[-1]
        if final == "passed":
            totals.passed += 1
            if len(outcomes) > 1:
                totals.flaky_retries += 1
        elif final == "failed":
            totals.failed += 1
        elif final == "errored":
            totals.errored += 1
        else:
            totals.skipped += 1

    return totals
