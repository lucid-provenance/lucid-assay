"""
Java mutation testing runner: PIT (org.pitest:pitest-maven), scoped to
just the `*.java` files a diff actually changed. Maven only for now --
Gradle's `gradle-pitest-plugin` has no equivalent per-invocation
class-scoping override the way `-DtargetClasses` does for Maven, so a
Gradle-only Java repo gets status="not_configured", not a guess.

Confirmed empirically, not assumed from web-search docs (real scratch
Maven+PIT 1.19.0 project, this session): **`scmMutationCoverage` does
not exist in open-source PIT** -- its real goal list is `help,
mutationCoverage, report, report-aggregate, report-aggregate-module`.
It's gated behind PIT's commercial ArcMutate add-on (confirmed: a real
run's own CLI output prints "Enhanced functionality available at
https://www.arcmutate.com/"). Diff-scoping here uses `-DtargetClasses`
instead -- a fully-qualified-class-name glob, confirmed as a real
per-invocation CLI override, same shape as mutmut's dotted-module
wildcard. Must run as `mvn clean test-compile
org.pitest:pitest-maven:mutationCoverage -DtargetClasses=...` -- the
bare `mutationCoverage` goal alone finds zero mutations (test-compile
has to run first; confirmed by hitting exactly that failure).

**Disclosed, not fixed by this module**: `mvn clean test-compile ...`
resolves plugins/dependencies from the local `~/.m2` repository,
downloading anything missing from Maven Central on first use. In an
ephemeral CI container with no persisted `.m2` (no `actions/cache` on
`~/.m2/repository`, or equivalent), the *first* run in that environment
downloads the entire plugin/dependency graph from scratch and can
easily exceed `--mutation-testing-timeout`'s default -- this module
can't warm a cache it has no control over; the target repo's own CI
config needs to persist `~/.m2` across runs the same way it already
should for its normal Maven build, or pass a larger
`--mutation-testing-timeout` for Java-touching diffs specifically.

Hardened against:
  - Runaway CI time: an outer `subprocess.run(timeout=...)` is the hard,
    provably-bounded backstop, same pattern as every other runner here
    -- it just won't be a *fast* backstop against a genuinely cold
    `.m2` cache (see above).
  - Unsafe/unresolvable repo_dir: the dispatcher already resolves
    repo_dir via common.safe_resolve_path() once, before calling any
    runner -- this module receives an already-safe Path.
  - PIT's own report directory (target/pit-reports/) is per-Maven-build,
    not a persistent cross-invocation cache the way mutmut's mutants/
    was -- `mvn clean` at the front of every invocation here guarantees
    a fresh target/ regardless.
"""
from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set

from .common import LANGUAGE_JAVA, LanguageRunResult, REASON_CODE_NO_COVERABLE_LINES, SurvivingMutant

_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
_PITEST_PLUGIN_MARKER = "pitest-maven"
_NO_MUTATIONS_MARKER = "No mutations found"
_REPORT_PATH = ("target", "pit-reports", "mutations.xml")


def _pitest_configured(repo_dir: Path) -> bool:
    pom = repo_dir / "pom.xml"
    if not pom.is_file():
        return False
    try:
        text = pom.read_text(encoding="utf-8")
    except OSError:
        return False
    return _PITEST_PLUGIN_MARKER in text


def _fully_qualified_class_name(repo_dir: Path, file_path: str) -> Optional[str]:
    """Reads the file's own `package` declaration and combines it with
    its filename -- PIT's -DtargetClasses wants FQCNs, not file paths.
    None (not guessed) when the file has no package declaration or
    can't be read; the caller simply excludes it from the scoped set
    rather than passing a wrong/partial name to Maven."""
    try:
        text = (repo_dir / file_path).read_text(encoding="utf-8")
    except OSError:
        return None
    class_name = Path(file_path).stem
    m = _PACKAGE_RE.search(text)
    if m:
        return f"{m.group(1)}.{class_name}"
    return class_name  # default package -- unusual but not invalid


def _run_mvn(args: List[str], *, cwd: Path, timeout_seconds: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["mvn", "-B", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )


def _parse_report(report_path: Path, scoped_classes: List[str], max_detail: int) -> LanguageRunResult:
    try:
        root = ET.parse(report_path).getroot()
    except (OSError, ET.ParseError):
        return LanguageRunResult(
            language=LANGUAGE_JAVA, status="unavailable",
            reason="pitest ran but its mutations.xml report could not be read",
        )

    killed = survived = timeout_ct = total_generated = 0
    surviving: List[SurvivingMutant] = []
    for mutation in root.findall("mutation"):
        total_generated += 1
        # "status" is an attribute of <mutation>, not a child element --
        # confirmed against a real PIT 1.19.0 report
        # (<mutation detected="true" status="KILLED" ...>).
        status = (mutation.get("status") or "").upper()
        if status == "KILLED":
            killed += 1
        elif status == "SURVIVED":
            survived += 1
        elif status == "TIMED_OUT":
            timeout_ct += 1

        if status in ("SURVIVED", "TIMED_OUT") and len(surviving) < max_detail:
            source_file = mutation.findtext("sourceFile") or ""
            mutated_method = mutation.findtext("mutatedMethod") or ""
            line_text = mutation.findtext("lineNumber")
            mutator = mutation.findtext("mutator") or ""
            description = mutation.findtext("description") or ""
            surviving.append(
                SurvivingMutant(
                    language=LANGUAGE_JAVA,
                    file=source_file,
                    function=mutated_method,
                    status=status.lower().replace("timed_out", "timeout"),
                    diff=f"{mutator.rsplit('.', 1)[-1]}: {description}",
                    line=int(line_text) if line_text and line_text.isdigit() else None,
                )
            )

    if killed + survived + timeout_ct == 0:
        return LanguageRunResult(
            language=LANGUAGE_JAVA, status="ran",
            scoped_files=scoped_classes, reason=REASON_CODE_NO_COVERABLE_LINES,
        )

    return LanguageRunResult(
        language=LANGUAGE_JAVA,
        status="ran",
        killed=killed,
        survived=survived,
        timeout=timeout_ct,
        total_generated=total_generated,
        scoped_files=scoped_classes,
        surviving_mutants=surviving,
    )


def run(
    repo_dir: Path,
    changed_files: List[str],
    *,
    timeout_seconds: int,
    max_surviving_detail: int,
    base_sha: Optional[str] = None,
    changed_lines: Optional[Dict[str, Set[int]]] = None,
) -> LanguageRunResult:
    """changed_files: already filtered to real, non-test *.java files by
    the dispatcher. `base_sha` is unused here -- accepted only for a
    uniform dispatcher calling convention across every runner (only
    go_runner.py's gremlins integration does its own git diffing).
    `changed_lines` is likewise unused here -- only python_runner.py
    narrows further to touched functions using it today; accepted for
    the same uniform calling convention."""
    existing_files = [f for f in changed_files if (repo_dir / f).is_file()]
    if not existing_files:
        return LanguageRunResult(language=LANGUAGE_JAVA, status="not_configured")

    if not _pitest_configured(repo_dir):
        return LanguageRunResult(language=LANGUAGE_JAVA, status="not_configured")

    class_names = [n for n in (_fully_qualified_class_name(repo_dir, f) for f in existing_files) if n]
    if not class_names:
        return LanguageRunResult(
            language=LANGUAGE_JAVA, status="ran",
            scoped_files=existing_files, reason=REASON_CODE_NO_COVERABLE_LINES,
        )

    try:
        proc = _run_mvn(
            [
                "clean", "test-compile", "org.pitest:pitest-maven:mutationCoverage",
                f"-DtargetClasses={','.join(class_names)}",
                "-DtimestampedReports=false",
            ],
            cwd=repo_dir,
            timeout_seconds=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return LanguageRunResult(
            language=LANGUAGE_JAVA, status="unavailable",
            reason=f"pitest exceeded the {timeout_seconds}s time budget",
        )
    except OSError as e:
        return LanguageRunResult(
            language=LANGUAGE_JAVA, status="unavailable", reason=f"mvn could not be invoked: {e}"
        )

    combined_output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        if _NO_MUTATIONS_MARKER in combined_output:
            return LanguageRunResult(
                language=LANGUAGE_JAVA, status="ran",
                scoped_files=existing_files, reason=REASON_CODE_NO_COVERABLE_LINES,
            )
        return LanguageRunResult(
            language=LANGUAGE_JAVA, status="unavailable",
            reason=f"pitest run failed (exit {proc.returncode}): {combined_output.strip()[-300:]}",
        )

    report_path = repo_dir.joinpath(*_REPORT_PATH)
    return _parse_report(report_path, existing_files, max_surviving_detail)
