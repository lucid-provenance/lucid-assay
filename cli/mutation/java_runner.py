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
  - A real multi-module Maven layout, fixed 2026-09-13 (code review):
    both `_pitest_configured()` and the report lookup used to assume a
    single-module (or root-only) project -- checking only the root
    pom.xml for the pitest-maven marker, and reading only
    repo_dir/target/pit-reports/mutations.xml. A genuine multi-module
    reactor build (the Maven norm for anything non-trivial) declares the
    plugin in a child module's own pom.xml and writes that module's
    report under its own target/, not the aggregator root's -- this
    runner silently reported not_configured or failed closed with
    "report could not be read" on every single invocation against one.
    `_pitest_configured()` now searches every pom.xml under repo_dir
    (excluding `target/`) for the marker; report discovery now globs
    every `pit-reports/mutations.xml` found anywhere under repo_dir and
    merges the results (`_find_report_paths`/`_merge_java_results`) --
    the same glob pattern matches both the single- and multi-module
    shape uniformly, no special-casing needed. Any one module's report
    failing to parse still fails the whole run closed, never silently
    reporting on only the modules that happened to succeed.
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


def _pitest_configured(repo_dir: Path) -> bool:
    """True when the pitest-maven plugin is declared in the root pom.xml
    or any real module's own pom.xml -- not just the root. Found via
    code review 2026-09-13: the original root-only check meant a real
    multi-module Maven project (the norm for anything non-trivial) was
    silently treated as not_configured whenever the plugin was declared
    only in a child module's own pom.xml rather than the root aggregator
    -- a very common real layout. Still requires a root pom.xml to exist
    regardless (mvn -B ... itself needs one to run at all); this only
    widens where the *marker string* can be found, not whether Maven's
    own reactor build is possible. Excludes anything under a `target/`
    directory -- never a source pom.xml, and it's exactly where a
    previous build's own copied/generated content (a shaded/assembled
    jar's exploded contents, a dependency's own vendored pom, ...) could
    otherwise produce a false positive or waste a scan on a large tree."""
    pom = repo_dir / "pom.xml"
    if not pom.is_file():
        return False
    for candidate in repo_dir.rglob("pom.xml"):
        if "target" in candidate.relative_to(repo_dir).parts:
            continue
        try:
            text = candidate.read_text(encoding="utf-8")
        except OSError:
            continue
        if _PITEST_PLUGIN_MARKER in text:
            return True
    return False


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


def _find_report_paths(repo_dir: Path) -> List[Path]:
    """Every module's own mutations.xml under repo_dir -- a real
    multi-module Maven reactor build writes one per module PIT actually
    ran against, not a single report at the repo root. Found via code
    review 2026-09-13: the previous hardcoded
    repo_dir/target/pit-reports/mutations.xml path only ever matched a
    single-module (or root-only) project; a real multi-module layout
    writes each module's own report under
    <module>/target/pit-reports/mutations.xml instead, and this runner
    failed closed on every single invocation against one.
    Path.rglob()'s implicit `**/` prefix matches both shapes uniformly --
    no need to special-case single- vs. multi-module. Sorted for
    deterministic ordering (surviving-mutant detail order, and which
    result "wins" is never ambiguous run to run)."""
    return sorted(repo_dir.rglob("pit-reports/mutations.xml"))


def _merge_java_results(
    results: List[LanguageRunResult], scoped_classes: List[str], max_detail: int
) -> LanguageRunResult:
    """Combines one LanguageRunResult per discovered mutations.xml (one
    per Maven module PIT actually ran against) into a single combined
    result -- the same "sum everything, grade once" contract
    cli.mutation's own dispatcher already applies across languages, one
    level down within Java's own multi-module case. Any single module's
    own unavailable result (its report failed to parse) fails the whole
    run closed rather than silently reporting on only the modules that
    happened to succeed -- a corrupt/partial report from one module is
    exactly the state that must never be reported as if the others
    already tell the whole story."""
    for r in results:
        if r.status == "unavailable":
            return r
    killed = sum(r.killed for r in results)
    survived = sum(r.survived for r in results)
    timeout_ct = sum(r.timeout for r in results)
    total_generated = sum(r.total_generated for r in results)
    surviving: List[SurvivingMutant] = []
    for r in results:
        surviving.extend(r.surviving_mutants)
    surviving = surviving[:max_detail]

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

    report_paths = _find_report_paths(repo_dir)
    if not report_paths:
        return LanguageRunResult(
            language=LANGUAGE_JAVA, status="unavailable",
            reason="pitest ran but no mutations.xml report was found anywhere under the repo",
        )
    results = [_parse_report(p, existing_files, max_surviving_detail) for p in report_paths]
    return _merge_java_results(results, existing_files, max_surviving_detail)
