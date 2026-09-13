"""
TypeScript/JavaScript mutation testing runner: Stryker
(@stryker-mutator/core), scoped to just the `*.ts`/`*.tsx`/`*.js`/`*.jsx`/
`*.mjs`/`*.cjs` files a diff actually changed.

Unlike Python (mutmut), this module never injects a test-runner/command
config of its own -- it requires the *target* repo to already carry a
complete, working Stryker config (whatever test runner it prefers: a
dedicated runner plugin, or Stryker's own "command" runner shelling the
target's `npm test`). The only CLI overrides this module ever passes are
`--mutate` (file-scoping) and `--reporters json` -- same "read the
target's own tool config" principle patch_coverage/mutmut/PIT all
already follow. A repo with no Stryker config at all gets
status="not_configured", never a guess at what its test setup might be.

Hardened against:
  - Stats leaking across unrelated files: Stryker's JSON reporter is a
    fresh, single write per invocation keyed by the files it actually
    processed (confirmed empirically against a real Stryker 10.0.0
    install) -- unlike mutmut's `mutants/` cache, there's no persistent
    cross-run directory to reset here.
  - Dirtying the target repo's own working tree: Stryker's sandbox
    directory (`.stryker-tmp/` by default) is confirmed empirically to
    survive in `repo_dir` after a run unless `--cleanTempDir always` is
    passed explicitly (a crashed/interrupted prior run leaves it behind
    regardless) -- left in place, it would sit as an untracked directory
    right where lucid-assay's own git-diff-based provenance hashing runs
    next, a real risk for a tool whose whole job is faithfully reporting
    repo state. Deleted defensively before every run (same
    belt-and-suspenders spirit as mutmut's own cache reset) *and*
    `--cleanTempDir always` passed on every invocation.
  - Runaway CI time: an outer `subprocess.run(timeout=...)` is the hard,
    provably-bounded backstop, same pattern as every other runner here.
  - Unsafe/unresolvable repo_dir: the dispatcher already resolves
    repo_dir via common.safe_resolve_path() once, before calling any
    runner -- this module receives an already-safe Path.
  - Silently granting full credit on a missing report, fixed 2026-09-13
    (code review): a customized `jsonReporter.fileName` (the JSON
    reporter's output path is config-file-only -- no CLI override
    exists, confirmed against Stryker's own docs) meant the hardcoded
    default report path could go unread while Stryker had genuinely run
    and mutated real code -- previously misread as "nothing to mutate"
    and scored at full credit purely because the file wasn't where this
    module assumed. `_resolve_report_path()` now reads a JSON-format
    config's own override when present; when the report still can't be
    found (a JS/CJS config this module can't safely evaluate), the
    result is `unavailable` (fail-closed), never full credit -- a real
    "nothing mutable here" result only ever comes from actually reading
    a report and finding it empty, never from failing to find one.

Confirmed empirically, not assumed from docs (real scratch npm+Stryker
10.0.0 project, this session): `--mutate <glob>` correctly scopes mutant
*generation* to just the given file(s) ("Found 1 of 5 file(s) to be
mutated"); the JSON reporter gives `location.start.line`/`end` and a
real `mutatorName` per mutant, so -- unlike Python -- no AST-based line
resolution is needed here at all. **Not separately verified**: Stryker's
exact behavior when `--mutate` matches a file with nothing mutable in it
(the zero-mutant case) -- handled the same way as a file simply absent
from the report's `files{}` map, but this specific path hasn't been
exercised against a real run the way the Python leg's AssertionError
marker was.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .common import LANGUAGE_TSJS, LanguageRunResult, REASON_CODE_NO_COVERABLE_LINES, SurvivingMutant

_CONFIG_CANDIDATES = (
    "stryker.conf.json",
    "stryker.conf.mjs",
    "stryker.conf.cjs",
    "stryker.config.mjs",
    "stryker.config.cjs",
    ".stryker.conf.json",
)
_DEFAULT_REPORT_PATH = ("reports", "mutation", "mutation.json")
_SURVIVED_STATUSES = {"Survived", "Timeout"}


def _stryker_configured(repo_dir: Path) -> bool:
    if any((repo_dir / name).is_file() for name in _CONFIG_CANDIDATES):
        return True
    package_json = repo_dir / "package.json"
    if not package_json.is_file():
        return False
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and "stryker" in data


def _resolve_report_path(repo_dir: Path) -> Path:
    """Resolves where Stryker's JSON reporter actually writes its report
    -- Stryker's own default ("reports/mutation/mutation.json", matching
    _DEFAULT_REPORT_PATH) unless the target's own config overrides
    `jsonReporter.fileName`. Found via code review 2026-09-13 and
    confirmed against Stryker's own docs: there is no CLI flag to
    override this setting -- `--reporters json` (this module's own CLI
    override) only controls *which* reporters run, never a given
    reporter's own output path, which is config-file-only. Best-effort:
    only a JSON-format config (`stryker.conf.json`/`.stryker.conf.json`)
    can be read safely here; a `.mjs`/`.cjs`/`.js` config would require
    executing arbitrary JavaScript to evaluate, which this module will
    never do. Falls back to the documented default when no JSON config
    overrides it, or when the config is JS-based -- see run()'s own
    fail-closed handling for what happens when the resolved path still
    isn't where the real report landed."""
    for name in ("stryker.conf.json", ".stryker.conf.json"):
        config_path = repo_dir / name
        if not config_path.is_file():
            continue
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        json_reporter = data.get("jsonReporter")
        if isinstance(json_reporter, dict):
            file_name = json_reporter.get("fileName")
            if isinstance(file_name, str) and file_name:
                return repo_dir / file_name
    return repo_dir.joinpath(*_DEFAULT_REPORT_PATH)


def _reset_stryker_sandbox(repo_dir: Path) -> None:
    """Deletes any pre-existing .stryker-tmp/ sandbox dir under repo_dir
    -- see the module docstring's "Dirtying the target repo's own
    working tree" hardening note. A crashed/interrupted prior run can
    leave this behind even with --cleanTempDir passed, so this runs
    before every invocation, not just once."""
    shutil.rmtree(repo_dir / ".stryker-tmp", ignore_errors=True)


def _run_stryker(files: List[str], *, cwd: Path, timeout_seconds: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "npx", "stryker", "run",
            "--mutate", ",".join(files),
            "--reporters", "json",
            "--cleanTempDir", "always",
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )


def _collect_from_report(report: Dict[str, Any], scoped_files: List[str], max_detail: int) -> LanguageRunResult:
    files = report.get("files")
    files = files if isinstance(files, dict) else {}

    killed = survived = timeout_ct = total_generated = 0
    surviving: List[SurvivingMutant] = []
    for file_path, file_data in files.items():
        if file_path not in scoped_files:
            continue
        mutants = file_data.get("mutants") if isinstance(file_data, dict) else None
        for m in mutants or []:
            total_generated += 1
            status = m.get("status")
            if status == "Killed":
                killed += 1
            elif status == "Survived":
                survived += 1
            elif status == "Timeout":
                timeout_ct += 1
            if status in _SURVIVED_STATUSES and len(surviving) < max_detail:
                location = m.get("location") if isinstance(m.get("location"), dict) else {}
                start = location.get("start") if isinstance(location.get("start"), dict) else {}
                surviving.append(
                    SurvivingMutant(
                        language=LANGUAGE_TSJS,
                        file=file_path,
                        function=m.get("mutatorName", "unknown"),
                        status=status.lower(),
                        diff=f"{m.get('mutatorName', '')}: replaced with `{m.get('replacement', '')}`",
                        line=start.get("line"),
                    )
                )

    if killed + survived + timeout_ct == 0:
        return LanguageRunResult(
            language=LANGUAGE_TSJS, status="ran",
            scoped_files=scoped_files, reason=REASON_CODE_NO_COVERABLE_LINES,
        )

    return LanguageRunResult(
        language=LANGUAGE_TSJS,
        status="ran",
        killed=killed,
        survived=survived,
        timeout=timeout_ct,
        total_generated=total_generated,
        scoped_files=scoped_files,
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
    """changed_files: already filtered to real, non-test *.ts/*.tsx/*.js/
    *.jsx/*.mjs/*.cjs files by the dispatcher. `base_sha` is unused here
    -- accepted only for a uniform dispatcher calling convention across
    every runner (only go_runner.py's gremlins integration does its own
    git diffing). `changed_lines` is likewise unused here -- only
    python_runner.py narrows further to touched functions using it
    today; accepted for the same uniform calling convention."""
    existing_files = [f for f in changed_files if (repo_dir / f).is_file()]
    if not existing_files:
        return LanguageRunResult(language=LANGUAGE_TSJS, status="not_configured")

    if not _stryker_configured(repo_dir):
        return LanguageRunResult(language=LANGUAGE_TSJS, status="not_configured")

    _reset_stryker_sandbox(repo_dir)
    try:
        return _run_and_collect(repo_dir, existing_files, timeout_seconds, max_surviving_detail)
    finally:
        # A killed/timed-out subprocess never reaches its own
        # --cleanTempDir cleanup -- guarantee no sandbox dir survives
        # this call regardless of which path above returned.
        _reset_stryker_sandbox(repo_dir)


def _run_and_collect(
    repo_dir: Path, existing_files: List[str], timeout_seconds: int, max_surviving_detail: int
) -> LanguageRunResult:
    try:
        proc = _run_stryker(existing_files, cwd=repo_dir, timeout_seconds=timeout_seconds)
    except subprocess.TimeoutExpired:
        return LanguageRunResult(
            language=LANGUAGE_TSJS, status="unavailable",
            reason=f"stryker exceeded the {timeout_seconds}s time budget",
        )
    except OSError as e:
        return LanguageRunResult(
            language=LANGUAGE_TSJS, status="unavailable", reason=f"stryker could not be invoked: {e}"
        )

    report_path = _resolve_report_path(repo_dir)
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        if proc.returncode == 0:
            # Changed 2026-09-13 (code review): this used to assume a
            # missing report plus a clean exit meant "nothing mutable in
            # the scoped files" and granted full credit
            # (REASON_CODE_NO_COVERABLE_LINES) -- wrong, and dangerously
            # so, whenever Stryker genuinely ran, mutated real code, and
            # simply wrote its report to a path _resolve_report_path
            # couldn't determine (a JS/CJS config overriding
            # jsonReporter.fileName -- Stryker's CLI has no flag to
            # override this, confirmed empirically, so a non-JSON
            # config's real path can't be known without executing
            # arbitrary JS, which this module never will). A genuinely
            # empty scope is still handled correctly and separately, by
            # _collect_from_report finding a real, readable report whose
            # relevant files/mutants are actually empty -- that's a
            # verified signal. An unreadable report is not a signal at
            # all, and must never be treated as one. Failing closed here
            # is strictly the safer direction: the worst case is a real
            # repo discounted (x0.85) for something this code couldn't
            # verify, never a real weak spot silently scored as if it
            # didn't exist.
            return LanguageRunResult(
                language=LANGUAGE_TSJS, status="unavailable",
                reason=f"stryker ran but its report at {report_path} could not be found or read",
            )
        return LanguageRunResult(
            language=LANGUAGE_TSJS, status="unavailable",
            reason=f"stryker run failed (exit {proc.returncode}): {(proc.stderr or '').strip()[:300]}",
        )

    return _collect_from_report(report, existing_files, max_surviving_detail)
