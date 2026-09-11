"""
Python mutation testing runner: mutmut, scoped to just the `*.py` files
a diff actually changed. See cli.mutation's own package docstring for
the overall multi-language contract; this module is the original,
Python-only implementation, unchanged in behavior from before the
multi-language restructure -- only its return shape changed (a
LanguageRunResult, for the dispatcher in cli.mutation.__init__ to
combine with whatever other languages' runners also ran).

Hardened against:
  - Stats leaking across unrelated files: mutmut's own `export-cicd-stats`
    aggregates across its *entire* `mutants/` cache directory, not just
    whatever a given invocation just tested -- confirmed empirically
    against a real mutmut 3.7.0 install, not assumed from its docs. This
    module always deletes any pre-existing `mutants/`/`.mutmut-cache`
    before running, so a stale result from a previous, differently-scoped
    PR/run can never bleed into this run's mutation_score. A generated
    mutant with no recorded exit code (never selected for testing by any
    wildcard) doesn't count in mutmut's own aggregate either way -- also
    confirmed empirically -- but starting clean removes any doubt.
  - A wildcard filter matching zero mutants: mutmut's own `run <wildcard>`
    raises an uncaught AssertionError when every wildcard's filter is
    empty (confirmed empirically) -- e.g. a diff that only touched
    comments/docstrings/type hints, where no executable statement
    actually changed. Detected via that specific, distinguishing stderr
    marker (not any non-zero exit code, which would also fire on a
    genuine mutmut crash) and reported as the zero-mutant exemption
    rather than a crash or a fail-closed penalty.
  - Runaway CI time: mutmut restricts each mutant's test run to only the
    tests that actually cover the mutated line (its own coverage-gathered
    baseline), which is what keeps this bounded against a 1000+-test
    suite in the common case -- but an outer `subprocess.run(timeout=...)`
    is the hard, provably-bounded backstop regardless, same pattern as
    `oidc_signer.py`'s OIDC-fetch retry.
  - Unsafe/unresolvable repo_dir reaching subprocess.run(cwd=...): the
    dispatcher already resolves repo_dir via common.safe_resolve_path()
    once, before calling any runner -- this module receives an
    already-safe Path, not a raw string.
"""
from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from .common import (
    LANGUAGE_PYTHON,
    LanguageRunResult,
    REASON_CODE_NO_COVERABLE_LINES,
    SurvivingMutant,
)

_NO_MATCH_MARKER = "Filtered for specific mutants, but nothing matches"
_MUTANT_KEY_RE = re.compile(r"^x_(?P<func>.+)__mutmut_\d+$")
_RESULT_LINE_RE = re.compile(r"^\s*(?P<key>\S+):\s*(?P<status>\S+)\s*$")


def _dotted_module(file_path: str) -> str:
    """"cli/parsers/sarif.py" -> "cli.parsers.sarif" -- mirrors mutmut's
    own dotted mutant-key namespacing, confirmed empirically (a mutant in
    pkg/mathy.py surfaces as "pkg.mathy.x_<func>__mutmut_<n>")."""
    return file_path[: -len(".py")].replace("/", ".")


def _wildcard_for(file_path: str) -> str:
    return f"{_dotted_module(file_path)}.*"


def _run_mutmut(args: List[str], *, cwd: Path, timeout_seconds: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "mutmut", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )


def _reset_mutmut_cache(repo_dir: Path) -> None:
    """Deletes any pre-existing mutants/ cache dir and .mutmut-cache file
    under repo_dir -- see the module docstring's "Stats leaking across
    unrelated files" hardening note for why this must happen every run,
    not just the first."""
    shutil.rmtree(repo_dir / "mutants", ignore_errors=True)
    (repo_dir / ".mutmut-cache").unlink(missing_ok=True)


def _resolve_function_line(repo_dir: Path, file_path: str, func_name: str) -> Optional[int]:
    """Best-effort: parses the real, unmutated source file with `ast` and
    returns the lineno of the first top-level-or-nested function/method
    named func_name. Ambiguous when multiple functions share a name
    (e.g. same-named methods on different classes) -- returns the first
    match rather than guessing further; the diff snippet itself (not this
    line number) is the ground-truth evidence for a surviving mutant, per
    CLAUDE.md's Ground-Truth-Only invariant, so an imprecise locator here
    never overstates its own confidence."""
    try:
        source = (repo_dir / file_path).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=file_path)
    except (OSError, SyntaxError, ValueError):
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            return node.lineno
    return None


def _parse_mutant_key(key: str, scoped_files: List[str]) -> Optional[tuple]:
    """Resolves a mutmut mutant key (e.g. "cli.parsers.sarif.x_foo__mutmut_1")
    back to one of our own scoped files + the real function name, by
    reversing the exact dotted-module transform this module applied when
    building the run wildcards -- no guessing at mutmut's internal naming
    beyond what was already confirmed empirically for the file/prefix
    half of the key."""
    for file_path in scoped_files:
        prefix = _dotted_module(file_path) + "."
        if key.startswith(prefix):
            tail = key[len(prefix):]
            m = _MUTANT_KEY_RE.match(tail)
            if m:
                return file_path, m.group("func")
    return None


def _collect_surviving_detail(
    repo_dir: Path,
    scoped_files: List[str],
    *,
    timeout_seconds: int,
    max_detail: int,
) -> List[SurvivingMutant]:
    try:
        proc = _run_mutmut(["results"], cwd=repo_dir, timeout_seconds=timeout_seconds)
    except (subprocess.TimeoutExpired, OSError):
        return []

    candidates: List[tuple] = []
    for line in proc.stdout.splitlines():
        m = _RESULT_LINE_RE.match(line)
        if not m or m.group("status") not in ("survived", "timeout"):
            continue
        resolved = _parse_mutant_key(m.group("key"), scoped_files)
        if resolved is not None:
            candidates.append((m.group("key"), m.group("status"), *resolved))

    detail: List[SurvivingMutant] = []
    for key, status, file_path, func_name in candidates[:max_detail]:
        try:
            show_proc = _run_mutmut(["show", key], cwd=repo_dir, timeout_seconds=timeout_seconds)
            diff_text = show_proc.stdout.strip()
        except (subprocess.TimeoutExpired, OSError):
            diff_text = ""
        detail.append(
            SurvivingMutant(
                language=LANGUAGE_PYTHON,
                file=file_path,
                function=func_name,
                status=status,
                diff=diff_text,
                line=_resolve_function_line(repo_dir, file_path, func_name),
            )
        )
    return detail


def run(
    repo_dir: Path,
    changed_files: List[str],
    *,
    timeout_seconds: int,
    max_surviving_detail: int,
) -> LanguageRunResult:
    """changed_files: already filtered to real, non-test *.py files by
    the dispatcher. Always returns status="ran" or "unavailable" --
    Python/mutmut has no "not configured" state the way Stryker/PIT do,
    since mutmut's own source_paths auto-guess (or the target repo's own
    [tool.mutmut] config) means there's always *something* to attempt."""
    existing_files = [f for f in changed_files if (repo_dir / f).is_file()]
    if not existing_files:
        return LanguageRunResult(language=LANGUAGE_PYTHON, status="not_configured")

    _reset_mutmut_cache(repo_dir)
    wildcards = [_wildcard_for(f) for f in existing_files]

    try:
        run_proc = _run_mutmut(["run", *wildcards], cwd=repo_dir, timeout_seconds=timeout_seconds)
    except subprocess.TimeoutExpired:
        return LanguageRunResult(
            language=LANGUAGE_PYTHON, status="unavailable",
            reason=f"mutmut exceeded the {timeout_seconds}s time budget",
        )
    except OSError as e:
        return LanguageRunResult(
            language=LANGUAGE_PYTHON, status="unavailable", reason=f"mutmut could not be invoked: {e}"
        )

    if run_proc.returncode != 0:
        if _NO_MATCH_MARKER in (run_proc.stderr or ""):
            return LanguageRunResult(
                language=LANGUAGE_PYTHON, status="ran",
                scoped_files=existing_files,
                reason=REASON_CODE_NO_COVERABLE_LINES,
            )
        return LanguageRunResult(
            language=LANGUAGE_PYTHON, status="unavailable",
            reason=f"mutmut run failed (exit {run_proc.returncode}): {(run_proc.stderr or '').strip()[:300]}",
        )

    try:
        _run_mutmut(["export-cicd-stats"], cwd=repo_dir, timeout_seconds=timeout_seconds)
        stats_path = repo_dir / "mutants" / "mutmut-cicd-stats.json"
        stats = json.loads(stats_path.read_text(encoding="utf-8"))
    except (subprocess.TimeoutExpired, OSError, ValueError, json.JSONDecodeError):
        return LanguageRunResult(
            language=LANGUAGE_PYTHON, status="unavailable",
            reason="mutmut ran but its results could not be read",
        )

    killed = int(stats.get("killed", 0))
    survived = int(stats.get("survived", 0))
    timeout_ct = int(stats.get("timeout", 0))
    total_generated = int(stats.get("total", 0))

    surviving_detail = (
        _collect_surviving_detail(repo_dir, existing_files, timeout_seconds=timeout_seconds, max_detail=max_surviving_detail)
        if survived or timeout_ct else []
    )

    return LanguageRunResult(
        language=LANGUAGE_PYTHON,
        status="ran",
        killed=killed,
        survived=survived,
        timeout=timeout_ct,
        total_generated=total_generated,
        scoped_files=existing_files,
        surviving_mutants=surviving_detail,
    )
