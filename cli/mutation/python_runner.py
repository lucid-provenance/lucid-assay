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
  - Whole-package generation cost that grows forever, independent of any
    single diff's size: confirmed empirically (2026-09-11, this feature's
    own PR landing itself) that `mutmut run "<wildcard>.*"` only restricts
    which *already-generated* mutants get *tested* -- generation itself is
    driven entirely by the target repo's static, on-disk `only_mutate`
    config (mutmut's own `run --help` has no per-invocation scoping flag
    at all), so every single invocation regenerates mutants for that
    *whole* glob (e.g. this repo's own `cli/*`) regardless of how small
    the current diff is. On this repo's own real feature-landing diff (8
    changed files) this meant 16,366 total mutants generated across the
    whole `cli/` tree, of which only 6,191 (38%) belonged to the actual
    diff -- an untouched file (`sarif.py`) alone contributed 1,950.
    `_scoped_only_mutate()` closes this by temporarily narrowing the
    target repo's own `pyproject.toml` `[tool.mutmut]` `only_mutate` list
    to just this invocation's own diffed files before calling mutmut,
    restoring the original file byte-for-byte afterward (success or
    exception) -- never leaves the target repo's real config modified.
    Falls back to a no-op (unscoped, slower but still correct) when the
    file can't be confidently, narrowly rewritten -- this is a performance
    optimization, never allowed to risk corrupting a target repo's real
    config to save time.
"""
from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, List, Optional

from .common import (
    LANGUAGE_PYTHON,
    LanguageRunResult,
    REASON_CODE_NO_COVERABLE_LINES,
    SurvivingMutant,
)

_NO_MATCH_MARKER = "Filtered for specific mutants, but nothing matches"
_MUTANT_KEY_RE = re.compile(r"^x_(?P<func>.+)__mutmut_\d+$")
_RESULT_LINE_RE = re.compile(r"^\s*(?P<key>\S+):\s*(?P<status>\S+)\s*$")

# Anchors on the [tool.mutmut] table header and captures everything up to
# the next top-level table header (or end of file) -- so an `only_mutate`
# key belonging to some *other* table is never touched.
_TOOL_MUTMUT_SECTION_RE = re.compile(r"(?ms)^\[tool\.mutmut\]\s*$(?P<body>.*?)(?=^\[|\Z)")
_ONLY_MUTATE_LINE_RE = re.compile(r"(?m)^only_mutate\s*=\s*\[[^\]]*\]\s*$")


def _build_scoped_pyproject_text(original_text: str, existing_files: List[str]) -> Optional[str]:
    """Returns pyproject.toml's text with only_mutate narrowed to just
    existing_files, or None when it can't be done with confidence (no
    [tool.mutmut] table, or not exactly one only_mutate assignment inside
    it) -- callers must fall back to the original, unscoped-but-correct
    text rather than guess. json.dumps is used for TOML string quoting: a
    plain file path (this function's only input) never hits a case where
    JSON's and TOML's basic-string escaping rules diverge."""
    section_match = _TOOL_MUTMUT_SECTION_RE.search(original_text)
    if section_match is None:
        return None
    body = section_match.group("body")
    matches = list(_ONLY_MUTATE_LINE_RE.finditer(body))
    if len(matches) != 1:
        return None
    scoped_list = ", ".join(json.dumps(f) for f in existing_files)
    new_line = f"only_mutate = [{scoped_list}]"
    new_body = body[: matches[0].start()] + new_line + body[matches[0].end():]
    start, end = section_match.span("body")
    return original_text[:start] + new_body + original_text[end:]


@contextmanager
def _scoped_only_mutate(repo_dir: Path, existing_files: List[str]) -> Iterator[None]:
    """Temporarily narrows the target repo's own pyproject.toml
    [tool.mutmut] only_mutate list to just this invocation's diffed files
    -- see this module's own "Hardened against" docstring for why this
    exists. Restores the original file byte-for-byte on exit, success or
    exception. A no-op (yields without any modification) when the file is
    unreadable or can't be confidently, narrowly rewritten."""
    pyproject_path = repo_dir / "pyproject.toml"
    try:
        original_text = pyproject_path.read_text(encoding="utf-8")
    except OSError:
        yield
        return
    scoped_text = _build_scoped_pyproject_text(original_text, existing_files)
    if scoped_text is None or scoped_text == original_text:
        yield
        return
    pyproject_path.write_text(scoped_text, encoding="utf-8")
    try:
        yield
    finally:
        pyproject_path.write_text(original_text, encoding="utf-8")


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
    base_sha: Optional[str] = None,
) -> LanguageRunResult:
    """changed_files: already filtered to real, non-test *.py files by
    the dispatcher. `base_sha` is unused here -- mutmut is scoped via a
    wildcard built from changed_files, not a git diff of its own (only
    go_runner.py's gremlins integration does its own diffing) -- accepted
    for a uniform dispatcher calling convention across every runner.
    Always returns status="ran" or "unavailable" -- Python/mutmut has no
    "not configured" state the way Stryker/PIT do,
    since mutmut's own source_paths auto-guess (or the target repo's own
    [tool.mutmut] config) means there's always *something* to attempt."""
    existing_files = [f for f in changed_files if (repo_dir / f).is_file()]
    if not existing_files:
        return LanguageRunResult(language=LANGUAGE_PYTHON, status="not_configured")

    _reset_mutmut_cache(repo_dir)
    wildcards = [_wildcard_for(f) for f in existing_files]

    # Scoped for the *entire* generate-run-through-read-results sequence,
    # not just the "run" subcommand: every mutmut subcommand this module
    # calls (run/export-cicd-stats/results/show) is its own subprocess that
    # independently reloads pyproject.toml (confirmed empirically -- each
    # calls Config.ensure_loaded() on startup), so restoring the original,
    # unscoped file before those later calls could hand them a config
    # inconsistent with what was actually generated.
    with _scoped_only_mutate(repo_dir, existing_files):
        return _run_scoped(
            repo_dir, existing_files, wildcards,
            timeout_seconds=timeout_seconds, max_surviving_detail=max_surviving_detail,
        )


def _run_scoped(
    repo_dir: Path,
    existing_files: List[str],
    wildcards: List[str],
    *,
    timeout_seconds: int,
    max_surviving_detail: int,
) -> LanguageRunResult:
    """The generate/run/read-results sequence proper, factored out of run()
    so the pyproject.toml scoping context manager can wrap it as a whole."""
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
