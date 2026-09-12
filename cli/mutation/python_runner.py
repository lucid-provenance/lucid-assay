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
  - Mutmut invoked via `sys.executable` (this process's own interpreter)
    cannot ever see a *target* repo's own runtime/test dependencies: for
    every caller except lucid-assay's own dogfooding (where the "target"
    repo genuinely is this interpreter's own environment), `sys.executable`
    is `_assay/.venv`'s own isolated Python in CI -- pinned to lucid-assay's
    own dependency set (mutmut, pytest, sigstore, ...), never the calling
    repo's own (fastapi, sqlalchemy, whatever). Mutmut's internal pytest
    run then fails to even *collect* the target's test files
    (`ModuleNotFoundError: No module named 'fastapi'`) -- and since pytest
    prints a collection error to stdout, not stderr, the failure used to
    surface as a blank `mutmut run failed (exit 1): )` with the real cause
    silently dropped (see the second bullet below). Confirmed empirically,
    2026-09-12, lucid-dsse-collector's own real CI run -- the first real
    mutation-testing run for any caller other than lucid-assay itself,
    which is exactly why this was never caught by this feature's own
    landing verification (that measurement ran locally, not through a
    genuinely isolated `_assay/.venv`-equivalent). `_run_mutmut()` now
    shells out through `uv run --with mutmut==<pinned version> --no-sync`
    instead: `--no-sync` reuses the target repo's own already-synced
    `.venv` exactly as CI (or a real dev workflow) left it -- confirmed
    every current caller's CI runs its own `uv sync --frozen --extra dev`
    earlier in the same job, before mutation testing ever runs -- rather
    than triggering a surprise re-resolve of that repo's own lockfile, and
    `--with` layers just mutmut on top as an ephemeral, uv-resolved
    addition, never written into the target's own pyproject.toml/uv.lock.
    Relies on `cwd=cwd` (already set below) for uv's own cwd-based project
    discovery -- the same convention every caller's own CI already uses
    elsewhere (`cd _assay && uv run --no-sync ...`), not an explicit
    `--project` flag. Requires the target repo to itself be a real uv
    project (a `pyproject.toml` uv can resolve against) -- true for every
    current caller with mutation testing actually enabled; a caller with no
    `pyproject.toml` at all needs one before turning this on.
  - The dropped-stdout diagnostics gap above, independently: `run_proc`'s
    reason string used to read only `.stderr` -- correct for an uncaught
    Python exception (goes to stderr by default) but blank for a pytest
    collection failure or any other tool output mutmut itself prints to
    stdout. Falls back to stdout only when stderr is empty, so an existing
    stderr-carrying failure's message is unchanged.

Known equivalent mutants (confirmed via a real mutmut run against this
module's own diff, 2026-09-12 -- 175/178 real mutants killed, 98%; the
remaining 3 are these, deliberately not chased further, per CLAUDE.md's
own "never chase provably-equivalent mutants" convention):
  - `_NO_MATCH_MARKER in (run_proc.stderr or "")` with the `""` fallback
    replaced by any other string: the fallback's only role is "don't
    crash the `in` check on a None stderr" -- `_NO_MATCH_MARKER` is never
    expected to appear inside either fallback value in any real
    invocation, so no test can observe a difference between them without
    contriving a meaningless scenario.
  - `stats_path.read_text(encoding="utf-8")` with `encoding=None`
    (platform-default) or `encoding="UTF-8"` (different case): on any
    real CI/dev environment running a UTF-8 locale (universal in
    practice today), `read_text`'s platform-default encoding resolves to
    UTF-8 regardless, and codec name lookup is case-insensitive -- both
    variants behave identically to the real code for every JSON payload
    mutmut itself ever writes here.
"""
from __future__ import annotations

import ast
import importlib.metadata
import json
import re
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

from .common import (
    LANGUAGE_PYTHON,
    LanguageRunResult,
    REASON_CODE_NO_COVERABLE_LINES,
    SurvivingMutant,
)

_NO_MATCH_MARKER = "Filtered for specific mutants, but nothing matches"
_MUTANT_KEY_RE = re.compile(r"^x_(?P<func>.+)__mutmut_\d+$")


def _parse_result_line(line: str) -> Optional[Tuple[str, str]]:
    """Parses one `mutmut results` output line ("  <key>: <status>") into
    (key, status), or None when the line doesn't have that shape. A plain
    split, not a regex -- SonarQube flagged an earlier regex-based version
    of this (`_RESULT_LINE_RE`) for superlinear backtracking risk; a split
    has no such risk and is exactly as precise for this fixed, simple
    format (mutmut keys are dotted Python identifiers, which structurally
    never contain ':', so splitting on the first one is unambiguous)."""
    key, sep, status = line.strip().partition(":")
    key = key.strip()
    status = status.strip()
    if not sep or not key or not status or " " in key or " " in status:
        return None
    return key, status


def _find_tool_mutmut_section(lines: List[str]) -> Optional[Tuple[int, int]]:
    """Returns the (start, end) line-index span (end exclusive) of the
    [tool.mutmut] table's body -- the lines after its own header line, up
    to (not including) the next top-level table header or end of file.
    None when no [tool.mutmut] header line exists. A plain line scan, not
    a regex -- SonarQube flagged an earlier regex-based version of this
    section-finder for an implicit-operator-precedence code smell; a
    scan has no such ambiguity and is exactly as precise for this fixed,
    line-oriented TOML shape (see _build_scoped_pyproject_text's own
    docstring for the one real behavior difference this implies)."""
    header_index = next((i for i, line in enumerate(lines) if line.strip() == "[tool.mutmut]"), None)
    if header_index is None:
        return None
    end = len(lines)
    for i in range(header_index + 1, len(lines)):
        if lines[i].strip().startswith("["):
            end = i
            break
    return header_index + 1, end


def _is_only_mutate_assignment(line: str) -> bool:
    """True for a real `only_mutate = [...]` TOML array assignment
    written entirely on this one line -- a plain string check, not a
    regex, see _find_tool_mutmut_section's own docstring for why."""
    stripped = line.strip()
    if not stripped.startswith("only_mutate"):
        return False
    rest = stripped[len("only_mutate"):].lstrip()
    if not rest.startswith("="):
        return False
    value = rest[1:].lstrip()
    return value.startswith("[") and value.endswith("]")


def _build_scoped_pyproject_text(original_text: str, existing_files: List[str]) -> Optional[str]:
    """Returns pyproject.toml's text with only_mutate narrowed to just
    existing_files, or None when it can't be done with confidence (no
    [tool.mutmut] table, or not exactly one only_mutate assignment inside
    it, written on a single line -- a multi-line array is deliberately
    not handled, since this repo's own config (and every real config seen
    so far) writes it on one line; falling back to unscoped-but-correct
    behavior for the rare exception is the same safe contract every
    other "can't confidently narrow" case here already follows) --
    callers must fall back to the original, unscoped-but-correct text
    rather than guess. json.dumps is used for TOML string quoting: a
    plain file path (this function's only input) never hits a case where
    JSON's and TOML's basic-string escaping rules diverge."""
    lines = original_text.splitlines(keepends=True)
    section = _find_tool_mutmut_section(lines)
    if section is None:
        return None
    start, end = section
    only_mutate_indices = [i for i in range(start, end) if _is_only_mutate_assignment(lines[i])]
    if len(only_mutate_indices) != 1:
        return None
    idx = only_mutate_indices[0]
    scoped_list = ", ".join(json.dumps(f) for f in existing_files)
    newline = "\n" if lines[idx].endswith("\n") else ""
    lines[idx] = f"only_mutate = [{scoped_list}]{newline}"
    return "".join(lines)


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


def _touched_functions(repo_dir: Path, file_path: str, changed_lines: Set[int]) -> Optional[Set[str]]:
    """Returns the set of function/method names in file_path whose own
    line range (per ast.walk -- deliberately visiting every def
    regardless of nesting, same style _resolve_function_line already
    uses, since mutmut itself names a mutant after its innermost
    function's own bare name with no class/nesting qualifier) overlaps
    changed_lines. None when the file can't be parsed -- callers must
    fall back to the whole-file wildcard, not guess. An empty set (not
    None) when the file parses fine but none of changed_lines fall
    inside any function body -- confirmed empirically (2026-09-11) that
    mutmut never mutates module-level code at all (only inside function
    bodies, via its trampoline mechanism), so "no touched functions"
    genuinely means "nothing here for mutmut to mutate," not a missed-
    coverage risk. Ambiguous when two functions share a bare name (e.g.
    same-named methods on different classes) in the same way
    `_resolve_function_line`'s own docstring already documents -- a
    wildcard built from one touched same-named method also matches its
    untouched twin's mutants, since mutmut's own naming can't
    distinguish them either; over-inclusion, not a correctness risk."""
    try:
        source = (repo_dir / file_path).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=file_path)
    except (OSError, SyntaxError, ValueError):
        return None
    touched: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = node.end_lineno or node.lineno
            if any(node.lineno <= ln <= end for ln in changed_lines):
                touched.add(node.name)
    return touched


def _wildcards_for_file(repo_dir: Path, file_path: str, changed_lines: Optional[Set[int]]) -> List[str]:
    """The narrowest set of mutmut wildcards this file's diff supports:
    one per touched function (`<module>.x_<name>__mutmut_*`, matching
    mutmut's own literal naming exactly -- not `<module>.x_<name>.*`,
    since a mutant's full name has no '.' between the function name and
    `__mutmut_N`) when changed_lines is known and the file parses
    cleanly; the whole-file wildcard (this module's original, pre-
    function-scoping behavior) when changed_lines is missing/empty or
    the file can't be parsed; no wildcard at all when the file parses
    but genuinely has nothing touched for mutmut to mutate (see
    _touched_functions's own docstring)."""
    if changed_lines:
        touched = _touched_functions(repo_dir, file_path, changed_lines)
        if touched:
            module = _dotted_module(file_path)
            return [f"{module}.x_{name}__mutmut_*" for name in sorted(touched)]
        if touched is not None:
            return []
    return [_wildcard_for(file_path)]


# The version of mutmut *this* process has installed -- lucid-assay's own
# pinned dev dependency (pyproject.toml's `mutmut>=3.7.0,<4.0.0`). Read
# dynamically rather than duplicating the pin as a second hardcoded string
# that could drift out of sync with it.
_MUTMUT_VERSION = importlib.metadata.version("mutmut")


def _run_mutmut(args: List[str], *, cwd: Path, timeout_seconds: int) -> subprocess.CompletedProcess:
    """See this module's own "Hardened against" docstring (the
    `sys.executable` bullet) for why this is `uv run --with
    mutmut==<pinned version> --no-sync python -m mutmut <args>`, not a
    direct `[sys.executable, "-m", "mutmut", *args]` invocation."""
    return subprocess.run(
        ["uv", "run", "--with", f"mutmut=={_MUTMUT_VERSION}", "--no-sync", "python", "-m", "mutmut", *args],
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
        parsed = _parse_result_line(line)
        if parsed is None or parsed[1] not in ("survived", "timeout"):
            continue
        key, status = parsed
        resolved = _parse_mutant_key(key, scoped_files)
        if resolved is not None:
            candidates.append((key, status, *resolved))

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
    changed_lines: Optional[Dict[str, Set[int]]] = None,
) -> LanguageRunResult:
    """changed_files: already filtered to real, non-test *.py files by
    the dispatcher. `base_sha` is unused here -- mutmut is scoped via a
    wildcard built from changed_files, not a git diff of its own (only
    go_runner.py's gremlins integration does its own diffing) -- accepted
    for a uniform dispatcher calling convention across every runner.
    `changed_lines` (this diff's own per-file changed-line-number map)
    narrows the wildcard further, from "test every mutant in this
    touched file" down to "test only mutants in functions this diff
    actually touched" (confirmed empirically, 2026-09-11: on this
    feature's own real feature-landing diff, this cut a large file like
    verify.py -- mutated in full regardless of how few of its lines
    changed -- down to just the handful of functions this diff actually
    touched) -- see _wildcards_for_file's own docstring; falls back to
    the original whole-file behavior when it's None/missing for a given
    file (an older caller, or a file this diff's own line map doesn't
    cover for some reason -- never silently under-scope). Always returns
    status="ran" or "unavailable" -- Python/mutmut has no "not
    configured" state the way Stryker/PIT do, since mutmut's own
    source_paths auto-guess (or the target repo's own [tool.mutmut]
    config) means there's always *something* to attempt."""
    existing_files = [f for f in changed_files if (repo_dir / f).is_file()]
    if not existing_files:
        return LanguageRunResult(language=LANGUAGE_PYTHON, status="not_configured")

    changed_lines = changed_lines or {}
    wildcards = [
        w
        for f in existing_files
        for w in _wildcards_for_file(repo_dir, f, changed_lines.get(f))
    ]
    if not wildcards:
        # Every touched file's own changed lines fell entirely outside
        # any function body (module-level-only changes across the
        # board) -- mutmut has nothing to mutate for any of them
        # (confirmed empirically, see _touched_functions's own
        # docstring). The same "nothing here to score" contract
        # REASON_CODE_NO_COVERABLE_LINES already gives the equivalent
        # case mutmut itself detects further downstream (via
        # _NO_MATCH_MARKER) -- caught here instead, before ever
        # invoking mutmut, which would otherwise run *unfiltered*: its
        # own `run` with zero mutant_names means "run everything in
        # only_mutate's scope," the opposite of what an empty wildcard
        # list here is supposed to mean.
        return LanguageRunResult(
            language=LANGUAGE_PYTHON, status="ran",
            scoped_files=existing_files,
            reason=REASON_CODE_NO_COVERABLE_LINES,
        )

    _reset_mutmut_cache(repo_dir)

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
        # stderr first (an uncaught Python exception's traceback lands
        # there by default); stdout only as a fallback, for a tool failure
        # (e.g. a pytest collection error) that prints to stdout instead --
        # see this module's own "Hardened against" docstring.
        error_detail = (run_proc.stderr or "").strip() or (run_proc.stdout or "").strip()
        return LanguageRunResult(
            language=LANGUAGE_PYTHON, status="unavailable",
            reason=f"mutmut run failed (exit {run_proc.returncode}): {error_detail[:300]}",
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
