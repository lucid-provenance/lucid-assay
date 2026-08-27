# Tenax Assay — Continuous Governance Control Plane (Foundation)

MVP foundation for bridging CI/CD execution to SOC 2 / FedRAMP / ISO 27001
evidence: cryptographically signed in-toto attestations of test, coverage,
static-analysis, and governance state, computed on the runner and stored
content-addressed in WORM storage — plus the admission gatekeeper that
verifies those attestations before a deploy/merge is allowed to proceed.

## Layout

```
schema/
  tenax-attestation-v1.schema.json    # in-toto predicate JSON Schema
cli/
  common.py                 # safe_resolve_path(): path-safety guard shared by every module below that opens an operator-supplied file
  parsers/junit.py          # streaming JUnit XML -> TestTotals (flaky-retry aware)
  parsers/coverage.py       # Cobertura XML + LCOV -> CoverageReport (per-line hit maps)
  parsers/ast_inspector.py  # backward-compat shim -> re-exports parsers/ast/
  parsers/ast/              # multi-language assertion integrity engine (registry/dispatcher)
    __init__.py                # inspect_test_suite(): discovery + per-language aggregation
    common.py                  # shared dataclasses (TestFunctionMetrics, TestSuiteMetrics, ...)
    python_visitor.py          # reference standard: stdlib `ast`, test_*.py / *_test.py
    tsjs_visitor.py             # Tree-sitter TS/JS: Jest/Vitest/Mocha, *.test.*/*.spec.*/__tests__/
    go_visitor.py                # Tree-sitter Go: testing.T + testify, *_test.go
    java_visitor.py               # Tree-sitter Java: JUnit 4/5, AssertJ, Hamcrest, *Test(s).java
  parsers/sarif.py          # SARIF 2.1.0 ingestion -> differential (patch vs. legacy) findings
  parsers/github_rules.py   # GitHub branch protection/ruleset inspection via REST API
  parsers/commit_author.py  # GitHub commit-author identity (verified account) via REST API
  parsers/lockfiles.py      # uv.lock/package-lock.json/go.sum/Gradle/Maven -> resolved_dependencies
  patch_coverage.py         # git diff base...head, intersected with coverage hit maps
  hashing.py                 # SHA-256 content hashing + WORM key derivation
  scorer.py                  # pure, deterministic Release Confidence Score (RCS)
  builder.py                 # assembles the unsigned in-toto Statement
  slsa_provenance.py          # assembles a *separate*, real SLSA v1.0 provenance Statement (--emit-slsa-provenance)
  oidc_signer.py              # ambient OIDC -> Fulcio cert -> DSSE sign -> Rekor log
  sign.py                      # `tenax-assay sign <file>`: standalone signing subcommand for an isolated attest job
  verify.py                   # admission gatekeeper: DSSE decode + Sigstore identity + policy gates
  main.py                     # CLI entrypoint wiring it all together (`tenax-assay verify` dispatches to verify.py)
tests/
  test_scorer.py               # adversarial edge-case tests for the RCS algorithm
  test_patch_coverage.py        # git-diff/coverage intersection + reason_code tests (real git repo)
  test_builder.py               # in-toto Statement assembly tests
  test_ast_inspector.py          # real/tautological/empty assertion detection tests (Python)
  test_adversarial_ast.py         # adversarial bypass suite for the Python AST visitor
  test_ast_assertions.py           # multi-language engine: fixtures, per-language heuristics,
                                    # registry dispatch, and DSSE predicate telemetry tests
  test_sarif.py                    # SARIF parsing, path-matching, and fail-closed aggregation tests
  test_github_rules.py              # branch governance API client tests (auth, pagination, bypass modes)
  test_commit_author.py              # commit-author identity API client tests (SLSA Source Level 3)
  test_verify.py                     # DSSE/Sigstore verification + policy-gate tests
  test_verify_boundaries.py           # verify.py hardening/edge-case suite
  test_verify_hardening.py             # envelope size guard, diagnostic schema validation, OIDC fetch retry
  test_security_boundaries.py          # cross-cutting adversarial-input suite
  test_common_path_safety.py            # safe_resolve_path() + its wiring into every open()/getsize() call site
  test_slsa_provenance.py               # SLSA v1.0 provenance builder: ground-truth/fail-closed tests, and proof
                                         # a genuine statement satisfies cli/verify.py's SLSA Level 1/2 checklist
  test_sign.py                          # `tenax-assay sign` CLI + cli.oidc_signer.sign_file_to_envelope tests
  fixtures/                             # sample cobertura.xml and a rendered statement
  fixtures/ast_assertions/                # per-language source-text fixtures for the AST engine
                                           # (python/, typescript/, javascript/, go/, java/) --
                                           # excluded from pytest's own collection, see
                                           # [tool.pytest.ini_options] in pyproject.toml
```

## Why this decomposition

Every module is a pure function or a thin, swappable I/O boundary:

- `parsers/*` and `scorer.py` have **zero network or filesystem side
  effects beyond reading the one file they're given** — they're the
  pieces auditors and adversarial tests will hammer on, so they're kept
  trivially unit-testable in isolation. `parsers/github_rules.py` is the
  one exception (it's a live GitHub API client by necessity), which is why
  it's the most defensively written module in the repo — see below.
- `common.py::safe_resolve_path()` is the one path-safety choke point every
  module reads an operator-supplied file through (`--junit-xml`,
  `--coverage-report`, `--sarif`, `--sonar-metrics`, `--out`, the `verify`
  envelope argument, plus `hashing.py`'s evidence-artifact hashing and
  `patch_coverage.py`'s `--repo-dir` as `subprocess.run()`'s `cwd`):
  resolves to an absolute, symlink-normalized `Path`
  and rejects null bytes/malformed input before it ever reaches
  `open()`/`os.path.getsize()`/`ET.parse()`. It does not enforce a single
  root/allowlist directory — these are CLI arguments an operator supplies
  at invocation time, the same as any file-taking CLI tool's, not
  attacker-controlled remote input — so this guards against a value that
  can't safely become a real filesystem path at all, not "escaping" a
  directory that was never fixed to begin with.
- `oidc_signer.py` and the WORM upload path in `main.py` are the **only**
  network-touching pieces in the *ingestion* pipeline, and they're isolated
  so the <50ms blocking budget can be measured and enforced on everything
  *except* them.
- `builder.py` is pure data transformation (parsed structs -> schema-shaped
  dict), so schema-conformance can be checked in this repo's own CI with a
  plain `jsonschema.validate()` against every sample statement it emits.
- `verify.py` is the standalone admission-side counterpart: it never trusts
  its input (a DSSE envelope from anywhere) and never raises on malformed or
  hostile data — every failure mode becomes a `violations`/`warnings` entry
  on its result instead of an exception, so a CI gate calling it always gets
  a clean pass/fail exit code.

## Performance contract

Measured in this sandbox on the sample fixtures (4 test cases, 1 class):

| Stage | Time |
|---|---|
| JUnit XML parse | ~0.5ms |
| Cobertura XML parse | ~0.1ms |

Both scale sub-linearly-enough with `iterparse` + immediate `elem.clear()`
(JUnit) and a single-pass line scan (LCOV) that multi-thousand-testcase
reports should stay well under the 50ms budget; the `main.py` entrypoint
self-measures and emits a `WARNING` to stderr if the budget is exceeded
on a given run, rather than silently drifting.

Two things are **explicitly excluded** from the 50ms budget, on purpose:
1. **Signing** (`--sign`): a real network round-trip to Fulcio + Rekor
   (~200-800ms typical). Bundling this into "ingestion overhead" would
   either blow the budget or pressure someone into skipping Rekor
   submission to hit a number — neither is acceptable, so it's metered
   separately.
2. **WORM upload**: fired via `ThreadPoolExecutor` and never awaited in
   the hot path. Integrity doesn't depend on the upload finishing before
   the CI step returns, because the DSSE envelope embeds a locally
   computed SHA-256 of the artifact; a separate reconciliation job
   verifies every hash referenced in a signed attestation eventually
   lands in WORM storage, and pages on drift past an SLA window. (The
   upload body itself is still an unimplemented integration point — see
   "Not yet built" below.)

Branch governance (`parsers/github_rules.py`) and SARIF ingestion are
network/filesystem calls that also happen inside `main.py`'s pipeline but
are **not** covered by the 50ms budget or its warning — the budget only
tracks parse+score+build, matching what the perf table above measures.

### Stage timing diagnostics (`--debug`)

`--debug` emits a high-resolution (`time.perf_counter_ns()`) per-stage
breakdown to stderr after a run, for diagnosing where wall-clock time
actually goes in a slow CI job (this is additive — output is identical to
a normal run when `--debug` is omitted):

```text
=== Tenax Assay Stage Profiling ===
- Inputs & Parsing:                 0.2 ms
- Diff & Patch Coverage:            0.0 ms
- AST Assertion Walking:           36.6 ms
- GitHub Ruleset API:             182.0 ms
- RCS Scoring Engine:               0.0 ms
- Lockfile Dependency Detection:     0.8 ms
- Predicate Serialization:          0.1 ms
- WORM Upload Dispatch:              0.4 ms
- Sigstore Signing (Total):    24,120.0 ms
    ↳ OIDC Token Fetch:            150.0 ms
    ↳ Fulcio/Rekor Round-Trip:  23,970.0 ms
Total Blocking Overhead:         219.3 ms (excluding Sigstore network)
Total Wall-Clock Time:            24.34 s
====================================
```

Stages map onto the pipeline steps in `main.py`'s numbered comments:
`parse_inputs` (JUnit + coverage + SARIF parsing — the SARIF portion is
timed where it actually runs, after patch analysis, but still reported
under this one line since it's still "parsing"), `diff_patch_analysis`
(`git diff`-based patch coverage, plus the separate diff SARIF uses to
cross-reference changed lines), `ast_inspection`, `github_rules_api`,
`rcs_scoring`, `lockfile_dependencies` (auto-detects and parses uv.lock/
package-lock.json/go.sum/Gradle/Maven locks under `--repo-dir` into the
predicate's `resolved_dependencies` -- independent of RCS scoring, feeds
only predicate assembly), `predicate_assembly`, and `worm_upload` (the
fire-and-forget dispatch cost only, not the background upload itself).
`Total Blocking Overhead` is the same figure the 50ms budget check above
measures — it does not change based on `--debug`.

Sigstore signing (`--sign`/`--dry-run-sign`) is broken out separately by
`cli/oidc_signer.py::sign_statement`'s `timing` param into ambient OIDC
token acquisition and the Fulcio-cert-issuance/Rekor-inclusion round trip.
That round trip is a real network call made through `Signer.sign_dsse()`
in-process — **not** a `python3 -m sigstore sign` subprocess; see
"Why this decomposition" below for why a CLI subprocess can't produce a
usable DSSE envelope here at all, so profiling deliberately measures the
actual code path rather than reintroducing one just to time it.

## Deterministic scoring (RCS)

`cli/scorer.py` computes a weighted rollup of **six** components (pure
function of its inputs — no I/O, no clock/randomness beyond the `reason`
strings, so identical inputs always produce an identical score):

| Component | Weight | Edge case handling |
|---|---|---|
| Test health | 35% | `pass_rate = passed / (passed+failed+errored)`. Zero executed tests **floors to 0** with an explicit reason distinguishing "all skipped" from "broken/bypassed gate" (never a neutral default — a broken test gate is a strong negative signal). Flaky retries (same `classname`+`name` seen more than once, final attempt passed) penalize 4pts/case, capped at −30, without being able to zero the run outright. |
| Patch coverage | 20% | Line-rate over just the lines touched by `git diff base...head`, intersected with the coverage report's hit map. Unavailable (no base SHA, or a docs/config-only diff with zero coverable changed lines) **falls back to overall coverage × 0.70**, and flags the whole result `degraded: true` — a proxy signal can never outscore the real measurement it's standing in for. A docs/config-only diff is tagged with its own `reason_code` (`no_coverable_lines`), since there's no code in it for coverage to be missing over — see `--disallow-degraded` below. |
| Overall coverage | 15% | Straight line-rate vs. configurable threshold (default 0.60). |
| Assertion integrity | 10% | `assertions / test_functions` normalized against a target density (1.5), capped at 100; zero test functions floors to 0. Fed by the multi-language AST engine (below), which filters out tautological/empty assertions — and excludes skipped/disabled tests entirely, from every supported language — before counting. |
| Governance | 15% | No PR/MR context scores a **neutral 50**, not full credit, and flags `degraded`. `changes_requested` and unresolved zeroes the component outright; a required-approvals count of 0 caps at 60 (flagged as a weak control). Independently, a **live GitHub branch-governance check** docks −35pts if it finds the branch would let the same change land unreviewed regardless of this PR's own state (see below) — **and docks the same −35pts if that check couldn't run at all** (missing/invalid `GITHUB_TOKEN`, API failure, or GitHub's own plan/visibility feature gate on rulesets), so omitting the token is never a cheaper way to dodge the penalty than a confirmed bypass. |
| Static analysis (SARIF) | 5% | No `--sarif` configured → full 100 (a control that was never invoked isn't penalized). Configured but unreadable/corrupt → −25pts, fails closed. Otherwise: **new-in-patch errors** cost 25pts each, **new-in-patch warnings** 5pts each, **pre-existing/legacy errors** cost only 2pts each capped at −15 total — gates hard on regressions *introduced by this diff* without making a legacy-heavy repo unshippable on day one. |

Every component's `reason` string is embedded verbatim in the predicate's
`release_confidence_score.components[*].reason` — an auditor reading the
signed JSON never has to reverse-engineer why a run scored what it did. A
separate top-level `degraded: true` flag (distinct from the score itself)
is set whenever any component fell back to a proxy or a check couldn't be
verified — a 95/100 that's quietly degraded stays visibly distinguishable
from a clean 95. Alongside it, `degraded_reasons` lists *which* independent
trigger(s) fired (`patch_coverage_unavailable` / a namespaced
`patch_coverage:<reason_code>` for a specific known cause,
`no_pr_context`, `sarif_unavailable`, `branch_governance_unverified` / a
namespaced `branch_governance:<reason_code>` when the governance check
identifies a specific known cause, or
`branch_governance_bypass_permitted`) — a run can be degraded for more
than one reason at once, and each shows up as its own entry, not a
single opaque flag. NaN/Inf arithmetic anywhere in the pipeline clamps
to the score floor rather than propagating.

Run the edge-case suite:

```bash
python3 -m unittest tests.test_scorer -v
```

## The other checks feeding RCS

**`parsers/junit.py`** streams `<testcase>` elements via `iterparse` +
`elem.clear()` so memory stays O(1) regardless of report size. Cases are
keyed by `(classname, name)`; more than one recorded attempt with a
passing final outcome is what "flaky" means here — only the final attempt
counts toward pass/fail/error/skip totals.

**`parsers/coverage.py`** parses Cobertura XML and LCOV into a common
`CoverageReport`, normalizing file paths (stripping absolute prefixes and
`./` tokens) so they can be matched against git-diff paths downstream. All
rates are clamped to `[0.0, 1.0]`; malformed attributes degrade to `0`
rather than raising.

**`patch_coverage.py`** runs `git diff --unified=0 base...head` and walks
hunk headers to get exactly the added/modified line numbers per file, then
intersects that against the coverage report's per-line hit map. Handles
the common mismatch where a coverage tool keys files relative to a
configured source root (e.g. Cobertura's `verify.py` under `<source>cli</source>`)
versus git's repo-root-relative path (`cli/verify.py`) via suffix-matching
on path components — an ambiguous tie is treated as no match rather than
guessed at. Hardened against git CLI option injection (`--end-of-options`
before the revision range) and quoted/escaped filenames in diff headers.
`base_sha`/`head_sha` are additionally validated against a strict
allowlist regex (`^[a-zA-Z0-9_./-]+$`) before ever reaching
`subprocess.run()` — defense in depth on top of, not instead of,
`--end-of-options`; every `subprocess.run()` call here takes a list of
argv tokens, never a shell string, so `shell=True`/shell metacharacter
injection isn't reachable to begin with. `--repo-dir` (`subprocess.run()`'s
`cwd`) gets the same treatment via `common.safe_resolve_path()` — it's as
real a subprocess argument as the argv list, not just an incidental
working-directory string. A ref or path that fails validation degrades
exactly like a failed `git diff` would (`available=False`, or an empty
mapping from `compute_patch_modified_lines`), never a raw crash.

**`parsers/ast/`** is a language-agnostic registry/dispatcher for assertion
integrity: `inspect_test_suite()` discovers test files across four
languages by naming convention (mutually exclusive, so file ownership is
unambiguous — see the package docstring), hands each to its visitor, and
aggregates the results into one `TestSuiteMetrics`, both overall and
per-language (`TestSuiteMetrics.languages`, embedded in the DSSE predicate
as `assertion_density.languages`). `parsers/ast_inspector.py` remains as a
thin backward-compatible shim re-exporting the same names.

- **`python_visitor.py`** (the reference standard, stdlib `ast`) walks every
  `test_*`/`*_test` function — including `unittest.TestCase` methods — and
  distinguishes real assertions from bogus ones via compile-time constant
  folding: `assert True`, `assert 1 == 1`, `assert x == x` (self-comparison),
  `assertTrue(True)`, `assertEqual(x, x)`, and bare truthy literals/collections
  are all caught as tautological. It also recognizes non-`assert` real-check
  idioms (`unittest.mock`'s allowlisted snake_case API, non-empty
  `pytest.raises`/`warns` blocks, PyHamcrest's `assert_that`, Chai/Jasmine-style
  `expect(x).to_equal(...)`) and flags empty bodies (`pass`/`...`/docstring-only)
  and `@skip`/`@skipif`/`@unittest.skip*`-decorated tests separately. Traversal
  is scope-aware: it never descends into a nested `def`/`lambda`/`class` inside
  a test body, and prunes statically-dead `if False:` branches and `try` bodies
  whose `except (AssertionError, ...): pass` would silently swallow a failed
  check — none of that unreachable code is credited or blamed.
- **`tsjs_visitor.py`** (Tree-sitter `tree-sitter-typescript`/
  `tree-sitter-javascript`) covers `.ts`/`.tsx`/`.js`/`.jsx`/`.mjs`/`.cjs`
  files matching Jest/Vitest/Mocha's own discovery conventions
  (`*.test.*`, `*.spec.*`, anything under `__tests__/`). Recognizes
  `expect(x).toBe/toEqual/toStrictEqual(y)` chains — including
  `.not`/`.resolves`/`.rejects` passthrough, where `.not` disables the
  tautology check outright rather than inverting it — plus bare
  Node `assert(x)` and chai's `assert.equal`/`.isTrue`/`.isFalse`/etc.
  `it.skip`/`test.skip`/`xit`/`xtest`/`it.todo` are tracked as skipped, not
  zero-assertion. Descends into inline arrow/function-expression callbacks
  (`.then(...)`, `.forEach(...)`) since those run synchronously as part of
  the test, but not into a named, unin­voked `function` declaration.
- **`go_visitor.py`** (Tree-sitter `tree-sitter-go`) covers `*_test.go`,
  matching `func TestXxx(t *testing.T)` declarations. Recognizes
  `t.Error/Errorf/Fatal/Fatalf/Fail/FailNow` and testify's
  `assert.*`/`require.*` (tautology-checked for `True`/`False`/`Equal`/`Same`
  with the leading `t` argument offset accounted for). A test is tracked as
  skipped only when `t.Skip`/`Skipf`/`SkipNow` is its very first statement —
  a *conditional* skip further down the body does not suppress the rest of
  the test's real assertions from counting. Descends into `func_literal`
  bodies (table-driven `t.Run(...)` subtests), unlike the Python visitor's
  nested-`def` pruning, since Go closures can't be declared without being
  used.
- **`java_visitor.py`** (Tree-sitter `tree-sitter-java`) covers
  `*Test.java`/`*Tests.java`/`*TestCase.java`, matching `@Test`-annotated
  methods (JUnit 4 and 5, matched by annotation name alone — no import
  resolution). Recognizes JUnit static/qualified `assertEquals`/`assertTrue`/
  `assertNotNull`/etc., AssertJ's `assertThat(x).isEqualTo/isTrue/isFalse(...)`
  fluent chains (evaluated at the chain's outermost call so
  `assertThat(x)` isn't double-counted as its own assertion), and
  Hamcrest's non-chained `assertThat(x, matcher)`. `@Disabled`/`@Ignore`
  (bare or fully-qualified) mark a method skipped.

Every visitor tracks skipped/disabled tests in their own bucket
(`TestSuiteMetrics.skipped_test_functions`, embedded as
`assertion_density.heuristics.ast_skipped_test_functions`) rather than
folding them into "zero-assertion" — a test a human explicitly disabled is
a different signal than one that ran and asserted nothing.

**Scoring note:** skip detection is new for Python too (the single-language
engine this replaced had none). A repo whose Python suite uses
`@pytest.mark.skip`/`@unittest.skip*` will now compute a different
`assertion_integrity` component than before this change — skipped tests no
longer drag the density average down (or, previously, silently inflate it
if a disabled test's dead body still contained real-looking assertions).
This is intentional and disclosed here, not a regression: a test that
never ran shouldn't count either way. If every test function in scope is
skipped, `total_test_functions` is `0` and the component's `reason`
distinguishes that ("no non-skipped test functions ... (N skipped/disabled)")
from the genuinely-no-tests-exist case.

**`parsers/sarif.py`** ingests one or more `--sarif` 2.1.0 reports (semgrep,
trivy, CodeQL, SonarQube, ESLint, ...), normalizing `level` (`error`/
`warning`/`note`/`none`; missing defaults to `warning` per spec) and
artifact paths, then cross-references each finding's file/line against the
diff's changed lines to flag `is_new_in_patch`. Aggregation across multiple
`--sarif` inputs **fails closed**: one unreadable/corrupt input taints the
whole aggregate to `available=False` rather than silently scoring on the
good subset.

On top of that differential per-finding scan, it also builds a per-tool
breakdown (`SarifSummaryReport.tools`, embedded in the predicate as
`static_analysis.tools[]`): driver metadata (name/version/informationUri),
findings grouped by rule ID with category/tags (sourced from the SARIF
driver's own `rules[]` descriptors), a SHA-256 integrity hash of the raw
report file, and an extensible `extensions` bag for tool-specific
enrichments. Currently that's SonarQube's quality gate / cognitive
complexity / technical debt, read from a SARIF run's own `properties`
bag (`properties.sonarqube.*`, or the flat bag itself if a tool writes
these keys directly) — and, for a scanner whose SARIF export doesn't embed
them, `--sonar-metrics <path>` ingests a SonarQube
`api/measures/component` JSON export separately (`parse_sonar_metrics_file`
+ `merge_sonar_metrics_into_tools`) and merges it into the SonarQube-named
tool (or the sole tool, if there's only one and none match by name — an
ambiguous multi-tool match is skipped with a warning, never guessed at).
Multiple `--sarif` inputs' `.tools` entries are **concatenated, not merged
by name**: each keeps its own file's `report_hash`, since collapsing two
same-named tools from two different files would leave no single honest
hash to attach to the merged entry.

`tenax-assay run` is an explicit alias for the pipeline above (it's also
what runs with no subcommand at all, so `run` is optional, not required —
existing invocations with no subcommand keep working unchanged).

**`parsers/github_rules.py`** (~450 lines, the most defensively written
module, since it's the one genuine live-API client in the ingestion path)
queries the *effective* rules for a branch plus every active
branch-targeting ruleset's bypass actors, to answer "can this branch
actually receive an unreviewed change" independent of what this PR's own
approval state claims. Notable hardening:
- An ambiguous 404 (no rules configured vs. a nonexistent repo/branch) is
  only trusted as benign once branch existence is independently confirmed
  via a second API call; otherwise it fails closed.
- A 401/403 anywhere — including the secondary per-ruleset detail fetch —
  invalidates the *whole* report. GitHub's own error-body message is
  extracted and led with in the diagnostic, since a 403 here is genuinely
  ambiguous: it's most often an under-scoped `GITHUB_TOKEN` missing
  `Administration: Read` (pointing at `actions/create-github-app-token` as
  the fix), but GitHub returns the *identical* status code when rulesets
  simply aren't a supported feature for the repo at all — a private repo
  on GitHub Free. That specific case is tagged with a machine-readable
  `reason_code` (`platform_unsupported_tier`) rather than left
  indistinguishable from a token problem, so downstream policy (see
  `--disallow-degraded` below) can tell an unavoidable platform limitation
  apart from a real governance gap.
- Bypass-actor `bypass_mode` is allowlisted, not blocklisted: only
  `"pull_request"` mode counts as a partial (PR-review-only) bypass;
  `"always"`, a missing mode, or any unrecognized value fails closed to
  "not enforced."
- Pagination is capped at 10 pages and only follows `Link: rel="next"`
  targets that stay same-origin/HTTPS — an SSRF guard against a hostile
  response header.

**`hashing.py`** computes SHA-256 in 1MB chunks (bounded memory for large
reports), resolving every path it hashes through `common.safe_resolve_path()`
first, the same choke point every other operator-supplied file path in the
pipeline goes through. The digest is both the in-toto `report_sha256` and
the WORM content-addressed key (`s3://evidence/sha256/<hex>` — same
content, same key, free dedup and idempotent uploads across re-attested
runs).

**`parsers/lockfiles.py`** auto-detects and parses lockfiles under
`--repo-dir` (uv.lock, package-lock.json, go.sum, Gradle/Maven locks — any
number/combination, at any depth outside vendored/build directories) into
the predicate's top-level `resolved_dependencies` array: one
`{uri, digest}` entry per dependency (a `pkg:` PURL plus an
algorithm→hex-digest map, empty when the lockfile format itself carries no
digest, e.g. Gradle/Maven), deduplicated by `uri`, `[]` when no recognized
lockfile is found. Like `static_analysis`, this is purely additive
predicate data — it's never an RCS scoring input. **It's also unrelated to
the SLSA v1.0 Build Level 2 checklist's "Materialized Resolved
Dependencies" item below**, which reads a differently-shaped
`buildDefinition.resolvedDependencies` on a SLSA-provenance predicate;
tenax-assay's own predicate isn't SLSA-shaped (see the checklist section),
so populating this field doesn't change that item's outcome.

## Signing flow (keyless / Sigstore)

`oidc_signer.py` implements the ambient-credential keyless model end to
end via `sigstore-python`'s `Signer.sign_dsse()` library call — the same
public entry point the `sigstore` CLI's own `sign`/`attest` subcommands
delegate to internally:

1. Fetch a short-lived OIDC token from the CI provider's ambient endpoint
   (`ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN` on GitHub Actions;
   `SIGSTORE_ID_TOKEN`/`CI_JOB_JWT_V2` on GitLab CI), with an SSRF guard
   forcing HTTPS on the token endpoint. **No static secret is ever read.**
   The GitHub Actions branch retries a transient failure (timeout,
   connection error, non-2xx) up to 3 times with a short capped
   exponential backoff between attempts, each attempt bounded by its own
   10s timeout — a brief blip talking to the ambient endpoint doesn't fail
   the whole run, but the retry is provably bounded (fixed attempt count,
   fixed per-attempt timeout, fixed backoff cap), never an unbounded or
   tight retry loop.
2. Ephemeral in-memory keypair; exchanged with Fulcio for a short-lived
   cert binding the key to the OIDC identity (`repo:org/repo:ref:...`).
3. Sign the DSSE PAE of the Statement via `Signer.sign_dsse()`; submit to
   Rekor for an inclusion proof.
4. Discard the ephemeral private key — no long-lived signing key exists
   to rotate or leak.

The library call is used deliberately over the `sigstore sign` CLI
subcommand: `sigstore sign` always produces a hashedrekord/messageSignature
bundle (an artifact signature), never a DSSE envelope, no matter what's
passed as input — verification would then fail outright ("cannot perform
DSSE verification on a bundle without a DSSE envelope"). `sigstore attest`
does produce a DSSE envelope, but restricts `--predicate-type` to the SLSA
provenance enum and derives its subject from a hash of the predicate file
itself, neither of which fits a custom predicate type over an
already-assembled Statement whose subject is a container image digest, not
a local file's hash. `Signer.sign_dsse()` takes the caller's exact Statement
bytes directly (`sigstore.dsse.Statement(bytes)`), with no such restriction.

The complete, untouched Sigstore bundle (`Bundle.to_json()` output,
including full `tlogEntries` inclusion-proof material) is preserved
verbatim in the envelope's `_sigstore_bundle` field, specifically so
`verify.py` can hand it straight to `sigstore.models.Bundle.from_json()`
later rather than hand-reconstructing a partial bundle that could never
satisfy its schema.

`fetch_ambient_oidc_token()` raises `AmbientIdentityError` rather than
falling back to an unsigned artifact if no ambient identity is found —
an unsigned attestation masquerading as verified is strictly worse than
a hard pipeline failure. `--dry-run-sign` produces an explicitly-marked
`DRY_RUN_UNSIGNED`/`DRY_RUN_NO_CERT` placeholder envelope instead, which
`verify.py` refuses to treat as a real signature.

## Verification (admission gate)

`cli/verify.py` (the largest module, ~740 lines) is the deploy/merge-time
counterpart to signing: `tenax-assay verify <envelope.json> [flags]`
decodes a signed DSSE envelope, best-effort verifies the Sigstore signing
identity, and enforces admission policy gates against the embedded RCS —
never raising on malformed or hostile input; every problem surfaces as a
`violations`/`warnings` entry so a CI gate always gets a clean pass/fail.

**Envelope size guard**: `load_envelope()` rejects any envelope file over
`MAX_ENVELOPE_SIZE` (10MB) via a `stat()` size check *before* opening or
reading a single byte of it — a hostile or corrupt multi-GB "envelope"
can't exhaust memory just by being pointed at. Reported as a clear
`ERROR: Attestation file exceeds maximum allowed size (10MB)` on stderr
and exit code `1`, the same as any other file error.

**Formal schema validation** (optional, diagnostic): when `jsonschema` is
installed, the extracted predicate is validated against
`schema/tenax-attestation-v1.schema.json` before policy/score evaluation,
and surfaced as `schema_validation_status` (`"passed"` / `"failed"` /
`"skipped"`). This is deliberately a `warnings` entry, **not** a blocking
gate: the predicate schema evolves over time (`branch_governance`,
`degraded_reasons`, and `static_analysis` were all added to the schema
after real, already-signed attestations existed without them), so a
mismatch alone must never fail an otherwise-valid `--min-rcs` run.
`jsonschema` not being installed, the packaged schema file being
unavailable, or validation itself raising unexpectedly all degrade to
`"skipped"` with a diagnostic `warnings` entry — never a crash, and never
treated as a failure.

When the predicate carries a `static_analysis.tools[]` block, the
human-readable (`--format text`, the default) output prints a clean summary
table — per-tool error/warning counts and SonarQube quality-gate status when
present — purely for display; it's never a gating input, so a malformed or
missing table never affects `passed`. The same table also renders into
`$GITHUB_STEP_SUMMARY` (see `_write_github_step_summary` below) — both
renderers share one code path so they can't drift apart. When a row's
SonarQube quality-gate data was merged in from a `--sonar-metrics` export
rather than that tool's own SARIF driver (e.g. onto a lone `CodeQL` row,
per `merge_sonar_metrics_into_tools` above), its name is suffixed
`(+ SonarQube)` so the merge is visible in the table itself — otherwise a
row named e.g. `CodeQL` carrying SonarQube's quality gate never mentions
SonarQube anywhere, and looks like that data went missing. `--format json`
output carries the same underlying data reshaped into `static_analysis.tools`
(see below), unaffected by this display-only label.

**`--format {text,json}` / `-f`** (default: `text`) controls output shape:
- `text` (default) prints the human-readable summary above to **stderr**
  (banner, RCS/degraded line, static-analysis table, violations/warnings).
- `json` suppresses all of that and emits **only** a single
  `json.dumps(..., indent=2)` document on **stdout** — safe to pipe into
  `jq` or another consumer without any banner/table text mixed in. Exit
  codes (`0`/`1`/`2`, below) are unaffected by `--format`. Shape:
  ```json
  {
    "version": "1.0.0",
    "verified": true,
    "envelope": {
      "statement_type": "https://in-toto.io/Statement/v1",
      "predicate_type": "https://tenax.io/attestations/assay/v1",
      "subject": [{"name": "registry.example.com/org/svc", "digest": {"sha256": "..."}}]
    },
    "verdict": "FINAL VERDICT: GATED (Source L2 / Build L1) — SLSA Build L2 Incomplete",
    "source": {
      "level_1": {"level": 1, "track": "Source", "name": "Source Level 1: Version Controlled Source", "passed": true, "items": ["..."]},
      "level_2": {"level": 2, "track": "Source", "name": "Source Level 2: Verified History & Explicit Lineage", "passed": true, "items": ["..."]},
      "level_3": {"level": 3, "track": "Source", "name": "Source Level 3: Retained History & Author Identity", "passed": false, "items": ["..."]},
      "level_4": {"level": 4, "track": "Source", "name": "Source Level 4: Two-Party Code Review & Branch Governance", "passed": false, "items": ["..."]}
    },
    "slsa": {
      "level_1": {
        "level": 1,
        "track": "Build",
        "name": "SLSA Build Level 1",
        "passed": true,
        "items": [
          {"label": "in-toto v1 Statement Envelope", "passed": true, "detail": ""},
          {"label": "SLSA v1.0 Provenance Predicate", "passed": true, "detail": ""},
          {"label": "Build Definition & Invocation Metadata", "passed": true, "detail": ""},
          {"label": "Subject Artifact Digest Verification", "passed": true, "detail": ""}
        ]
      },
      "level_2": {
        "level": 2,
        "track": "Build",
        "name": "SLSA Build Level 2",
        "passed": false,
        "items": [
          {"label": "Hosted Builder Identity", "passed": false, "detail": "missing runDetails.builder.id"},
          {"label": "Cryptographic Envelope Signature (Sigstore Keyless OIDC)", "passed": true, "detail": ""},
          {"label": "Authenticated Source Repository Binding", "passed": true, "detail": ""},
          {"label": "Materialized Resolved Dependencies", "passed": false, "detail": "buildDefinition.resolvedDependencies is missing or empty"}
        ]
      },
      "level_3": {"level": 3, "track": "Build", "name": "SLSA Build Level 3", "passed": false, "items": ["..."]}
    },
    "release_confidence_score": {"score": 89, "degraded": false, "degraded_field_present": true, "degraded_reasons": [], "components": {"...": "..."}},
    "static_analysis": {"tools": {"codeql": {"errors": 0, "warnings": 0}, "sonarcloud": {"quality_gate": "PASSED"}}},
    "identity": {"status": "verified", "detail": "..."},
    "violations": [],
    "warnings": []
  }
  ```
  `source.level_1`..`level_4` and `slsa.level_1`..`level_3` are exactly
  `result.source_level1`..`source_level4`/`slsa_level1`..`slsa_level3` —
  the same SLSA Source Track and Build Track checklists the text
  formatter renders to stderr via `_format_track_report` (see "SLSA
  Source & Build Track checklists" below for what each item means and
  how each level builds on the one below it), reshaped as JSON here
  rather than recomputed, so `--format json` and the default text output
  can never disagree about SLSA compliance for the same run. `verdict` is
  the same synthesized `FINAL VERDICT: ...` headline the text banner
  prints (see below) — the highest level each track cumulatively
  satisfies, plus the actual hard-gate outcome.

  `--json` (no `-f`) is kept as a **deprecated alias** for `--format json`
  — it emits the same payload and prints a one-line deprecation notice to
  stderr (never stdout, so it can't corrupt a `--json` consumer's parsing).

Policy gates:
- `--min-rcs N` — fail if `release_confidence_score.value < N`.
- `--require-digest sha256:<hex>` — fail unless that digest is among the
  Statement's attested subjects.
- `--disallow-degraded` — fails a degraded run, but isn't a flat
  `degraded == true` check: it inspects `degraded_reasons` and only lets a
  degraded run through when that list is non-empty **and every entry** is
  one of a small, deliberate allowlist of known, unavoidable states —
  currently `branch_governance:platform_unsupported_tier` (a private repo
  on GitHub Free, where branch rulesets simply aren't supported at any
  token scope) and `patch_coverage:no_coverable_lines` (a docs/config-only
  diff with no code for patch coverage to be missing over). Any other
  cause present — a real governance gap, missing PR context, a broken
  SARIF input, or `degraded_reasons` missing/malformed entirely (e.g. an
  older attestation predating this field) — still blocks. `degraded`
  itself is schema-optional (defaults to `false` for *display* when a
  predicate omits it — that default is documented in
  `schema/tenax-attestation-v1.schema.json`, not a guess) — but
  `--disallow-degraded` never trusts that display default as a compliance
  signal: `degraded` missing or malformed entirely is its own fail-closed
  violation under this flag (`degraded_field_present == False`), same
  severity as a confirmed `degraded == true` with no exempted reason. This
  deliberately can't be approximated by simpler proxies like repo
  visibility (`private == true`): private repos on GitHub Pro/Team/
  Enterprise *do* support rulesets, so a repo-visibility check would
  wrongly waive strict enforcement for a paid private repo with a real,
  fixable governance problem too.

Identity verification (best-effort, four possible outcomes):
- **`verified`** — cryptographic signature *and* asserted identity checks
  (`--cert-identity`, `--cert-oidc-issuer`, `--expected-issuer`,
  `--expected-repository`, `--expected-workflow`, `--expected-ref`) both
  passed. Every asserted claim is AND-ed together (a certificate must
  satisfy *all* of them, not merely one), and repository is checked against
  both the legacy and current Fulcio GitHub Actions certificate extension
  OIDs (whichever version minted the cert — extraction falls back v1→v2
  transparently) since which one a given cert carries depends on Fulcio's
  version at signing time. Asserting no identity claims at all still runs
  signature verification, but the result is explicitly labeled `UnsafeNoOp`
  in `identity_detail` so a bare "verified" is never ambiguous about
  whether identity was actually checked.
- **`skipped`** — `--dry-run` was passed, or the envelope carries only a
  `--dry-run-sign` placeholder signature.
- **`unavailable`** — offline, no TUF trust root reachable, or the bundle
  lacked enough material to reconstruct (e.g. a legacy pre-`_sigstore_bundle`
  envelope with a real Rekor entry). Non-blocking.
- **`failed`** — Sigstore explicitly rejected the signature or identity
  match. This is the **only** identity outcome that fails the gate; on a
  mismatch, expected-vs-actual certificate claims are dumped to stderr so
  it's immediately diagnoseable from CI logs.

Exit codes: `0` = pass, `1` = file/parse error, `2` = policy violation.

**SLSA Source & Build Track checklists** (informational by default,
non-gating): every `verify` run additionally evaluates the decoded
statement(s) against both halves of the SLSA v1.0 framework — the
[Source track](https://slsa.dev/spec/v1.0/source-requirements) (Levels
1-4) and the [Build track](https://slsa.dev/spec/v1.0/provenance) (Levels
1-3) — and prints a scannable, grouped report to stderr (`--format json`
carries the same data under `source.level_1`..`level_4` and
`slsa.level_1`..`level_3`; the deprecated `--json` alias does too).

**`--slsa-envelope PATH`** loads a *second* DSSE envelope alongside the
primary one so both tracks can be evaluated together from the right
source: the Source track reads `vcs`/`branch_governance` off whichever
loaded statement is tenax-assay's own RCS predicate, and the Build track
reads `buildDefinition`/`runDetails` off whichever is SLSA-provenance-
shaped — regardless of which one is the primary positional argument.
Without `--slsa-envelope` (unchanged from before it existed), both
tracks evaluate against whatever the single envelope decodes to,
honestly reporting missing/wrong-shaped fields as failures rather than a
separate "unavailable" state — the same fail-closed contract this
checklist has always had.

```text
SLSA Source Track
=== Source Level 1: Version Controlled Source Assessment ===
[✓] Version Controlled Source (VCS provider & branch binding)
Status: PASSED (SLSA Source Level 1)

=== Source Level 2: Verified History & Explicit Lineage Assessment ===
[✓] Verified History & Explicit Lineage (commit SHA, base SHA, PR lineage)
Status: PASSED (SLSA Source Level 2)

=== Source Level 3: Retained History & Author Identity Assessment ===
[✓] Retained History & Author Identity (commit author resolves to a verified GitHub account) (author: @octocat)
Status: PASSED (SLSA Source Level 3)

=== Source Level 4: Two-Party Code Review & Branch Governance Assessment ===
[✓] Two-Party Code Review & Branch Governance (branch_governance.approvals_required >= 1) (2 approval(s) required)
Status: PASSED (SLSA Source Level 4)
=====================================

SLSA Build Track
=== SLSA Build Level 1 Assessment ===
[✓] in-toto v1 Statement Envelope
[✓] SLSA v1.0 Provenance Predicate
[✓] Build Definition & Invocation Metadata
[✓] Subject Artifact Digest Verification
Status: PASSED (SLSA Build Level 1)

=== SLSA Build Level 2 Assessment ===
[✓] Hosted Builder Identity (https://github.com/actions/runner)
[✓] Cryptographic Envelope Signature (Sigstore Keyless OIDC)
[✓] Authenticated Source Repository Binding
[✓] Materialized Resolved Dependencies (142 packages recorded)
Status: PASSED (SLSA Build Level 2)

=== SLSA Build Level 3 Assessment ===
[✗] Unforgeable Control-Plane Builder Identity (https://github.com/actions/runner) -- builder id is not in the trusted isolated-control-plane allowlist [...]
[✗] Isolated Provenance Generation (signer identity matches builder identity) -- ...
[✓] Materialized Locked Dependencies (142 packages recorded)
Status: FAILED (SLSA Build Level 3)
=====================================

=== Assay Health & Governance Metrics ===
Release Confidence Score (RCS): 89 (degraded=False)
Component breakdown:
  - governance: raw=100.0 weight=0.15 weighted=15.0
      2/2 required approvals (approved)
  ...

================================================================================
FINAL VERDICT: GATED (Source L4 / Build L2) — SLSA Build L3 Incomplete
================================================================================
```

**Source track** (each level is one check; SLSA's own leveling is
cumulative, same rule as the Build track below):
- **Level 1** — `vcs.provider`/`vcs.repository`/`vcs.branch` are all present.
- **Level 2** — `vcs.commit_sha` and `vcs.base_commit_sha` are both present
  and hash-shaped; when this run has PR context, `vcs.pull_request.number`
  and `.target_branch` are present too (explicit lineage).
- **Level 3** — `vcs.commit_author.verified_github_account` is `true`:
  the commit's author email resolves, via GitHub's own commits API
  (`GET /repos/{repo}/commits/{sha}`), to a linked, *verified* GitHub
  account (`author.login`) — not merely a free-text git author
  name/email, which is self-reported by whoever authored the commit
  object and trivially spoofable (`git commit --author=...`, or simply
  an unconfigured `git config user.*`). Collected by
  `parsers/commit_author.py` using the same ambient `GITHUB_TOKEN` as
  branch governance; fails closed (`[✗]`) on a missing/unavailable
  check (no token, API failure) exactly the same as an unverified
  author — the two are distinguished by reason text, not by outcome.
  Cryptographic commit signing would be a stronger binding still, but
  isn't required to pass this check.
- **Level 4** — `branch_governance.approvals_required >= 1` (the branch's
  own rule, not merely that this PR happened to get a reviewer — see
  `vcs.pull_request.required_approvals` for that separate, PR-scoped
  field); fails on `0`, a missing `branch_governance` block, or a
  `platform_unsupported_tier` reason code.

**Build track**:
- **Level 1** — `_type` is `https://in-toto.io/Statement/v1`; `predicateType`
  is `https://slsa.dev/provenance/v1`; `buildDefinition.buildType` is
  present *and* `runDetails.metadata` carries either an `invocationId` or
  both `startedOn`/`finishedOn` (combined into one checklist row); and at
  least one subject digest is attested.
- **Level 2** — `runDetails.builder.id` is a trusted hosted builder
  (currently just `https://github.com/actions/runner` — a deliberately
  narrow, explicit allowlist); the envelope's Sigstore identity check
  (the same `identity_status` computed above) came back `verified`;
  `buildDefinition.externalParameters.workflow.repository` is present
  (and matches `--expected-repository` when that flag is set); and
  `buildDefinition.resolvedDependencies` has at least one entry with a
  non-empty `uri`.
- **Level 3** — an *unforgeable* builder identity: `runDetails.builder.id`
  names the isolated control-plane signer workflow itself (a narrower
  allowlist than Level 2's, currently
  `https://github.com/tenax-io/tenax-attest/.github/workflows/sign.yml`),
  *and* the verified Sigstore signer identity (`--cert-identity`) is
  provably that same workflow — proving the entity that signed the
  envelope is the same one that claims to have built it, so an untrusted
  build job can no longer forge `buildDefinition`/`runDetails` even
  though it never could forge the signature either. Plus materialized
  locked dependencies: at least one `buildDefinition.resolvedDependencies`
  entry must be a real `pkg:` PURL with a `sha256` digest, not just the
  synthetic source-commit entry every statement already carries.
  **Fails closed for every caller today** — the architecture that would
  make the first two checks pass (provenance constructed inside
  `tenax-attest`'s isolated signer job, not the untrusted build job — see
  "Isolating signing from the build" below) doesn't exist yet.

**`--require-slsa-build-l3`** (off by default) folds the Build track's
cumulative Level 3 outcome into `passed`/exit code — opt-in, so no
existing caller's gate changes until they choose to require full Build
Level 3 compliance (which, per the above, no caller can satisfy yet).

**FINAL VERDICT banner**: one synthesized line summarizing the whole
report — `PASSED` when the hard gate passed *and* both tracks are fully
compliant through their top level; `GATED` when the hard gate passed but
one or both tracks aren't fully compliant yet (shippable, not yet fully
certified); `FAILED` when the hard gate itself rejected the run. The
`(Source Lx / Build Ly)` pair is the highest level each track
cumulatively satisfies, and the trailing clause names the first
incomplete level standing between `GATED` and `PASSED`.

**`$GITHUB_STEP_SUMMARY`**: whenever that environment variable is set
(i.e. running as a GitHub Actions job step), `verify` additionally
*appends* the same report as markdown to the file it points at — a
one-line PASS/FAIL heading, the plain-text report in a fenced code
block, and a bulleted violations list when any exist. A no-op (never
raises) everywhere else, or if the file can't be written.

## SLSA v1.0 provenance attestation (`--emit-slsa-provenance`)

`--emit-slsa-provenance` (`cli/slsa_provenance.py`) makes `cli.main` write a
**second, separate** in-toto Statement alongside tenax-assay's own RCS
predicate — same subject artifact, but `predicateType`
`https://slsa.dev/provenance/v1`, real SLSA-shaped `buildDefinition`/
`runDetails`, and its own output file (`--slsa-provenance-out`, default
derived from `--out`, e.g. `attestation.slsa-provenance.unsigned.json`). If
`--sign`/`--dry-run-sign` was also passed, this second statement is signed
into its own DSSE envelope the same way the primary one is. The two
predicates are kept apart rather than merged — see `parsers/lockfiles.py`'s
note above and the SLSA checklist section for why tenax-assay's own
predicate is deliberately not SLSA-shaped; this is the statement built
specifically to *be* SLSA-shaped instead.

**Ground-truth only, fail-closed** (same contract as the rest of `cli/`):
every `buildDefinition`/`runDetails` field is populated strictly from data
that genuinely describes the run — ambient `GITHUB_REPOSITORY`/`_SHA`/
`_RUN_ID`/`_RUN_ATTEMPT`/`_WORKFLOW_REF`/`RUNNER_ENVIRONMENT` env vars
Actions itself sets, plus tenax-assay's own already-parsed lockfile
dependency list (`resolved_dependencies`, reshaped into SLSA's `{uri,
digest}` form). Nothing is inferred or defaulted to a plausible-looking
value:
- Off-CI (no ambient GitHub Actions env), `buildDefinition.externalParameters`
  and `.resolvedDependencies` are empty and `runDetails.builder`/
  `metadata.invocationId` are absent — a legitimately less-complete
  statement, not a fabricated one.
- `runDetails.builder.id` (`https://github.com/actions/runner`, matching
  `cli/verify.py`'s `TRUSTED_HOSTED_BUILDER_IDS` allowlist) is only ever set
  when `RUNNER_ENVIRONMENT=github-hosted` — a self-hosted runner gets no
  builder id at all rather than a false "hosted" claim.
- `buildDefinition.buildType` is always
  `https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1`,
  the real published buildType for a GitHub Actions workflow build (from
  the [slsa-github-generator](https://github.com/slsa-framework/github-actions-buildtypes)
  project, not invented here).

Because it's populated this way, this statement legitimately satisfies
`cli/verify.py`'s SLSA Build Level 1/2 checklist when run on a
GitHub-hosted Actions runner with a real signature — `tests/
test_slsa_provenance.py::GenuineGitHubActionsRunTests::
test_satisfies_verify_py_slsa_build_level_1_and_2_checklists` asserts this
directly against `_evaluate_slsa_l1`/`_evaluate_slsa_l2`. Note that
`cli.verify`'s own `--min-rcs`/`--disallow-degraded`/`--require-digest`
gates (and its unconditional `predicateType`/`release_confidence_score`
checks) are specific to tenax-assay's RCS predicate and would always
report `passed: false` if evaluated against a lone SLSA statement outside
`--slsa-envelope` — that's expected and unrelated to the SLSA checklist's
outcome. `.github/workflows/assay.yml`'s own `verify` job evaluates both
statements together in one `cli.verify --slsa-envelope` call rather than
as a separate step (see "Isolating signing from the build" below for how
that statement is constructed and signed in the first place). See
`tests/fixtures/slsa_provenance_statement.output.json` for a minimal
fully-populated example.

## Isolating signing from the build (`tenax-assay sign`)

A signed, checklist-passing statement is not by itself a defensible SLSA
Build Level 2 claim. Level 2's actual requirement is that provenance is
generated by the *build platform*, isolated from the tenant's own build
steps — so a compromised build (a malicious dependency, a tampered test
fixture) can't also forge its own provenance. Signing the statement in the
same job, under the same script, as the code that runs a PR's tests and
dependencies doesn't provide that: nothing stops that code from reaching
the signing credential, in principle, since both share one trust boundary.

`tenax-assay sign <statement.json> [--out PATH] [--dry-run-sign]`
(`cli/sign.py`) exists to make real isolation possible: it signs an
already-built unsigned statement *file*, nothing else — no scoring,
coverage, SARIF, or branch-governance re-execution, so a job invoking only
this subcommand never needs read access to any of that. It's the same
`cli.oidc_signer.sign_file_to_envelope()` either path uses; `cli.main`'s
own `--sign`/`--dry-run-sign` flags still build-then-sign in one process
for local/single-command use exactly as before — `tenax-assay sign` is
additive, not a replacement.

`.github/workflows/assay.yml` uses this to split into three jobs:

```text
build (contents: read, security-events: write)
  checkout -> tests -> coverage -> CodeQL -> RCS score
  -> unsigned RCS statement.json (no id-token permission at all)
  -> upload-artifact "unsigned-statements"
         |
         v  (artifacts only -- no shared runner/credentials)
attest (id-token: write -- the ONLY job with it)
  download-artifact -> `tenax-assay provenance` (constructs SLSA statement
  from this job's own trusted context, not build's) -> `tenax-assay sign`
  (both statements, atomically) -> upload-artifact "signed-statements"
         |
         v
verify (contents: read)
  download-artifact -> admission gate + both SLSA tracks in one
  `cli.verify --slsa-envelope` call -> final attestation artifact
```

`build`'s test/dependency execution can never reach the Sigstore signing
credential — `id-token: write` is granted to `attest` alone. `attest` is a
`uses:` call to [`tenax-io/tenax-attest`](https://github.com/tenax-io/tenax-attest),
a separate, branch-protected repository hosting the signing job as a
`workflow_call` reusable workflow, checked out at a commit SHA hardcoded
inside that repo's own `sign.yml` (`env.TRUSTED_SIGNER_SHA`) — deliberately
*not* a value `tenax-assay`'s `attest` job (or any other caller) can supply
(the same pattern [`slsa-framework/slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator)
uses). That's the gap that matters: even a PR that fully rewrites
`tenax-assay`'s own workflow file in the same PR can't also rewrite what
the signer trusts, since that code isn't part of the PR's diff at all. The
source for that repo's content lives in `contrib/tenax-attest-repo/` in
this repo (not part of `tenax-assay`'s own CI — a header comment there
says so) along with setup instructions; `assay.yml`'s `attest` job comment
cross-references it.

What this still doesn't claim: reproducible builds, ephemeral/hardened
isolation of individual build *steps* within the `build` job itself, or
third-party/official certification — the former is genuinely further
scope (hermetic build inputs, not just an isolated signer), and the
latter is independent-assessment territory, neither attempted here. The
concrete, verifiable claim this architecture *does* support, as of the
provenance-construction shift below: the code that builds and tests a PR
cannot mint the identity that signs what gets said about it, **and**
cannot forge the content of what gets signed either.

**`tenax-assay provenance`** (`cli/provenance.py`) is what makes that
second half real: `tenax-assay provenance --subject-name NAME
--subject-digest sha256:HEX --repo-dir DIR --builder-id ID --out PATH`
constructs a SLSA v1.0 provenance statement using nothing but *this
process's own* ambient GitHub Actions context — the same
`cli.slsa_provenance.build_slsa_provenance_statement()`
`--emit-slsa-provenance` already used, completely unchanged, just called
from a new entry point (and `--builder-id`, asserting the caller's own
known identity explicitly rather than an ambient signal — see that
flag's own help text for why: `GITHUB_WORKFLOW_REF` reflects the
top-level *calling* workflow, not the reusable workflow file actually
executing a `workflow_call` job, a distinction a real run caught before
this flag existed). `attest` above runs it instead of `build`, so every
`buildDefinition`/`runDetails` field (builder identity, source binding,
resolved dependencies) is derived from the trusted signer job's own
environment and its own read-only checkout of the source commit (for
lockfile scanning only — the checkout is never executed), not from
anything the untrusted `build` job claims — then signs both statements
atomically in the same job via `tenax-assay sign`.

## Try it

```bash
cd tenax-assay
python3 -m unittest discover -s tests -v

python3 -m cli.main \
  --junit-xml path/to/your/junit.xml \
  --coverage-format cobertura \
  --coverage-report tests/fixtures/cobertura.xml \
  --image-ref registry.example.com/org/svc \
  --image-digest sha256:$(python3 -c "print('a'*64)") \
  --head-sha $(python3 -c "print('b'*40)") \
  --repository org/svc --branch feature/x \
  --pr-number 42 --pr-approvers alice,bob --pr-required-approvals 2 --pr-review-state approved \
  --sarif path/to/semgrep.sarif.json --sarif path/to/sonarqube.sarif.json \
  --sonar-metrics path/to/sonar-measures.json \
  --skip-perf-budget-check --debug \
  --emit-slsa-provenance --slsa-provenance-out /tmp/attestation.slsa-provenance.unsigned.json \
  --out /tmp/attestation.unsigned.json
# `tenax-assay run --sarif ... --sonar-metrics ...` is an equivalent, explicit
# spelling of the same pipeline invocation above. Omit --emit-slsa-provenance/
# --slsa-provenance-out to skip the second, SLSA-shaped statement entirely.

# Admission gate against the unsigned statement's DSSE-shaped output
# (only meaningful once --sign/--dry-run-sign has produced a real envelope):
python3 -m cli.main verify /tmp/attestation.dsse.json --min-rcs 60 --dry-run

# Print the SLSA Build Level 1/2 checklist for the second statement
# (its own --min-rcs/--disallow-degraded outcome is expected to fail --
# see "SLSA v1.0 provenance attestation" above -- this is only useful for
# the checklist stderr generates, not this command's own exit code):
python3 -m cli.main verify /tmp/attestation.slsa-provenance.dsse.json --dry-run

# Standalone signing of an already-built unsigned statement file (no
# scoring/coverage/SARIF re-execution) -- what an isolated `attest` CI job
# invokes instead of --sign; see "Isolating signing from the build" above:
python3 -m cli.main sign /tmp/attestation.unsigned.json --dry-run-sign
```

`tests/fixtures/` currently ships `cobertura.xml` and a rendered
`sample_statement.output.json` (tenax-assay's own RCS predicate) plus
`slsa_provenance_statement.output.json` (a minimal, fully-populated
`--emit-slsa-provenance` statement); supply your own `junit.xml` (the
schema is standard JUnit XML — pytest's `--junitxml=`, jest-junit, etc.
all work) to exercise the full pipeline end to end.

(Omit `--sign` unless running inside an actual GitHub Actions/GitLab CI
job with `id-token: write` permissions and the `sigstore` package
installed — outside CI there's no ambient identity to fetch, by design.
`--dry-run-sign` exercises the DSSE envelope shape without any of that.)

## Test suite

~355 test cases across 16 modules, including dedicated adversarial suites:
`test_adversarial_ast.py` (Python assertion-integrity bypass attempts),
`test_ast_assertions.py` (the multi-language engine: on-disk fixtures for
every supported language, per-language gaming heuristics, registry
dispatch, and DSSE predicate telemetry), `test_security_boundaries.py`,
`test_verify_boundaries.py`, and `test_sarif_adversarial.py` (malformed/
hostile-input hardening), `test_verify_hardening.py` (envelope size guard,
diagnostic schema validation, OIDC fetch retry bounding),
`test_github_rules.py` (auth failure modes, pagination limits, bypass-mode
edge cases against a mocked GitHub API), `test_slsa_provenance.py`
(ground-truth/fail-closed tests for `--emit-slsa-provenance`, plus proof
that a genuine statement satisfies `cli/verify.py`'s SLSA Level 1/2
checklist), and `test_sign.py` (`tenax-assay sign`'s CLI surface and
`cli.oidc_signer.sign_file_to_envelope`'s size-guard/fail-closed paths).

Run the full suite in parallel:

```bash
python3 -m pip install pytest-xdist
python3 -m pytest -n auto -v tests/
```

## Not yet built (flagged, not hidden)

- `main.py`'s `pipeline.run_id` / `workflow_ref` are placeholders pending
  wiring to `GITHUB_RUN_ID`/`GITHUB_WORKFLOW_REF` or GitLab CI equivalents.
- The WORM upload body in `upload_to_worm_async()` is an integration
  point (swap in `boto3` S3 Object Lock COMPLIANCE-mode PUT or
  `minio-py`), intentionally left unimplemented here since it's
  infra-credential-dependent and out of scope for the schema/scoring
  foundation this task covers.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
