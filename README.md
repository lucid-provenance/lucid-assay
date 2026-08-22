# Plinth Assay — Continuous Governance Control Plane (Foundation)

MVP foundation for bridging CI/CD execution to SOC 2 / FedRAMP / ISO 27001
evidence: cryptographically signed in-toto attestations of test, coverage,
static-analysis, and governance state, computed on the runner and stored
content-addressed in WORM storage — plus the admission gatekeeper that
verifies those attestations before a deploy/merge is allowed to proceed.

## Layout

```
schema/
  plinth-attestation-v1.schema.json   # in-toto predicate JSON Schema
cli/
  parsers/junit.py          # streaming JUnit XML -> TestTotals (flaky-retry aware)
  parsers/coverage.py       # Cobertura XML + LCOV -> CoverageReport (per-line hit maps)
  parsers/ast_inspector.py  # scoped AST walk of test files -> assertion integrity metrics
  parsers/sarif.py          # SARIF 2.1.0 ingestion -> differential (patch vs. legacy) findings
  parsers/github_rules.py   # GitHub branch protection/ruleset inspection via REST API
  patch_coverage.py         # git diff base...head, intersected with coverage hit maps
  hashing.py                 # SHA-256 content hashing + WORM key derivation
  scorer.py                  # pure, deterministic Release Confidence Score (RCS)
  builder.py                 # assembles the unsigned in-toto Statement
  oidc_signer.py              # ambient OIDC -> Fulcio cert -> DSSE sign -> Rekor log
  verify.py                   # admission gatekeeper: DSSE decode + Sigstore identity + policy gates
  main.py                     # CLI entrypoint wiring it all together (`plinth-assay verify` dispatches to verify.py)
tests/
  test_scorer.py               # adversarial edge-case tests for the RCS algorithm
  test_patch_coverage.py        # git-diff/coverage intersection + reason_code tests (real git repo)
  test_builder.py               # in-toto Statement assembly tests
  test_ast_inspector.py          # real/tautological/empty assertion detection tests
  test_adversarial_ast.py         # adversarial bypass suite for the AST inspector
  test_sarif.py                    # SARIF parsing, path-matching, and fail-closed aggregation tests
  test_github_rules.py              # branch governance API client tests (auth, pagination, bypass modes)
  test_verify.py                     # DSSE/Sigstore verification + policy-gate tests
  test_verify_boundaries.py           # verify.py hardening/edge-case suite
  test_security_boundaries.py          # cross-cutting adversarial-input suite
  fixtures/                             # sample cobertura.xml and a rendered statement
```

## Why this decomposition

Every module is a pure function or a thin, swappable I/O boundary:

- `parsers/*` and `scorer.py` have **zero network or filesystem side
  effects beyond reading the one file they're given** — they're the
  pieces auditors and adversarial tests will hammer on, so they're kept
  trivially unit-testable in isolation. `parsers/github_rules.py` is the
  one exception (it's a live GitHub API client by necessity), which is why
  it's the most defensively written module in the repo — see below.
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

## Deterministic scoring (RCS)

`cli/scorer.py` computes a weighted rollup of **six** components (pure
function of its inputs — no I/O, no clock/randomness beyond the `reason`
strings, so identical inputs always produce an identical score):

| Component | Weight | Edge case handling |
|---|---|---|
| Test health | 35% | `pass_rate = passed / (passed+failed+errored)`. Zero executed tests **floors to 0** with an explicit reason distinguishing "all skipped" from "broken/bypassed gate" (never a neutral default — a broken test gate is a strong negative signal). Flaky retries (same `classname`+`name` seen more than once, final attempt passed) penalize 4pts/case, capped at −30, without being able to zero the run outright. |
| Patch coverage | 20% | Line-rate over just the lines touched by `git diff base...head`, intersected with the coverage report's hit map. Unavailable (no base SHA, or a docs/config-only diff with zero coverable changed lines) **falls back to overall coverage × 0.70**, and flags the whole result `degraded: true` — a proxy signal can never outscore the real measurement it's standing in for. A docs/config-only diff is tagged with its own `reason_code` (`no_coverable_lines`), since there's no code in it for coverage to be missing over — see `--disallow-degraded` below. |
| Overall coverage | 15% | Straight line-rate vs. configurable threshold (default 0.60). |
| Assertion integrity | 10% | `assertions / test_functions` normalized against a target density (1.5), capped at 100; zero test functions floors to 0. Fed by the AST inspector (below), which filters out tautological/empty assertions before counting. |
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

**`parsers/ast_inspector.py`** (the largest parser, ~570 lines) walks every
`test_*`/`*_test` function — including `unittest.TestCase` methods — and
distinguishes real assertions from bogus ones via compile-time constant
folding: `assert True`, `assert 1 == 1`, `assert x == x` (self-comparison),
`assertTrue(True)`, `assertEqual(x, x)`, and bare truthy literals/collections
are all caught as tautological. It also recognizes non-`assert` real-check
idioms (`unittest.mock`'s allowlisted snake_case API, non-empty
`pytest.raises`/`warns` blocks, PyHamcrest's `assert_that`, Chai/Jasmine-style
`expect(x).to_equal(...)`) and flags empty bodies (`pass`/`...`/docstring-only)
separately. Traversal is scope-aware: it never descends into a nested
`def`/`lambda`/`class` inside a test body, and prunes statically-dead `if
False:` branches and `try` bodies whose `except (AssertionError, ...): pass`
would silently swallow a failed check — none of that unreachable code is
credited or blamed.

**`parsers/sarif.py`** ingests one or more `--sarif` 2.1.0 reports (semgrep,
trivy, CodeQL, ...), normalizing `level` (defaults to `warning` per spec)
and artifact paths, then cross-references each finding's file/line against
the diff's changed lines to flag `is_new_in_patch`. Aggregation across
multiple `--sarif` inputs **fails closed**: one unreadable/corrupt input
taints the whole aggregate to `available=False` rather than silently
scoring on the good subset.

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
reports). The digest is both the in-toto `report_sha256` and the WORM
content-addressed key (`s3://evidence/sha256/<hex>` — same content, same
key, free dedup and idempotent uploads across re-attested runs).

## Signing flow (keyless / Sigstore)

`oidc_signer.py` implements the ambient-credential keyless model end to
end via `sigstore-python`'s `Signer.sign_dsse()` library call — the same
public entry point the `sigstore` CLI's own `sign`/`attest` subcommands
delegate to internally:

1. Fetch a short-lived OIDC token from the CI provider's ambient endpoint
   (`ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN` on GitHub Actions;
   `SIGSTORE_ID_TOKEN`/`CI_JOB_JWT_V2` on GitLab CI), with an SSRF guard
   forcing HTTPS on the token endpoint. **No static secret is ever read.**
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
counterpart to signing: `plinth-assay verify <envelope.json> [flags]`
decodes a signed DSSE envelope, best-effort verifies the Sigstore signing
identity, and enforces admission policy gates against the embedded RCS —
never raising on malformed or hostile input; every problem surfaces as a
`violations`/`warnings` entry so a CI gate always gets a clean pass/fail.

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
  older attestation predating this field) — still blocks. This
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

## Try it

```bash
cd plinth-assay
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
  --skip-perf-budget-check \
  --out /tmp/attestation.unsigned.json

# Admission gate against the unsigned statement's DSSE-shaped output
# (only meaningful once --sign/--dry-run-sign has produced a real envelope):
python3 -m cli.main verify /tmp/attestation.dsse.json --min-rcs 60 --dry-run
```

`tests/fixtures/` currently ships `cobertura.xml` and a rendered
`sample_statement.output.json`; supply your own `junit.xml` (the schema is
standard JUnit XML — pytest's `--junitxml=`, jest-junit, etc. all work) to
exercise the full pipeline end to end.

(Omit `--sign` unless running inside an actual GitHub Actions/GitLab CI
job with `id-token: write` permissions and the `sigstore` package
installed — outside CI there's no ambient identity to fetch, by design.
`--dry-run-sign` exercises the DSSE envelope shape without any of that.)

## Test suite

~230 test cases across 10 modules, including dedicated adversarial suites:
`test_adversarial_ast.py` (assertion-integrity bypass attempts),
`test_security_boundaries.py` and `test_verify_boundaries.py`
(malformed/hostile-input hardening), and `test_github_rules.py` (auth
failure modes, pagination limits, bypass-mode edge cases against a mocked
GitHub API).

## Not yet built (flagged, not hidden)

- `main.py`'s `pipeline.run_id` / `workflow_ref` are placeholders pending
  wiring to `GITHUB_RUN_ID`/`GITHUB_WORKFLOW_REF` or GitLab CI equivalents.
- The WORM upload body in `upload_to_worm_async()` is an integration
  point (swap in `boto3` S3 Object Lock COMPLIANCE-mode PUT or
  `minio-py`), intentionally left unimplemented here since it's
  infra-credential-dependent and out of scope for the schema/scoring
  foundation this task covers.
