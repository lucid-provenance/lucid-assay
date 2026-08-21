# IUI Continuous Governance Control Plane — Foundation (Task 1)

MVP foundation for bridging CI/CD execution to SOC 2 / FedRAMP / ISO 27001
evidence: cryptographically signed in-toto attestations of test, coverage,
and governance state, computed on the runner and stored content-addressed
in WORM storage.

## Layout

```
schema/
  attestation-lifecycle-v0.1.schema.json   # in-toto predicate JSON Schema
cli/
  parsers/junit.py        # streaming JUnit XML -> TestTotals
  parsers/coverage.py     # Cobertura XML + LCOV -> CoverageReport (per-line hit maps)
  patch_coverage.py       # git diff base...head, intersected with coverage hit maps
  hashing.py              # SHA-256 content hashing + WORM key derivation
  scorer.py               # pure, deterministic Release Confidence Score (RCS)
  builder.py              # assembles the unsigned in-toto Statement
  oidc_signer.py          # ambient OIDC -> Fulcio cert -> DSSE sign -> Rekor log
  main.py                 # CLI entrypoint wiring it all together
tests/
  test_scorer.py          # adversarial edge-case tests for the RCS algorithm
  fixtures/                # sample junit.xml, cobertura.xml, and rendered statement
```

## Why this decomposition

Every module is a pure function or a thin, swappable I/O boundary:

- `parsers/*` and `scorer.py` have **zero network or filesystem side
  effects beyond reading the one file they're given** — they're the
  pieces auditors and adversarial tests will hammer on, so they're kept
  trivially unit-testable in isolation.
- `oidc_signer.py` and the WORM upload path in `main.py` are the **only**
  network-touching pieces, and they're isolated so the <50ms blocking
  budget can be measured and enforced on everything *except* them.
- `builder.py` is pure data transformation (parsed structs -> schema-shaped
  dict), so schema-conformance can be checked in this repo's own CI with a
  plain `jsonschema.validate()` against every sample statement it emits.

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
   lands in WORM storage, and pages on drift past an SLA window.

## Deterministic scoring (RCS)

`cli/scorer.py` computes a weighted rollup:

| Component | Weight | Edge case handling |
|---|---|---|
| Test health | 35% | Zero tests executed **floors to 0** with an explicit reason (never a neutral default — a broken/bypassed test gate is a strong negative signal). Flaky retries penalize (4pts/case, capped at 30) without being able to zero the run outright. |
| Patch coverage | 25% | Unavailable (no base SHA, or a docs/config-only diff with zero coverable changed lines) **falls back to overall coverage × 0.70**, and flags the whole result `degraded: true` — a proxy signal can never outscore the real measurement it's standing in for. |
| Overall coverage | 15% | Straight line-rate vs. configurable threshold. |
| Assertion integrity | 10% | `assertions / test_functions` normalized against a target density (1.5), capped at 100; zero test functions floors to 0. |
| Governance | 15% | No PR/MR context scores a **neutral 50**, not full credit, and flags `degraded`. `changes_requested` and unresolved zeroes the component outright. A branch protection rule requiring 0 approvals is itself flagged as a weak control (caps at 60). |

Every component's `reason` string is embedded verbatim in the predicate's
`release_confidence_score.components[*].reason` — an auditor reading the
signed JSON never has to reverse-engineer why a run scored what it did.

Run the edge-case suite:

```bash
python3 -m unittest tests.test_scorer -v
```

11/11 pass, covering: zero-tests, missing patch coverage w/ fallback,
docs-only diffs, flaky retries, changes-requested, no-PR-context,
zero-assertion runs, determinism/boundedness, and a compound
failing-tests+low-coverage scenario.

## Signing flow (keyless / Sigstore)

`oidc_signer.py` implements the ambient-credential keyless model end to
end at the interface level (delegating cert-transparency and DSSE PAE
construction to `sigstore-python` rather than hand-rolling it):

1. Fetch a short-lived OIDC token from the CI provider's ambient endpoint
   (`ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN` on GitHub Actions;
   `id_tokens:`/`CI_JOB_JWT_V2` on GitLab CI). **No static secret is ever
   read.**
2. Ephemeral in-memory keypair; exchanged with Fulcio for a short-lived
   cert binding the key to the OIDC identity (`repo:org/repo:ref:...`).
3. Sign the DSSE PAE of the Statement; submit to Rekor for an inclusion
   proof.
4. Discard the ephemeral private key — no long-lived signing key exists
   to rotate or leak.

`fetch_ambient_oidc_token()` raises `AmbientIdentityError` rather than
falling back to an unsigned artifact if no ambient identity is found —
an unsigned attestation masquerading as verified is strictly worse than
a hard pipeline failure.

## Try it

```bash
cd iui-govplane
python3 -m unittest tests.test_scorer -v

python3 -m cli.main \
  --junit-xml tests/fixtures/junit.xml \
  --coverage-format cobertura \
  --coverage-report tests/fixtures/cobertura.xml \
  --image-ref registry.example.com/org/svc \
  --image-digest sha256:$(python3 -c "print('a'*64)") \
  --head-sha $(python3 -c "print('b'*40)") \
  --repository org/svc --branch feature/x \
  --pr-number 42 --pr-approvers alice,bob --pr-required-approvals 2 --pr-review-state approved \
  --skip-perf-budget-check \
  --out /tmp/attestation.unsigned.json
```

(Omit `--sign` unless running inside an actual GitHub Actions/GitLab CI
job with `id-token: write` permissions and the `sigstore` package
installed — outside CI there's no ambient identity to fetch, by design.)

## Not yet built (flagged, not hidden)

- `_estimate_assertion_density()` in `main.py` is a stub returning
  `(0, 0)`; the schema and scorer both already handle that as "zero test
  functions" gracefully, but the real AST-walking pass (scoped to
  diff-touched test files only, to stay proportional to patch size) is
  Task 2 work.
- `main.py`'s `pipeline.run_id` / `workflow_ref` are placeholders pending
  wiring to `GITHUB_RUN_ID`/`GITHUB_WORKFLOW_REF` or GitLab CI equivalents.
- The WORM upload body in `upload_to_worm_async()` is an integration
  point (swap in `boto3` S3 Object Lock COMPLIANCE-mode PUT or
  `minio-py`), intentionally left unimplemented here since it's
  infra-credential-dependent and out of scope for the schema/scoring
  foundation this task covers.
