# Contributing

How to set up, run and test `lucid-assay`. Read [`ARCHITECTURE.md`](ARCHITECTURE.md)
first for the design and the rules that must not be broken.

## Ground rules

- **Work on a branch; never commit to `main`.** It is the protected default and
  every merge runs the real dogfooding pipeline.
- **Keep `README.md` in step with the code.** A PR that changes CLI flags, the
  attestation predicate, degraded reasons or admission rules is not done until
  the README's flag tables, scoring table and predicate documentation match.
  Scoring weights live in two places (`cli/scorer.py`'s `WEIGHTS` and the
  README table) and have drifted before: change both together.
- **No configured linter or type-checker.** Don't add one as a side effect.
- **Every module opens with a "Hardened against:" docstring** listing the failure
  modes it defends against. Read it before editing, and preserve every listed
  guarantee.
- **Fail closed, and explain.** New failure paths must reject *and* say what is
  wrong and how to fix it (expected vs. actual, the exact permission needed).

## Environment rules (do not bypass)

- Invoke tools through the active interpreter: `python3 -m pytest`,
  `python3 -m pip`, `python3 -m sigstore`.
- **Never** run `rm -rf .venv` or create new virtual environments.
- **Never** call `.venv/bin/*` binaries or a bare `pytest` (it avoids
  container/host shebang mismatches).

## Setup

```bash
python3 -m pip install -e ".[dev]"
```

Python 3.10+ is declared in `pyproject.toml`; CI runs 3.13. CI itself installs
with `uv sync --frozen --extra dev` against the committed `uv.lock` (pinned
versions and hashes) so there is no implicit re-resolution. `uv.lock` and
`pyproject.toml`'s `[project.optional-dependencies].dev` must stay in sync: after
editing either, run `uv lock` (or `python3 -m pip install --user uv` first if `uv`
isn't on `PATH`) and commit both together. A stale lock makes `--frozen`
silently install the old dependency set instead of failing.

## Running the tests

```bash
python3 -m pytest -v tests/                                   # what CI runs
python3 -m pytest -v tests/test_scorer.py                     # one file
python3 -m pytest -v tests/test_scorer.py::RCSScorerTests::test_perfect_run_scores_high
python3 -m unittest tests.test_scorer -v                      # the RCS edge-case suite, via unittest
python3 -m pip install pytest-xdist && python3 -m pytest -n auto -v tests/   # in parallel
```

## Test suite taxonomy

Everything under `tests/` is hermetic: no test needs a network, a real signing
identity or a running service. Fixtures live in `tests/fixtures/`. The suites
fall into three kinds.

| Kind | Files (examples) | What they defend |
|---|---|---|
| **Behaviour** | `test_scorer.py`, `test_builder.py`, `test_junit_parser.py`, `test_coverage_parsers.py`, `test_patch_coverage.py`, `test_main.py` | The scoring rollup, statement assembly, parsers, orchestration. |
| **Adversarial / boundary** | `test_adversarial_ast.py`, `test_adversarial_verifier.py`, `test_adversarial_governance_and_exemptions.py`, `test_security_boundaries.py`, `test_verify_boundaries.py`, `test_sarif_adversarial.py`, `test_verify_hardening.py`, `test_red_team_pass.py` | The "Hardened against" guarantees: hostile or malformed input, bypass attempts, size and retry bounds. **These hold the line; don't weaken or delete one to make a change pass.** |
| **Contract** | `test_verify.py`, `test_verify_cli_output.py`, `test_slsa_provenance.py`, `test_source_track_and_build_l3.py`, `test_repository_governance.py`, `test_s2c2f.py` | What `verify` and the predicate promise, including that a genuine statement satisfies the SLSA checklists and that gate flags fold in only what they should. |

Two habits the suite depends on:

- **Assert exact values, not shapes.** The mutation-testing gate (below) fails a
  PR whose changed code is covered by tests that only check `.status` or a
  substring. Import the private function directly, patch only its immediate
  dependency, and assert equality on every field.
- **Test fixtures stay in `tests/`.** Never add a synthetic payload, mock
  signature or hardcoded score to `cli/`.

## Mutation testing applies to your PR

This repo dogfoods its own diff-scoped mutation testing. For each changed source
file (in `cli/`, per this repo's `[tool.mutmut]` config) it mutates the touched
functions and checks your tests kill the mutants. The kill rate discounts the RCS
via `mutation_multiplier` (1.0 at 80%+, 0.85 at 60-79%, 0.50 below 60%), and the
weak tier makes the run `degraded`, which `--disallow-degraded` blocks on `main`.

Practical consequences:

- Granularity is the **whole touched function**, not just your changed lines, so
  a small edit to a large, weakly-tested function pulls its old survivors into
  your PR.
- Skipping the step (`--skip-mutation-testing`) or a tool failure is *not* full
  credit; it takes the same 0.85 multiplier, on purpose.
- Some survivors are genuine equivalent mutants (e.g. `"utf-8"` vs `"UTF-8"`).
  Document those in the module docstring instead of chasing them.
- `mutants/` is a generated cache. Never `git add` it, and check `git status`
  before staging.

## Changing a degradation trigger or an admission rule

- Give a new degradation trigger **its own** `DEGRADED_REASON_*` / `REASON_CODE_*`
  constant. Don't reuse one, or you silently change what `--disallow-degraded`
  exempts.
- Then decide, deliberately, whether `cli/verify.py`'s `_ALLOWED_DEGRADED_REASONS`
  should exempt it (only for a genuinely unavoidable, non-gameable state) or
  `_DEGRADED_REASONS_BLOCKED_DELIBERATELY` should list it. The guardrail test in
  `tests/test_verify.py` fails until every constant is in exactly one set.
- Adding a `--require-*` gate flag, or wiring an informational section into
  `passed`, is a separate decision. Don't do it in passing.

## Signing, packaging and the container image

- Signing uses `Signer.sign_dsse()` directly. Don't reintroduce a `sigstore`
  CLI subprocess (see `ARCHITECTURE.md`).
- `schema/` is only installed by a plain `pip install .` because it has an
  `__init__.py` **and** a `[tool.setuptools.package-data]` entry. If you touch
  packaging, verify with a real install into a throwaway environment and check
  `cli.verify._SCHEMA_PATH` exists; reading the config and assuming is how this
  bug went unnoticed once.
- The container image installs with `uv sync --frozen --no-dev` and copies the
  project to the identical absolute path in the runtime stage (the editable
  install's path is baked in). `HOME=/tmp` is deliberate so any `--user` UID can
  write.

## Workflow security posture (`.github/workflows/assay.yml`)

- Every third-party Action is pinned to a full commit SHA with a `# vX` comment.
- `permissions:` stays least-privilege. `administration` is not a valid workflow
  scope; branch-governance queries use a separate GitHub App token, which is
  skipped for fork PRs.
- The workflow triggers on `pull_request`, never `pull_request_target`: it
  executes code from the PR head, so it must run without secrets on forks.
- Build multi-flag shell arguments as a bash array (`ARGS=(--flag "$val")`,
  `"${ARGS[@]}"`), never by string concatenation that relies on word splitting.
- Steps needing a secret that fork PRs don't get are guarded with an `if:`
  condition instead of failing on every external contributor's PR.

## Functional verification

`lucid-assay` is where the functional-adequacy evaluator lives
(`cli/parsers/functional_adequacy.py`, exposed as `--functional-*` flags on
`cli.main` and as the standalone `cli/functional.py`), and callers declare their
journeys in a `.lucid/functional-verification.json`. **This repo does not declare
a contract of its own.** If you change the evaluator, the contract format (`ci` /
`cd` / `both` tiers, the legacy flat list) or its reason codes, update the README's
"Functional test adequacy evaluation" section and the schema
(`schema/lucid-attestation-v1.schema.json`, whose `functional_verification` block
is `additionalProperties: false`) in the same PR. Callers pin this repo by
commit, so a new flag must merge and be re-pinned by a caller *before* that
caller starts passing it.

**Per-test results (`tests` / `tests_truncated`)** are part of that signed block, and
lucid-console renders them, so treat their shape as a contract:

- The evaluator keeps each case's `name`/`classname`/`status`/`duration_s`/`message`/
  `journeys` (`_NormalizedCase`) and `_test_rows` emits the bounded list. It is emitted
  only alongside the tier fields, so a legacy flat contract stays byte-identical.
- `message` comes from the outcome element's own attribute, never element text. Keep it
  that way: the text body is the traceback, and captured output can hold secrets. The
  `PerTestResultsEvaluationTests` case plants a secret in all three places and asserts it
  never reaches the output -- don't weaken it.
- Changing a field, a cap or the ordering means the schema (`additionalProperties: false`),
  the README section, and lucid-console's `parseTestResults` all change together, and a
  console change must tolerate records without the new shape (a missing `tests` means "not
  recorded", never "zero tests").
- New behavior gets direct-field tests (exact equality on every field), because the
  mutation gate scores the whole touched function.
