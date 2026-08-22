# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Plinth Assay: a single-binary CI tool (`cli/main.py`, packaged as `plinth`/`plinth-assay`) that turns test/coverage/governance signals from a CI run into a deterministic Release Confidence Score (RCS), assembles that into a signed in-toto attestation (DSSE + Sigstore keyless signing), and provides a standalone admission gate (`cli/verify.py`) that CI can enforce against the signed attestation before allowing a merge/deploy.

## Git workflow

**Always work from a branch — never commit directly to `main`.** Before making any change, create or switch to a feature/topic branch first (`git switch -c <name>` or similar). `main` is the default/protected branch this repo ships from.

## Commands

Environment/execution rules (never bypass):
- **NEVER** run `rm -rf .venv` or create new virtual environments.
- **NEVER** invoke `.venv/bin/*` binaries or a bare `pytest` directly (avoids container/host shebang mismatch).
- **ALWAYS** invoke tools via the active `python3` interpreter (`python3 -m pytest`, `python3 -m pip`, `python3 -m sigstore`).

```bash
# Install
python3 -m pip install -e ".[dev]"

# Full test suite (what CI runs)
python3 -m pytest -v tests/

# Single test file / test / class
python3 -m pytest -v tests/test_scorer.py
python3 -m pytest -v tests/test_scorer.py::RCSScorerTests::test_perfect_run_scores_high

# The RCS edge-case suite can also be run via unittest directly
python3 -m unittest tests.test_scorer -v

# Run the attestation pipeline end-to-end (unsigned; see README.md "Try it"
# for the full flag set)
python3 -m cli.main --junit-xml ... --coverage-report ... --image-ref ... \
  --image-digest ... --head-sha ... --repository org/repo --branch main \
  --skip-perf-budget-check --out /tmp/attestation.unsigned.json

# Verify a signed DSSE envelope against admission policy gates
python3 -m cli.verify build/plinth-assay.dsse.json --min-rcs 65 --disallow-degraded
```

There is no configured linter/type-checker in `pyproject.toml` — don't invent one.

## Architecture

`cli/main.py::main()` is the pipeline orchestrator; its numbered comments (`# 1.` … `# 10.`) are the canonical map of the flow: parse JUnit/coverage → compute patch coverage from `git diff base...head` → inspect branch governance (GitHub rulesets) → optionally ingest SARIF → hash evidence artifacts → AST-walk the test suite for assertion integrity → `scorer.score_pipeline()` → `builder.build_statement()` → write the unsigned statement → fire-and-forget WORM upload → optional Sigstore signing → gate on `--min-rcs`.

**Module boundary discipline** (see README.md "Why this decomposition" for the full rationale): `parsers/*` and `scorer.py` are pure/side-effect-free by design — they're what the adversarial test suites hammer on. `oidc_signer.py` and the WORM upload are the *only* network-touching code, isolated so the pipeline's self-measured 50ms blocking budget (warned on, not enforced, via `--skip-perf-budget-check`) excludes them deliberately.

**RCS scoring** (`cli/scorer.py`): a weighted rollup (test health 35%, patch coverage 25%, overall coverage 15%, assertion integrity 10%, governance 15%) where almost every edge case fails *closed* rather than defaulting neutral — zero tests executed floors to 0, missing patch coverage falls back to overall coverage × 0.70 and flags `degraded: true`, no PR context scores a neutral 50 (not full credit). Every component's `reason` is embedded verbatim in the signed predicate so an auditor never has to reverse-engineer a score. See README.md's scoring table before changing weights or edge-case behavior.

**Signing** (`cli/oidc_signer.py`): calls Sigstore's `Signer.sign_dsse()` library API directly (`sigstore.sign.SigningContext` + `sigstore.dsse.Statement`), **not** the `sigstore` CLI. This matters: `sigstore sign` always produces a hashedrekord/`messageSignature` bundle (a signature over raw artifact bytes), never a DSSE envelope, no matter what's passed as input — and `cli/verify.py` calls `Verifier.verify_dsse()`, which requires a real DSSE envelope and rejects a hashedrekord one outright ("cannot perform DSSE verification on a bundle without a DSSE envelope"). `sigstore attest` doesn't fit either: it restricts `--predicate-type` to the SLSA provenance enum and derives its subject from a hash of the predicate file, rather than accepting the already-assembled Statement's own subject (a container image digest). `Signer.sign_dsse()` is the public entry point both CLI subcommands delegate to internally — if you're touching signing, use it directly rather than reintroducing a CLI subprocess. Fetches the ambient OIDC token itself (GitHub Actions `ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN`, or GitLab `CI_JOB_JWT_V2`) and raises rather than silently falling back to an unsigned artifact. The full Sigstore bundle (`Bundle.to_json()`) is embedded verbatim in the DSSE envelope under `_sigstore_bundle` — `cli/verify.py` must load it via `Bundle.from_json()` on that embedded bundle, not by hand-reconstructing bundle fields from scraps (an earlier version did this and could never satisfy `sigstore_models`' schema for `tlogEntries`).

**Verification / admission gate** (`cli/verify.py`): decodes the DSSE envelope defensively (never raises on malformed input, only reports `violations`), and does best-effort Sigstore identity verification (`--cert-identity`/`--expected-repository`/`--expected-workflow`/`--expected-ref`) distinguishing `verified`/`skipped`/`unavailable`/`failed` — only `failed` (an explicit Sigstore rejection) blocks the gate; `unavailable` (offline, no trust root) is a warning, not a failure. `--dry-run` and a `--dry-run-sign`-produced placeholder signature are both treated as `skipped`, never mistaken for a real signature. `--expected-repository` is checked against *both* the legacy v1 (`GitHubWorkflowRepository`, raw `owner/repo`) and current v2 (`OIDCSourceRepositoryURI`, full `https://github.com/owner/repo`) Fulcio cert extensions via `AnyOf`, since which one a given cert carries depends on the Fulcio/token version that minted it. On a `SigstoreVerificationError`, the expected vs. actual certificate claims (SAN, issuer, repo, ref) are dumped to `sys.stderr` so a mismatch is diagnoseable straight from CI logs.

**SARIF static-analysis ingestion** (`cli/parsers/sarif.py`): normalizes one or more `--sarif` inputs (semgrep, trivy, CodeQL, ...) and cross-references each finding's file/line against the patch's changed lines, falling back to suffix-matching on path components when a SARIF artifact URI is absolute or CI-runner-prefixed and doesn't line up with git's repo-root-relative paths. The scorer weighs a finding newly introduced in the patch far more heavily than a pre-existing baseline one. Aggregating multiple `--sarif` inputs fails closed: any single unreadable/corrupt report taints the whole aggregate (`available=False`), same as a bad token taints the whole branch-governance report.

**Branch governance** (`cli/parsers/github_rules.py`): queries GitHub's rules-for-branch and rulesets REST endpoints to check whether "branch protection" *actually* prevents an unreviewed direct push/merge (PR required, non-zero approvals, no bypass actor, admin-enforced) as opposed to merely appearing to. These endpoints normally require `Administration: Read` repository permission, which the default `GITHUB_TOKEN` can never be granted via a workflow's `permissions:` block (`administration` is not a valid scope there — don't try to add it, it breaks the whole workflow at parse time). `.github/workflows/assay.yml` mints a separate GitHub App installation token for this (`actions/create-github-app-token`, skipped on fork PRs since `secrets.APP_PRIVATE_KEY` isn't available in that context) and passes it via `--github-token`. Any 401/403 from these endpoints fails the whole governance report closed (`available=False`) rather than trusting partial data from a bad/under-scoped token; `_actionable_auth_failure_reason()` leads with GitHub's own error-body message (extracted via `_extract_http_error_detail`) rather than assuming it's a token-scope problem.

**Known, formerly-live constraint (now handled)**: on this repo (`billwonch/iui-govplane`, private, GitHub Free), the rules-for-branch endpoint 403s unconditionally with `"Upgrade to GitHub Pro or make this repository public to enable this feature."` — confirmed empirically (correctly-scoped App token, correct branch name, still 403s) — branch rulesets simply aren't a supported feature on this plan/visibility combination, full stop; no token fixes it. `BranchGovernanceReport.reason_code` is set to `REASON_CODE_PLATFORM_UNSUPPORTED_TIER` specifically for this condition (detected via GitHub's own 403 error-body wording) and flows through into `predicate.branch_governance.reason_code`. **Note**: private Pro/Team/Enterprise repos *do* support rulesets, so gating policy on repo visibility alone (e.g. `github.event.repository.private`) is wrong — it would also waive strict enforcement for a private paid-plan repo with a real, fixable governance gap.

**`--disallow-degraded` is `reason_code`-aware, not a flat boolean gate.** `RCSResult.degraded_reasons` (`cli/scorer.py`) records *why* a run is degraded -- one entry per independent trigger (`DEGRADED_REASON_*` constants there; branch-governance's entry is namespaced `f"branch_governance:{reason_code}"` when a `reason_code` is set, else the generic `DEGRADED_REASON_BRANCH_GOVERNANCE_UNVERIFIED`) -- and is embedded as `predicate.release_confidence_score.degraded_reasons`. `cli/verify.py`'s `--disallow-degraded` gate only lets a degraded run pass when `degraded_reasons` is non-empty **and every entry** equals `"branch_governance:platform_unsupported_tier"`; anything else (a real governance gap, missing PR context, broken SARIF/patch-coverage, or `degraded_reasons` missing/malformed on an older or corrupt attestation) still blocks -- fail-closed by construction, not by omission. If you add a new degradation trigger to `score_pipeline()`, give it its own reason code; don't reuse an existing one, or you'll silently change what `--disallow-degraded` exempts.

Also: on a `pull_request` event, `github.ref_name` resolves to the synthetic `"<number>/merge"` ref, not a real branch — `assay.yml` resolves `--branch` from `github.event.pull_request.base.ref || github.ref_name` instead. If branch governance starts erroring on a nonsense branch name, check that this resolution didn't regress.

**AST assertion-integrity checker** (`cli/parsers/ast_inspector.py`): per `.continue/rules/plinth-assay.md`, preserve *scoped* AST visitor isolation when touching this — never use `ast.walk()` inside a test function's scope, since that would credit assertions inside dead branches, nested defs/lambdas, or swallowed-exception `try` blocks as if they actually execute. It also recognizes and rejects tautological assertions (`assert True`, `self.assertEqual(x, x)`, etc.) and mock-typo bypasses (`mock.assert_called()`).

**Hardening pattern**: nearly every module in `cli/` opens with a docstring block titled "Hardened against:" enumerating the specific failure modes it defends against (injection, auth failures, malformed input, adversarial pagination, etc.). When editing one of these modules, check its docstring first and preserve every listed guarantee — the adversarial/boundary test files (`tests/test_security_boundaries.py`, `tests/test_verify_boundaries.py`, `tests/test_adversarial_ast.py`) exist specifically to hold the line on these.

**Diagnostics-first convention**: a policy violation or auth failure (Sigstore identity mismatch in `cli/verify.py`, a 401/403 from GitHub in `cli/parsers/github_rules.py`) must fail closed *and* explain exactly what's wrong and how to fix it — expected-vs-actual values, the specific permission/scope needed — not just a bare exception message or status code. Follow this when adding new failure paths in these modules.

**Workflow security posture** (`.github/workflows/assay.yml`): every third-party Action is pinned to a full commit SHA with a `# vX` version comment (never a mutable tag alone); `permissions:` stays least-privilege (only what's actually used — see the branch-governance note above for why `administration` can't live there); and any step needing a secret unavailable to fork PRs (e.g. `secrets.APP_PRIVATE_KEY`) is guarded with an `if:` condition rather than left to fail loudly on every external contributor's PR. Build multi-flag shell args as a bash array (`ARGS=(--flag "$val")` / `"${ARGS[@]}"`), never string-concatenation handed to word-splitting (`ARGS="$ARGS --flag \"$val\""` then `$ARGS` unquoted) — the latter can't actually strip embedded quote characters without `eval`, and this exact mistake broke both the Mint and Verify steps' argument passing here before being fixed.

## Documentation & README Discipline
**Always keep `README.md` synchronized with architecture and CLI changes.**
- **Flags & CLI Contract:** Whenever arguments or flags are added, modified, or deprecated in `cli/main.py` or `cli/verify.py`, update the usage examples, flag reference tables, and "Try it" sections in `README.md`.
- **Scoring & Predicate Changes:** If scoring weights, degraded state reasons (`degraded_reasons`), or predicate schemas are updated, update the corresponding tables and in-toto predicate structure documentation in `README.md`.
- **Definition of Done:** A PR that changes user-facing CLI behavior, attestation payload schemas, or admission gate rules is incomplete until `README.md` reflects those exact mechanics.