# lucid-attest

The trusted signing boundary for [lucid-assay](https://github.com/lucid-provenance/lucid-assay)
attestations.

## What this is (and isn't)

This is **not** a code-reuse convenience — it's a trust boundary. It exists
because a build job that runs a PR's own tests/dependencies/CodeQL analysis
must never also be the job that mints the Sigstore identity used to sign
what that build claims about itself. If both lived in the same job (or the
same repo, on the same ref), a compromise of the build step — a malicious
dependency, a tampered test fixture — could in principle tamper with both
the artifact *and* its own attestation at once.

Splitting signing into its own job (`id-token: write` granted nowhere else)
closes most of that gap already. This repo closes the rest: the signing
job's *code* lives here, checked out at a commit SHA the caller pins
independently of whatever ref triggered its own run — so even a PR that
fully rewrites `lucid-assay`'s own workflow file (or the pipeline code
itself) in the same PR cannot also change what this job trusts. Bumping
the pin is a separate, deliberate, reviewable act.

This repo is public deliberately: the signing logic isn't secret, and a
public, independently-inspectable trust boundary is more credible than a
private one to anyone verifying a `lucid-assay` attestation.

The commit of `lucid-assay` this job trusts enough to check out and run
(`cli/sign.py` + `cli/oidc_signer.py`) is hardcoded inside `sign.yml` itself
(`env.TRUSTED_SIGNER_SHA`) — it is deliberately **not** a `workflow_call`
input the caller can set. The privileged job here (`id-token: write`) must
never execute code checked out from a ref an untrusted caller supplies
dynamically; only a commit to *this* repo can move that pin.

## What's here

- `.github/workflows/sign.yml` — the reusable `workflow_call` workflow.
  Called from `lucid-provenance/lucid-assay`'s own `assay.yml` `attest` job. See
  that file's header comment for the full contract (inputs, what it checks
  out, what it does and doesn't trust from the caller).

## Setup (for whoever stands this repo up)

1. Create this repo as `lucid-provenance/lucid-attest` (public).
2. Push this directory's contents (`.github/workflows/sign.yml` + this
   `README.md`) to its `main` branch.
3. Protect `main` the same way `lucid-provenance/lucid-assay`'s own default branch
   is protected — this file's integrity *is* the trust boundary.
4. Note the commit SHA of that push. In `lucid-provenance/lucid-assay`'s
   `assay.yml`, swap the `attest` job's local placeholder steps for:

   ```yaml
   attest:
     needs: build
     permissions:
       id-token: write
       contents: read
     uses: lucid-provenance/lucid-attest/.github/workflows/sign.yml@<that-sha> # v1
     with:
       artifact-name: unsigned-statements
       statement-files: |
         lucid-assay.unsigned.json
         lucid-assay.slsa-provenance.unsigned.json
   ```

5. Whenever `lucid-assay`'s signing code (`cli/sign.py`,
   `cli/oidc_signer.py`) changes in a way you want the signer to pick up,
   bump `env.TRUSTED_SIGNER_SHA` at the top of *this repo's* `sign.yml`, in
   a deliberate, reviewed commit — never point it at a moving branch, and
   never re-expose it as something `lucid-assay`'s workflow can set.
6. Whenever this repo's own `sign.yml` changes, bump the SHA in
   `lucid-assay`'s `uses:` line the same way every other pinned action in
   that repo is bumped (full commit SHA, `# vX` comment, never a mutable
   tag alone).
