# tenax-attest

The trusted signing boundary for [tenax-assay](https://github.com/tenax-io/tenax-assay)
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
fully rewrites `tenax-assay`'s own workflow file (or the pipeline code
itself) in the same PR cannot also change what this job trusts. Bumping
the pin is a separate, deliberate, reviewable act.

This repo is public deliberately: the signing logic isn't secret, and a
public, independently-inspectable trust boundary is more credible than a
private one to anyone verifying a `tenax-assay` attestation.

## What's here

- `.github/workflows/sign.yml` — the reusable `workflow_call` workflow.
  Called from `tenax-io/tenax-assay`'s own `assay.yml` `attest` job. See
  that file's header comment for the full contract (inputs, what it checks
  out, what it does and doesn't trust from the caller).

## Setup (for whoever stands this repo up)

1. Create this repo as `tenax-io/tenax-attest` (public).
2. Push this directory's contents (`.github/workflows/sign.yml` + this
   `README.md`) to its `main` branch.
3. Protect `main` the same way `tenax-io/tenax-assay`'s own default branch
   is protected — this file's integrity *is* the trust boundary.
4. Note the commit SHA of that push. In `tenax-io/tenax-assay`'s
   `assay.yml`, swap the `attest` job's local placeholder steps for:

   ```yaml
   attest:
     needs: build
     permissions:
       id-token: write
       contents: read
     uses: tenax-io/tenax-attest/.github/workflows/sign.yml@<that-sha> # v1
     with:
       artifact-name: unsigned-statements
       statement-files: |
         tenax-assay.unsigned.json
         tenax-assay.slsa-provenance.unsigned.json
       signer-ref: <a pinned tenax-assay commit SHA providing cli/sign.py>
   ```

5. Whenever `tenax-assay`'s signing code (`cli/sign.py`,
   `cli/oidc_signer.py`) changes in a way you want the signer to pick up,
   bump `signer-ref` in a deliberate, reviewed commit — never point it at
   a moving branch.
6. Whenever this repo's own `sign.yml` changes, bump the SHA in
   `tenax-assay`'s `uses:` line the same way every other pinned action in
   that repo is bumped (full commit SHA, `# vX` comment, never a mutable
   tag alone).
