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
job's *code* lives here, checked out at a ref hardcoded in this repo's own
`sign.yml` — deliberately not a value the caller can supply, so even a PR
that fully rewrites `tenax-assay`'s own workflow file (or the pipeline code
itself) in the same PR cannot also change what this job trusts. Bumping
that ref is a separate, deliberate, reviewable change to *this* repo alone.

This repo is public deliberately: the signing logic isn't secret, and a
public, independently-inspectable trust boundary is more credible than a
private one to anyone verifying a `tenax-assay` attestation.

The commit of `tenax-assay` this job trusts enough to check out and run
(`cli/sign.py` + `cli/oidc_signer.py`) is tracked via `sign.yml`'s
`env.TRUSTED_SIGNER_REF` — it is deliberately **not** a `workflow_call`
input the caller can set. The privileged job here (`id-token: write`) must
never execute code checked out from a ref an untrusted caller supplies
dynamically; only a change to *this* repo (and, per below, a release on
`tenax-assay` itself) can move that pin.

## What's here

- `.github/workflows/sign.yml` — the reusable `workflow_call` workflow.
  Called from `tenax-io/tenax-assay`'s own `assay.yml` `attest` job. See
  that file's header comment for the full contract (inputs, what it checks
  out, what it does and doesn't trust from the caller).

## Releases and tag protection

`tenax-assay`'s `attest` job tracks this repo's `v1` tag
(`uses: tenax-io/tenax-attest/.github/workflows/sign.yml@v1`) rather than a
pinned commit SHA — a new `v1.x.y` release here is picked up by every
caller automatically, with no corresponding commit required on their side.
The trade-off: the identity check `tenax-assay`'s verify gate runs
(`--cert-identity .../sign.yml@refs/tags/v1`) matches by *ref name*, not by
resolved commit — Fulcio certificates carry the ref a reusable workflow was
checked out at, not the commit it happened to resolve to. That means the
entire guarantee a commit-SHA pin used to provide — "this can only ever be
the one specific, reviewed commit" — now depends completely on `v1` never
being repointed to unreviewed code.

**This repo's `v1` tag, and `tenax-assay`'s own `v1` tag** (which
`TRUSTED_SIGNER_REF` in `sign.yml` tracks — see that file's header) **must
both be protected by a repository ruleset**, not just ordinary branch
protection:

1. Settings → Rules → Rulesets → New ruleset → **Tag ruleset**.
2. Target: tags matching `v*`.
3. Enforcement status: Active.
4. Rules: **Restrict deletions**, **Block force pushes** (this is what
   prevents an existing `v1` from being silently repointed — without it,
   moving the tag is exactly one `git push --force`), and restrict which
   roles/bypass list may create or update matching refs to release
   managers only.
5. Apply the identical ruleset to `tenax-io/tenax-assay`'s `v1` tag —
   `sign.yml`'s `TRUSTED_SIGNER_REF` trusts it the same way this repo's
   `v1` is trusted, with no independent check on the other side.

Treat changes to either ruleset with the same scrutiny as a
branch-protection change on `main`: it is no longer a convenience setting,
it is the mechanism that makes tag-based pinning here safe at all.

## Setup (for whoever stands this repo up)

1. Create this repo as `tenax-io/tenax-attest` (public).
2. Push this directory's contents (`.github/workflows/sign.yml` + this
   `README.md`) to its `main` branch.
3. Protect `main` the same way `tenax-io/tenax-assay`'s own default branch
   is protected — this file's integrity *is* the trust boundary. Also set
   up the tag-protection ruleset described above, on *both* repos, before
   wiring anything up to `v1` in step 4.
4. Cut a `v1.0.0` release (tag + GitHub Release) on `main`, and point the
   `v1` tag at the same commit. In `tenax-io/tenax-assay`'s `assay.yml`,
   swap the `attest` job's local placeholder steps for:

   ```yaml
   attest:
     needs: build
     permissions:
       id-token: write
       contents: read
     uses: tenax-io/tenax-attest/.github/workflows/sign.yml@v1
     with:
       artifact-name: unsigned-statements
       statement-files: |
         tenax-assay.unsigned.json
         tenax-assay.slsa-provenance.unsigned.json
   ```

5. Whenever `tenax-assay`'s signing code (`cli/sign.py`,
   `cli/oidc_signer.py`) changes in a way you want the signer to pick up:
   cut a new `tenax-assay` `v1.x.y` release and repoint *that repo's* `v1`
   tag at it (its own release process) — `TRUSTED_SIGNER_REF` here already
   tracks `refs/tags/v1`, so no edit is needed in this repo. Never
   hand-edit `TRUSTED_SIGNER_REF` to a branch or an arbitrary ref, and
   never re-expose it as something `tenax-assay`'s workflow can set.
6. Whenever this repo's own `sign.yml` changes: cut a new `vX.Y.Z` release
   here and repoint `v1` at it. Bump `env.SIGNER_WORKFLOW_REF` in
   `tenax-assay`'s `assay.yml` only on a *major* version change (a new
   `v2` that callers must opt into deliberately) — a `v1.x.y` release
   requires no change on the caller side at all, that's the point of
   tracking `v1`.
