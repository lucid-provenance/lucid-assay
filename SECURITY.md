# Security Policy

`lucid-assay` computes a signed Release Confidence Score from CI signals and
produces the DSSE/Sigstore attestation the rest of the Lucid platform trusts.
It also runs the admission gate (`cli/verify.py`) that enforces policy
against that attestation before a merge/deploy proceeds. A vulnerability
here can mean a forged or inflated score, a bypassed admission gate, or a
signing/OIDC-token handling bug — please report it privately rather than
filing a public issue.

## Reporting a Vulnerability

Use GitHub's private vulnerability reporting for this repo:

**[github.com/lucid-provenance/lucid-assay/security/advisories/new](https://github.com/lucid-provenance/lucid-assay/security/advisories/new)**
(also reachable from the repo's **Security** tab → **Report a vulnerability**)

Please include, where you can:
- A description of the issue and its potential impact
- Steps to reproduce, or a minimal proof of concept
- The affected commit SHA or file(s)

## Scope

In scope:
- The RCS scoring pipeline and its edge-case handling (`cli/scorer.py`,
  `cli/parsers/*`) — especially anything that lets an untrusted CI input
  (JUnit XML, coverage reports, SARIF, SBOMs, lockfiles) inflate a score or
  crash the pipeline
- The admission gate (`cli/verify.py`) — any bypass of `--min-rcs`,
  `--disallow-degraded`, `--require-digest`, or Sigstore identity
  verification
- DSSE/Sigstore signing and OIDC token handling (`cli/oidc_signer.py`)
- The GitHub Actions workflow (`.github/workflows/assay.yml`) — pinning,
  permissions, secret handling

Out of scope:
- Vulnerabilities in third-party dependencies themselves — please report
  those upstream (Dependabot already tracks and patches these here)
- The `sigstore-python` library's own cryptographic implementation

## Supported Versions

This project doesn't yet publish versioned releases — only the latest
commit on `main` is supported. A fix lands as a normal PR, not a backport.

## Response

This is maintained on a best-effort basis, not under a formal SLA. We'll
acknowledge reports as promptly as we can and keep you updated as we
investigate.
