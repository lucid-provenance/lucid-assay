---
description: Environment, AST inspection, and Sigstore rules for Lucid Assay
globs: ["**/*"]
---

# Lucid Assay Project Guardrails

- DO NOT run `rm -rf .venv` or create virtual environments.
- Always execute commands via `python3 -m <module>` (e.g., `python3 -m pytest -v tests/`).
- Schema URI is `https://lucidprovenance.io/attestations/assay/v1`.
- Preserve scoped AST visitor isolation; never use `ast.walk` inside test function scopes.
- Use `python3 -m sigstore sign` subprocess for OIDC signing operations.
