# Makes `schema/` a real Python package, not just a data directory.
#
# Required for `[tool.setuptools.packages.find] include = ["schema*"]` in
# pyproject.toml to actually work -- without this file, setuptools' package
# finder silently skips `schema/` despite it being listed, and a plain
# `pip install .` never installs the schema JSON at all. Verified
# empirically (a real `pip install .` into a throwaway venv, checked
# against cli.verify._SCHEMA_PATH) before this fix: schema/ was not being
# installed, and cli.verify's schema validation was silently degrading to
# "skipped" on every run for anyone who didn't build via `uv sync`
# specifically (which happens to install the project editable, masking
# the bug by keeping schema/ at its original on-disk location instead of
# actually packaging it).
#
# No functional code belongs here -- this package holds one JSON file
# (lucid-attestation-v1.schema.json), declared as package data via
# `[tool.setuptools.package-data]` in pyproject.toml.
