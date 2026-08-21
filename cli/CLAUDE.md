cat << 'EOF' > CLAUDE.md
# Plinth Assay — AI Collaboration & Architecture Contract

## Environment & Execution Rules
- **NEVER** run `rm -rf .venv` or create new virtual environments.
- **NEVER** invoke `.venv/bin/*` binaries or bare `pytest` directly (avoids container/host shebang mismatch).
- **ALWAYS** invoke tools using the active Python interpreter:
  ```bash
  python3 -m pytest -v tests/
  python3 -m pip install -e ".[dev]"