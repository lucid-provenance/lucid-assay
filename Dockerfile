# syntax=docker/dockerfile:1.7

# Immutable Assay CLI image -- Lucid roadmap Milestone #19
# ("Immutable Assay Container (Bridge to #4)").
#
# Unlike lucid-attest's signer image (Milestone #18), this one carries no
# trust-boundary constraint -- lucid-assay's scoring/parsing code never
# runs with `id-token: write`, so this image is a full, self-contained
# package of the entire CLI (cli/main.py, cli/verify.py, cli/scorer.py,
# cli/parsers/*, cli/builder.py -- everything), not a narrow, hand-picked
# file list. See the Lucid vault's "Container trust-boundary discipline"
# note for why the two images are held to genuinely different standards,
# not just "the same idea done twice."
#
# What this closes: the same source-pinned/runtime-not-pinned gap #18
# closed for the signer, but against a goal lucid-assay already claims for
# itself -- RCS scoring's whole premise is determinism, but today only the
# *source* commit is pinned; the execution environment (OS libraries,
# exact interpreter patch build, and a live runtime dependency on PyPI's
# availability) is reassembled fresh via `uv sync` on whatever runner
# executes it. This image freezes all of that, the same way #18 did for
# signing.
#
# Reuses #18's hard-won lessons rather than rediscovering them:
#   - HOME=/tmp from the start (see the runtime stage below) -- #18 hit a
#     real permission failure under `docker run --user "$(id -u):$(id -g)"`
#     when HOME pointed at a fixed non-root user's home directory that the
#     runtime UID didn't own.
#   - Published publicly on GHCR from the first build -- no reason for
#     this image to default private given lucid-assay's own source is
#     already public, and #18 lost a full round trip to an org policy
#     blocking a later visibility change.
#   - Base image digests below are the same ones #18 resolved and pinned
#     the same day (2026-08-31) -- re-verify before reusing much later.

# ---- uv's own static binary, vendored rather than pip-installed ----
FROM ghcr.io/astral-sh/uv:0.9.5@sha256:f459f6f73a8c4ef5d69f4e6fbbdb8af751d6fa40ec34b39a1ab469acd6e289b7 AS uv-binary

# ---- Stage 1: install the full project via `uv sync` (not `pip install`) ----
FROM python:3.13-slim@sha256:7ce4b6dfe35e55397b7cda544f8a13f191b7ae28dc5aad71fe664dbc9bc2623f AS builder
COPY --from=uv-binary /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY cli/ cli/
COPY schema/ schema/

# `uv sync`, not `pip install .` -- verified empirically before writing
# this: a plain `pip install .` into a venv does NOT actually install
# schema/ as package data (pyproject.toml's `[tool.setuptools.packages.find]
# include = ["schema*"]` silently fails to pick it up -- schema/ has no
# __init__.py), which breaks cli/verify.py's own schema-file resolution
# (`Path(__file__).resolve().parent.parent / "schema" / "*.json"`) --
# not a crash, but a silent degrade to schema_validation_status="skipped"
# for every single run. `uv sync` installs the local project *editable*
# by default, which keeps cli/ and schema/ as real sibling directories on
# disk at this exact path (verified: the resulting _SCHEMA_PATH resolves
# and exists) -- exactly like running from a normal checkout. This means
# the runtime stage below MUST copy this whole directory to the identical
# absolute path (/app), never rename it -- the editable install's own
# path reference is an absolute path baked in at sync time, not relative.
RUN uv sync --frozen --no-dev

# ---- Stage 2: runtime -- git is a real, new requirement here ----
FROM python:3.13-slim@sha256:7ce4b6dfe35e55397b7cda544f8a13f191b7ae28dc5aad71fe664dbc9bc2623f AS runtime

# git: needed for real, unlike #18's signer image (which never touches
# git history at all) -- cli/patch_coverage.py and cli/provenance.py run
# `git diff`/`git log` against whatever repo is mounted in at runtime.
# ca-certificates: same reasoning as #18 -- real network calls (GitHub API
# for branch governance/commit-author checks, optional Sigstore signing,
# WORM upload) need a working, current CA bundle, not assumed present.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Fixed, non-root UID/GID -- same discipline as #18's signer image, for
# the same reason: a safe default for anyone running this standalone.
# Any invocation that needs to write to a bind-mounted host directory
# (a tenant's --out path, almost always) overrides this via
# `docker run --user "$(id -u):$(id -g)"`.
RUN groupadd --gid 65532 assay \
 && useradd --uid 65532 --gid assay --no-create-home --shell /usr/sbin/nologin assay \
 && mkdir -p /workspace \
 && chown assay:assay /workspace

# Copied to the IDENTICAL path as the builder stage (/app) -- see that
# stage's comment on `uv sync`'s editable install for why renaming this
# would silently break schema-file resolution again.
COPY --from=builder /app /app

# HOME=/tmp, not a fixed user's home directory -- see this file's header:
# #18 already hit this exact failure mode (Sigstore's cache directory
# under a UID-owned $HOME breaking when the runtime UID doesn't match)
# and the fix generalizes to any tool this CLI might invoke that wants to
# write a cache/config file under $HOME. World-writable (sticky bit,
# mode 1777) regardless of which UID actually runs the container.
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

# A tenant mounts their own repo checkout here (with full history --
# `fetch-depth: 0` on their own checkout step -- patch coverage computes
# `git diff base...head`). --repo-dir defaults to "." in cli/main.py, so
# mounting the checkout at exactly this WORKDIR lets that default work
# without every invocation needing to pass --repo-dir explicitly.
WORKDIR /workspace
USER assay
ENTRYPOINT ["lucid"]
