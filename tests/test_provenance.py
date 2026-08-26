"""
CLI-level tests for `tenax-assay provenance` (cli/provenance.py) -- the
standalone SLSA v1.0 provenance-CONSTRUCTION subcommand intended to run
inside an isolated, trusted signer job (see that module's docstring for
why it's separate from cli.main's --emit-slsa-provenance). Mirrors
tests/test_sign.py's CLI-level style.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.main import main as cli_main
from cli.provenance import EXIT_FILE_ERROR, EXIT_PASS, main as provenance_main
from cli.slsa_provenance import GITHUB_HOSTED_BUILDER_ID, SLSA_PROVENANCE_PREDICATE_TYPE

_GITHUB_ENV = {
    "GITHUB_REPOSITORY": "acme/widgets",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_SHA": "b" * 40,
    "GITHUB_RUN_ID": "999",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_WORKFLOW_REF": "acme/widgets/.github/workflows/sign.yml@refs/heads/main",
    "RUNNER_ENVIRONMENT": "github-hosted",
}


class _TempDirTestCase(unittest.TestCase):
    def _tmp(self) -> str:
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d


class ProvenanceSubcommandTests(_TempDirTestCase):
    def test_constructs_statement_from_ambient_env(self):
        tmp = self._tmp()
        out_path = os.path.join(tmp, "provenance.unsigned.json")

        with mock.patch.dict(os.environ, _GITHUB_ENV, clear=False):
            exit_code = provenance_main(
                [
                    "--subject-name", "registry.example.com/org/svc",
                    "--subject-digest", "sha256:" + "a" * 64,
                    "--repo-dir", tmp,
                    "--out", out_path,
                ]
            )

        self.assertEqual(exit_code, EXIT_PASS)
        with open(out_path, "r", encoding="utf-8") as f:
            statement = json.load(f)

        self.assertEqual(statement["predicateType"], SLSA_PROVENANCE_PREDICATE_TYPE)
        self.assertEqual(statement["subject"][0]["digest"]["sha256"], "a" * 64)
        # Not the generic GITHUB_HOSTED_BUILDER_ID: builder.id asserts
        # *this process's own* trusted workflow identity (derived from
        # ambient GITHUB_WORKFLOW_REF), which is the whole point of this
        # subcommand -- see _control_plane_builder_id()'s docstring.
        self.assertEqual(
            statement["predicate"]["runDetails"]["builder"]["id"],
            "https://github.com/acme/widgets/.github/workflows/sign.yml",
        )

    def test_bare_hex_digest_normalized_same_as_sha256_prefixed(self):
        tmp = self._tmp()
        out_path = os.path.join(tmp, "provenance.unsigned.json")

        with mock.patch.dict(os.environ, _GITHUB_ENV, clear=False):
            provenance_main(
                ["--subject-name", "x", "--subject-digest", "A" * 64, "--repo-dir", tmp, "--out", out_path]
            )

        with open(out_path, "r", encoding="utf-8") as f:
            statement = json.load(f)
        self.assertEqual(statement["subject"][0]["digest"]["sha256"], "a" * 64)

    def test_falls_back_to_generic_hosted_builder_id_without_workflow_ref(self):
        """RUNNER_ENVIRONMENT=github-hosted but no GITHUB_WORKFLOW_REF
        (shouldn't happen in real Actions, but must still fail closed to
        *something* real rather than crash): falls back to the same
        generic GITHUB_HOSTED_BUILDER_ID the untrusted build job's
        --emit-slsa-provenance path always used."""
        tmp = self._tmp()
        out_path = os.path.join(tmp, "provenance.unsigned.json")
        env = dict(_GITHUB_ENV)
        del env["GITHUB_WORKFLOW_REF"]

        with mock.patch.dict(os.environ, env, clear=False):
            os.environ.pop("GITHUB_WORKFLOW_REF", None)
            provenance_main(
                ["--subject-name", "x", "--subject-digest", "sha256:" + "a" * 64, "--repo-dir", tmp, "--out", out_path]
            )

        with open(out_path, "r", encoding="utf-8") as f:
            statement = json.load(f)
        self.assertEqual(statement["predicate"]["runDetails"]["builder"]["id"], GITHUB_HOSTED_BUILDER_ID)

    def test_off_ci_produces_a_legitimately_less_complete_statement(self):
        """Ground-truth-only, fail-closed: with no ambient GitHub Actions
        env, the builder/workflow claims are simply absent, never faked."""
        tmp = self._tmp()
        out_path = os.path.join(tmp, "provenance.unsigned.json")
        saved = {k: os.environ.pop(k, None) for k in _GITHUB_ENV}
        try:
            provenance_main(
                ["--subject-name", "x", "--subject-digest", "sha256:" + "a" * 64, "--repo-dir", tmp, "--out", out_path]
            )
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

        with open(out_path, "r", encoding="utf-8") as f:
            statement = json.load(f)
        self.assertEqual(statement["predicate"]["runDetails"]["builder"], {})
        self.assertEqual(statement["predicate"]["buildDefinition"]["externalParameters"], {})

    def test_dispatches_from_cli_main(self):
        tmp = self._tmp()
        out_path = os.path.join(tmp, "provenance.unsigned.json")

        with mock.patch.dict(os.environ, _GITHUB_ENV, clear=False):
            exit_code = cli_main(
                [
                    "provenance",
                    "--subject-name", "x",
                    "--subject-digest", "sha256:" + "a" * 64,
                    "--repo-dir", tmp,
                    "--out", out_path,
                ]
            )

        self.assertEqual(exit_code, EXIT_PASS)
        self.assertTrue(os.path.exists(out_path))

    def test_unsafe_output_path_fails_closed(self):
        exit_code = provenance_main(
            ["--subject-name", "x", "--subject-digest", "sha256:" + "a" * 64, "--out", "/tmp/foo\x00bar"]
        )
        self.assertEqual(exit_code, EXIT_FILE_ERROR)


if __name__ == "__main__":
    unittest.main()
