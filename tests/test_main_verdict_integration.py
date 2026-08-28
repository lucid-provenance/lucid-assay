"""
One true end-to-end integration test driving cli.main.main() with
--dry-run-sign, confirming the signed envelope artifact the CLI produces
automatically carries a valid `_verdict` sibling block (see
cli/main.py's _maybe_annotate_verdict) -- without a separate,
explicit `tenax-assay verify --write-verdict` step.

Deliberately kept to a single class/test, and separate from
tests/test_main_helpers.py (whose own docstring explains why that file
tests cli.main's pipeline-step helpers directly rather than driving
main() end to end: doing so needs GitHub's branch-governance/commit-
author REST API mocked, and this test provides exactly that mocking so
the one true full-CLI-drive case for this feature still exists).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.main import derive_signed_path, main
from cli.parsers.commit_author import CommitAuthorReport
from cli.parsers.github_rules import BranchGovernanceReport

_JUNIT_XML = """<testsuites><testsuite>
  <testcase classname="C" name="t1" time="0.1"/>
</testsuite></testsuites>"""

_COBERTURA_XML = '<coverage line-rate="0.9" branch-rate="0.8"></coverage>'


def _write(tmp_dir: str, name: str, content: str) -> str:
    path = os.path.join(tmp_dir, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


class SignedEnvelopeCarriesVerdictIntegrationTest(unittest.TestCase):
    @patch.dict(os.environ, {}, clear=False)
    @patch("cli.main.inspect_commit_author")
    @patch("cli.main.inspect_branch_governance")
    def test_dry_run_sign_produces_an_envelope_with_a_verdict_block(
        self, mock_branch_governance, mock_commit_author
    ):
        # No live GitHub API calls: branch governance/commit author are
        # mocked directly (same "o/r" fake repository main() is invoked
        # with below couldn't resolve for real anyway), and GITHUB_TOKEN
        # is scrubbed so cli.parsers.s2c2f's own GitHub-API-backed checks
        # degrade to not_yet_reported rather than attempting a real call.
        os.environ.pop("GITHUB_TOKEN", None)
        mock_branch_governance.return_value = BranchGovernanceReport(
            available=True, branch="main", pull_request_required=True, approvals_required=1,
            direct_push_prevented=True, bypass_actors_count=0, admin_enforced=True,
            warnings=[], reason="ok",
        )
        mock_commit_author.return_value = CommitAuthorReport(
            available=False, commit_sha="b" * 40, reason="mocked: no live GitHub API call in this test"
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            junit_path = _write(tmp_dir, "junit.xml", _JUNIT_XML)
            coverage_path = _write(tmp_dir, "coverage.xml", _COBERTURA_XML)
            out_path = os.path.join(tmp_dir, "attestation.unsigned.json")

            rc = main([
                "--junit-xml", junit_path,
                "--coverage-report", coverage_path,
                "--image-ref", "ghcr.io/acme/widgets",
                "--image-digest", "sha256:" + "a" * 64,
                "--head-sha", "b" * 40,
                "--repository", "acme/widgets",
                "--branch", "main",
                "--repo-dir", tmp_dir,
                "--out", out_path,
                "--min-rcs", "0",
                "--dry-run-sign",
            ])

            self.assertIn(rc, (0, 1))  # this run's own gate outcome isn't what's under test here

            signed_path = derive_signed_path(out_path)
            self.assertTrue(os.path.exists(signed_path), f"expected a signed envelope at {signed_path}")
            with open(signed_path, "r", encoding="utf-8") as f:
                envelope = json.load(f)

        # The envelope produced by the CLI's own --dry-run-sign path
        # carries a real _verdict block -- no separate `tenax-assay
        # verify --write-verdict` step was run.
        self.assertIn("_verdict", envelope)
        verdict = envelope["_verdict"]
        self.assertIn(verdict["word"], ("FAILED", "GATED", "PASSED"))
        self.assertIn("banner", verdict)
        self.assertIn("passed", verdict)
        self.assertIn("rcs_value", verdict)
        self.assertIsInstance(verdict["rcs_value"], int)
        self.assertIn("gate_params", verdict)
        self.assertEqual(verdict["gate_params"]["min_rcs"], 0)
        self.assertIn("computed_at", verdict)

        # The signed payload/signatures are still exactly what dry-run
        # signing produces -- _verdict is an unsigned sibling field only.
        self.assertEqual(envelope["signatures"][0]["sig"], "DRY_RUN_UNSIGNED")
        json.dumps(envelope)  # must remain a fully JSON-serializable file end to end


if __name__ == "__main__":
    unittest.main()
