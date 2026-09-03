"""
One true end-to-end integration test driving cli.main.main() with --sbom
and --dry-run-sign together, confirming the full --sbom pipeline actually
wires up when run for real: predicate.artifact.sbom populated,
predicate.s2c2f's SCA-2 flipped to met, and the companion sbom.unsigned.json
in-toto statement (cli/sbom_statement.py) written *and* signed alongside
the primary attestation -- not just each piece's own isolated unit tests.

Deliberately kept to a single class/test and separate from
tests/test_main_helpers.py/tests/test_main_verdict_integration.py, same
rationale as the latter's own docstring: a full main() drive needs
GitHub's branch-governance/commit-author REST API mocked, and each
feature's one true full-CLI-drive case gets its own small file rather than
accreting into an existing one.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.main import derive_signed_path, derive_sbom_statement_path, main
from cli.parsers.commit_author import CommitAuthorReport
from cli.parsers.github_rules import BranchGovernanceReport

_JUNIT_XML = """<testsuites><testsuite>
  <testcase classname="C" name="t1" time="0.1"/>
</testsuite></testsuites>"""

_COBERTURA_XML = '<coverage line-rate="0.9" branch-rate="0.8"></coverage>'

_CYCLONEDX_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {"name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0",
         "licenses": [{"license": {"id": "BSD-3-Clause"}}]},
        {"name": "copyleft-dep", "version": "1.0.0", "purl": "pkg:pypi/copyleft-dep@1.0.0",
         "licenses": [{"license": {"id": "AGPL-3.0"}}]},
    ],
}


def _write(tmp_dir: str, name: str, content: str) -> str:
    path = os.path.join(tmp_dir, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def _write_json(tmp_dir: str, name: str, doc) -> str:
    return _write(tmp_dir, name, json.dumps(doc))


class SbomEndToEndIntegrationTest(unittest.TestCase):
    @patch.dict(os.environ, {}, clear=False)
    @patch("cli.main.inspect_commit_author")
    @patch("cli.main.inspect_branch_governance")
    def test_sbom_flows_through_artifact_block_s2c2f_and_a_signed_sibling_statement(
        self, mock_branch_governance, mock_commit_author
    ):
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
            sbom_path = _write_json(tmp_dir, "bom.json", _CYCLONEDX_SBOM)
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
                "--sbom", sbom_path,
                "--out", out_path,
                "--min-rcs", "0",
                "--dry-run-sign",
            ])
            self.assertIn(rc, (0, 1))  # this run's own gate outcome isn't what's under test here

            with open(out_path, "r", encoding="utf-8") as f:
                unsigned = json.load(f)

            # predicate.artifact.sbom populated for real.
            sbom_block = unsigned["predicate"]["artifact"]["sbom"]
            self.assertEqual(sbom_block["format"], "cyclonedx-json")
            self.assertEqual(sbom_block["component_count"], 2)
            self.assertRegex(sbom_block["sha256"], r"^[a-f0-9]{64}$")
            self.assertIn(sbom_block["sha256"], sbom_block["uri"])

            # S2C2F SCA-2 ("License Checks") flips to met from the SBOM
            # alone -- the whole point of this feature.
            sca2 = next(c for c in unsigned["predicate"]["s2c2f"]["controls"] if c["id"] == "SCA-2")
            self.assertEqual(sca2["status"], "met")

            # The synthetic SBOM SARIF tool's report_hash matches
            # predicate.artifact.sbom.sha256 -- the same file hashed once,
            # reused honestly in both places (cli.main._merge_sbom_into_
            # sarif's whole reason for existing as a separate, ordered
            # step ahead of scoring).
            sbom_tool = next(
                t for t in unsigned["predicate"]["static_analysis"]["tools"]
                if t["name"] == "lucid-assay-sbom-license-policy"
            )
            self.assertEqual(sbom_tool["report_hash"]["value"], sbom_block["sha256"])
            self.assertEqual(sbom_tool["summary"]["errors"], 1)  # the AGPL-3.0 component

            # The companion sbom.unsigned.json statement was written...
            sbom_statement_path = derive_sbom_statement_path(out_path, None)
            self.assertTrue(os.path.exists(sbom_statement_path))
            with open(sbom_statement_path, "r", encoding="utf-8") as f:
                sbom_statement = json.load(f)
            self.assertEqual(sbom_statement["predicateType"], "https://cyclonedx.org/bom")
            self.assertEqual(sbom_statement["predicate"], _CYCLONEDX_SBOM)  # verbatim, not re-derived
            self.assertEqual(
                sbom_statement["subject"],
                [{"name": "ghcr.io/acme/widgets", "digest": {"sha256": "a" * 64}}],
            )

            # ...and --dry-run-sign signed it too, as its own sibling
            # envelope -- not just the primary attestation.
            sbom_signed_path = derive_signed_path(sbom_statement_path)
            self.assertTrue(os.path.exists(sbom_signed_path))
            with open(sbom_signed_path, "r", encoding="utf-8") as f:
                sbom_envelope = json.load(f)
            self.assertEqual(sbom_envelope["signatures"][0]["sig"], "DRY_RUN_UNSIGNED")
            json.dumps(sbom_envelope)  # fully JSON-serializable end to end


if __name__ == "__main__":
    unittest.main()
