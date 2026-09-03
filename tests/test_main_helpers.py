"""
Direct unit tests for cli/main.py's pipeline-step helper functions
(_merge_sonar_metrics, _ingest_sarif, _maybe_sign, _emit_run_warnings,
_maybe_emit_slsa_provenance), extracted from main() during the SonarCloud
complexity sweep. These are tested directly here rather than by driving
main() end to end, since a full run requires mocking GitHub's
branch-governance API and a real git repo for patch coverage -- these
helpers don't need either.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr

from pathlib import Path

from cli.main import (
    _build_sbom_artifact_block,
    _detect_lockfile_dependencies,
    _emit_run_warnings,
    _ingest_sarif,
    _ingest_sbom,
    _maybe_annotate_verdict,
    _maybe_emit_sbom_statement,
    _maybe_emit_slsa_provenance,
    _maybe_sign,
    _merge_sbom_into_sarif,
    _merge_sonar_metrics,
    derive_sbom_statement_path,
    derive_slsa_provenance_path,
)
from cli.parsers.github_rules import BranchGovernanceReport
from cli.parsers.junit import TestTotals
from cli.parsers.sarif import SarifSummaryReport, SarifToolSummary
from cli.parsers.sbom import SBOM_LICENSE_TOOL_NAME, SbomComponent, SbomReport
from cli.scorer import RCSResult


def _write(tmp_path: str, name: str, content: str) -> str:
    path = os.path.join(tmp_path, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def _sarif_doc(tool_name: str, results=None) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool_name}}, "results": results or []}],
    }


def _sonar_metrics_doc(alert_status="OK") -> dict:
    return {"component": {"measures": [{"metric": "alert_status", "value": alert_status}]}}


def _cdx_doc(components) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}


def _governance(
    *,
    available=True,
    pull_request_required=True,
    approvals_required=1,
    direct_push_prevented=True,
    bypass_actors_count=0,
    admin_enforced=True,
    warnings=None,
    reason="ok",
    reason_code=None,
) -> BranchGovernanceReport:
    return BranchGovernanceReport(
        available=available,
        branch="main",
        pull_request_required=pull_request_required,
        approvals_required=approvals_required,
        direct_push_prevented=direct_push_prevented,
        bypass_actors_count=bypass_actors_count,
        admin_enforced=admin_enforced,
        warnings=warnings or [],
        reason=reason,
        reason_code=reason_code,
    )


def _rcs(*, value=80, degraded=False, degraded_reasons=None) -> RCSResult:
    return RCSResult(
        value=value,
        algorithm_version="v1",
        components={},
        degraded=degraded,
        degraded_reasons=degraded_reasons or [],
    )


class MergeSonarMetricsTests(unittest.TestCase):
    def _tmp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def test_unreadable_file_warns(self):
        sarif_report = SarifSummaryReport(available=True, tools=[SarifToolSummary(name="semgrep")])
        buf = io.StringIO()
        with redirect_stderr(buf):
            _merge_sonar_metrics(os.path.join(self._tmp(), "missing.json"), sarif_report)
        self.assertIn("could not be read/parsed", buf.getvalue())

    def test_ambiguous_target_warns(self):
        path = _write(self._tmp(), "metrics.json", json.dumps(_sonar_metrics_doc()))
        sarif_report = SarifSummaryReport(
            available=True,
            tools=[SarifToolSummary(name="semgrep"), SarifToolSummary(name="trivy")],
        )
        buf = io.StringIO()
        with redirect_stderr(buf):
            _merge_sonar_metrics(path, sarif_report)
        self.assertIn("no unambiguous SARIF tool to attach to", buf.getvalue())

    def test_successful_merge_is_silent(self):
        path = _write(self._tmp(), "metrics.json", json.dumps(_sonar_metrics_doc()))
        tool = SarifToolSummary(name="sonarqube")
        sarif_report = SarifSummaryReport(available=True, tools=[tool])
        buf = io.StringIO()
        with redirect_stderr(buf):
            _merge_sonar_metrics(path, sarif_report)
        self.assertEqual(buf.getvalue(), "")
        self.assertEqual(tool.extensions["sonarqube"]["quality_gate"], "PASSED")


class IngestSarifTests(unittest.TestCase):
    def _tmp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def _args(self, **overrides):
        base = dict(sarif=None, sonar_metrics=None, base_sha=None, head_sha="a" * 40, repo_dir=".")
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_no_sarif_no_sonar_metrics_returns_none_silently(self):
        buf = io.StringIO()
        with redirect_stderr(buf):
            result = _ingest_sarif(self._args(), {})
        self.assertIsNone(result)
        self.assertEqual(buf.getvalue(), "")

    def test_sonar_metrics_without_sarif_warns_and_returns_none(self):
        buf = io.StringIO()
        with redirect_stderr(buf):
            result = _ingest_sarif(self._args(sonar_metrics="m.json"), {})
        self.assertIsNone(result)
        self.assertIn("without any --sarif input", buf.getvalue())

    def test_single_valid_sarif_report(self):
        path = _write(self._tmp(), "r.sarif", json.dumps(_sarif_doc("semgrep")))
        stage_ns = {}
        buf = io.StringIO()
        with redirect_stderr(buf):
            result = _ingest_sarif(self._args(sarif=[path]), stage_ns)
        self.assertIsNotNone(result)
        self.assertTrue(result.available)
        self.assertEqual(result.tools_scanned, ["semgrep"])
        self.assertIn("diff_patch_analysis", stage_ns)
        self.assertIn("parse_inputs", stage_ns)

    def test_unreadable_sarif_path_warns_and_degrades(self):
        missing = os.path.join(self._tmp(), "does-not-exist.sarif")
        buf = io.StringIO()
        with redirect_stderr(buf):
            result = _ingest_sarif(self._args(sarif=[missing]), {})
        self.assertFalse(result.available)
        self.assertIn(f"SARIF report '{missing}' could not be read/parsed", buf.getvalue())
        self.assertIn("static analysis (SARIF) ingestion degraded", buf.getvalue())

    def test_sonar_metrics_attached_when_sarif_available(self):
        sarif_path = _write(self._tmp(), "r.sarif", json.dumps(_sarif_doc("sonarqube")))
        metrics_path = _write(self._tmp(), "m.json", json.dumps(_sonar_metrics_doc("ERROR")))
        result = _ingest_sarif(self._args(sarif=[sarif_path], sonar_metrics=metrics_path), {})
        self.assertTrue(result.available)
        tool = next(t for t in result.tools if t.name == "sonarqube")
        self.assertEqual(tool.extensions["sonarqube"]["quality_gate"], "FAILED")


class DetectLockfileDependenciesTests(unittest.TestCase):
    def _tmp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def _args(self, repo_dir):
        return argparse.Namespace(repo_dir=repo_dir)

    def test_no_lockfiles_returns_empty_list(self):
        stage_ns = {}
        result = _detect_lockfile_dependencies(self._args(self._tmp()), stage_ns)
        self.assertEqual(result, [])
        self.assertIn("lockfile_dependencies", stage_ns)

    def test_uv_lock_is_detected_and_parsed(self):
        repo_dir = self._tmp()
        toml = """
[[package]]
name = "pytest"
version = "8.3.2"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://example/pytest-8.3.2-py3-none-any.whl", hash = "sha256:deadbeef" },
]
"""
        _write(repo_dir, "uv.lock", toml)

        stage_ns = {}
        result = _detect_lockfile_dependencies(self._args(repo_dir), stage_ns)

        self.assertEqual(result, [{"uri": "pkg:pypi/pytest@8.3.2", "digest": {"sha256": "deadbeef"}}])
        self.assertIn("lockfile_dependencies", stage_ns)
        self.assertGreaterEqual(stage_ns["lockfile_dependencies"], 0)

    def test_nonexistent_repo_dir_returns_empty_list_not_raise(self):
        result = _detect_lockfile_dependencies(
            self._args(os.path.join(self._tmp(), "does-not-exist")), {}
        )
        self.assertEqual(result, [])

    def test_falls_back_to_sbom_when_no_lockfile_found(self):
        sbom_report = SbomReport(
            available=True, format="cyclonedx",
            components=[SbomComponent(name="flask", purl="pkg:pypi/flask@3.0.0", digest={"sha256": "aa"})],
        )
        result = _detect_lockfile_dependencies(self._args(self._tmp()), {}, sbom_report=sbom_report)
        self.assertEqual(result, [{"uri": "pkg:pypi/flask@3.0.0", "digest": {"sha256": "aa"}}])

    def test_lockfile_wins_over_sbom_when_both_present(self):
        repo_dir = self._tmp()
        toml = """
[[package]]
name = "pytest"
version = "8.3.2"
source = { registry = "https://pypi.org/simple" }
"""
        _write(repo_dir, "uv.lock", toml)
        sbom_report = SbomReport(
            available=True, components=[SbomComponent(name="other", purl="pkg:pypi/other@1.0")]
        )
        result = _detect_lockfile_dependencies(self._args(repo_dir), {}, sbom_report=sbom_report)
        self.assertEqual(result, [{"uri": "pkg:pypi/pytest@8.3.2", "digest": {}}])

    def test_unavailable_sbom_report_is_not_used_as_a_fallback(self):
        sbom_report = SbomReport(available=False, reasons=["broken"])
        result = _detect_lockfile_dependencies(self._args(self._tmp()), {}, sbom_report=sbom_report)
        self.assertEqual(result, [])


class IngestSbomTests(unittest.TestCase):
    def _tmp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def _args(self, **overrides):
        base = dict(sbom=None)
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_no_sbom_returns_none_silently(self):
        buf = io.StringIO()
        with redirect_stderr(buf):
            result = _ingest_sbom(self._args(), {})
        self.assertIsNone(result)
        self.assertEqual(buf.getvalue(), "")

    def test_valid_cyclonedx_sbom_is_parsed(self):
        path = _write(self._tmp(), "bom.json", json.dumps(_cdx_doc(
            [{"name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0",
              "licenses": [{"license": {"id": "BSD-3-Clause"}}]}]
        )))
        stage_ns = {}
        buf = io.StringIO()
        with redirect_stderr(buf):
            result = _ingest_sbom(self._args(sbom=path), stage_ns)
        self.assertTrue(result.available)
        self.assertEqual(result.format, "cyclonedx")
        self.assertEqual(len(result.components), 1)
        self.assertEqual(buf.getvalue(), "")
        self.assertIn("parse_inputs", stage_ns)

    def test_unreadable_sbom_path_warns_and_degrades(self):
        missing = os.path.join(self._tmp(), "does-not-exist.json")
        buf = io.StringIO()
        with redirect_stderr(buf):
            result = _ingest_sbom(self._args(sbom=missing), {})
        self.assertFalse(result.available)
        self.assertIn(f"SBOM '{missing}' could not be read/parsed", buf.getvalue())


class MergeSbomIntoSarifTests(unittest.TestCase):
    def test_no_sbom_report_returns_sarif_unchanged(self):
        sarif_report = SarifSummaryReport(available=True, tools_scanned=["semgrep"])
        result = _merge_sbom_into_sarif(sarif_report, None)
        self.assertIs(result, sarif_report)

    def test_unavailable_sbom_report_returns_sarif_unchanged(self):
        sarif_report = SarifSummaryReport(available=True, tools_scanned=["semgrep"])
        sbom_report = SbomReport(available=False, reasons=["broken"])
        result = _merge_sbom_into_sarif(sarif_report, sbom_report)
        self.assertIs(result, sarif_report)

    def test_sbom_only_becomes_the_sarif_report_when_none_was_configured(self):
        sbom_report = SbomReport(
            available=True, components=[SbomComponent(name="bad", license_expression="AGPL-3.0")]
        )
        result = _merge_sbom_into_sarif(None, sbom_report)
        self.assertTrue(result.available)
        self.assertEqual(result.tools_scanned, [SBOM_LICENSE_TOOL_NAME])
        self.assertEqual(result.errors_count, 1)

    def test_sbom_findings_merge_alongside_a_real_sarif_report(self):
        sarif_report = SarifSummaryReport(
            available=True, tools_scanned=["semgrep"], tools=[SarifToolSummary(name="semgrep")]
        )
        sbom_report = SbomReport(
            available=True, components=[SbomComponent(name="bad", license_expression="AGPL-3.0")]
        )
        result = _merge_sbom_into_sarif(sarif_report, sbom_report)
        self.assertTrue(result.available)
        self.assertEqual(set(result.tools_scanned), {"semgrep", SBOM_LICENSE_TOOL_NAME})
        self.assertEqual(result.errors_count, 1)

    def test_unavailable_real_sarif_report_taints_the_merge(self):
        # Matches aggregate_sarif_reports' own fail-closed contract: one
        # broken --sarif input taints the whole aggregate, even when the
        # SBOM half is perfectly valid.
        sarif_report = SarifSummaryReport(available=False, reasons=["corrupt"])
        sbom_report = SbomReport(
            available=True, components=[SbomComponent(name="bad", license_expression="AGPL-3.0")]
        )
        result = _merge_sbom_into_sarif(sarif_report, sbom_report)
        self.assertFalse(result.available)

    def test_sbom_report_sha_becomes_the_synthetic_tools_report_hash(self):
        sbom_report = SbomReport(
            available=True, components=[SbomComponent(name="bad", license_expression="AGPL-3.0")]
        )
        result = _merge_sbom_into_sarif(None, sbom_report, sbom_report_sha="d" * 64)
        tool = next(t for t in result.tools if t.name == SBOM_LICENSE_TOOL_NAME)
        self.assertEqual(tool.report_hash, {"algorithm": "sha256", "value": "d" * 64})

    def test_no_sbom_report_sha_leaves_report_hash_none(self):
        sbom_report = SbomReport(
            available=True, components=[SbomComponent(name="bad", license_expression="AGPL-3.0")]
        )
        result = _merge_sbom_into_sarif(None, sbom_report)
        tool = next(t for t in result.tools if t.name == SBOM_LICENSE_TOOL_NAME)
        self.assertIsNone(tool.report_hash)


class BuildSbomArtifactBlockTests(unittest.TestCase):
    def test_none_when_no_sbom_report(self):
        self.assertIsNone(_build_sbom_artifact_block(None, None))

    def test_none_when_sbom_unavailable(self):
        sbom_report = SbomReport(available=False, reasons=["broken"])
        self.assertIsNone(_build_sbom_artifact_block(sbom_report, "a" * 64))

    def test_none_when_no_hash_given(self):
        sbom_report = SbomReport(available=True, format="cyclonedx", components=[])
        self.assertIsNone(_build_sbom_artifact_block(sbom_report, None))

    def test_cyclonedx_maps_to_cyclonedx_json(self):
        sbom_report = SbomReport(
            available=True, format="cyclonedx",
            components=[SbomComponent(name="a"), SbomComponent(name="b")],
        )
        block = _build_sbom_artifact_block(sbom_report, "a" * 64)
        self.assertEqual(block, {
            "format": "cyclonedx-json", "sha256": "a" * 64,
            "uri": "s3://evidence/sha256/" + "a" * 64, "component_count": 2,
        })

    def test_spdx2_and_spdx3_both_map_to_spdx_json(self):
        for fmt in ("spdx2", "spdx3"):
            sbom_report = SbomReport(available=True, format=fmt, components=[])
            block = _build_sbom_artifact_block(sbom_report, "b" * 64)
            self.assertEqual(block["format"], "spdx-json", fmt)

    def test_unrecognized_format_is_none(self):
        sbom_report = SbomReport(available=True, format="some-future-format", components=[])
        self.assertIsNone(_build_sbom_artifact_block(sbom_report, "c" * 64))


class DeriveSbomStatementPathTests(unittest.TestCase):
    def test_explicit_path_wins(self):
        self.assertEqual(derive_sbom_statement_path("build/attestation.unsigned.json", "custom.json"), "custom.json")

    def test_derives_fixed_basename_sibling_in_same_directory(self):
        self.assertEqual(
            derive_sbom_statement_path("build/attestation.unsigned.json", None), "build/sbom.unsigned.json"
        )

    def test_out_basename_is_irrelevant_to_the_derived_name(self):
        # Unlike derive_slsa_provenance_path's suffix scheme, this is a
        # fixed basename regardless of --out's own filename.
        self.assertEqual(
            derive_sbom_statement_path("build/lucid-console.unsigned.json", None), "build/sbom.unsigned.json"
        )

    def test_no_directory_component(self):
        self.assertEqual(derive_sbom_statement_path("attestation.unsigned.json", None), "sbom.unsigned.json")


class MaybeEmitSbomStatementTests(unittest.TestCase):
    def _tmp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def _args(self, out, **overrides):
        base = dict(out=out, sbom_statement_out=None, image_ref="registry.example.com/org/svc")
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_no_sbom_report_is_a_noop(self):
        out = os.path.join(self._tmp(), "attestation.unsigned.json")
        result = _maybe_emit_sbom_statement(self._args(out), sbom_report=None, image_digest="a" * 64)
        self.assertIsNone(result)

    def test_unavailable_sbom_report_is_a_noop(self):
        out = os.path.join(self._tmp(), "attestation.unsigned.json")
        sbom_report = SbomReport(available=False, reasons=["broken"])
        result = _maybe_emit_sbom_statement(self._args(out), sbom_report=sbom_report, image_digest="a" * 64)
        self.assertIsNone(result)

    def test_writes_a_real_sibling_statement_file(self):
        d = self._tmp()
        out = os.path.join(d, "attestation.unsigned.json")
        raw_doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
        sbom_report = SbomReport(available=True, format="cyclonedx", components=[], raw_document=raw_doc)

        result = _maybe_emit_sbom_statement(self._args(out), sbom_report=sbom_report, image_digest="a" * 64)

        expected_path = os.path.join(d, "sbom.unsigned.json")
        self.assertEqual(str(result), expected_path)
        with open(expected_path) as f:
            written = json.load(f)
        self.assertEqual(written["predicateType"], "https://cyclonedx.org/bom")
        self.assertEqual(written["predicate"], raw_doc)
        self.assertEqual(written["subject"], [{"name": "registry.example.com/org/svc", "digest": {"sha256": "a" * 64}}])

    def test_unmappable_format_is_a_noop(self):
        out = os.path.join(self._tmp(), "attestation.unsigned.json")
        sbom_report = SbomReport(available=True, format="unknown-format", components=[], raw_document={"x": 1})
        result = _maybe_emit_sbom_statement(self._args(out), sbom_report=sbom_report, image_digest="a" * 64)
        self.assertIsNone(result)


class MaybeSignTests(unittest.TestCase):
    def _tmp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def _args(self, **overrides):
        base = dict(sign=False, dry_run_sign=False)
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_neither_flag_set_is_a_noop(self):
        from cli.main import derive_signed_path

        out_path = _write(self._tmp(), "out.json", "{}")
        sign_total_ns, sign_sub_ns, signed_path = _maybe_sign(self._args(), out_path)
        self.assertIsNone(sign_total_ns)
        self.assertEqual(sign_sub_ns, {})
        self.assertIsNone(signed_path)
        self.assertFalse(os.path.exists(derive_signed_path(out_path)))

    def test_dry_run_sign_writes_signed_envelope(self):
        out_path = _write(self._tmp(), "out.json", json.dumps({"hello": "world"}))
        buf = io.StringIO()
        with redirect_stderr(buf):
            sign_total_ns, sign_sub_ns, signed_path = _maybe_sign(self._args(dry_run_sign=True), out_path)
        self.assertIsInstance(sign_total_ns, int)
        self.assertEqual(sign_sub_ns, {"oidc_token_fetch_ns": 0, "fulcio_rekor_ns": 0})
        self.assertIn("signed envelope written to", buf.getvalue())

        from cli.main import derive_signed_path

        self.assertEqual(str(signed_path), str(derive_signed_path(out_path)))
        self.assertTrue(os.path.exists(signed_path))
        with open(signed_path, "r", encoding="utf-8") as f:
            envelope = json.load(f)
        self.assertEqual(envelope["signatures"][0]["sig"], "DRY_RUN_UNSIGNED")


class MaybeAnnotateVerdictTests(unittest.TestCase):
    """Direct unit tests for _maybe_annotate_verdict, built off a real
    signed envelope (cli.builder.build_statement + cli.oidc_signer.
    sign_statement, dry-run) rather than driving cli.main.main() end to
    end -- same rationale as MaybeSignTests/this module's own docstring:
    no GitHub API mocking or git repo needed to exercise this helper
    directly. See tests/test_main_verdict_integration.py for the one true
    full-CLI-drive integration test this feature also gets."""

    def _tmp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def _args(self, **overrides):
        base = dict(min_rcs=0, dry_run_sign=True)
        base.update(overrides)
        return argparse.Namespace(**base)

    def _signed_envelope_path(self, tmp_dir: str, rcs_value: int) -> str:
        from cli.builder import build_statement
        from cli.oidc_signer import sign_statement
        from cli.parsers.coverage import CoverageReport
        from cli.patch_coverage import PatchCoverageResult
        from cli.scorer import RCSResult

        bg = BranchGovernanceReport(
            available=True, branch="main", pull_request_required=True, approvals_required=1,
            direct_push_prevented=True, bypass_actors_count=0, admin_enforced=True,
            warnings=[], reason="ok",
        )
        statement = build_statement(
            subject_name="ghcr.io/x/y", subject_sha256="b" * 64, vcs_provider="github",
            repository="acme/widgets", branch="main", commit_sha="c" * 40, base_commit_sha=None,
            pr_number=None, pr_target_branch=None, pr_approvers=[], pr_required_approvals=0,
            pr_review_state="not_applicable", branch_governance=bg, test_framework="junit",
            test_report_sha256="d" * 64, test_report_uri="worm://x",
            test_totals=TestTotals(tests=1, passed=1, failed=0, errored=0, skipped=0),
            coverage_format="cobertura-xml", coverage_report_sha256="e" * 64, coverage_report_uri="worm://y",
            coverage=CoverageReport(overall_line_rate=0.9, overall_branch_rate=0.8),
            patch_coverage=PatchCoverageResult(
                available=True, line_rate=0.9, lines_changed=10, lines_covered=9, reason="ok"
            ),
            patch_coverage_min=0.8, overall_coverage_min=0.6, total_assertions=5, total_test_functions=1,
            empty_test_bodies=0, assertion_only_true=0,
            rcs=RCSResult(
                value=rcs_value, algorithm_version="rcs-v0.1", components={}, degraded=False, degraded_reasons=[]
            ),
        )
        envelope = sign_statement(json.dumps(statement).encode("utf-8"), dry_run=True).to_dict()
        path = os.path.join(tmp_dir, "attestation.dsse.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(envelope, f)
        return path

    def test_noop_when_signing_was_skipped(self):
        stage_ns: dict = {}

        word = _maybe_annotate_verdict(self._args(), None, stage_ns)

        self.assertIsNone(word)
        self.assertNotIn("verdict_annotation", stage_ns)

    def test_writes_verdict_block_onto_signed_envelope(self):
        path = self._signed_envelope_path(self._tmp(), rcs_value=90)
        stage_ns: dict = {}

        word = _maybe_annotate_verdict(self._args(min_rcs=0), Path(path), stage_ns)

        self.assertIsNotNone(word)
        with open(path, "r", encoding="utf-8") as f:
            written = json.load(f)
        self.assertIn("_verdict", written)
        self.assertEqual(written["_verdict"]["word"], word)
        self.assertEqual(written["_verdict"]["rcs_value"], 90)
        self.assertIn("verdict_annotation", stage_ns)
        # payload/signatures must survive completely untouched -- only an
        # unsigned sibling field is ever added.
        self.assertIn("payload", written)
        self.assertIn("signatures", written)

    def test_gate_violation_is_still_written_not_treated_as_an_error(self):
        """A GATED/FAILED verdict is a normal, correctly-computed outcome
        here -- not an error -- so it's still written, and the function
        still returns the word rather than None (None is reserved for
        "annotation itself couldn't happen")."""
        path = self._signed_envelope_path(self._tmp(), rcs_value=10)

        word = _maybe_annotate_verdict(self._args(min_rcs=80), Path(path), {})

        self.assertEqual(word, "FAILED")
        with open(path, "r", encoding="utf-8") as f:
            written = json.load(f)
        self.assertEqual(written["_verdict"]["word"], "FAILED")

    def test_missing_envelope_file_warns_and_returns_none_without_raising(self):
        buf = io.StringIO()

        with redirect_stderr(buf):
            word = _maybe_annotate_verdict(self._args(), Path("/nonexistent/env.dsse.json"), {})

        self.assertIsNone(word)
        self.assertIn("WARNING", buf.getvalue())


class EmitRunWarningsTests(unittest.TestCase):
    def test_clean_run_only_prints_summary_line(self):
        buf = io.StringIO()
        with redirect_stderr(buf):
            _emit_run_warnings(_rcs(), _governance(), "main", 5.0, skip_perf_budget_check=False)
        out = buf.getvalue()
        self.assertIn("RCS=80", out)
        self.assertNotIn("WARNING", out)

    def test_degraded_run_prints_reasons(self):
        buf = io.StringIO()
        rcs = _rcs(degraded=True, degraded_reasons=["patch_coverage:no_coverable_lines"])
        with redirect_stderr(buf):
            _emit_run_warnings(rcs, _governance(), "main", 5.0, skip_perf_budget_check=False)
        self.assertIn("degraded_reasons=['patch_coverage:no_coverable_lines']", buf.getvalue())

    def test_unavailable_governance_warns(self):
        buf = io.StringIO()
        gov = _governance(available=False, reason="token expired")
        with redirect_stderr(buf):
            _emit_run_warnings(_rcs(), gov, "main", 5.0, skip_perf_budget_check=False)
        self.assertIn("branch governance for 'main' could not be verified: token expired", buf.getvalue())

    def test_bypass_permits_unreviewed_change_warns(self):
        buf = io.StringIO()
        gov = _governance(bypass_actors_count=1)
        with redirect_stderr(buf):
            _emit_run_warnings(_rcs(), gov, "main", 5.0, skip_perf_budget_check=False)
        self.assertIn("permit an unreviewed bypass", buf.getvalue())

    def test_governance_warnings_list_printed(self):
        buf = io.StringIO()
        gov = _governance(warnings=["0 approving reviews required"])
        with redirect_stderr(buf):
            _emit_run_warnings(_rcs(), gov, "main", 5.0, skip_perf_budget_check=False)
        self.assertIn("branch governance: 0 approving reviews required", buf.getvalue())

    def test_perf_budget_exceeded_warns_unless_skipped(self):
        buf = io.StringIO()
        with redirect_stderr(buf):
            _emit_run_warnings(_rcs(), _governance(), "main", 75.0, skip_perf_budget_check=False)
        self.assertIn("exceeded the 50ms budget", buf.getvalue())

        buf2 = io.StringIO()
        with redirect_stderr(buf2):
            _emit_run_warnings(_rcs(), _governance(), "main", 75.0, skip_perf_budget_check=True)
        self.assertNotIn("exceeded the 50ms budget", buf2.getvalue())


class DeriveSlsaProvenancePathTests(unittest.TestCase):
    def test_explicit_path_wins_over_any_derivation(self):
        self.assertEqual(
            derive_slsa_provenance_path("attestation.unsigned.json", "custom.json"),
            "custom.json",
        )

    def test_derives_alongside_dot_unsigned_dot_json_out(self):
        self.assertEqual(
            derive_slsa_provenance_path("attestation.unsigned.json", None),
            "attestation.slsa-provenance.unsigned.json",
        )

    def test_derives_alongside_plain_dot_json_out(self):
        self.assertEqual(
            derive_slsa_provenance_path("attestation.json", None),
            "attestation.slsa-provenance.json",
        )

    def test_derives_alongside_extensionless_out(self):
        self.assertEqual(
            derive_slsa_provenance_path("build/attestation", None),
            "build/attestation.slsa-provenance.json",
        )


class MaybeEmitSlsaProvenanceTests(unittest.TestCase):
    def _tmp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def _args(self, out_path, **overrides):
        base = dict(
            emit_slsa_provenance=False,
            slsa_provenance_out=None,
            image_ref="registry.example.com/org/svc",
            out=out_path,
        )
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_flag_not_set_is_a_noop(self):
        out_path = os.path.join(self._tmp(), "attestation.unsigned.json")
        result = _maybe_emit_slsa_provenance(
            self._args(out_path),
            image_digest="a" * 64,
            pipeline_started_at="2026-08-23T12:00:00Z",
            resolved_dependencies=[],
        )
        self.assertIsNone(result)
        self.assertFalse(os.path.exists(derive_slsa_provenance_path(out_path, None)))

    def test_flag_set_writes_a_slsa_shaped_statement_at_the_derived_path(self):
        out_path = os.path.join(self._tmp(), "attestation.unsigned.json")
        result = _maybe_emit_slsa_provenance(
            self._args(out_path, emit_slsa_provenance=True),
            image_digest="a" * 64,
            pipeline_started_at="2026-08-23T12:00:00Z",
            resolved_dependencies=[{"uri": "pkg:pypi/requests@2.31.0", "digest": {"sha256": "c" * 64}}],
        )
        # _maybe_emit_slsa_provenance resolves the path via
        # common.safe_resolve_path() (same as every other operator-supplied
        # output path in cli/main.py), which returns an absolute, symlink-
        # normalized Path -- compare the resolved forms, not raw strings.
        self.assertEqual(str(result), os.path.realpath(derive_slsa_provenance_path(out_path, None)))
        self.assertTrue(os.path.exists(result))

        with open(result, "r", encoding="utf-8") as f:
            statement = json.load(f)
        self.assertEqual(statement["predicateType"], "https://slsa.dev/provenance/v1")
        self.assertEqual(statement["subject"][0]["digest"]["sha256"], "a" * 64)
        self.assertIn(
            {"uri": "pkg:pypi/requests@2.31.0", "digest": {"sha256": "c" * 64}},
            statement["predicate"]["buildDefinition"]["resolvedDependencies"],
        )

    def test_explicit_slsa_provenance_out_is_honored(self):
        tmp = self._tmp()
        out_path = os.path.join(tmp, "attestation.unsigned.json")
        explicit_path = os.path.join(tmp, "custom-slsa.json")
        result = _maybe_emit_slsa_provenance(
            self._args(out_path, emit_slsa_provenance=True, slsa_provenance_out=explicit_path),
            image_digest="a" * 64,
            pipeline_started_at="2026-08-23T12:00:00Z",
            resolved_dependencies=None,
        )
        self.assertEqual(str(result), os.path.realpath(explicit_path))
        self.assertTrue(os.path.exists(explicit_path))


if __name__ == "__main__":
    unittest.main()
