"""
Direct unit tests for cli/main.py's pipeline-step helper functions
(_merge_sonar_metrics, _ingest_sarif, _maybe_sign, _emit_run_warnings),
extracted from main() during the SonarCloud complexity sweep. These are
tested directly here rather than by driving main() end to end, since a
full run requires mocking GitHub's branch-governance API and a real git
repo for patch coverage -- these helpers don't need either.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr

from cli.main import _detect_lockfile_dependencies, _emit_run_warnings, _ingest_sarif, _maybe_sign, _merge_sonar_metrics
from cli.parsers.github_rules import BranchGovernanceReport
from cli.parsers.sarif import SarifSummaryReport, SarifToolSummary
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
        sign_total_ns, sign_sub_ns = _maybe_sign(self._args(), out_path)
        self.assertIsNone(sign_total_ns)
        self.assertEqual(sign_sub_ns, {})
        self.assertFalse(os.path.exists(derive_signed_path(out_path)))

    def test_dry_run_sign_writes_signed_envelope(self):
        out_path = _write(self._tmp(), "out.json", json.dumps({"hello": "world"}))
        buf = io.StringIO()
        with redirect_stderr(buf):
            sign_total_ns, sign_sub_ns = _maybe_sign(self._args(dry_run_sign=True), out_path)
        self.assertIsInstance(sign_total_ns, int)
        self.assertEqual(sign_sub_ns, {"oidc_token_fetch_ns": 0, "fulcio_rekor_ns": 0})
        self.assertIn("signed envelope written to", buf.getvalue())

        from cli.main import derive_signed_path

        signed_path = derive_signed_path(out_path)
        self.assertTrue(os.path.exists(signed_path))
        with open(signed_path, "r", encoding="utf-8") as f:
            envelope = json.load(f)
        self.assertEqual(envelope["signatures"][0]["sig"], "DRY_RUN_UNSIGNED")


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


if __name__ == "__main__":
    unittest.main()
