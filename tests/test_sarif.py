import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.builder import build_statement
from cli.parsers.coverage import CoverageReport
from cli.parsers.github_rules import BranchGovernanceReport
from cli.parsers.junit import TestTotals
from cli.parsers.sarif import (
    SarifFinding,
    SarifSummaryReport,
    aggregate_sarif_reports,
    parse_sarif_file,
)
from cli.patch_coverage import PatchCoverageResult
from cli.scorer import (
    STATIC_ANALYSIS_LEGACY_ERROR_PENALTY_CAP,
    STATIC_ANALYSIS_PATCH_ERROR_PENALTY,
    STATIC_ANALYSIS_PATCH_WARNING_PENALTY,
    STATIC_ANALYSIS_UNAVAILABLE_PENALTY,
    score_pipeline,
)
from cli.verify import verify_dsse_attestation


def _sarif_result(rule_id, level, uri, line, message="finding"):
    result = {
        "ruleId": rule_id,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    if level is not None:
        result["level"] = level
    return result


def _sarif_doc(runs):
    return {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": runs,
    }


def _run(tool_name, results):
    return {"tool": {"driver": {"name": tool_name}}, "results": results}


def _write_json(doc) -> str:
    fd, path = tempfile.mkstemp(suffix=".sarif.json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    return path


class ParseSarifFileTests(unittest.TestCase):
    def setUp(self):
        self._paths = []
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for p in self._paths:
            try:
                os.remove(p)
            except OSError:
                pass

    def _write(self, doc) -> str:
        path = _write_json(doc)
        self._paths.append(path)
        return path

    def test_missing_file_is_unavailable(self):
        report = parse_sarif_file("/nonexistent/path/does-not-exist.sarif.json")
        self.assertFalse(report.available)
        self.assertTrue(report.reasons)

    def test_malformed_json_is_unavailable(self):
        fd, path = tempfile.mkstemp(suffix=".sarif.json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("{not valid json")
        self._paths.append(path)

        report = parse_sarif_file(path)

        self.assertFalse(report.available)
        self.assertTrue(report.reasons)

    def test_non_object_json_is_unavailable(self):
        path = self._write(["not", "an", "object"])

        report = parse_sarif_file(path)

        self.assertFalse(report.available)

    def test_missing_runs_array_is_unavailable(self):
        path = self._write({"version": "2.1.0"})

        report = parse_sarif_file(path)

        self.assertFalse(report.available)

    def test_single_run_single_tool_parses_findings(self):
        doc = _sarif_doc([
            _run("semgrep", [
                _sarif_result("rule.a", "error", "cli/foo.py", 10),
                _sarif_result("rule.b", "warning", "cli/foo.py", 20),
            ])
        ])
        path = self._write(doc)

        report = parse_sarif_file(path)

        self.assertTrue(report.available)
        self.assertEqual(report.total_findings, 2)
        self.assertEqual(report.errors_count, 1)
        self.assertEqual(report.warnings_count, 1)
        self.assertEqual(report.tools_scanned, ["semgrep"])

    def test_multiple_runs_multiple_tools_are_all_captured(self):
        doc = _sarif_doc([
            _run("semgrep", [_sarif_result("rule.a", "error", "cli/foo.py", 10)]),
            _run("trivy", [_sarif_result("CVE-1234", "error", "requirements.txt", 3)]),
        ])
        path = self._write(doc)

        report = parse_sarif_file(path)

        self.assertTrue(report.available)
        self.assertEqual(report.total_findings, 2)
        self.assertEqual(set(report.tools_scanned), {"semgrep", "trivy"})
        self.assertEqual(report.errors_count, 2)

    def test_missing_level_defaults_to_warning(self):
        doc = _sarif_doc([_run("semgrep", [_sarif_result("rule.a", None, "cli/foo.py", 10)])])
        path = self._write(doc)

        report = parse_sarif_file(path)

        self.assertEqual(report.findings[0].level, "warning")

    def test_unrecognized_level_defaults_to_warning(self):
        doc = _sarif_doc([_run("semgrep", [_sarif_result("rule.a", "critical", "cli/foo.py", 10)])])
        path = self._write(doc)

        report = parse_sarif_file(path)

        self.assertEqual(report.findings[0].level, "warning")

    def test_differential_mapping_flags_changed_lines_new_and_unchanged_lines_not_new(self):
        doc = _sarif_doc([
            _run("semgrep", [
                _sarif_result("rule.a", "error", "cli/foo.py", 10),  # changed
                _sarif_result("rule.b", "error", "cli/foo.py", 99),  # unchanged
            ])
        ])
        path = self._write(doc)
        patch_modified_lines = {"cli/foo.py": {10, 11, 12}}

        report = parse_sarif_file(path, patch_modified_lines=patch_modified_lines)

        by_line = {f.start_line: f.is_new_in_patch for f in report.findings}
        self.assertTrue(by_line[10])
        self.assertFalse(by_line[99])
        self.assertEqual(report.patch_errors_count, 1)

    def test_differential_mapping_matches_via_suffix_when_path_prefixed(self):
        # SARIF artifact URIs are frequently absolute / CI-workspace-prefixed
        # (e.g. a runner's checkout path) rather than repo-root-relative.
        doc = _sarif_doc([
            _run("semgrep", [_sarif_result("rule.a", "error", "/home/runner/work/repo/repo/cli/foo.py", 10)])
        ])
        path = self._write(doc)
        patch_modified_lines = {"cli/foo.py": {10}}

        report = parse_sarif_file(path, patch_modified_lines=patch_modified_lines)

        self.assertTrue(report.findings[0].is_new_in_patch)


class AggregateSarifReportsTests(unittest.TestCase):
    def test_empty_list_is_unavailable(self):
        report = aggregate_sarif_reports([])
        self.assertFalse(report.available)

    def test_merges_multiple_available_reports(self):
        r1 = SarifSummaryReport(
            available=True,
            total_findings=1,
            errors_count=1,
            findings=[SarifFinding("semgrep", "rule.a", "error", "m", "cli/foo.py", 10)],
            tools_scanned=["semgrep"],
        )
        r2 = SarifSummaryReport(
            available=True,
            total_findings=1,
            warnings_count=1,
            findings=[SarifFinding("trivy", "CVE-1", "warning", "m", "requirements.txt", 1)],
            tools_scanned=["trivy"],
        )

        merged = aggregate_sarif_reports([r1, r2])

        self.assertTrue(merged.available)
        self.assertEqual(merged.total_findings, 2)
        self.assertEqual(merged.errors_count, 1)
        self.assertEqual(merged.warnings_count, 1)
        self.assertEqual(set(merged.tools_scanned), {"semgrep", "trivy"})
        self.assertEqual(len(merged.findings), 2)

    def test_fails_closed_when_any_report_is_unavailable(self):
        good = SarifSummaryReport(available=True, total_findings=1, tools_scanned=["semgrep"])
        bad = SarifSummaryReport(available=False, reasons=["SARIF file not found: x.json"])

        merged = aggregate_sarif_reports([good, bad])

        self.assertFalse(merged.available)
        self.assertIn("SARIF file not found: x.json", merged.reasons)


def _clean_branch_governance() -> BranchGovernanceReport:
    return BranchGovernanceReport(
        available=True,
        branch="main",
        pull_request_required=True,
        approvals_required=2,
        direct_push_prevented=True,
        bypass_actors_count=0,
        admin_enforced=True,
        warnings=[],
        reason="queried GitHub rules for example/app@main: 1 applicable rule(s), 0 bypass actor(s)",
    )


def _score_kwargs(**overrides):
    kwargs = dict(
        test_totals=TestTotals(tests=100, passed=100, failed=0, errored=0, skipped=0, duration_ms=1000),
        patch_coverage=PatchCoverageResult(available=True, line_rate=0.95, lines_changed=40, lines_covered=38, reason="ok"),
        overall_line_rate=0.85,
        total_assertions=200,
        total_test_functions=100,
        pr_present=True,
        approvers_count=2,
        required_approvals=2,
        review_state="approved",
        branch_governance=_clean_branch_governance(),
    )
    kwargs.update(overrides)
    return kwargs


class ScorerSarifPenaltyTests(unittest.TestCase):
    def test_not_configured_scores_full_baseline_undocked(self):
        result = score_pipeline(**_score_kwargs(sarif_report=None))
        self.assertEqual(result.components["static_analysis"].raw_score, 100.0)
        self.assertFalse(result.degraded)

    def test_configured_clean_scan_also_scores_full_baseline(self):
        clean = SarifSummaryReport(available=True, total_findings=0, tools_scanned=["semgrep"])
        result = score_pipeline(**_score_kwargs(sarif_report=clean))
        self.assertEqual(result.components["static_analysis"].raw_score, 100.0)
        self.assertFalse(result.degraded)

    def test_patch_error_docks_25_points_per_finding(self):
        sarif_report = SarifSummaryReport(
            available=True,
            total_findings=1,
            errors_count=1,
            patch_errors_count=1,
            findings=[SarifFinding("semgrep", "rule.a", "error", "m", "cli/foo.py", 10, is_new_in_patch=True)],
            tools_scanned=["semgrep"],
        )
        result = score_pipeline(**_score_kwargs(sarif_report=sarif_report))
        self.assertAlmostEqual(
            result.components["static_analysis"].raw_score, 100.0 - STATIC_ANALYSIS_PATCH_ERROR_PENALTY
        )

    def test_patch_warning_docks_5_points_per_finding(self):
        sarif_report = SarifSummaryReport(
            available=True,
            total_findings=1,
            warnings_count=1,
            patch_warnings_count=1,
            findings=[SarifFinding("semgrep", "rule.a", "warning", "m", "cli/foo.py", 10, is_new_in_patch=True)],
            tools_scanned=["semgrep"],
        )
        result = score_pipeline(**_score_kwargs(sarif_report=sarif_report))
        self.assertAlmostEqual(
            result.components["static_analysis"].raw_score, 100.0 - STATIC_ANALYSIS_PATCH_WARNING_PENALTY
        )

    def test_legacy_errors_are_capped_at_15_points(self):
        # 10 legacy (non-patch) errors * 2pts = 20pts, capped to 15pts.
        sarif_report = SarifSummaryReport(
            available=True,
            total_findings=10,
            errors_count=10,
            patch_errors_count=0,
            findings=[
                SarifFinding("semgrep", f"rule.{i}", "error", "m", "legacy.py", i, is_new_in_patch=False)
                for i in range(10)
            ],
            tools_scanned=["semgrep"],
        )
        result = score_pipeline(**_score_kwargs(sarif_report=sarif_report))
        self.assertAlmostEqual(
            result.components["static_analysis"].raw_score, 100.0 - STATIC_ANALYSIS_LEGACY_ERROR_PENALTY_CAP
        )

    def test_patch_errors_outweigh_legacy_errors(self):
        patch_error_report = SarifSummaryReport(
            available=True, total_findings=1, errors_count=1, patch_errors_count=1,
            findings=[SarifFinding("t", "r", "error", "m", "f.py", 1, is_new_in_patch=True)],
        )
        legacy_error_report = SarifSummaryReport(
            available=True, total_findings=1, errors_count=1, patch_errors_count=0,
            findings=[SarifFinding("t", "r", "error", "m", "f.py", 1, is_new_in_patch=False)],
        )
        patch_result = score_pipeline(**_score_kwargs(sarif_report=patch_error_report))
        legacy_result = score_pipeline(**_score_kwargs(sarif_report=legacy_error_report))
        self.assertLess(
            patch_result.components["static_analysis"].raw_score,
            legacy_result.components["static_analysis"].raw_score,
        )

    def test_unavailable_report_docks_points_and_flags_degraded(self):
        clean = score_pipeline(**_score_kwargs(sarif_report=None))
        broken = SarifSummaryReport(available=False, reasons=["SARIF file not found: x.json"])
        result = score_pipeline(**_score_kwargs(sarif_report=broken))

        self.assertTrue(result.degraded)
        self.assertAlmostEqual(
            result.components["static_analysis"].raw_score,
            clean.components["static_analysis"].raw_score - STATIC_ANALYSIS_UNAVAILABLE_PENALTY,
        )
        self.assertLess(result.value, clean.value)


class EndToEndAttestationTests(unittest.TestCase):
    def test_static_analysis_predicate_present_and_correct_in_dsse_envelope(self):
        from cli.oidc_signer import sign_statement

        sarif_report = SarifSummaryReport(
            available=True,
            total_findings=2,
            errors_count=1,
            warnings_count=1,
            patch_errors_count=1,
            patch_warnings_count=0,
            findings=[
                SarifFinding("semgrep", "rule.a", "error", "bad thing", "cli/foo.py", 10, is_new_in_patch=True),
                SarifFinding("trivy", "CVE-1", "warning", "old thing", "legacy.py", 1, is_new_in_patch=False),
            ],
            tools_scanned=["semgrep", "trivy"],
        )

        test_totals = TestTotals(tests=10, passed=10, failed=0, errored=0, skipped=0, duration_ms=100)
        patch_coverage = PatchCoverageResult(available=True, line_rate=0.9, lines_changed=10, lines_covered=9, reason="ok")
        coverage = CoverageReport(overall_line_rate=0.85, overall_branch_rate=0.75, files={})
        branch_governance = _clean_branch_governance()

        rcs = score_pipeline(
            test_totals=test_totals,
            patch_coverage=patch_coverage,
            overall_line_rate=coverage.overall_line_rate,
            total_assertions=20,
            total_test_functions=10,
            pr_present=True,
            approvers_count=2,
            required_approvals=2,
            review_state="approved",
            branch_governance=branch_governance,
            sarif_report=sarif_report,
        )

        statement = build_statement(
            subject_name="ghcr.io/example/app",
            subject_sha256="a" * 64,
            vcs_provider="github",
            repository="example/app",
            branch="main",
            commit_sha="b" * 40,
            base_commit_sha="c" * 40,
            pr_number=7,
            pr_target_branch="main",
            pr_approvers=["alice", "bob"],
            pr_required_approvals=2,
            pr_review_state="approved",
            branch_governance=branch_governance,
            test_framework="junit",
            test_report_sha256="d" * 64,
            test_report_uri="worm://evidence/d",
            test_totals=test_totals,
            coverage_format="cobertura-xml",
            coverage_report_sha256="e" * 64,
            coverage_report_uri="worm://evidence/e",
            coverage=coverage,
            patch_coverage=patch_coverage,
            patch_coverage_min=0.80,
            overall_coverage_min=0.60,
            total_assertions=20,
            total_test_functions=10,
            empty_test_bodies=0,
            assertion_only_true=0,
            rcs=rcs,
            sarif_report=sarif_report,
        )

        statement_bytes = json.dumps(statement).encode("utf-8")
        envelope = sign_statement(statement_bytes, dry_run=True).to_dict()

        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)
        self.assertTrue(result.passed, result.violations)

        decoded = json.loads(base64.b64decode(envelope["payload"]))
        static_block = decoded["predicate"]["static_analysis"]

        self.assertTrue(static_block["available"])
        self.assertEqual(set(static_block["tools_scanned"]), {"semgrep", "trivy"})
        self.assertEqual(static_block["total_findings"], 2)
        self.assertEqual(static_block["patch_errors_count"], 1)
        self.assertEqual(static_block["patch_warnings_count"], 0)
        self.assertEqual(len(static_block["findings"]), 2)
        self.assertEqual(static_block["findings"][0]["tool_name"], "semgrep")
        self.assertTrue(static_block["findings"][0]["is_new_in_patch"])
        self.assertFalse(static_block["findings"][1]["is_new_in_patch"])


if __name__ == "__main__":
    unittest.main()
