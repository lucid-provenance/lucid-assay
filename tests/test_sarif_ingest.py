"""
Tests for the unified SARIF 2.1.0 ingestion feature: per-level/rule/tool
aggregation, driver metadata, SonarQube-style extension enrichment (both
embedded in a SARIF run's `properties` bag and merged in externally via
`--sonar-metrics`), report integrity hashing, malformed/empty-input
handling, and the CLI/schema/signature surface it's wired into.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jsonschema import Draft202012Validator

from cli.builder import build_statement
from cli.oidc_signer import sign_statement
from cli.parsers.coverage import CoverageReport
from cli.parsers.github_rules import BranchGovernanceReport
from cli.parsers.junit import TestTotals
from cli.parsers.sarif import (
    aggregate_sarif_reports,
    merge_sonar_metrics_into_tools,
    parse_sarif_file,
    parse_sonar_metrics_file,
)
from cli.patch_coverage import PatchCoverageResult
from cli.scorer import score_pipeline
from cli.verify import verify_dsse_attestation

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCHEMA_PATH = os.path.join(_REPO_ROOT, "schema", "lucid-attestation-v1.schema.json")


def _sarif_result(rule_id, level, uri, line, message="finding"):
    result = {
        "ruleId": rule_id,
        "message": {"text": message},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}
        ],
    }
    if level is not None:
        result["level"] = level
    return result


def _driver(name, version=None, information_uri=None, rules=None):
    driver = {"name": name}
    if version is not None:
        driver["version"] = version
    if information_uri is not None:
        driver["informationUri"] = information_uri
    if rules is not None:
        driver["rules"] = rules
    return driver


def _run(tool_name, results, version=None, information_uri=None, rules=None, properties=None):
    run = {"tool": {"driver": _driver(tool_name, version, information_uri, rules)}, "results": results}
    if properties is not None:
        run["properties"] = properties
    return run


def _sarif_doc(runs):
    return {"version": "2.1.0", "runs": runs}


def _write_json(doc) -> str:
    fd, path = tempfile.mkstemp(suffix=".sarif.json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    return path


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
        reason="clean",
    )


class _TempFileMixin:
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

    def _write_text(self, text: str, suffix=".json") -> str:
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        self._paths.append(path)
        return path


class LevelAggregationTests(_TempFileMixin, unittest.TestCase):
    """Standard SARIF 2.1.0 report with errors, warnings, notes, and the
    spec-valid 'none' level, all counted into their own buckets."""

    def test_counts_every_level_including_none(self):
        doc = _sarif_doc([
            _run("semgrep", [
                _sarif_result("r.error", "error", "a.py", 1),
                _sarif_result("r.warning", "warning", "a.py", 2),
                _sarif_result("r.note", "note", "a.py", 3),
                _sarif_result("r.none", "none", "a.py", 4),
            ]),
        ])
        report = parse_sarif_file(self._write(doc))

        self.assertTrue(report.available)
        self.assertEqual(report.total_findings, 4)
        self.assertEqual(report.errors_count, 1)
        self.assertEqual(report.warnings_count, 1)
        self.assertEqual(report.notes_count, 1)
        self.assertEqual(report.none_count, 1)

    def test_missing_level_still_defaults_to_warning_not_none(self):
        doc = _sarif_doc([_run("semgrep", [_sarif_result("r.a", None, "a.py", 1)])])
        report = parse_sarif_file(self._write(doc))
        self.assertEqual(report.findings[0].level, "warning")
        self.assertEqual(report.warnings_count, 1)
        self.assertEqual(report.none_count, 0)

    def test_report_hash_is_sha256_of_raw_file_bytes(self):
        import hashlib

        doc = _sarif_doc([_run("semgrep", [_sarif_result("r.a", "error", "a.py", 1)])])
        path = self._write(doc)
        report = parse_sarif_file(path)

        with open(path, "rb") as f:
            expected = hashlib.sha256(f.read()).hexdigest()

        self.assertEqual(len(report.tools), 1)
        self.assertEqual(report.tools[0].report_hash, {"algorithm": "sha256", "value": expected})


class MultiRunMultiToolTests(_TempFileMixin, unittest.TestCase):
    """Multi-run SARIF files (same tool merged) and multi-tool ingestion,
    both within one file and aggregated across multiple --sarif inputs."""

    def test_two_runs_from_the_same_tool_in_one_file_are_merged(self):
        doc = _sarif_doc([
            _run("semgrep", [_sarif_result("r.a", "error", "a.py", 1)], version="1.0.0"),
            _run("semgrep", [_sarif_result("r.b", "warning", "b.py", 2)], version="1.0.0"),
        ])
        report = parse_sarif_file(self._write(doc))

        self.assertEqual(report.tools_scanned, ["semgrep"])
        self.assertEqual(len(report.tools), 1)
        tool = report.tools[0]
        self.assertEqual(tool.errors_count, 1)
        self.assertEqual(tool.warnings_count, 1)
        self.assertEqual(tool.total_findings, 2)
        self.assertEqual({r.rule_id for r in tool.rules}, {"r.a", "r.b"})

    def test_two_tools_in_one_file_produce_two_tool_summaries(self):
        doc = _sarif_doc([
            _run("semgrep", [_sarif_result("r.a", "error", "a.py", 1)]),
            _run("sonarqube", [_sarif_result("S100", "warning", "b.py", 2)]),
        ])
        report = parse_sarif_file(self._write(doc))

        self.assertEqual(set(report.tools_scanned), {"semgrep", "sonarqube"})
        self.assertEqual(len(report.tools), 2)
        names = {t.name for t in report.tools}
        self.assertEqual(names, {"semgrep", "sonarqube"})

    def test_aggregate_concatenates_tools_across_files_without_merging_by_name(self):
        doc_a = _sarif_doc([_run("semgrep", [_sarif_result("r.a", "error", "a.py", 1)])])
        doc_b = _sarif_doc([_run("semgrep", [_sarif_result("r.b", "error", "b.py", 1)])])

        report_a = parse_sarif_file(self._write(doc_a))
        report_b = parse_sarif_file(self._write(doc_b))
        aggregated = aggregate_sarif_reports([report_a, report_b])

        # Two separate file-scoped tool entries, not one merged "semgrep"
        # entry -- each keeps its own file's report_hash.
        self.assertEqual(len(aggregated.tools), 2)
        self.assertEqual({t.name for t in aggregated.tools}, {"semgrep"})
        hashes = {t.report_hash["value"] for t in aggregated.tools}
        self.assertEqual(len(hashes), 2)
        self.assertEqual(aggregated.total_findings, 2)
        self.assertEqual(aggregated.errors_count, 2)

    def test_driver_metadata_extracted(self):
        doc = _sarif_doc([
            _run("semgrep", [_sarif_result("r.a", "error", "a.py", 1)],
                 version="1.50.0", information_uri="https://semgrep.dev"),
        ])
        report = parse_sarif_file(self._write(doc))
        tool = report.tools[0]
        self.assertEqual(tool.version, "1.50.0")
        self.assertEqual(tool.information_uri, "https://semgrep.dev")

    def test_missing_driver_name_defaults_to_unknown(self):
        doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": [_sarif_result("r.a", "error", "a.py", 1)]}]}
        report = parse_sarif_file(self._write(doc))
        self.assertEqual(report.tools_scanned, ["unknown"])


class RuleGroupingTests(_TempFileMixin, unittest.TestCase):
    """Rule violations grouped by rule ID and category/tags, sourced from
    the driver's own `rules[]` ReportingDescriptor array."""

    def test_findings_grouped_by_rule_id_with_category_and_tags(self):
        rules = [{"id": "S1234", "properties": {"category": "code-smell", "tags": ["maintainability", "brain-overload"]}}]
        doc = _sarif_doc([
            _run("sonarqube", [
                _sarif_result("S1234", "warning", "a.py", 1),
                _sarif_result("S1234", "warning", "b.py", 2),
                _sarif_result("S5678", "error", "c.py", 3),
            ], rules=rules),
        ])
        report = parse_sarif_file(self._write(doc))

        tool = report.tools[0]
        by_id = {r.rule_id: r for r in tool.rules}
        self.assertEqual(by_id["S1234"].count, 2)
        self.assertEqual(by_id["S1234"].category, "code-smell")
        self.assertEqual(set(by_id["S1234"].tags), {"maintainability", "brain-overload"})
        self.assertEqual(by_id["S5678"].count, 1)
        self.assertIsNone(by_id["S5678"].category)
        self.assertEqual(by_id["S5678"].tags, [])

    def test_findings_carry_category_and_tags_individually(self):
        rules = [{"id": "S1234", "properties": {"category": "security", "tags": ["cwe-79"]}}]
        doc = _sarif_doc([_run("semgrep", [_sarif_result("S1234", "error", "a.py", 1)], rules=rules)])
        report = parse_sarif_file(self._write(doc))
        self.assertEqual(report.findings[0].category, "security")
        self.assertEqual(report.findings[0].tags, ["cwe-79"])

    def test_missing_rule_id_falls_back_to_unknown_rule(self):
        result = {"message": {"text": "x"}, "locations": [], "level": "error"}
        doc = _sarif_doc([{"tool": {"driver": {"name": "t"}}, "results": [result]}])
        report = parse_sarif_file(self._write(doc))
        self.assertEqual(report.findings[0].rule_id, "unknown-rule")


class SonarQubeExtensionTests(_TempFileMixin, unittest.TestCase):
    """SonarQube SARIF export with extension/property-bag parsing, both
    embedded in the SARIF file and merged in externally via
    --sonar-metrics."""

    def test_nested_sonarqube_properties_bag_extracted(self):
        doc = _sarif_doc([
            _run("sonarqube", [_sarif_result("S1", "warning", "a.py", 1)],
                 properties={"sonarqube": {"qualityGate": "OK", "cognitiveComplexity": 7, "technicalDebtMinutes": 30}}),
        ])
        report = parse_sarif_file(self._write(doc))
        ext = report.tools[0].extensions["sonarqube"]
        self.assertEqual(ext["quality_gate"], "PASSED")
        self.assertEqual(ext["cognitive_complexity"], 7)
        self.assertEqual(ext["technical_debt_minutes"], 30)

    def test_flat_properties_bag_without_nested_sonarqube_key_also_works(self):
        doc = _sarif_doc([
            _run("sonarqube", [_sarif_result("S1", "warning", "a.py", 1)],
                 properties={"quality_gate": "FAILED", "cognitive_complexity": 3}),
        ])
        report = parse_sarif_file(self._write(doc))
        ext = report.tools[0].extensions["sonarqube"]
        self.assertEqual(ext["quality_gate"], "FAILED")
        self.assertEqual(ext["cognitive_complexity"], 3)

    def test_unrecognized_quality_gate_value_is_dropped_not_raised(self):
        doc = _sarif_doc([
            _run("sonarqube", [_sarif_result("S1", "warning", "a.py", 1)],
                 properties={"sonarqube": {"qualityGate": "SOMETHING_WEIRD"}}),
        ])
        report = parse_sarif_file(self._write(doc))
        self.assertNotIn("sonarqube", report.tools[0].extensions)

    def test_no_properties_bag_yields_no_extensions(self):
        doc = _sarif_doc([_run("semgrep", [_sarif_result("r.a", "error", "a.py", 1)])])
        report = parse_sarif_file(self._write(doc))
        self.assertEqual(report.tools[0].extensions, {})

    def test_parse_sonar_metrics_file_maps_alert_status_and_sqale_index(self):
        path = self._write({"component": {"measures": [
            {"metric": "alert_status", "value": "OK"},
            {"metric": "sqale_index", "value": "120"},
        ]}})
        ext = parse_sonar_metrics_file(path)
        self.assertEqual(ext, {"quality_gate": "PASSED", "technical_debt_minutes": 120})

    def test_parse_sonar_metrics_file_accepts_top_level_measures_shape(self):
        path = self._write({"measures": [{"metric": "cognitive_complexity", "value": "5"}]})
        ext = parse_sonar_metrics_file(path)
        self.assertEqual(ext, {"cognitive_complexity": 5})

    def test_parse_sonar_metrics_file_missing_file_returns_none(self):
        self.assertIsNone(parse_sonar_metrics_file("/nonexistent/measures.json"))

    def test_parse_sonar_metrics_file_malformed_json_returns_none(self):
        path = self._write_text("{not valid json")
        self.assertIsNone(parse_sonar_metrics_file(path))

    def test_parse_sonar_metrics_file_missing_measures_returns_none(self):
        path = self._write({"component": {"key": "x"}})
        self.assertIsNone(parse_sonar_metrics_file(path))

    def test_merge_attaches_to_tool_named_like_sonar(self):
        doc = _sarif_doc([
            _run("semgrep", [_sarif_result("r.a", "error", "a.py", 1)]),
            _run("SonarQube Scanner", [_sarif_result("S1", "warning", "b.py", 2)]),
        ])
        report = parse_sarif_file(self._write(doc))
        attached = merge_sonar_metrics_into_tools(report.tools, {"quality_gate": "PASSED"})

        self.assertTrue(attached)
        by_name = {t.name: t for t in report.tools}
        self.assertEqual(by_name["SonarQube Scanner"].extensions["sonarqube"]["quality_gate"], "PASSED")
        self.assertNotIn("sonarqube", by_name["semgrep"].extensions)

    def test_merge_attaches_to_sole_tool_when_no_name_matches(self):
        doc = _sarif_doc([_run("my-custom-scanner", [_sarif_result("r.a", "error", "a.py", 1)])])
        report = parse_sarif_file(self._write(doc))
        attached = merge_sonar_metrics_into_tools(report.tools, {"quality_gate": "PASSED"})

        self.assertTrue(attached)
        self.assertEqual(report.tools[0].extensions["sonarqube"]["quality_gate"], "PASSED")

    def test_merge_is_ambiguous_and_skipped_with_multiple_unnamed_tools(self):
        doc = _sarif_doc([
            _run("tool-a", [_sarif_result("r.a", "error", "a.py", 1)]),
            _run("tool-b", [_sarif_result("r.b", "error", "b.py", 1)]),
        ])
        report = parse_sarif_file(self._write(doc))
        attached = merge_sonar_metrics_into_tools(report.tools, {"quality_gate": "PASSED"})

        self.assertFalse(attached)
        self.assertNotIn("sonarqube", report.tools[0].extensions)
        self.assertNotIn("sonarqube", report.tools[1].extensions)

    def test_merge_with_empty_extension_is_a_noop(self):
        doc = _sarif_doc([_run("sonarqube", [_sarif_result("r.a", "error", "a.py", 1)])])
        report = parse_sarif_file(self._write(doc))
        self.assertFalse(merge_sonar_metrics_into_tools(report.tools, {}))
        self.assertFalse(merge_sonar_metrics_into_tools(report.tools, None))

    def test_merge_preserves_embedded_extension_keys_not_overwritten(self):
        doc = _sarif_doc([
            _run("sonarqube", [_sarif_result("S1", "warning", "a.py", 1)],
                 properties={"sonarqube": {"qualityGate": "OK"}}),
        ])
        report = parse_sarif_file(self._write(doc))
        merge_sonar_metrics_into_tools(report.tools, {"technical_debt_minutes": 45})

        ext = report.tools[0].extensions["sonarqube"]
        self.assertEqual(ext["quality_gate"], "PASSED")
        self.assertEqual(ext["technical_debt_minutes"], 45)


class MalformedAndEmptySarifTests(_TempFileMixin, unittest.TestCase):
    """Malformed and empty SARIF inputs degrade to available=False (or an
    honest zero-findings report), never raise."""

    def test_missing_file_is_unavailable(self):
        report = parse_sarif_file("/nonexistent/path/does-not-exist.sarif.json")
        self.assertFalse(report.available)
        self.assertTrue(report.reasons)
        self.assertEqual(report.tools, [])

    def test_malformed_json_is_unavailable(self):
        path = self._write_text("{not valid json")
        report = parse_sarif_file(path)
        self.assertFalse(report.available)
        self.assertTrue(report.reasons)

    def test_non_object_document_is_unavailable(self):
        path = self._write_text("[1, 2, 3]")
        report = parse_sarif_file(path)
        self.assertFalse(report.available)

    def test_missing_runs_array_is_unavailable(self):
        path = self._write({"version": "2.1.0"})
        report = parse_sarif_file(path)
        self.assertFalse(report.available)

    def test_empty_runs_array_is_available_with_zero_findings(self):
        path = self._write(_sarif_doc([]))
        report = parse_sarif_file(path)
        self.assertTrue(report.available)
        self.assertEqual(report.total_findings, 0)
        self.assertEqual(report.tools, [])

    def test_empty_results_in_a_run_is_available_with_zero_findings_but_tool_recorded(self):
        doc = _sarif_doc([_run("semgrep", [])])
        report = parse_sarif_file(self._write(doc))
        self.assertTrue(report.available)
        self.assertEqual(report.total_findings, 0)
        self.assertEqual(report.tools_scanned, ["semgrep"])
        self.assertEqual(report.tools[0].total_findings, 0)

    def test_non_dict_result_entries_are_skipped_not_raised(self):
        doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": ["not-a-dict", None, 42]}]}
        report = parse_sarif_file(self._write(doc))
        self.assertTrue(report.available)
        self.assertEqual(report.total_findings, 0)

    def test_aggregate_of_no_reports_is_unavailable(self):
        aggregated = aggregate_sarif_reports([])
        self.assertFalse(aggregated.available)

    def test_aggregate_fails_closed_when_any_input_unavailable(self):
        good = parse_sarif_file(self._write(_sarif_doc([_run("semgrep", [_sarif_result("r.a", "error", "a.py", 1)])])))
        bad = parse_sarif_file("/nonexistent/does-not-exist.sarif.json")
        aggregated = aggregate_sarif_reports([good, bad])
        self.assertFalse(aggregated.available)


class SchemaComplianceAndSignatureTests(unittest.TestCase):
    """Full pipeline: parsed SARIF (with tool extensions) -> scored ->
    assembled into the in-toto predicate -> validated against
    schema/lucid-attestation-v1.schema.json -> signed (dry-run) -> verified,
    exercising the same DSSE/Sigstore path production signing uses."""

    def _build_sarif_report(self):
        rules = [{"id": "S1234", "properties": {"category": "code-smell", "tags": ["maintainability"]}}]
        doc = _sarif_doc([
            _run("sonarqube", [
                _sarif_result("S1234", "warning", "cli/foo.py", 5),
                _sarif_result("S1234", "none", "cli/bar.py", 9),
            ], version="10.4", information_uri="https://www.sonarsource.com", rules=rules,
               properties={"sonarqube": {"qualityGate": "OK", "cognitiveComplexity": 7}}),
            _run("semgrep", [_sarif_result("rule.a", "error", "cli/foo.py", 5)], version="1.50.0"),
        ])
        fd, path = tempfile.mkstemp(suffix=".sarif.json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        self.addCleanup(lambda: os.remove(path) if os.path.exists(path) else None)
        return parse_sarif_file(path)

    def _build_statement(self):
        sarif_report = aggregate_sarif_reports([self._build_sarif_report()])

        test_totals = TestTotals(tests=10, passed=10, failed=0, errored=0, skipped=0, duration_ms=100)
        patch_coverage = PatchCoverageResult(available=True, line_rate=0.9, lines_changed=10, lines_covered=9, reason="ok")
        coverage = CoverageReport(overall_line_rate=0.85, overall_branch_rate=0.75, files={})
        branch_governance = _clean_branch_governance()

        rcs = score_pipeline(
            test_totals=test_totals, patch_coverage=patch_coverage, overall_line_rate=coverage.overall_line_rate,
            total_assertions=20, total_test_functions=10, pr_present=True, approvers_count=2,
            required_approvals=2, review_state="approved", branch_governance=branch_governance,
            sarif_report=sarif_report,
        )
        return build_statement(
            subject_name="ghcr.io/example/app", subject_sha256="a" * 64, vcs_provider="github",
            repository="example/app", branch="main", commit_sha="b" * 40, base_commit_sha="c" * 40,
            pr_number=7, pr_target_branch="main", pr_approvers=["alice", "bob"], pr_required_approvals=2,
            pr_review_state="approved", branch_governance=branch_governance, test_framework="junit",
            test_report_sha256="d" * 64, test_report_uri="worm://evidence/d", test_totals=test_totals,
            coverage_format="cobertura-xml", coverage_report_sha256="e" * 64,
            coverage_report_uri="worm://evidence/e", coverage=coverage, patch_coverage=patch_coverage,
            patch_coverage_min=0.80, overall_coverage_min=0.60, total_assertions=20, total_test_functions=10,
            empty_test_bodies=0, assertion_only_true=0, rcs=rcs, sarif_report=sarif_report,
        )

    def test_predicate_static_analysis_block_validates_against_schema(self):
        statement = self._build_statement()

        with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema = json.load(f)
        validator = Draft202012Validator(schema)
        errors = list(validator.iter_errors(statement["predicate"]))
        static_analysis_errors = [e for e in errors if "static_analysis" in list(e.absolute_path)]
        self.assertEqual(static_analysis_errors, [], msg=[e.message for e in static_analysis_errors])

        static_block = statement["predicate"]["static_analysis"]
        self.assertEqual(static_block["format"], "sarif-2.1.0")
        self.assertEqual(len(static_block["tools"]), 2)

    def test_signed_envelope_verifies_and_exposes_static_analysis_tools(self):
        statement = self._build_statement()

        statement_bytes = json.dumps(statement).encode("utf-8")
        envelope = sign_statement(statement_bytes, dry_run=True).to_dict()

        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)
        self.assertTrue(result.passed, result.violations)

        tools_by_name = {t["name"]: t for t in result.static_analysis_tools}
        self.assertEqual(set(tools_by_name), {"sonarqube", "semgrep"})
        self.assertEqual(tools_by_name["sonarqube"]["extensions"]["sonarqube"]["quality_gate"], "PASSED")
        self.assertEqual(tools_by_name["sonarqube"]["summary"]["warnings"], 1)
        self.assertEqual(tools_by_name["sonarqube"]["summary"]["none"], 1)
        self.assertEqual(tools_by_name["semgrep"]["summary"]["errors"], 1)

    def test_as_dict_json_output_includes_static_analysis_tools(self):
        statement = self._build_statement()
        statement_bytes = json.dumps(statement).encode("utf-8")
        envelope = sign_statement(statement_bytes, dry_run=True).to_dict()

        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)
        as_dict = result.as_dict()
        self.assertIn("static_analysis_tools", as_dict)
        self.assertEqual(len(as_dict["static_analysis_tools"]), 2)


class VerifyTableRenderingTests(unittest.TestCase):
    def test_table_renders_tool_error_warning_and_quality_gate(self):
        from cli.verify import _format_static_analysis_table

        tools = [
            {"name": "semgrep", "summary": {"errors": 2, "warnings": 1}, "extensions": {}},
            {"name": "sonarqube", "summary": {"errors": 0, "warnings": 3},
             "extensions": {"sonarqube": {"quality_gate": "FAILED"}}},
        ]
        lines = _format_static_analysis_table(tools)
        self.assertEqual(len(lines), 3)  # header + 2 rows
        self.assertIn("TOOL", lines[0])
        self.assertIn("QUALITY GATE", lines[0])
        self.assertTrue(any("semgrep" in line and "2" in line for line in lines))
        self.assertTrue(any("sonarqube" in line and "FAILED" in line for line in lines))

    def test_merged_sonar_metrics_on_non_sonar_tool_are_labeled(self):
        """Regression coverage: SonarQube Cloud/Server doesn't emit its own
        SARIF file, so --sonar-metrics merges its quality-gate data into
        whatever SARIF tool was actually scanned (e.g. a lone "CodeQL" run
        -- see merge_sonar_metrics_into_tools). Left unlabeled, that row
        never mentions "SonarQube" at all despite carrying its data, which
        reads as the SonarQube info being silently dropped from the table."""
        from cli.verify import _format_static_analysis_table

        tools = [
            {"name": "CodeQL", "summary": {"errors": 0, "warnings": 0},
             "extensions": {"sonarqube": {"quality_gate": "PASSED"}}},
        ]
        lines = _format_static_analysis_table(tools)
        self.assertTrue(any("CodeQL" in line and "SonarQube" in line and "PASSED" in line for line in lines))

    def test_empty_tools_renders_no_lines(self):
        from cli.verify import _format_static_analysis_table

        self.assertEqual(_format_static_analysis_table([]), [])

    def test_missing_fields_degrade_to_dash_not_raise(self):
        from cli.verify import _format_static_analysis_table

        lines = _format_static_analysis_table([{"name": "weird-tool"}])
        self.assertEqual(len(lines), 2)
        self.assertIn("-", lines[1])


class CliSurfaceTests(unittest.TestCase):
    """--sarif/--sonar-metrics flags and the `run` subcommand alias."""

    def _base_argv(self, extra=None):
        argv = [
            "--junit-xml", "j.xml", "--coverage-report", "c.xml",
            "--image-ref", "r", "--image-digest", "sha256:" + "a" * 64,
            "--head-sha", "b" * 40, "--repository", "o/r", "--branch", "main",
        ]
        return argv + (extra or [])

    def test_parse_args_accepts_repeated_sarif_and_sonar_metrics(self):
        from cli.main import parse_args

        args = parse_args(self._base_argv(["--sarif", "f1.json", "--sarif", "f2.json", "--sonar-metrics", "m.json"]))
        self.assertEqual(args.sarif, ["f1.json", "f2.json"])
        self.assertEqual(args.sonar_metrics, "m.json")

    def test_sonar_metrics_defaults_to_none(self):
        from cli.main import parse_args

        args = parse_args(self._base_argv())
        self.assertIsNone(args.sonar_metrics)

    def test_emit_slsa_provenance_defaults_off_and_out_path_defaults_to_none(self):
        from cli.main import parse_args

        args = parse_args(self._base_argv())
        self.assertFalse(args.emit_slsa_provenance)
        self.assertIsNone(args.slsa_provenance_out)

    def test_emit_slsa_provenance_and_its_out_path_are_parsed(self):
        from cli.main import parse_args

        args = parse_args(
            self._base_argv(["--emit-slsa-provenance", "--slsa-provenance-out", "slsa.unsigned.json"])
        )
        self.assertTrue(args.emit_slsa_provenance)
        self.assertEqual(args.slsa_provenance_out, "slsa.unsigned.json")

    def test_run_subcommand_is_stripped_before_arg_parsing(self):
        from cli.main import main

        with self.assertRaises(SystemExit) as without_run:
            main([])
        with self.assertRaises(SystemExit) as with_run:
            main(["run"])

        self.assertEqual(without_run.exception.code, with_run.exception.code)

    def test_run_subcommand_with_full_args_parses_identically_to_no_subcommand(self):
        from cli.main import parse_args

        argv = self._base_argv(["--sarif", "f.json"])
        direct = parse_args(argv)
        via_run = parse_args(argv)  # `run` stripping happens in main(), not parse_args
        self.assertEqual(vars(direct), vars(via_run))


if __name__ == "__main__":
    unittest.main()
