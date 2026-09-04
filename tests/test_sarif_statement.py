"""
Direct unit tests for cli.sarif_statement: the --sarif companion in-toto
Statement builder (predicateType
https://lucidprovenance.io/attestations/sarif-reports/v1), wrapping every
raw --sarif input's own document verbatim, keyed by tool name, as one
predicate.
"""
import json
import os
import tempfile
import unittest

from cli.sarif_statement import (
    SARIF_REPORTS_PREDICATE_TYPE,
    STATEMENT_TYPE,
    _load_raw_sarif_document,
    _run_tool_names,
    build_sarif_reports_statement,
)
from cli.parsers.sarif import MAX_SARIF_FILE_SIZE


class RunToolNamesTests(unittest.TestCase):
    def test_single_run_single_tool(self):
        doc = {"runs": [{"tool": {"driver": {"name": "grype"}}}]}
        self.assertEqual(_run_tool_names(doc), ["grype"])

    def test_multiple_runs_multiple_tools_preserve_order_dedup(self):
        doc = {
            "runs": [
                {"tool": {"driver": {"name": "grype"}}},
                {"tool": {"driver": {"name": "codeql"}}},
                {"tool": {"driver": {"name": "grype"}}},  # duplicate, not re-added
            ]
        }
        self.assertEqual(_run_tool_names(doc), ["grype", "codeql"])

    def test_missing_or_blank_driver_name_falls_back_to_unknown(self):
        self.assertEqual(_run_tool_names({"runs": [{"tool": {"driver": {}}}]}), ["unknown"])
        self.assertEqual(_run_tool_names({"runs": [{"tool": {"driver": {"name": "   "}}}]}), ["unknown"])
        self.assertEqual(_run_tool_names({"runs": [{"tool": {}}]}), ["unknown"])
        self.assertEqual(_run_tool_names({"runs": [{}]}), ["unknown"])

    def test_missing_or_malformed_runs_never_raises(self):
        self.assertEqual(_run_tool_names({}), [])
        self.assertEqual(_run_tool_names({"runs": "not-a-list"}), [])
        self.assertEqual(_run_tool_names({"runs": [None, "not-a-dict", 123]}), [])

    def test_driver_name_is_stripped_but_not_lowercased(self):
        # Verbatim casing preserved -- ground truth, never normalized here
        # (collector-side lookup is what's case-insensitive, not this).
        doc = {"runs": [{"tool": {"driver": {"name": "  Grype  "}}}]}
        self.assertEqual(_run_tool_names(doc), ["Grype"])


class LoadRawSarifDocumentTests(unittest.TestCase):
    def setUp(self):
        self._paths = []

    def tearDown(self):
        for p in self._paths:
            try:
                os.remove(p)
            except OSError:
                pass

    def _write(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".sarif")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        self._paths.append(path)
        return path

    def test_valid_document_round_trips_verbatim(self):
        doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "grype"}}}]}
        path = self._write(json.dumps(doc))
        self.assertEqual(_load_raw_sarif_document(path), doc)

    def test_missing_file_returns_none(self):
        self.assertIsNone(_load_raw_sarif_document("/nonexistent/path/report.sarif"))

    def test_malformed_json_returns_none(self):
        path = self._write("{not valid json")
        self.assertIsNone(_load_raw_sarif_document(path))

    def test_non_object_top_level_returns_none(self):
        path = self._write(json.dumps([1, 2, 3]))
        self.assertIsNone(_load_raw_sarif_document(path))

    def test_oversized_file_returns_none(self):
        path = self._write("{" * (MAX_SARIF_FILE_SIZE + 1024))
        self.assertIsNone(_load_raw_sarif_document(path))

    def test_path_traversal_attempt_returns_none(self):
        self.assertIsNone(_load_raw_sarif_document("../../../../etc/passwd"))


class BuildSarifReportsStatementTests(unittest.TestCase):
    def setUp(self):
        self._paths = []

    def tearDown(self):
        for p in self._paths:
            try:
                os.remove(p)
            except OSError:
                pass

    def _write_doc(self, doc: dict) -> str:
        fd, path = tempfile.mkstemp(suffix=".sarif")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        self._paths.append(path)
        return path

    def test_no_paths_returns_none(self):
        self.assertIsNone(
            build_sarif_reports_statement(subject_name="x", subject_sha256="a" * 64, sarif_paths=[])
        )

    def test_single_real_input_produces_statement_shape(self):
        doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "grype"}}}]}
        path = self._write_doc(doc)
        statement = build_sarif_reports_statement(
            subject_name="registry.example.com/org/svc", subject_sha256="a" * 64, sarif_paths=[path]
        )
        self.assertEqual(statement["_type"], STATEMENT_TYPE)
        self.assertEqual(
            statement["subject"], [{"name": "registry.example.com/org/svc", "digest": {"sha256": "a" * 64}}]
        )
        self.assertEqual(statement["predicateType"], SARIF_REPORTS_PREDICATE_TYPE)
        # Verbatim (round-tripped through a real file read, so equal, not
        # identical, unlike cli.sbom_statement's in-memory raw_document).
        self.assertEqual(statement["predicate"], {"reports": {"grype": doc}})

    def test_multiple_inputs_multiple_tools_all_represented(self):
        grype_doc = {"runs": [{"tool": {"driver": {"name": "grype"}}}]}
        codeql_doc = {"runs": [{"tool": {"driver": {"name": "codeql"}}}]}
        statement = build_sarif_reports_statement(
            subject_name="x",
            subject_sha256="a" * 64,
            sarif_paths=[self._write_doc(grype_doc), self._write_doc(codeql_doc)],
        )
        self.assertEqual(set(statement["predicate"]["reports"].keys()), {"grype", "codeql"})

    def test_all_inputs_unreadable_returns_none(self):
        self.assertIsNone(
            build_sarif_reports_statement(
                subject_name="x", subject_sha256="a" * 64, sarif_paths=["/nonexistent/a.sarif", "/nonexistent/b.sarif"]
            )
        )

    def test_one_bad_input_does_not_taint_a_good_sibling_input(self):
        # Deliberately looser than aggregate_sarif_reports' own fail-closed-
        # on-any-bad-input contract -- see this module's own docstring.
        good_doc = {"runs": [{"tool": {"driver": {"name": "grype"}}}]}
        statement = build_sarif_reports_statement(
            subject_name="x",
            subject_sha256="a" * 64,
            sarif_paths=["/nonexistent/bad.sarif", self._write_doc(good_doc)],
        )
        self.assertIsNotNone(statement)
        self.assertEqual(list(statement["predicate"]["reports"].keys()), ["grype"])

    def test_first_document_to_claim_a_tool_name_wins(self):
        first = {"runs": [{"tool": {"driver": {"name": "grype", "version": "1.0"}}}]}
        second = {"runs": [{"tool": {"driver": {"name": "grype", "version": "2.0"}}}]}
        statement = build_sarif_reports_statement(
            subject_name="x", subject_sha256="a" * 64, sarif_paths=[self._write_doc(first), self._write_doc(second)]
        )
        self.assertEqual(
            statement["predicate"]["reports"]["grype"]["runs"][0]["tool"]["driver"]["version"], "1.0"
        )

    def test_a_document_with_no_addressable_tool_name_is_still_represented_as_unknown(self):
        doc = {"runs": [{}]}
        statement = build_sarif_reports_statement(
            subject_name="x", subject_sha256="a" * 64, sarif_paths=[self._write_doc(doc)]
        )
        self.assertEqual(list(statement["predicate"]["reports"].keys()), ["unknown"])

    def test_document_with_no_runs_at_all_yields_no_addressable_report(self):
        # {} has no "runs" key -- _run_tool_names returns [] for it, so
        # nothing in `reports` claims it; a lone such input means no
        # addressable tool name exists at all, so the statement is None
        # (never fabricated) -- same contract as build_sbom_statement's own
        # "nothing honest to wrap" cases.
        statement = build_sarif_reports_statement(
            subject_name="x", subject_sha256="a" * 64, sarif_paths=[self._write_doc({})]
        )
        self.assertIsNone(statement)


if __name__ == "__main__":
    unittest.main()
