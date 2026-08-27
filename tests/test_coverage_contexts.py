"""
Direct unit tests for cli.parsers.coverage_contexts.parse_coverage_contexts():
parses a `coverage json --show-contexts` export into per-line, per-test
attribution. Covers the happy path against a realistic export shape, and
the module's own "Hardened against" edge cases: missing/malformed input,
an export missing --show-contexts, the "|run" phase-suffix strip, and the
empty-string context.
"""
import json
import os
import shutil
import tempfile
import unittest

from cli.parsers.coverage_contexts import CoverageContextReport, parse_coverage_contexts


class TmpDirMixin:
    def _tmp(self) -> str:
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        return d

    def _write_json(self, doc, name: str = "coverage.json") -> str:
        path = os.path.join(self._tmp(), name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        return path


def _export_doc(files: dict) -> dict:
    return {"meta": {"show_contexts": True}, "files": files}


class ParseCoverageContextsTests(TmpDirMixin, unittest.TestCase):
    def test_happy_path_parses_contexts_per_line(self):
        doc = _export_doc(
            {
                "cli/scorer.py": {
                    "executed_lines": [10, 11],
                    "contexts": {
                        "10": ["tests/test_scorer.py::RCSScorerTests::test_perfect_run_scores_high|run"],
                        "11": [
                            "tests/test_scorer.py::RCSScorerTests::test_perfect_run_scores_high|run",
                            "tests/test_scorer.py::test_bare_function|run",
                        ],
                    },
                }
            }
        )
        path = self._write_json(doc)

        report = parse_coverage_contexts(path)

        self.assertTrue(report.available)
        file_contexts = report.files["cli/scorer.py"]
        self.assertEqual(
            file_contexts[10], frozenset({"tests/test_scorer.py::RCSScorerTests::test_perfect_run_scores_high"})
        )
        self.assertEqual(
            file_contexts[11],
            frozenset(
                {
                    "tests/test_scorer.py::RCSScorerTests::test_perfect_run_scores_high",
                    "tests/test_scorer.py::test_bare_function",
                }
            ),
        )

    def test_empty_string_context_dropped_not_treated_as_a_test_id(self):
        doc = _export_doc({"cli/foo.py": {"contexts": {"1": [""]}}})
        path = self._write_json(doc)

        report = parse_coverage_contexts(path)

        self.assertTrue(report.available)
        # Empty frozenset: "covered, no known covering test" -- not absent.
        self.assertEqual(report.files["cli/foo.py"][1], frozenset())

    def test_mixed_setup_run_teardown_phase_suffixes_stripped(self):
        doc = _export_doc(
            {
                "cli/foo.py": {
                    "contexts": {
                        "1": [
                            "tests/test_foo.py::test_a|setup",
                            "tests/test_foo.py::test_a|run",
                            "tests/test_foo.py::test_a|teardown",
                        ]
                    }
                }
            }
        )
        path = self._write_json(doc)

        report = parse_coverage_contexts(path)

        # All three phase-suffixed labels collapse to the same test id.
        self.assertEqual(report.files["cli/foo.py"][1], frozenset({"tests/test_foo.py::test_a"}))

    def test_non_numeric_lineno_key_skipped(self):
        doc = _export_doc({"cli/foo.py": {"contexts": {"not-a-number": ["x|run"]}}})
        path = self._write_json(doc)

        report = parse_coverage_contexts(path)

        self.assertEqual(report.files["cli/foo.py"], {})

    def test_non_list_context_value_skipped(self):
        doc = _export_doc({"cli/foo.py": {"contexts": {"1": "not-a-list"}}})
        path = self._write_json(doc)

        report = parse_coverage_contexts(path)

        self.assertEqual(report.files["cli/foo.py"], {})

    def test_missing_show_contexts_flag_is_distinct_reason(self):
        # A normal `coverage json` export (no --show-contexts) has no
        # 'contexts' key on any file at all.
        doc = {"files": {"cli/foo.py": {"executed_lines": [1, 2], "summary": {}}}}
        path = self._write_json(doc)

        report = parse_coverage_contexts(path)

        self.assertFalse(report.available)
        self.assertIn("--show-contexts", report.reason)

    def test_missing_files_key_unavailable(self):
        path = self._write_json({"meta": {}})

        report = parse_coverage_contexts(path)

        self.assertFalse(report.available)

    def test_non_object_json_unavailable(self):
        path = self._write_json([1, 2, 3])

        report = parse_coverage_contexts(path)

        self.assertFalse(report.available)

    def test_missing_file_returns_unavailable(self):
        report = parse_coverage_contexts(os.path.join(self._tmp(), "does-not-exist.json"))

        self.assertFalse(report.available)
        self.assertIn("failed to read", report.reason)

    def test_malformed_json_returns_unavailable(self):
        path = os.path.join(self._tmp(), "bad.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not valid json")

        report = parse_coverage_contexts(path)

        self.assertFalse(report.available)
        self.assertIn("failed to parse", report.reason)

    def test_deeply_nested_json_fails_closed_not_crash(self):
        depth = 10_000
        nested = ("{\"a\":" * depth) + "1" + ("}" * depth)
        path = os.path.join(self._tmp(), "deep.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(nested)

        report = parse_coverage_contexts(path)

        self.assertFalse(report.available)

    def test_null_byte_path_returns_unavailable(self):
        report = parse_coverage_contexts("coverage\x00evil.json")

        self.assertFalse(report.available)

    def test_non_dict_file_entry_skipped(self):
        doc = _export_doc({"cli/foo.py": "not-a-dict", "cli/bar.py": {"contexts": {"1": ["x|run"]}}})
        path = self._write_json(doc)

        report = parse_coverage_contexts(path)

        self.assertTrue(report.available)
        self.assertNotIn("cli/foo.py", report.files)
        self.assertIn("cli/bar.py", report.files)

    def test_path_normalization_matches_coverage_module_convention(self):
        doc = _export_doc({"./cli/foo.py": {"contexts": {}}})
        path = self._write_json(doc)

        report = parse_coverage_contexts(path)

        self.assertIn("cli/foo.py", report.files)


if __name__ == "__main__":
    unittest.main()
