"""
Direct unit tests for cli.parsers.coverage: parse_cobertura() and
parse_lcov(). Neither had dedicated coverage before this file -- the
existing sample fixtures (tests/fixtures/cobertura.xml) were only ever
loaded incidentally (e.g. via cli.hashing.sha256_file in other tests), not
parsed. These exercise both the sample fixture and the edge cases the
module's own "Hardened against" docstring calls out: missing/corrupted
line numbers, unbounded rate clamping, and non-standard LCOV negative hit
counts.
"""
import os
import unittest

from cli.parsers.coverage import CoverageReport, FileCoverage, parse_cobertura, parse_lcov

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _write(tmp_path: str, name: str, content: str) -> str:
    path = os.path.join(tmp_path, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


class ParseCoberturaTests(unittest.TestCase):
    def _tmp(self):
        import tempfile

        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def test_sample_fixture(self):
        report = parse_cobertura(os.path.join(FIXTURES_DIR, "cobertura.xml"))
        self.assertIsInstance(report, CoverageReport)
        self.assertAlmostEqual(report.overall_line_rate, 0.85)
        self.assertAlmostEqual(report.overall_branch_rate, 0.70)
        fc = report.files["src/pkg/core/foo.py"]
        self.assertEqual(fc.line_hits, {1: 1, 2: 1, 3: 0, 10: 3})

    def test_rate_clamped_above_one(self):
        xml = '<coverage line-rate="1.5" branch-rate="2.0"></coverage>'
        path = _write(self._tmp(), "cobertura.xml", xml)
        report = parse_cobertura(path)
        self.assertEqual(report.overall_line_rate, 1.0)
        self.assertEqual(report.overall_branch_rate, 1.0)

    def test_rate_clamped_below_zero(self):
        xml = '<coverage line-rate="-0.5"></coverage>'
        path = _write(self._tmp(), "cobertura.xml", xml)
        report = parse_cobertura(path)
        self.assertEqual(report.overall_line_rate, 0.0)

    def test_missing_line_rate_defaults_to_zero(self):
        xml = "<coverage></coverage>"
        path = _write(self._tmp(), "cobertura.xml", xml)
        report = parse_cobertura(path)
        self.assertEqual(report.overall_line_rate, 0.0)
        self.assertIsNone(report.overall_branch_rate)

    def test_malformed_line_rate_defaults_to_zero(self):
        xml = '<coverage line-rate="not-a-number" branch-rate="also-bad"></coverage>'
        path = _write(self._tmp(), "cobertura.xml", xml)
        report = parse_cobertura(path)
        self.assertEqual(report.overall_line_rate, 0.0)
        self.assertIsNone(report.overall_branch_rate)

    def test_class_without_filename_is_skipped(self):
        xml = """<coverage line-rate="1.0">
          <packages><package><classes>
            <class><lines><line number="1" hits="1"/></lines></class>
          </classes></package></packages>
        </coverage>"""
        path = _write(self._tmp(), "cobertura.xml", xml)
        report = parse_cobertura(path)
        self.assertEqual(report.files, {})

    def test_class_without_lines_element(self):
        xml = """<coverage line-rate="1.0">
          <packages><package><classes>
            <class filename="a.py"></class>
          </classes></package></packages>
        </coverage>"""
        path = _write(self._tmp(), "cobertura.xml", xml)
        report = parse_cobertura(path)
        self.assertIn("a.py", report.files)
        self.assertEqual(report.files["a.py"].line_hits, {})

    def test_missing_and_malformed_line_numbers_skipped(self):
        xml = """<coverage line-rate="1.0">
          <packages><package><classes>
            <class filename="a.py"><lines>
              <line hits="1"/>
              <line number="notanumber" hits="1"/>
              <line number="5" hits="2"/>
              <line number="5" hits="notanumber"/>
            </lines></class>
          </classes></package></packages>
        </coverage>"""
        path = _write(self._tmp(), "cobertura.xml", xml)
        report = parse_cobertura(path)
        # Only the well-formed <line number="5" hits="2"/> should register;
        # the later malformed hits="notanumber" for the same line number
        # is skipped entirely rather than overwriting the good value.
        self.assertEqual(report.files["a.py"].line_hits, {5: 2})

    def test_duplicate_class_entries_take_max_hits(self):
        xml = """<coverage line-rate="1.0">
          <packages><package><classes>
            <class filename="a.py"><lines><line number="1" hits="1"/></lines></class>
            <class filename="a.py"><lines><line number="1" hits="9"/></lines></class>
          </classes></package></packages>
        </coverage>"""
        path = _write(self._tmp(), "cobertura.xml", xml)
        report = parse_cobertura(path)
        self.assertEqual(report.files["a.py"].line_hits, {1: 9})

    def test_absolute_and_relative_paths_normalized(self):
        xml = """<coverage line-rate="1.0">
          <packages><package><classes>
            <class filename="/abs/pkg/foo.py"><lines><line number="1" hits="1"/></lines></class>
          </classes></package></packages>
        </coverage>"""
        path = _write(self._tmp(), "cobertura.xml", xml)
        report = parse_cobertura(path)
        self.assertIn("abs/pkg/foo.py", report.files)



class ParseLcovTests(unittest.TestCase):
    def _tmp(self):
        import tempfile

        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def test_basic_tracefile(self):
        lcov = (
            "SF:src/foo.py\n"
            "DA:1,1\n"
            "DA:2,0\n"
            "DA:3,5\n"
            "end_of_record\n"
        )
        path = _write(self._tmp(), "lcov.info", lcov)
        report = parse_lcov(path)
        self.assertIsInstance(report, CoverageReport)
        self.assertIsNone(report.overall_branch_rate)
        fc = report.files["src/foo.py"]
        self.assertEqual(fc.line_hits, {1: 1, 2: 0, 3: 5})
        # 2 of 3 recorded lines covered
        self.assertAlmostEqual(report.overall_line_rate, 2 / 3)

    def test_multiple_files(self):
        lcov = (
            "SF:a.py\n"
            "DA:1,1\n"
            "end_of_record\n"
            "SF:b.py\n"
            "DA:1,0\n"
            "end_of_record\n"
        )
        path = _write(self._tmp(), "lcov.info", lcov)
        report = parse_lcov(path)
        self.assertEqual(set(report.files.keys()), {"a.py", "b.py"})
        self.assertAlmostEqual(report.overall_line_rate, 0.5)

    def test_no_da_records_defaults_rate_to_zero(self):
        lcov = "SF:a.py\nend_of_record\n"
        path = _write(self._tmp(), "lcov.info", lcov)
        report = parse_lcov(path)
        self.assertEqual(report.overall_line_rate, 0.0)
        self.assertEqual(report.files["a.py"].line_hits, {})

    def test_negative_hit_count_clamped_to_zero(self):
        lcov = "SF:a.py\nDA:1,-5\nend_of_record\n"
        path = _write(self._tmp(), "lcov.info", lcov)
        report = parse_lcov(path)
        self.assertEqual(report.files["a.py"].line_hits, {1: 0})
        self.assertEqual(report.overall_line_rate, 0.0)

    def test_da_record_before_sf_is_ignored(self):
        # A DA: line with no preceding SF: has nowhere to attach -- must
        # not raise (e.g. a KeyError from files[current]).
        lcov = "DA:1,1\nSF:a.py\nDA:2,1\nend_of_record\n"
        path = _write(self._tmp(), "lcov.info", lcov)
        report = parse_lcov(path)
        self.assertEqual(report.files["a.py"].line_hits, {2: 1})

    def test_malformed_da_record_skipped(self):
        lcov = "SF:a.py\nDA:1,notanumber\nDA:2,1\nend_of_record\n"
        path = _write(self._tmp(), "lcov.info", lcov)
        report = parse_lcov(path)
        # DA:1,notanumber doesn't match the regex at all (hits must be
        # digits), so only DA:2,1 registers.
        self.assertEqual(report.files["a.py"].line_hits, {2: 1})

    def test_blank_lines_and_unknown_directives_ignored(self):
        lcov = "SF:a.py\n\nTN:some_test\nDA:1,1\nFNH:0\nend_of_record\n"
        path = _write(self._tmp(), "lcov.info", lcov)
        report = parse_lcov(path)
        self.assertEqual(report.files["a.py"].line_hits, {1: 1})

    def test_end_of_record_resets_current_file(self):
        # A DA: line after end_of_record with no new SF: must not attach
        # to the previous file.
        lcov = "SF:a.py\nDA:1,1\nend_of_record\nDA:2,1\n"
        path = _write(self._tmp(), "lcov.info", lcov)
        report = parse_lcov(path)
        self.assertEqual(report.files["a.py"].line_hits, {1: 1})
        self.assertEqual(len(report.files), 1)

    def test_path_normalization(self):
        lcov = "SF:/abs/src/foo.py\nDA:1,1\nend_of_record\n"
        path = _write(self._tmp(), "lcov.info", lcov)
        report = parse_lcov(path)
        self.assertIn("abs/src/foo.py", report.files)


if __name__ == "__main__":
    unittest.main()
