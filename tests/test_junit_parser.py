"""
Direct unit tests for cli.parsers.junit.parse_junit_xml(). Not previously
exercised directly -- tests/fixtures/junit.xml existed but nothing parsed
it. Covers the module's own design notes: outcome priority
(failure > error > skipped > passed), flaky-retry detection (>1 recorded
attempt for the same (classname, name) AND the final attempt passed), and
multi-<testsuite> aggregation.
"""
import os
import unittest

from cli.parsers.junit import TestTotals, parse_junit_xml

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _write(tmp_path: str, name: str, content: str) -> str:
    path = os.path.join(tmp_path, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


class ParseJunitXmlTests(unittest.TestCase):
    def _tmp(self):
        import tempfile

        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def test_sample_fixture(self):
        totals = parse_junit_xml(os.path.join(FIXTURES_DIR, "junit.xml"))
        self.assertIsInstance(totals, TestTotals)
        # 4 distinct (classname, name) keys: test_add, test_sub, test_flaky
        # (2 attempts -> 1 case), test_skip.
        self.assertEqual(totals.tests, 4)
        self.assertEqual(totals.passed, 3)  # test_add, test_sub, test_flaky (final attempt passed)
        self.assertEqual(totals.failed, 0)
        self.assertEqual(totals.errored, 0)
        self.assertEqual(totals.skipped, 1)
        self.assertEqual(totals.flaky_retries, 1)  # test_flaky: 2 attempts, final passed

    def test_all_passed(self):
        xml = """<testsuites><testsuite>
          <testcase classname="C" name="t1" time="0.1"/>
          <testcase classname="C" name="t2" time="0.2"/>
        </testsuite></testsuites>"""
        path = _write(self._tmp(), "junit.xml", xml)
        totals = parse_junit_xml(path)
        self.assertEqual((totals.tests, totals.passed), (2, 2))
        self.assertEqual(totals.duration_ms, 300)

    def test_failure_takes_priority_over_error_and_skipped(self):
        xml = """<testsuites><testsuite>
          <testcase classname="C" name="t1">
            <failure message="x">boom</failure>
            <error message="y">also boom</error>
            <skipped/>
          </testcase>
        </testsuite></testsuites>"""
        path = _write(self._tmp(), "junit.xml", xml)
        totals = parse_junit_xml(path)
        self.assertEqual(totals.failed, 1)
        self.assertEqual(totals.errored, 0)
        self.assertEqual(totals.skipped, 0)

    def test_error_without_failure(self):
        xml = """<testsuites><testsuite>
          <testcase classname="C" name="t1"><error message="y">boom</error></testcase>
        </testsuite></testsuites>"""
        path = _write(self._tmp(), "junit.xml", xml)
        totals = parse_junit_xml(path)
        self.assertEqual((totals.errored, totals.failed, totals.passed), (1, 0, 0))

    def test_skipped_without_failure_or_error(self):
        xml = """<testsuites><testsuite>
          <testcase classname="C" name="t1"><skipped/></testcase>
        </testsuite></testsuites>"""
        path = _write(self._tmp(), "junit.xml", xml)
        totals = parse_junit_xml(path)
        self.assertEqual((totals.skipped, totals.passed), (1, 0))

    def test_missing_time_attribute_defaults_to_zero(self):
        xml = """<testsuites><testsuite>
          <testcase classname="C" name="t1"/>
        </testsuite></testsuites>"""
        path = _write(self._tmp(), "junit.xml", xml)
        totals = parse_junit_xml(path)
        self.assertEqual(totals.duration_ms, 0)

    def test_flaky_retry_final_attempt_failed_not_counted_as_flaky(self):
        # Two attempts of the same case, but the *final* one failed --
        # this is not "flaky" (a flaky case is one that eventually
        # passes after retries), it's a genuine failure.
        xml = """<testsuites><testsuite>
          <testcase classname="C" name="t1" time="0.1"/>
          <testcase classname="C" name="t1" time="0.1"><failure>boom</failure></testcase>
        </testsuite></testsuites>"""
        path = _write(self._tmp(), "junit.xml", xml)
        totals = parse_junit_xml(path)
        self.assertEqual(totals.tests, 1)
        self.assertEqual(totals.failed, 1)
        self.assertEqual(totals.passed, 0)
        self.assertEqual(totals.flaky_retries, 0)

    def test_single_attempt_passing_is_not_flaky(self):
        xml = """<testsuites><testsuite>
          <testcase classname="C" name="t1" time="0.1"/>
        </testsuite></testsuites>"""
        path = _write(self._tmp(), "junit.xml", xml)
        totals = parse_junit_xml(path)
        self.assertEqual(totals.flaky_retries, 0)

    def test_multiple_testsuites_aggregate(self):
        xml = """<testsuites>
          <testsuite name="a"><testcase classname="C" name="t1"/></testsuite>
          <testsuite name="b"><testcase classname="D" name="t2"><failure>x</failure></testcase></testsuite>
        </testsuites>"""
        path = _write(self._tmp(), "junit.xml", xml)
        totals = parse_junit_xml(path)
        self.assertEqual(totals.tests, 2)
        self.assertEqual(totals.passed, 1)
        self.assertEqual(totals.failed, 1)

    def test_same_name_different_classname_are_distinct_cases(self):
        xml = """<testsuites><testsuite>
          <testcase classname="C" name="t1"/>
          <testcase classname="D" name="t1"><failure>x</failure></testcase>
        </testsuite></testsuites>"""
        path = _write(self._tmp(), "junit.xml", xml)
        totals = parse_junit_xml(path)
        self.assertEqual(totals.tests, 2)
        self.assertEqual(totals.passed, 1)
        self.assertEqual(totals.failed, 1)

    def test_missing_classname_and_name_default_to_empty_string(self):
        xml = "<testsuites><testsuite><testcase/></testsuite></testsuites>"
        path = _write(self._tmp(), "junit.xml", xml)
        totals = parse_junit_xml(path)
        self.assertEqual(totals.tests, 1)
        self.assertEqual(totals.passed, 1)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            parse_junit_xml(os.path.join(self._tmp(), "does-not-exist.xml"))

    def test_malformed_xml_raises_parse_error(self):
        import xml.etree.ElementTree as ET

        path = _write(self._tmp(), "junit.xml", "<not-closed>")
        with self.assertRaises(ET.ParseError):
            parse_junit_xml(path)


if __name__ == "__main__":
    unittest.main()
