import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.mutation.common import LANGUAGE_JAVA, REASON_CODE_NO_COVERABLE_LINES
from cli.mutation.java_runner import _fully_qualified_class_name, _parse_report, _pitest_configured, run

_POM_WITH_PITEST = """<project>
  <build><plugins><plugin>
    <groupId>org.pitest</groupId><artifactId>pitest-maven</artifactId>
  </plugin></plugins></build>
</project>
"""

_MUTATIONS_XML = """<?xml version="1.0"?>
<mutations partial="true">
  <mutation detected="true" status="KILLED" numberOfTestsRun="1">
    <sourceFile>Mathy.java</sourceFile>
    <mutatedClass>mathy.Mathy</mutatedClass>
    <mutatedMethod>add</mutatedMethod>
    <lineNumber>5</lineNumber>
    <mutator>org.pitest.mutationtest.engine.gregor.mutators.MathMutator</mutator>
    <description>Replaced integer addition with subtraction</description>
  </mutation>
  <mutation detected="false" status="SURVIVED" numberOfTestsRun="1">
    <sourceFile>Mathy.java</sourceFile>
    <mutatedClass>mathy.Mathy</mutatedClass>
    <mutatedMethod>weaklyTested</mutatedMethod>
    <lineNumber>9</lineNumber>
    <mutator>org.pitest.mutationtest.engine.gregor.mutators.ConditionalsBoundaryMutator</mutator>
    <description>changed conditional boundary</description>
  </mutation>
</mutations>
"""


def _ok(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=["mvn"], returncode=returncode, stdout=stdout, stderr=stderr)


class PitestConfigDetectionTests(unittest.TestCase):

    def test_no_pom_is_not_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(_pitest_configured(Path(tmp)))

    def test_pom_without_pitest_plugin_is_not_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "pom.xml").write_text("<project></project>", encoding="utf-8")
            self.assertFalse(_pitest_configured(Path(tmp)))

    def test_pom_with_pitest_plugin_is_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "pom.xml").write_text(_POM_WITH_PITEST, encoding="utf-8")
            self.assertTrue(_pitest_configured(Path(tmp)))

    def test_unreadable_pom_is_not_configured(self):
        # Distinct code path from "no pom.xml at all" -- the file exists
        # and passes .is_file(), but read_text() itself raises OSError.
        with tempfile.TemporaryDirectory() as tmp:
            pom = Path(tmp) / "pom.xml"
            pom.write_text(_POM_WITH_PITEST, encoding="utf-8")
            os.chmod(pom, 0o000)
            try:
                self.assertFalse(_pitest_configured(Path(tmp)))
            finally:
                os.chmod(pom, 0o644)  # restore so tempdir cleanup can delete it


class FullyQualifiedClassNameTests(unittest.TestCase):

    def test_reads_real_package_declaration(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "src").mkdir()
            f = repo / "src" / "Mathy.java"
            f.write_text("package mathy;\n\npublic class Mathy {}\n", encoding="utf-8")
            self.assertEqual(_fully_qualified_class_name(repo, "src/Mathy.java"), "mathy.Mathy")

    def test_no_package_declaration_falls_back_to_bare_class_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            f = repo / "Mathy.java"
            f.write_text("public class Mathy {}\n", encoding="utf-8")
            self.assertEqual(_fully_qualified_class_name(repo, "Mathy.java"), "Mathy")

    def test_unreadable_file_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(_fully_qualified_class_name(Path(tmp), "DoesNotExist.java"))


class RunTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self._tmp.name)
        (self.repo_dir / "pom.xml").write_text(_POM_WITH_PITEST, encoding="utf-8")
        src = self.repo_dir / "src" / "main" / "java" / "mathy"
        src.mkdir(parents=True)
        (src / "Mathy.java").write_text("package mathy;\n\npublic class Mathy {}\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _diff_files(self):
        return ["src/main/java/mathy/Mathy.java"]

    def _write_report(self):
        report_dir = self.repo_dir / "target" / "pit-reports"
        report_dir.mkdir(parents=True)
        (report_dir / "mutations.xml").write_text(_MUTATIONS_XML, encoding="utf-8")

    def test_no_pom_reports_not_configured_without_invoking_mvn(self):
        (self.repo_dir / "pom.xml").unlink()
        with patch("cli.mutation.java_runner._run_mvn") as run_mock:
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        run_mock.assert_not_called()
        self.assertEqual(result.status, "not_configured")
        self.assertEqual(result.language, LANGUAGE_JAVA)

    def test_no_existing_diff_files_reports_not_configured_without_invoking_mvn(self):
        # Distinct call site from the "no pitest plugin" case above --
        # run() short-circuits here *before* even checking pom.xml,
        # whenever none of the diff's own files exist on disk.
        with patch("cli.mutation.java_runner._run_mvn") as run_mock:
            result = run(self.repo_dir, ["does/not/exist.java"], timeout_seconds=90, max_surviving_detail=5)
        run_mock.assert_not_called()
        self.assertEqual(result.status, "not_configured")
        self.assertEqual(result.language, LANGUAGE_JAVA)

    def test_real_report_is_parsed_into_killed_survived_with_ground_truth_operator(self):
        # Real shape confirmed empirically against a live PIT 1.19.0
        # run this session -- status/lineNumber/mutator/description per
        # mutation.
        def side_effect(args, *, cwd, timeout_seconds):
            self._write_report()
            return _ok()

        with patch("cli.mutation.java_runner._run_mvn", side_effect=side_effect):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.language, LANGUAGE_JAVA)
        self.assertEqual(result.killed, 1)
        self.assertEqual(result.survived, 1)
        self.assertEqual(result.scoped_files, self._diff_files())
        detail = result.surviving_mutants[0]
        self.assertEqual(detail.language, LANGUAGE_JAVA)
        self.assertEqual(detail.status, "survived")
        self.assertEqual(detail.line, 9)
        self.assertEqual(detail.diff, "ConditionalsBoundaryMutator: changed conditional boundary")

    def test_targetClasses_argument_uses_fully_qualified_class_name(self):
        captured = {}

        def side_effect(args, *, cwd, timeout_seconds):
            captured["args"] = args
            captured["cwd"] = cwd
            captured["timeout_seconds"] = timeout_seconds
            self._write_report()
            return _ok()

        with patch("cli.mutation.java_runner._run_mvn", side_effect=side_effect):
            run(self.repo_dir, self._diff_files(), timeout_seconds=123, max_surviving_detail=5)
        # Exact argv, not just the -DtargetClasses value -- pins the
        # literal goal string, the clean/test-compile ordering, and the
        # -DtimestampedReports flag all in one assertion.
        self.assertEqual(
            captured["args"],
            [
                "clean", "test-compile", "org.pitest:pitest-maven:mutationCoverage",
                "-DtargetClasses=mathy.Mathy",
                "-DtimestampedReports=false",
            ],
        )
        self.assertEqual(captured["cwd"], self.repo_dir)
        self.assertEqual(captured["timeout_seconds"], 123)

    def test_targetClasses_joins_multiple_fqcns_with_a_real_comma(self):
        second_src = self.repo_dir / "src" / "main" / "java" / "mathy"
        (second_src / "Other.java").write_text("package mathy;\n\npublic class Other {}\n", encoding="utf-8")
        captured = {}

        def side_effect(args, *, cwd, timeout_seconds):
            captured["args"] = args
            self._write_report()
            return _ok()

        with patch("cli.mutation.java_runner._run_mvn", side_effect=side_effect):
            run(
                self.repo_dir,
                ["src/main/java/mathy/Mathy.java", "src/main/java/mathy/Other.java"],
                timeout_seconds=90, max_surviving_detail=5,
            )
        target_classes_arg = next(a for a in captured["args"] if a.startswith("-DtargetClasses="))
        self.assertEqual(target_classes_arg, "-DtargetClasses=mathy.Mathy,mathy.Other")

    def test_no_mutations_found_error_is_the_exemption_not_a_failure(self):
        # Confirmed empirically: PIT's real failure message for zero
        # mutable statements in the target classes/filters.
        def side_effect(args, *, cwd, timeout_seconds):
            return _ok(returncode=1, stderr="[ERROR] ... No mutations found. This probably means...")

        with patch("cli.mutation.java_runner._run_mvn", side_effect=side_effect):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.language, LANGUAGE_JAVA)
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)
        self.assertEqual(result.scoped_files, self._diff_files())

    def test_a_genuine_build_failure_is_unavailable_not_the_exemption(self):
        def side_effect(args, *, cwd, timeout_seconds):
            return _ok(returncode=1, stderr="[ERROR] Compilation failure")

        with patch("cli.mutation.java_runner._run_mvn", side_effect=side_effect):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.language, LANGUAGE_JAVA)
        self.assertNotEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)
        self.assertEqual(result.reason, "pitest run failed (exit 1): [ERROR] Compilation failure")

    def test_stdout_and_stderr_are_both_present_in_the_failure_reason(self):
        # Pins the `+` concatenation of stdout and stderr -- a `stdout and
        # ""` mutant would silently drop stdout whenever it's non-empty.
        def side_effect(args, *, cwd, timeout_seconds):
            return _ok(returncode=1, stdout="[INFO] real build output", stderr="[ERROR] real failure detail")

        with patch("cli.mutation.java_runner._run_mvn", side_effect=side_effect):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertIn("[INFO] real build output", result.reason)
        self.assertIn("[ERROR] real failure detail", result.reason)

    def test_empty_stderr_has_no_placeholder_text_in_the_failure_reason(self):
        # Distinct from the test above -- pins the *other* fallback
        # (`stderr or "XXXX"`) by making stderr itself the falsy side.
        def side_effect(args, *, cwd, timeout_seconds):
            return _ok(returncode=1, stdout="[ERROR] only in stdout", stderr="")

        with patch("cli.mutation.java_runner._run_mvn", side_effect=side_effect):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.reason, "pitest run failed (exit 1): [ERROR] only in stdout")

    def test_failure_reason_is_truncated_to_exactly_the_last_300_chars(self):
        def side_effect(args, *, cwd, timeout_seconds):
            return _ok(returncode=1, stderr="e" * 350)

        with patch("cli.mutation.java_runner._run_mvn", side_effect=side_effect):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.reason, f"pitest run failed (exit 1): {'e' * 300}")

    def test_timeout_is_unavailable_never_full_credit(self):
        with patch("cli.mutation.java_runner._run_mvn", side_effect=subprocess.TimeoutExpired(cmd=[], timeout=1)):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=1, max_surviving_detail=5)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.language, LANGUAGE_JAVA)
        self.assertEqual(result.reason, "pitest exceeded the 1s time budget")

    def test_missing_mvn_binary_is_unavailable(self):
        with patch("cli.mutation.java_runner._run_mvn", side_effect=FileNotFoundError("mvn not found")):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.language, LANGUAGE_JAVA)
        self.assertIn("mvn could not be invoked", result.reason)

    def test_no_class_names_resolved_is_the_exemption_without_invoking_mvn(self):
        # Every existing_files entry has no `package` declaration to
        # anchor an FQCN from *and* also can't be read -- covered instead
        # by giving _fully_qualified_class_name nothing to work with via
        # an empty existing_files list is impossible here (run() already
        # short-circuits earlier on that), so this exercises the real
        # remaining path: a file that exists but whose read fails.
        bad_file = self.repo_dir / "src" / "main" / "java" / "mathy" / "Unreadable.java"
        bad_file.write_text("package mathy;\npublic class Unreadable {}\n", encoding="utf-8")
        os.chmod(bad_file, 0o000)
        try:
            with patch("cli.mutation.java_runner._run_mvn") as run_mock:
                result = run(
                    self.repo_dir, ["src/main/java/mathy/Unreadable.java"],
                    timeout_seconds=90, max_surviving_detail=5,
                )
        finally:
            os.chmod(bad_file, 0o644)
        run_mock.assert_not_called()
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.language, LANGUAGE_JAVA)
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)
        self.assertEqual(result.scoped_files, ["src/main/java/mathy/Unreadable.java"])


class ParseReportTests(unittest.TestCase):
    """Direct, no-subprocess unit tests against _parse_report itself --
    real PIT mutations.xml shapes written straight to disk."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.report_path = Path(self._tmp.name) / "mutations.xml"

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, xml_text: str) -> Path:
        self.report_path.write_text(xml_text, encoding="utf-8")
        return self.report_path

    def test_unreadable_report_is_unavailable_with_exact_reason(self):
        result = _parse_report(self.report_path, [], 5)  # never written
        self.assertEqual(result.language, LANGUAGE_JAVA)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.reason, "pitest ran but its mutations.xml report could not be read")

    def test_malformed_xml_is_unavailable_with_exact_reason(self):
        self._write("<not><valid</xml")
        result = _parse_report(self.report_path, [], 5)
        self.assertEqual(result.language, LANGUAGE_JAVA)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.reason, "pitest ran but its mutations.xml report could not be read")

    def test_full_status_taxonomy_pins_exact_counts_and_fields(self):
        xml = """<?xml version="1.0"?>
<mutations>
  <mutation detected="true" status="KILLED">
    <sourceFile>Mathy.java</sourceFile>
    <mutatedMethod>add</mutatedMethod>
    <lineNumber>5</lineNumber>
    <mutator>org.pitest.mutators.MathMutator</mutator>
    <description>killed one</description>
  </mutation>
  <mutation detected="false" status="SURVIVED">
    <sourceFile>Mathy.java</sourceFile>
    <mutatedMethod>weaklyTested</mutatedMethod>
    <lineNumber>9</lineNumber>
    <mutator>org.pitest.mutators.ConditionalsBoundaryMutator</mutator>
    <description>changed conditional boundary</description>
  </mutation>
  <mutation detected="true" status="KILLED">
    <sourceFile>Mathy.java</sourceFile>
    <mutatedMethod>add2</mutatedMethod>
    <lineNumber>6</lineNumber>
    <mutator>org.pitest.mutators.MathMutator</mutator>
    <description>killed two</description>
  </mutation>
  <mutation detected="false" status="TIMED_OUT">
    <sourceFile>Mathy.java</sourceFile>
    <mutatedMethod>slowPath</mutatedMethod>
    <lineNumber>14</lineNumber>
    <mutator>org.pitest.mutators.VoidMethodCallMutator</mutator>
    <description>removed a call</description>
  </mutation>
  <mutation detected="false" status="TIMED_OUT">
    <sourceFile>Mathy.java</sourceFile>
    <mutatedMethod>slowPath2</mutatedMethod>
    <lineNumber>15</lineNumber>
    <mutator>org.pitest.mutators.VoidMethodCallMutator</mutator>
    <description>removed another call</description>
  </mutation>
  <mutation detected="false" status="NO_COVERAGE">
    <sourceFile>Mathy.java</sourceFile>
    <mutatedMethod>neverReached</mutatedMethod>
    <lineNumber>20</lineNumber>
    <mutator>org.pitest.mutators.ReturnValsMutator</mutator>
    <description>unrecognized status, not one of the three handled buckets</description>
  </mutation>
</mutations>
"""
        # Two KILLED, two TIMED_OUT -- `+= 1` and `= 1` are
        # indistinguishable from a single occurrence.
        result = _parse_report(self._write(xml), ["mathy.Mathy"], 5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.language, LANGUAGE_JAVA)
        self.assertEqual(result.killed, 2)
        self.assertEqual(result.survived, 1)
        self.assertEqual(result.timeout, 2)
        self.assertEqual(result.total_generated, 6)
        self.assertEqual(result.scoped_files, ["mathy.Mathy"])
        self.assertEqual(len(result.surviving_mutants), 3)

        survived, timed_out_1, timed_out_2 = result.surviving_mutants
        self.assertEqual(survived.language, LANGUAGE_JAVA)
        self.assertEqual(survived.file, "Mathy.java")
        self.assertEqual(survived.function, "weaklyTested")
        self.assertEqual(survived.status, "survived")
        self.assertEqual(survived.diff, "ConditionalsBoundaryMutator: changed conditional boundary")
        self.assertEqual(survived.line, 9)

        self.assertEqual(timed_out_1.function, "slowPath")
        self.assertEqual(timed_out_1.status, "timeout")
        self.assertEqual(timed_out_1.diff, "VoidMethodCallMutator: removed a call")
        self.assertEqual(timed_out_1.line, 14)

        self.assertEqual(timed_out_2.function, "slowPath2")
        self.assertEqual(timed_out_2.status, "timeout")
        self.assertEqual(timed_out_2.diff, "VoidMethodCallMutator: removed another call")
        self.assertEqual(timed_out_2.line, 15)

    def test_missing_optional_text_elements_default_to_empty_string(self):
        # sourceFile/mutatedMethod/mutator/description each fall back to
        # ""  when the child element is absent -- distinct from a bogus
        # placeholder default.
        xml = """<?xml version="1.0"?>
<mutations>
  <mutation detected="false" status="SURVIVED">
    <lineNumber>3</lineNumber>
  </mutation>
</mutations>
"""
        result = _parse_report(self._write(xml), [], 5)
        detail = result.surviving_mutants[0]
        self.assertEqual(detail.file, "")
        self.assertEqual(detail.function, "")
        self.assertEqual(detail.diff, ": ")  # empty mutator suffix + empty description

    def test_missing_line_number_element_defaults_to_none_without_crashing(self):
        xml = """<?xml version="1.0"?>
<mutations>
  <mutation detected="false" status="SURVIVED">
    <sourceFile>Mathy.java</sourceFile>
    <mutatedMethod>weaklyTested</mutatedMethod>
    <mutator>org.pitest.mutators.ConditionalsBoundaryMutator</mutator>
    <description>no lineNumber element at all</description>
  </mutation>
</mutations>
"""
        result = _parse_report(self._write(xml), [], 5)
        self.assertIsNone(result.surviving_mutants[0].line)

    def test_non_digit_line_number_defaults_to_none(self):
        xml = """<?xml version="1.0"?>
<mutations>
  <mutation detected="false" status="SURVIVED">
    <sourceFile>Mathy.java</sourceFile>
    <mutatedMethod>weaklyTested</mutatedMethod>
    <lineNumber>not-a-number</lineNumber>
    <mutator>org.pitest.mutators.ConditionalsBoundaryMutator</mutator>
    <description>d</description>
  </mutation>
</mutations>
"""
        result = _parse_report(self._write(xml), [], 5)
        self.assertIsNone(result.surviving_mutants[0].line)

    def test_mutator_without_package_prefix_uses_the_whole_name(self):
        xml = """<?xml version="1.0"?>
<mutations>
  <mutation detected="false" status="SURVIVED">
    <sourceFile>Mathy.java</sourceFile>
    <mutatedMethod>m</mutatedMethod>
    <lineNumber>1</lineNumber>
    <mutator>BareMutatorNoPackage</mutator>
    <description>d</description>
  </mutation>
</mutations>
"""
        result = _parse_report(self._write(xml), [], 5)
        self.assertEqual(result.surviving_mutants[0].diff, "BareMutatorNoPackage: d")

    def test_missing_status_attribute_counts_generated_but_no_bucket(self):
        xml = """<?xml version="1.0"?>
<mutations>
  <mutation detected="false">
    <sourceFile>Mathy.java</sourceFile>
    <mutatedMethod>m</mutatedMethod>
    <lineNumber>1</lineNumber>
    <mutator>org.pitest.mutators.X</mutator>
    <description>d</description>
  </mutation>
</mutations>
"""
        result = _parse_report(self._write(xml), [], 5)
        # A status attribute unrecognized by any of the three buckets
        # lands in none of them -- killed+survived+timeout stays 0, which
        # is itself indistinguishable from the real zero-mutant exemption
        # (the exemption branch doesn't preserve total_generated either).
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)
        self.assertEqual(result.killed, 0)
        self.assertEqual(result.survived, 0)
        self.assertEqual(result.timeout, 0)

    def test_max_detail_boundary_is_strict_less_than(self):
        mutations = "\n".join(
            f"""<mutation detected="false" status="SURVIVED">
    <sourceFile>Mathy.java</sourceFile>
    <mutatedMethod>m{i}</mutatedMethod>
    <lineNumber>{i}</lineNumber>
    <mutator>org.pitest.mutators.X</mutator>
    <description>d</description>
  </mutation>"""
            for i in (10, 20, 30)
        )
        xml = f"<?xml version=\"1.0\"?>\n<mutations>\n{mutations}\n</mutations>\n"
        result = _parse_report(self._write(xml), [], 2)
        self.assertEqual(result.survived, 3)
        self.assertEqual(len(result.surviving_mutants), 2)
        self.assertEqual([m.line for m in result.surviving_mutants], [10, 20])

    def test_killed_and_timeout_present_is_not_the_zero_mutant_exemption(self):
        xml = """<?xml version="1.0"?>
<mutations>
  <mutation detected="true" status="KILLED">
    <sourceFile>Mathy.java</sourceFile><mutatedMethod>a</mutatedMethod>
    <lineNumber>1</lineNumber><mutator>org.pitest.mutators.X</mutator><description>d</description>
  </mutation>
  <mutation detected="false" status="TIMED_OUT">
    <sourceFile>Mathy.java</sourceFile><mutatedMethod>b</mutatedMethod>
    <lineNumber>2</lineNumber><mutator>org.pitest.mutators.X</mutator><description>d</description>
  </mutation>
</mutations>
"""
        result = _parse_report(self._write(xml), [], 5)
        self.assertEqual(result.status, "ran")
        self.assertIsNone(result.reason)
        self.assertEqual(result.killed, 1)
        self.assertEqual(result.timeout, 1)

    def test_killed_equals_survived_is_not_the_zero_mutant_exemption(self):
        xml = """<?xml version="1.0"?>
<mutations>
  <mutation detected="true" status="KILLED">
    <sourceFile>Mathy.java</sourceFile><mutatedMethod>a</mutatedMethod>
    <lineNumber>1</lineNumber><mutator>org.pitest.mutators.X</mutator><description>d</description>
  </mutation>
  <mutation detected="false" status="SURVIVED">
    <sourceFile>Mathy.java</sourceFile><mutatedMethod>b</mutatedMethod>
    <lineNumber>2</lineNumber><mutator>org.pitest.mutators.X</mutator><description>d</description>
  </mutation>
</mutations>
"""
        result = _parse_report(self._write(xml), [], 5)
        self.assertEqual(result.status, "ran")
        self.assertIsNone(result.reason)
        self.assertEqual(result.killed, 1)
        self.assertEqual(result.survived, 1)

    def test_zero_mutations_in_report_is_the_exemption(self):
        xml = '<?xml version="1.0"?>\n<mutations>\n</mutations>\n'
        result = _parse_report(self._write(xml), ["mathy.Mathy"], 5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.language, LANGUAGE_JAVA)
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)
        self.assertEqual(result.scoped_files, ["mathy.Mathy"])


if __name__ == "__main__":
    unittest.main()
