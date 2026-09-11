import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.mutation.common import LANGUAGE_JAVA, REASON_CODE_NO_COVERABLE_LINES
from cli.mutation.java_runner import _fully_qualified_class_name, _pitest_configured, run

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
        self.assertEqual(result.killed, 1)
        self.assertEqual(result.survived, 1)
        detail = result.surviving_mutants[0]
        self.assertEqual(detail.language, LANGUAGE_JAVA)
        self.assertEqual(detail.line, 9)
        self.assertIn("ConditionalsBoundaryMutator", detail.diff)
        self.assertIn("changed conditional boundary", detail.diff)

    def test_targetClasses_argument_uses_fully_qualified_class_name(self):
        captured = {}

        def side_effect(args, *, cwd, timeout_seconds):
            captured["args"] = args
            self._write_report()
            return _ok()

        with patch("cli.mutation.java_runner._run_mvn", side_effect=side_effect):
            run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        target_classes_arg = next(a for a in captured["args"] if a.startswith("-DtargetClasses="))
        self.assertEqual(target_classes_arg, "-DtargetClasses=mathy.Mathy")

    def test_no_mutations_found_error_is_the_exemption_not_a_failure(self):
        # Confirmed empirically: PIT's real failure message for zero
        # mutable statements in the target classes/filters.
        def side_effect(args, *, cwd, timeout_seconds):
            return _ok(returncode=1, stderr="[ERROR] ... No mutations found. This probably means...")

        with patch("cli.mutation.java_runner._run_mvn", side_effect=side_effect):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "ran")
        self.assertEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)

    def test_a_genuine_build_failure_is_unavailable_not_the_exemption(self):
        def side_effect(args, *, cwd, timeout_seconds):
            return _ok(returncode=1, stderr="[ERROR] Compilation failure")

        with patch("cli.mutation.java_runner._run_mvn", side_effect=side_effect):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "unavailable")
        self.assertNotEqual(result.reason, REASON_CODE_NO_COVERABLE_LINES)

    def test_timeout_is_unavailable_never_full_credit(self):
        with patch("cli.mutation.java_runner._run_mvn", side_effect=subprocess.TimeoutExpired(cmd=[], timeout=1)):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=1, max_surviving_detail=5)
        self.assertEqual(result.status, "unavailable")

    def test_missing_mvn_binary_is_unavailable(self):
        with patch("cli.mutation.java_runner._run_mvn", side_effect=FileNotFoundError("mvn not found")):
            result = run(self.repo_dir, self._diff_files(), timeout_seconds=90, max_surviving_detail=5)
        self.assertEqual(result.status, "unavailable")


if __name__ == "__main__":
    unittest.main()
