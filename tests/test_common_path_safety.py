"""
Tests for cli/common.py::safe_resolve_path, and its wiring into every
operator-supplied file path across cli/main.py, cli/parsers/coverage.py,
cli/parsers/sarif.py, and cli/verify.py.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathlib import Path

from cli.common import UnsafePathError, safe_resolve_path


class SafeResolvePathTests(unittest.TestCase):
    def test_resolves_a_real_relative_path_to_absolute(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            resolved = safe_resolve_path(path)
            self.assertTrue(resolved.is_absolute())
            self.assertEqual(resolved, Path(path).resolve())
        finally:
            os.remove(path)

    def test_accepts_a_path_object_not_just_a_string(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            resolved = safe_resolve_path(Path(path))
            self.assertTrue(resolved.is_absolute())
        finally:
            os.remove(path)

    def test_does_not_require_the_file_to_exist(self):
        # Rejects unsafe *strings*, not missing files -- existing
        # FileNotFoundError handling at each call site is unaffected.
        resolved = safe_resolve_path("/nonexistent/path/does-not-exist.json")
        self.assertTrue(resolved.is_absolute())

    def test_rejects_null_byte(self):
        with self.assertRaises(UnsafePathError):
            safe_resolve_path("a\x00b")

    def test_rejects_empty_string(self):
        with self.assertRaises(UnsafePathError):
            safe_resolve_path("")

    def test_rejects_non_string_non_pathlike(self):
        with self.assertRaises(UnsafePathError):
            safe_resolve_path(12345)  # type: ignore[arg-type]

    def test_rejects_none(self):
        with self.assertRaises(UnsafePathError):
            safe_resolve_path(None)  # type: ignore[arg-type]

    def test_normalizes_dot_dot_segments(self):
        resolved = safe_resolve_path("/tmp/./foo/../bar")
        self.assertNotIn("..", resolved.parts)
        self.assertNotIn(".", resolved.parts)

    def test_unsafe_path_error_is_a_value_error(self):
        self.assertTrue(issubclass(UnsafePathError, ValueError))


class WiringIntoCallSitesTests(unittest.TestCase):
    """Each of the 4 modules this guard was applied to still behaves
    correctly on a null-byte-laced path: never a raw crash of an
    unexpected type, and each module's own "never raises" / "raises a
    known type" contract is preserved."""

    def test_parse_lcov_rejects_null_byte_path(self):
        from cli.parsers.coverage import parse_lcov

        with self.assertRaises(UnsafePathError):
            parse_lcov("a\x00b.lcov")

    def test_parse_cobertura_rejects_null_byte_path(self):
        from cli.parsers.coverage import parse_cobertura

        with self.assertRaises(UnsafePathError):
            parse_cobertura("a\x00b.xml")

    def test_parse_sarif_file_degrades_gracefully_on_null_byte_path(self):
        # sarif.py's contract is "never raises" -- a bad path degrades to
        # available=False like any other unreadable input, not an
        # exception escaping to the caller.
        from cli.parsers.sarif import parse_sarif_file

        report = parse_sarif_file("a\x00b.sarif.json")
        self.assertFalse(report.available)
        self.assertTrue(any("unsafe" in r.lower() for r in report.reasons))

    def test_parse_sonar_metrics_file_degrades_gracefully_on_null_byte_path(self):
        # Same "never raises" contract, returns None instead.
        from cli.parsers.sarif import parse_sonar_metrics_file

        self.assertIsNone(parse_sonar_metrics_file("a\x00b.json"))

    def test_verify_load_envelope_rejects_null_byte_path(self):
        from cli.verify import load_envelope

        with self.assertRaises(UnsafePathError):
            load_envelope("a\x00b.dsse.json")

    def test_verify_main_reports_unsafe_path_cleanly(self):
        from io import StringIO
        from unittest import mock

        from cli.verify import EXIT_FILE_ERROR, main

        with mock.patch("sys.stderr", new_callable=StringIO) as fake_stderr:
            exit_code = main(["a\x00b.dsse.json"])

        self.assertEqual(exit_code, EXIT_FILE_ERROR)
        self.assertIn("unsafe envelope file path", fake_stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
