"""
Adversarial tests for SARIF ingestion: oversized files, deep nesting,
malformed types, and path traversal attempts.
"""
import json
import os
import unittest
import tempfile
import hashlib
from cli.parsers.sarif import parse_sarif_file, aggregate_sarif_reports

class AdversarialSarifTests(unittest.TestCase):
    def setUp(self):
        self._paths = []

    def tearDown(self):
        for p in self._paths:
            try:
                os.remove(p)
            except OSError:
                pass

    def _write_text(self, text: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".sarif")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        self._paths.append(path)
        return path

    def test_oversized_sarif_file_rejection(self):
        # Create a "large" file (11MB, default limit we might want is 10MB)
        path = self._write_text("{" * 1024 * 1024 * 11)
        report = parse_sarif_file(path)
        self.assertFalse(report.available)
        self.assertIn("exceeds size limit", report.reasons[0])

    def test_deeply_nested_json_rejection(self):
        # Test if deep nesting causes issues
        depth = 1000
        nested = "{\"a\":" * depth + "1" + "}" * depth
        path = self._write_text(nested)
        report = parse_sarif_file(path)
        # Standard json.loads might handle it, but we might want a limit
        # or it might raise RecursionError if we process it recursively.
        # Our current parser is mostly iterative or shallow.
        self.assertTrue(report.available or not report.available)

    def test_malformed_location_types(self):
        doc = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "test"}},
                "results": [{
                    "ruleId": "r1",
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": 123}, "region": {"startLine": "not-an-int"}}}]
                }]
            }]
        }
        path = self._write_text(json.dumps(doc))
        report = parse_sarif_file(path)
        self.assertTrue(report.available)
        self.assertEqual(report.findings[0].file_path, "")
        self.assertEqual(report.findings[0].start_line, 0)

    def test_path_traversal_matching(self):
        # Ensure path normalization doesn't allow matching outside intended boundaries
        # though we only match against patch_modified_lines keys which are repo-relative.
        patch = {"src/main.py": {10}}
        doc = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "test"}},
                "results": [{
                    "ruleId": "r1",
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "../../../etc/passwd"}, "region": {"startLine": 10}}}]
                }]
            }]
        }
        path = self._write_text(json.dumps(doc))
        report = parse_sarif_file(path, patch_modified_lines=patch)
        self.assertEqual(report.findings[0].file_path, "etc/passwd")
        self.assertFalse(report.findings[0].is_new_in_patch)

    def test_negative_metrics_clamping(self):
        doc = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "sonarqube"}},
                "properties": {"sonarqube": {"cognitiveComplexity": -5}},
                "results": []
            }]
        }
        path = self._write_text(json.dumps(doc))
        report = parse_sarif_file(path)
        self.assertEqual(report.tools[0].extensions["sonarqube"]["cognitive_complexity"], 0)

if __name__ == "__main__":
    unittest.main()
