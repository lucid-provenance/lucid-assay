import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.parsers.functional_adequacy import (
    ADEQUACY_STATUS_EVALUATED,
    ADEQUACY_STATUS_NOT_CONFIGURED,
    ADEQUACY_STATUS_UNAVAILABLE,
    FRAMEWORK_GENERIC_JSON,
    FRAMEWORK_PLAYWRIGHT,
    FRAMEWORK_PYTEST,
    REASON_CODE_NOT_CONFIGURED,
    REASON_CODE_NO_TESTS_EXECUTED,
    REASON_CODE_PARTIAL_ADEQUACY,
    REASON_CODE_REPORT_MALFORMED,
    REASON_CODE_REPORT_MISSING,
    REASON_CODE_TEST_FAILURES,
    REASON_CODE_UNSUPPORTED_FRAMEWORK,
    FunctionalVerificationConfig,
    _compute_adequacy,
    _NormalizedCase,
    _parse_generic_json_report,
    _parse_junit_functional_report,
    _parse_playwright_report,
    _playwright_final_status,
    _unavailable_report,
    evaluate_functional_adequacy,
    load_functional_verification_config,
)


class TempRepoTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _write_config(self, doc):
        lucid_dir = Path(self.repo_dir) / ".lucid"
        lucid_dir.mkdir(parents=True, exist_ok=True)
        (lucid_dir / "functional-verification.json").write_text(json.dumps(doc), encoding="utf-8")

    def _write_report(self, name, content):
        path = Path(self.repo_dir) / name
        path.write_text(content, encoding="utf-8")
        return str(path)

    def _write_json_report(self, name, doc):
        return self._write_report(name, json.dumps(doc))


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


class LoadFunctionalVerificationConfigTests(TempRepoTestCase):
    def test_missing_file_returns_none(self):
        self.assertIsNone(load_functional_verification_config(self.repo_dir))

    def test_malformed_json_returns_none(self):
        Path(self.repo_dir, ".lucid").mkdir()
        Path(self.repo_dir, ".lucid", "functional-verification.json").write_text("{not json", encoding="utf-8")
        self.assertIsNone(load_functional_verification_config(self.repo_dir))

    def test_non_object_json_returns_none(self):
        Path(self.repo_dir, ".lucid").mkdir()
        Path(self.repo_dir, ".lucid", "functional-verification.json").write_text("[1, 2, 3]", encoding="utf-8")
        self.assertIsNone(load_functional_verification_config(self.repo_dir))

    def test_missing_declared_journeys_returns_none(self):
        self._write_config({"framework": "playwright"})
        self.assertIsNone(load_functional_verification_config(self.repo_dir))

    def test_empty_declared_journeys_returns_none(self):
        self._write_config({"framework": "playwright", "declared_journeys": []})
        self.assertIsNone(load_functional_verification_config(self.repo_dir))

    def test_declared_journeys_not_a_list_returns_none(self):
        self._write_config({"framework": "playwright", "declared_journeys": "auth-flow"})
        self.assertIsNone(load_functional_verification_config(self.repo_dir))

    def test_valid_config_parses_all_fields(self):
        self._write_config(
            {
                "framework": "playwright",
                "min_adequacy_pct": 90,
                "declared_journeys": ["auth-flow", "attestation-ingest"],
            }
        )
        config = load_functional_verification_config(self.repo_dir)
        self.assertEqual(config.framework, "playwright")
        self.assertEqual(config.min_adequacy_pct, 90.0)
        self.assertEqual(config.declared_journeys, ["auth-flow", "attestation-ingest"])

    def test_missing_min_adequacy_pct_defaults_to_100(self):
        self._write_config({"framework": "playwright", "declared_journeys": ["auth-flow"]})
        config = load_functional_verification_config(self.repo_dir)
        self.assertEqual(config.min_adequacy_pct, 100.0)

    def test_non_numeric_min_adequacy_pct_falls_back_to_default(self):
        self._write_config(
            {"framework": "playwright", "declared_journeys": ["auth-flow"], "min_adequacy_pct": "mostly"}
        )
        config = load_functional_verification_config(self.repo_dir)
        self.assertEqual(config.min_adequacy_pct, 100.0)

    def test_boolean_min_adequacy_pct_falls_back_to_default(self):
        self._write_config(
            {"framework": "playwright", "declared_journeys": ["auth-flow"], "min_adequacy_pct": True}
        )
        config = load_functional_verification_config(self.repo_dir)
        self.assertEqual(config.min_adequacy_pct, 100.0)

    def test_blank_entries_in_declared_journeys_are_dropped(self):
        self._write_config({"framework": "playwright", "declared_journeys": ["auth-flow", "  ", "", 5]})
        config = load_functional_verification_config(self.repo_dir)
        self.assertEqual(config.declared_journeys, ["auth-flow"])

    def test_missing_framework_yields_empty_string(self):
        self._write_config({"declared_journeys": ["auth-flow"]})
        config = load_functional_verification_config(self.repo_dir)
        self.assertEqual(config.framework, "")


# ---------------------------------------------------------------------------
# Playwright JSON reporter ingestion
# ---------------------------------------------------------------------------


def _playwright_doc(*specs_by_suite):
    """Builds a minimal Playwright JSON reporter document with one
    top-level suite containing the given (title, status, retries=1) specs."""
    specs = []
    for title, status in specs_by_suite:
        specs.append(
            {
                "title": title,
                "tests": [{"results": [{"status": status}]}],
            }
        )
    return {"suites": [{"title": "e2e", "specs": specs, "suites": []}]}


class ParsePlaywrightReportTests(TempRepoTestCase):
    def test_parses_tagged_specs_and_status(self):
        doc = _playwright_doc(
            ("logs in @cuj:auth-flow", "passed"),
            ("ingests attestation @cuj:attestation-ingest", "passed"),
        )
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(len(cases), 2)
        self.assertEqual(cases[0].journeys, ("auth-flow",))
        self.assertEqual(cases[0].status, "passed")

    def test_final_retry_attempt_wins(self):
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": [
                        {
                            "title": "flaky @cuj:auth-flow",
                            "tests": [{"results": [{"status": "failed"}, {"status": "passed"}]}],
                        }
                    ],
                    "suites": [],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(cases[0].status, "passed")

    def test_timed_out_status_folds_to_failed(self):
        doc = _playwright_doc(("slow @cuj:auth-flow", "timedOut"))
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(cases[0].status, "failed")

    def test_no_results_folds_to_skipped(self):
        doc = {"suites": [{"title": "e2e", "specs": [{"title": "never ran @cuj:auth-flow", "tests": [{"results": []}]}], "suites": []}]}
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(cases[0].status, "skipped")

    def test_a_real_skipped_status_from_playwright_itself_folds_to_skipped(self):
        # Distinct from test_no_results_folds_to_skipped above: this hits
        # `if final_status in _PLAYWRIGHT_SKIP_STATUSES: return "skipped"`,
        # not the `if not results: return "skipped"` early-return -- a real
        # Playwright run reports an explicitly skipped test this way, with
        # a real (non-empty) results entry.
        doc = _playwright_doc(("skipped test @cuj:auth-flow", "skipped"))
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(cases[0].status, "skipped")

    def test_a_non_dict_spec_is_skipped_but_later_specs_in_the_same_suite_still_process(self):
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": ["not-a-dict", {"title": "login @cuj:auth-flow", "tests": [{"results": [{"status": "passed"}]}]}],
                    "suites": [],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].journeys, ("auth-flow",))

    def test_a_non_dict_test_is_skipped_but_later_tests_in_the_same_spec_still_process(self):
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": [
                        {
                            "title": "login @cuj:auth-flow",
                            "tests": ["not-a-dict", {"results": [{"status": "passed"}]}],
                        }
                    ],
                    "suites": [],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].status, "passed")

    def test_tag_embedded_only_in_the_suite_level_title_is_found(self):
        doc = {
            "suites": [
                {"title": "e2e @cuj:auth-flow", "specs": [{"title": "login", "tests": [{"results": [{"status": "passed"}]}]}], "suites": []}
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow",))

    def test_parent_suite_title_propagates_through_nested_recursion(self):
        # Pins that the *real* accumulated title_prefix (not a dropped/None
        # one) is threaded into the recursive call -- a tag embedded only
        # in the outermost suite's own title must still reach a spec two
        # levels of nesting down.
        doc = {
            "suites": [
                {
                    "title": "@cuj:auth-flow",
                    "specs": [],
                    "suites": [
                        {
                            "title": "auth",
                            "specs": [{"title": "login", "tests": [{"results": [{"status": "passed"}]}]}],
                            "suites": [],
                        }
                    ],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].journeys, ("auth-flow",))

    def test_nested_suites_are_walked(self):
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": [],
                    "suites": [
                        {
                            "title": "auth",
                            "specs": [{"title": "login @cuj:auth-flow", "tests": [{"results": [{"status": "passed"}]}]}],
                            "suites": [],
                        }
                    ],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].journeys, ("auth-flow",))

    def test_untagged_spec_has_no_journeys(self):
        doc = _playwright_doc(("plain smoke test", "passed"))
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(cases[0].journeys, ())

    def test_non_object_root_raises(self):
        path = self._write_json_report("pw.json", [1, 2, 3])
        with self.assertRaisesRegex(ValueError, r"^playwright report root is not a JSON object$"):
            _parse_playwright_report(path)


class ParsePlaywrightNativeTagsTests(TempRepoTestCase):
    """Playwright's native `tag`/`tags` feature (test.tags / { tag: [...] })
    is a real, independent way to associate a journey with a test, distinct
    from the @cuj: title-scan convention -- a modern Playwright config may
    use tags exclusively and never embed a marker in the title at all."""

    def test_spec_level_tags_with_cuj_prefix(self):
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": [
                        {
                            "title": "logs in",
                            "tags": ["@cuj:auth-flow"],
                            "tests": [{"results": [{"status": "passed"}]}],
                        }
                    ],
                    "suites": [],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow",))

    def test_test_level_tags_with_cuj_prefix(self):
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": [
                        {
                            "title": "logs in",
                            "tests": [{"tags": ["@cuj:auth-flow"], "results": [{"status": "passed"}]}],
                        }
                    ],
                    "suites": [],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow",))

    def test_bare_tag_without_cuj_prefix_is_accepted_directly(self):
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": [
                        {
                            "title": "logs in",
                            "tags": ["auth-flow"],
                            "tests": [{"results": [{"status": "passed"}]}],
                        }
                    ],
                    "suites": [],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow",))

    def test_bare_tag_with_leading_at_sign_and_no_cuj_prefix(self):
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": [
                        {
                            "title": "logs in",
                            "tags": ["@auth-flow"],
                            "tests": [{"results": [{"status": "passed"}]}],
                        }
                    ],
                    "suites": [],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow",))

    def test_cuj_prefix_without_leading_at_sign(self):
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": [
                        {
                            "title": "logs in",
                            "tags": ["cuj:auth-flow"],
                            "tests": [{"results": [{"status": "passed"}]}],
                        }
                    ],
                    "suites": [],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow",))

    def test_spec_tags_and_test_tags_are_unioned(self):
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": [
                        {
                            "title": "logs in",
                            "tags": ["@cuj:auth-flow"],
                            "tests": [{"tags": ["@cuj:policy-evaluation"], "results": [{"status": "passed"}]}],
                        }
                    ],
                    "suites": [],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow", "policy-evaluation"))

    def test_title_tag_and_tags_array_are_unioned(self):
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": [
                        {
                            "title": "logs in @cuj:auth-flow",
                            "tags": ["@cuj:policy-evaluation"],
                            "tests": [{"results": [{"status": "passed"}]}],
                        }
                    ],
                    "suites": [],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow", "policy-evaluation"))

    def test_unrelated_tags_produce_no_journey(self):
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": [
                        {
                            "title": "logs in",
                            "tags": ["@smoke", "@slow"],
                            "tests": [{"results": [{"status": "passed"}]}],
                        }
                    ],
                    "suites": [],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        # "smoke"/"slow" are accepted as bare candidate ids (harmless --
        # they only ever matter if they coincidentally equal a real
        # declared journey), but they're clearly not "auth-flow".
        self.assertNotIn("auth-flow", cases[0].journeys)

    def test_non_list_tags_field_is_ignored_not_raised(self):
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": [
                        {"title": "logs in", "tags": "not-a-list", "tests": [{"results": [{"status": "passed"}]}]}
                    ],
                    "suites": [],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        cases = _parse_playwright_report(path)
        self.assertEqual(cases[0].journeys, ())

    def test_full_adequacy_via_end_to_end_evaluate_using_only_tags(self):
        self._write_config({"framework": "playwright", "declared_journeys": ["auth-flow"]})
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": [
                        {
                            "title": "logs in",  # no @cuj: in the title at all
                            "tags": ["@cuj:auth-flow"],
                            "tests": [{"results": [{"status": "passed"}]}],
                        }
                    ],
                    "suites": [],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        report = evaluate_functional_adequacy(self.repo_dir, path)
        self.assertTrue(report.met)
        self.assertEqual(report.covered, ["auth-flow"])


# ---------------------------------------------------------------------------
# JUnit XML ingestion
# ---------------------------------------------------------------------------


class ParseJunitFunctionalReportTests(TempRepoTestCase):
    def test_tag_in_name_is_extracted(self):
        xml = """<testsuite><testcase classname="e2e" name="test_login @cuj:auth-flow"/></testsuite>"""
        path = self._write_report("junit.xml", xml)
        cases = _parse_junit_functional_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow",))
        self.assertEqual(cases[0].status, "passed")

    def test_tag_in_property_value_is_extracted(self):
        xml = """<testsuite><testcase classname="e2e" name="test_login">
            <properties><property name="cuj" value="@cuj:auth-flow"/></properties>
        </testcase></testsuite>"""
        path = self._write_report("junit.xml", xml)
        cases = _parse_junit_functional_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow",))

    def test_tag_in_classname_alone_is_extracted(self):
        # Distinct from test_tag_in_name_is_extracted -- pins that
        # classname is genuinely read on its own, not just name.
        xml = """<testsuite><testcase classname="e2e @cuj:auth-flow" name="test_login"/></testsuite>"""
        path = self._write_report("junit.xml", xml)
        cases = _parse_junit_functional_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow",))

    def test_tag_in_property_name_alone_is_extracted(self):
        # Distinct from test_tag_in_property_value_is_extracted -- pins
        # that a <property>'s own `name` attribute is genuinely read too,
        # not just its `value`.
        xml = """<testsuite><testcase classname="e2e" name="test_login">
            <properties><property name="@cuj:auth-flow" value="irrelevant"/></properties>
        </testcase></testsuite>"""
        path = self._write_report("junit.xml", xml)
        cases = _parse_junit_functional_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow",))

    def test_missing_classname_and_name_attributes_do_not_crash(self):
        xml = """<testsuite><testcase/></testsuite>"""
        path = self._write_report("junit.xml", xml)
        cases = _parse_junit_functional_report(path)
        self.assertEqual(cases[0].journeys, ())
        self.assertEqual(cases[0].status, "passed")

    def test_failure_element_marks_failed(self):
        xml = """<testsuite><testcase classname="e2e" name="test_login @cuj:auth-flow">
            <failure message="boom"/>
        </testcase></testsuite>"""
        path = self._write_report("junit.xml", xml)
        cases = _parse_junit_functional_report(path)
        self.assertEqual(cases[0].status, "failed")

    def test_error_element_marks_failed(self):
        xml = """<testsuite><testcase classname="e2e" name="test_login">
            <error message="boom"/>
        </testcase></testsuite>"""
        path = self._write_report("junit.xml", xml)
        cases = _parse_junit_functional_report(path)
        self.assertEqual(cases[0].status, "failed")

    def test_skipped_element_marks_skipped(self):
        xml = """<testsuite><testcase classname="e2e" name="test_login">
            <skipped/>
        </testcase></testsuite>"""
        path = self._write_report("junit.xml", xml)
        cases = _parse_junit_functional_report(path)
        self.assertEqual(cases[0].status, "skipped")

    def test_multiple_journeys_on_one_case(self):
        xml = """<testsuite><testcase classname="e2e" name="combo @cuj:auth-flow @cuj:policy-evaluation"/></testsuite>"""
        path = self._write_report("junit.xml", xml)
        cases = _parse_junit_functional_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow", "policy-evaluation"))

    def test_malformed_xml_raises(self):
        path = self._write_report("junit.xml", "<testsuite><testcase")
        with self.assertRaises(Exception):
            _parse_junit_functional_report(path)


# ---------------------------------------------------------------------------
# generic_json ingestion
# ---------------------------------------------------------------------------


class ParseGenericJsonReportTests(TempRepoTestCase):
    def test_explicit_journeys_field(self):
        doc = {"tests": [{"name": "login works", "status": "passed", "journeys": ["auth-flow"]}]}
        path = self._write_json_report("report.json", doc)
        cases = _parse_generic_json_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow",))

    def test_explicit_journeys_field_normalizes_cuj_prefixed_entries(self):
        doc = {"tests": [{"name": "login works", "status": "passed", "journeys": ["@cuj:auth-flow"]}]}
        path = self._write_json_report("report.json", doc)
        cases = _parse_generic_json_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow",))
        self.assertEqual(cases[0].status, "passed")

    def test_cuj_tag_in_name_is_also_honored(self):
        doc = {"tests": [{"name": "login works @cuj:auth-flow", "status": "passed"}]}
        path = self._write_json_report("report.json", doc)
        cases = _parse_generic_json_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow",))

    def test_journeys_field_and_tag_are_merged_deduplicated(self):
        doc = {
            "tests": [
                {"name": "login @cuj:auth-flow", "status": "passed", "journeys": ["auth-flow", "policy-evaluation"]}
            ]
        }
        path = self._write_json_report("report.json", doc)
        cases = _parse_generic_json_report(path)
        self.assertEqual(cases[0].journeys, ("auth-flow", "policy-evaluation"))

    def test_unrecognized_status_folds_to_failed(self):
        doc = {"tests": [{"name": "flaky", "status": "quarantined"}]}
        path = self._write_json_report("report.json", doc)
        cases = _parse_generic_json_report(path)
        self.assertEqual(cases[0].status, "failed")

    def test_skip_status_variants(self):
        doc = {"tests": [{"name": "a", "status": "skip"}, {"name": "b", "status": "Skipped"}]}
        path = self._write_json_report("report.json", doc)
        cases = _parse_generic_json_report(path)
        self.assertEqual([c.status for c in cases], ["skipped", "skipped"])

    def test_missing_tests_array_raises(self):
        path = self._write_json_report("report.json", {"not_tests": []})
        with self.assertRaisesRegex(ValueError, r"^generic_json report is missing a 'tests' array$"):
            _parse_generic_json_report(path)

    def test_non_object_root_raises(self):
        path = self._write_json_report("report.json", ["a", "b"])
        with self.assertRaisesRegex(ValueError, r"^generic_json report root is not a JSON object$"):
            _parse_generic_json_report(path)

    def test_non_dict_test_entries_are_skipped_not_raised(self):
        doc = {"tests": ["not-a-dict", {"name": "ok", "status": "passed"}]}
        path = self._write_json_report("report.json", doc)
        cases = _parse_generic_json_report(path)
        self.assertEqual(len(cases), 1)


# ---------------------------------------------------------------------------
# _compute_adequacy
# ---------------------------------------------------------------------------


class ComputeAdequacyTests(unittest.TestCase):
    def test_journey_with_pass_and_no_fail_is_covered(self):
        cases = [_NormalizedCase(status="passed", journeys=("auth-flow",))]
        total, passed, failed, skipped, covered, missing = _compute_adequacy(cases, ["auth-flow"])
        self.assertEqual(covered, ["auth-flow"])
        self.assertEqual(missing, [])

    def test_journey_with_pass_and_fail_is_not_covered(self):
        cases = [
            _NormalizedCase(status="passed", journeys=("auth-flow",)),
            _NormalizedCase(status="failed", journeys=("auth-flow",)),
        ]
        total, passed, failed, skipped, covered, missing = _compute_adequacy(cases, ["auth-flow"])
        self.assertEqual(covered, [])
        self.assertEqual(missing, ["auth-flow"])

    def test_journey_never_executed_is_missing(self):
        cases = [_NormalizedCase(status="passed", journeys=("auth-flow",))]
        total, passed, failed, skipped, covered, missing = _compute_adequacy(cases, ["auth-flow", "policy-evaluation"])
        self.assertEqual(covered, ["auth-flow"])
        self.assertEqual(missing, ["policy-evaluation"])

    def test_declared_order_is_preserved(self):
        cases = [
            _NormalizedCase(status="passed", journeys=("b",)),
            _NormalizedCase(status="passed", journeys=("a",)),
        ]
        _, _, _, _, covered, _ = _compute_adequacy(cases, ["a", "b"])
        self.assertEqual(covered, ["a", "b"])

    def test_totals_are_counted(self):
        cases = [
            _NormalizedCase(status="passed", journeys=()),
            _NormalizedCase(status="failed", journeys=()),
            _NormalizedCase(status="skipped", journeys=()),
        ]
        total, passed, failed, skipped, _, _ = _compute_adequacy(cases, [])
        self.assertEqual((total, passed, failed, skipped), (3, 1, 1, 1))


# ---------------------------------------------------------------------------
# _unavailable_report: every field, exactly (imported/called directly --
# every evaluate_functional_adequacy() failure branch delegates here, so
# one exhaustive test of the helper itself covers every call site's shared
# field-construction logic without needing to independently re-verify each
# of "total/passed/failed/skipped/score_pct/declared/covered/missing" at
# every one of evaluate_functional_adequacy's own four call sites).
# ---------------------------------------------------------------------------


class UnavailableReportDirectFieldTests(unittest.TestCase):
    def test_every_field_is_exact(self):
        report = _unavailable_report(
            framework="playwright",
            target_env="staging",
            declared_journeys=["auth-flow", "attestation-ingest"],
            report_uri="https://ci/example",
            reason="a specific real reason",
            reason_code="report_missing",
        )
        self.assertEqual(
            report.as_dict(),
            {
                "available": False,
                "met": False,
                "framework": "playwright",
                "target_env": "staging",
                "metrics": {"total": 0, "passed": 0, "failed": 0, "skipped": 0},
                "adequacy": {
                    "status": "unavailable",
                    "metric_type": "cuj_coverage",
                    "score_pct": 0.0,
                    "declared": ["auth-flow", "attestation-ingest"],
                    "covered": [],
                    "missing": ["auth-flow", "attestation-ingest"],
                },
                "report_uri": "https://ci/example",
                "reason": "a specific real reason",
                "reason_code": "report_missing",
            },
        )

    def test_framework_and_target_env_can_be_none(self):
        report = _unavailable_report(
            framework=None,
            target_env=None,
            declared_journeys=["auth-flow"],
            report_uri=None,
            reason="x",
            reason_code="unsupported_framework",
        )
        self.assertIsNone(report.framework)
        self.assertIsNone(report.target_env)
        self.assertIsNone(report.report_uri)

    def test_empty_declared_journeys_yields_empty_declared_and_missing(self):
        report = _unavailable_report(
            framework="playwright", target_env=None, declared_journeys=[], report_uri=None, reason="x", reason_code="report_missing"
        )
        self.assertEqual(report.declared, [])
        self.assertEqual(report.missing, [])
        self.assertEqual(report.covered, [])


# ---------------------------------------------------------------------------
# evaluate_functional_adequacy: end-to-end behavior
# ---------------------------------------------------------------------------


class EvaluateFunctionalAdequacyTests(TempRepoTestCase):
    def test_not_configured_reports_honest_opt_out_never_a_silent_pass(self):
        # Fail-closed by design (CLAUDE.md's Fail-Closed Verification
        # invariant): an unconfigured contract must report met=False, not
        # a naive "emerald pass" a downstream console might render at
        # face value -- available/adequacy.status/reason_code are what
        # distinguish "never configured" from "evaluated and failed".
        report = evaluate_functional_adequacy(self.repo_dir, None)
        self.assertEqual(
            report.as_dict(),
            {
                "available": False,
                "met": False,
                "framework": None,
                "target_env": None,
                "metrics": {"total": 0, "passed": 0, "failed": 0, "skipped": 0},
                "adequacy": {
                    "status": "not_configured",
                    "metric_type": "cuj_coverage",
                    "score_pct": 0.0,
                    "declared": [],
                    "covered": [],
                    "missing": [],
                },
                "report_uri": None,
                "reason": (
                    "no declared_journeys configured at .lucid/functional-verification.json -- "
                    "functional test adequacy is not evaluated for this run (reported as unmet, "
                    "not a silent pass, to avoid a false 'evaluated and passed' signal for a "
                    "control that never actually ran)"
                ),
                "reason_code": "not_configured",
            },
        )

    def test_not_configured_carries_report_uri_and_target_env_through_even_though_unconfigured(self):
        report = evaluate_functional_adequacy(self.repo_dir, None, target_env="staging", report_uri="https://ci/1")
        self.assertEqual(report.target_env, "staging")
        self.assertEqual(report.report_uri, "https://ci/1")

    def test_configured_but_no_report_path_is_unavailable(self):
        self._write_config({"framework": "playwright", "declared_journeys": ["auth-flow"]})
        report = evaluate_functional_adequacy(self.repo_dir, None, target_env="staging", report_uri="https://ci/1")
        self.assertEqual(
            report.as_dict(),
            {
                "available": False,
                "met": False,
                "framework": "playwright",
                "target_env": "staging",
                "metrics": {"total": 0, "passed": 0, "failed": 0, "skipped": 0},
                "adequacy": {
                    "status": "unavailable",
                    "metric_type": "cuj_coverage",
                    "score_pct": 0.0,
                    "declared": ["auth-flow"],
                    "covered": [],
                    "missing": ["auth-flow"],
                },
                "report_uri": "https://ci/1",
                "reason": (
                    ".lucid/functional-verification.json declares 1 journey(s), but "
                    "--functional-report was not provided for this run"
                ),
                "reason_code": "report_missing",
            },
        )

    def test_unsupported_framework_is_unavailable(self):
        self._write_config({"framework": "cypress", "declared_journeys": ["auth-flow"]})
        path = self._write_json_report("report.json", {"tests": []})
        report = evaluate_functional_adequacy(self.repo_dir, path, target_env="staging", report_uri="https://ci/1")
        self.assertEqual(report.framework, "cypress")
        self.assertEqual(report.target_env, "staging")
        self.assertEqual(report.report_uri, "https://ci/1")
        self.assertEqual(report.reason_code, REASON_CODE_UNSUPPORTED_FRAMEWORK)
        self.assertEqual(
            report.reason,
            ".lucid/functional-verification.json declares an unsupported framework 'cypress' "
            "(expected one of ['generic_json', 'playwright', 'pytest'])",
        )
        self.assertEqual(report.declared, ["auth-flow"])
        self.assertEqual(report.missing, ["auth-flow"])

    def test_unreadable_report_path_is_malformed(self):
        self._write_config({"framework": "generic_json", "declared_journeys": ["auth-flow"]})
        missing_path = str(Path(self.repo_dir) / "does-not-exist.json")
        report = evaluate_functional_adequacy(self.repo_dir, missing_path, target_env="staging", report_uri="https://ci/1")
        self.assertFalse(report.available)
        self.assertEqual(report.reason_code, REASON_CODE_REPORT_MALFORMED)
        self.assertEqual(report.framework, "generic_json")
        self.assertEqual(report.target_env, "staging")
        self.assertEqual(report.report_uri, "https://ci/1")
        self.assertIn(f"--functional-report {missing_path!r} could not be read as a 'generic_json' report:", report.reason)

    def test_malformed_report_content_is_malformed(self):
        self._write_config({"framework": "generic_json", "declared_journeys": ["auth-flow"]})
        path = self._write_report("report.json", "{not json")
        report = evaluate_functional_adequacy(self.repo_dir, path, target_env="staging", report_uri="https://ci/1")
        self.assertFalse(report.available)
        self.assertEqual(report.reason_code, REASON_CODE_REPORT_MALFORMED)
        self.assertEqual(report.target_env, "staging")
        self.assertEqual(report.report_uri, "https://ci/1")
        self.assertIn(f"--functional-report {path!r} could not be read as a 'generic_json' report:", report.reason)

    def test_full_adequacy_pass_case(self):
        self._write_config(
            {
                "framework": "generic_json",
                "min_adequacy_pct": 100,
                "declared_journeys": ["auth-flow", "attestation-ingest"],
            }
        )
        doc = {
            "tests": [
                {"name": "login", "status": "passed", "journeys": ["auth-flow"]},
                {"name": "ingest", "status": "passed", "journeys": ["attestation-ingest"]},
            ]
        }
        path = self._write_json_report("report.json", doc)
        report = evaluate_functional_adequacy(self.repo_dir, path, target_env="staging", report_uri="https://ci/artifacts/1")
        self.assertEqual(
            report.as_dict(),
            {
                "available": True,
                "met": True,
                "framework": "generic_json",
                "target_env": "staging",
                "metrics": {"total": 2, "passed": 2, "failed": 0, "skipped": 0},
                "adequacy": {
                    "status": "evaluated",
                    "metric_type": "cuj_coverage",
                    "score_pct": 100.0,
                    "declared": ["auth-flow", "attestation-ingest"],
                    "covered": ["auth-flow", "attestation-ingest"],
                    "missing": [],
                },
                "report_uri": "https://ci/artifacts/1",
                "reason": "2/2 declared journey(s) covered (100.0% >= 100.0% required), 0 failed test(s)",
                "reason_code": None,
            },
        )

    def test_score_pct_rounds_to_exactly_two_decimal_places(self):
        # A fraction that actually differs at the 3rd decimal place (1/3 !=
        # 0.33 at 3+ digits) -- pins the literal `2` in `round(..., 2)`,
        # which a coincidentally-round percentage (e.g. 50%/100%) can't.
        self._write_config(
            {"framework": "generic_json", "min_adequacy_pct": 0, "declared_journeys": ["a", "b", "c"]}
        )
        doc = {"tests": [{"name": "t", "status": "passed", "journeys": ["a"]}]}
        path = self._write_json_report("report.json", doc)
        report = evaluate_functional_adequacy(self.repo_dir, path)
        self.assertEqual(report.score_pct, 33.33)

    def test_partial_adequacy_is_amber_not_met(self):
        self._write_config(
            {
                "framework": "generic_json",
                "min_adequacy_pct": 100,
                "declared_journeys": ["auth-flow", "attestation-ingest", "policy-evaluation"],
            }
        )
        doc = {
            "tests": [
                {"name": "login", "status": "passed", "journeys": ["auth-flow"]},
                {"name": "ingest", "status": "passed", "journeys": ["attestation-ingest"]},
            ]
        }
        path = self._write_json_report("report.json", doc)
        report = evaluate_functional_adequacy(self.repo_dir, path)
        self.assertTrue(report.available)
        self.assertFalse(report.met)
        self.assertEqual(report.reason_code, REASON_CODE_PARTIAL_ADEQUACY)
        self.assertEqual(report.score_pct, 66.67)
        self.assertEqual(report.missing, ["policy-evaluation"])
        self.assertEqual(
            report.reason,
            "only 2/3 declared journey(s) covered (66.7% < 100.0% required); missing: ['policy-evaluation']",
        )

    def test_partial_adequacy_passes_when_below_min_threshold(self):
        self._write_config(
            {
                "framework": "generic_json",
                "min_adequacy_pct": 50,
                "declared_journeys": ["auth-flow", "attestation-ingest"],
            }
        )
        doc = {"tests": [{"name": "login", "status": "passed", "journeys": ["auth-flow"]}]}
        path = self._write_json_report("report.json", doc)
        report = evaluate_functional_adequacy(self.repo_dir, path)
        self.assertTrue(report.met)
        self.assertEqual(report.score_pct, 50.0)

    def test_failed_test_blocks_met_regardless_of_full_journey_coverage(self):
        self._write_config(
            {
                "framework": "generic_json",
                "min_adequacy_pct": 100,
                "declared_journeys": ["auth-flow"],
            }
        )
        doc = {
            "tests": [
                {"name": "login", "status": "passed", "journeys": ["auth-flow"]},
                {"name": "unrelated flaky check", "status": "failed", "journeys": []},
            ]
        }
        path = self._write_json_report("report.json", doc)
        report = evaluate_functional_adequacy(self.repo_dir, path)
        self.assertFalse(report.met)
        self.assertEqual(report.score_pct, 100.0)
        self.assertEqual(report.reason_code, REASON_CODE_TEST_FAILURES)
        self.assertEqual(
            report.reason,
            "1 executed test(s) failed -- functional adequacy cannot be met regardless of 100.0% journey coverage",
        )

    def test_zero_tests_executed_is_not_met(self):
        self._write_config({"framework": "generic_json", "declared_journeys": ["auth-flow"]})
        path = self._write_json_report("report.json", {"tests": []})
        report = evaluate_functional_adequacy(self.repo_dir, path)
        self.assertTrue(report.available)
        self.assertFalse(report.met)
        self.assertEqual(report.reason_code, REASON_CODE_NO_TESTS_EXECUTED)
        self.assertEqual(report.total, 0)
        self.assertEqual(report.reason, f"'generic_json' report at {path!r} parsed but contained zero executed tests")

    def test_met_requires_total_strictly_greater_than_zero_even_with_a_zero_threshold(self):
        # Pins `total > 0` (not `total >= 0`, which is always true): with
        # min_adequacy_pct=0 and zero declared_journeys ever executed,
        # score_pct is 0.0 (0 covered / N declared) which already clears a
        # 0 threshold, and failed==0 too -- only the total>0 guard stops
        # this from being incorrectly reported as met.
        self._write_config({"framework": "generic_json", "min_adequacy_pct": 0, "declared_journeys": ["auth-flow"]})
        path = self._write_json_report("report.json", {"tests": []})
        report = evaluate_functional_adequacy(self.repo_dir, path)
        self.assertEqual(report.total, 0)
        self.assertEqual(report.score_pct, 0.0)
        self.assertFalse(report.met)
        self.assertEqual(report.reason_code, REASON_CODE_NO_TESTS_EXECUTED)

    def test_playwright_framework_end_to_end(self):
        self._write_config({"framework": "playwright", "declared_journeys": ["auth-flow"]})
        doc = {
            "suites": [
                {
                    "title": "e2e",
                    "specs": [{"title": "login @cuj:auth-flow", "tests": [{"results": [{"status": "passed"}]}]}],
                    "suites": [],
                }
            ]
        }
        path = self._write_json_report("pw.json", doc)
        report = evaluate_functional_adequacy(self.repo_dir, path)
        self.assertTrue(report.met)
        self.assertEqual(report.framework, "playwright")

    def test_pytest_junit_framework_end_to_end(self):
        self._write_config({"framework": "pytest", "declared_journeys": ["auth-flow"]})
        xml = """<testsuite><testcase classname="e2e" name="test_login @cuj:auth-flow"/></testsuite>"""
        path = self._write_report("junit.xml", xml)
        report = evaluate_functional_adequacy(self.repo_dir, path)
        self.assertTrue(report.met)
        self.assertEqual(report.framework, "pytest")


if __name__ == "__main__":
    unittest.main()
