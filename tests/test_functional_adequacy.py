import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.parsers.functional_adequacy import (
    MAX_REPORTED_TESTS,
    _CONFIG_PATH,
    _TEST_MESSAGE_MAX_LEN,
    _TEST_NAME_MAX_LEN,
    _clean_duration,
    _clean_test_text,
    _junit_case_message,
    _test_rows,
    _JOURNEY_DESCRIPTION_MAX_LEN,
    _JOURNEY_NAME_MAX_LEN,
    _load_contract,
    _normalize_report_paths,
    _parse_reports,
    _ReportFailure,
    _optional_text,
    _tier_fields,
    JourneyDeclaration,
    REASON_CODE_CONFIG_INVALID,
    REASON_CODE_EXECUTION_ABORTED,
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


# ---------------------------------------------------------------------------
# Tiers (contract v2), multi-report aggregation, execution_aborted
# ---------------------------------------------------------------------------


def _junit_xml(cases):
    """cases: [(name, status, [journey ids])] -> a pytest-style JUnit document
    whose tagged tests carry @cuj:<id> properties (what tests/conftest.py-style
    plumbing emits)."""
    out = ['<testsuites><testsuite name="s">']
    for name, status, tags in cases:
        props = "".join(f'<property name="cuj" value="@cuj:{t}"/>' for t in tags)
        inner = f"<properties>{props}</properties>" if props else ""
        if status == "failed":
            inner += '<failure message="boom"/>'
        elif status == "skipped":
            inner += "<skipped/>"
        out.append(f'<testcase classname="t" name="{name}">{inner}</testcase>')
    out.append("</testsuite></testsuites>")
    return "".join(out)


_MIXED_CONTRACT = {
    "framework": "pytest",
    "journeys": [
        {"id": "a", "tier": "ci", "name": "Alpha", "description": "the a journey"},
        {"id": "b", "tier": "cd"},
        {"id": "c", "tier": "both", "name": "Cee"},
    ],
}


class ContractV2LoadingTests(TempRepoTestCase):
    def test_v2_journeys_load_with_every_field_and_are_marked_tiered(self):
        self._write_config({**_MIXED_CONTRACT, "min_adequacy_pct": 80})
        config, invalid = _load_contract(self.repo_dir)
        self.assertIsNone(invalid)
        self.assertIs(config.tiered, True)
        self.assertEqual(config.framework, "pytest")
        self.assertEqual(config.min_adequacy_pct, 80.0)
        self.assertEqual(
            config.journeys,
            [
                JourneyDeclaration(id="a", tier="ci", name="Alpha", description="the a journey"),
                JourneyDeclaration(id="b", tier="cd", name=None, description=None),
                JourneyDeclaration(id="c", tier="both", name="Cee", description=None),
            ],
        )
        self.assertEqual(config.declared_journeys, ["a", "b", "c"])

    def test_legacy_flat_list_reads_as_all_ci_and_is_not_tiered(self):
        self._write_config({"framework": "pytest", "declared_journeys": ["x", " y "]})
        config, invalid = _load_contract(self.repo_dir)
        self.assertIsNone(invalid)
        self.assertIs(config.tiered, False)
        self.assertEqual(config.journeys, [JourneyDeclaration(id="x", tier="ci"), JourneyDeclaration(id="y", tier="ci")])

    def test_journeys_wins_when_both_forms_are_present(self):
        self._write_config({"framework": "pytest", "declared_journeys": ["legacy"], "journeys": [{"id": "new", "tier": "cd"}]})
        config, _ = _load_contract(self.repo_dir)
        self.assertEqual(config.declared_journeys, ["new"])
        self.assertTrue(config.tiered)

    def test_an_empty_journeys_array_is_not_configured_not_invalid(self):
        self._write_config({"framework": "pytest", "journeys": []})
        self.assertEqual(_load_contract(self.repo_dir), (None, None))

    def test_a_present_but_empty_journeys_does_not_fall_back_to_the_legacy_list(self):
        self._write_config({"framework": "pytest", "journeys": [], "declared_journeys": ["legacy"]})
        self.assertEqual(_load_contract(self.repo_dir), (None, None))

    def test_invalid_declarations_are_reported_with_the_specific_reason_never_repaired(self):
        cases = {
            "not a list": ({"journeys": "a"}, "`journeys` must be a JSON array of journey objects"),
            "object not list": ({"journeys": {"id": "a", "tier": "ci"}}, "`journeys` must be a JSON array of journey objects"),
            "item not object": ({"journeys": ["a"]}, "journeys[0] must be an object with an id and a tier"),
            "missing id": ({"journeys": [{"tier": "ci"}]}, "journeys[0].id must be a non-empty string of letters, digits, '_' or '-'"),
            "blank id": ({"journeys": [{"id": "  ", "tier": "ci"}]}, "journeys[0].id must be a non-empty string of letters, digits, '_' or '-'"),
            "non-string id": ({"journeys": [{"id": 7, "tier": "ci"}]}, "journeys[0].id must be a non-empty string of letters, digits, '_' or '-'"),
            "bad chars": ({"journeys": [{"id": "has space", "tier": "ci"}]}, "journeys[0].id must be a non-empty string of letters, digits, '_' or '-'"),
            "bad chars 2": ({"journeys": [{"id": "a.b", "tier": "ci"}]}, "journeys[0].id must be a non-empty string of letters, digits, '_' or '-'"),
            "duplicate": ({"journeys": [{"id": "a", "tier": "ci"}, {"id": "a", "tier": "cd"}]}, "journeys[1].id 'a' is declared more than once"),
            "missing tier": ({"journeys": [{"id": "a"}]}, "journeys[0].tier must be one of ['ci', 'cd', 'both'], got None"),
            "unknown tier": ({"journeys": [{"id": "a", "tier": "staging"}]}, "journeys[0].tier must be one of ['ci', 'cd', 'both'], got 'staging'"),
            "tier wrong case": ({"journeys": [{"id": "a", "tier": "CI"}]}, "journeys[0].tier must be one of ['ci', 'cd', 'both'], got 'CI'"),
            "tier wrong type": ({"journeys": [{"id": "a", "tier": 1}]}, "journeys[0].tier must be one of ['ci', 'cd', 'both'], got 1"),
            "second entry bad": ({"journeys": [{"id": "a", "tier": "ci"}, {"id": "b", "tier": "x"}]}, "journeys[1].tier must be one of ['ci', 'cd', 'both'], got 'x'"),
        }
        for label, (doc, expected) in cases.items():
            with self.subTest(label=label):
                self._write_config({"framework": "pytest", **doc})
                self.assertEqual(_load_contract(self.repo_dir), (None, expected))

    def test_an_invalid_journey_is_never_dropped_to_leave_the_valid_ones(self):
        self._write_config({"framework": "pytest", "journeys": [{"id": "good", "tier": "ci"}, {"id": "bad", "tier": "nope"}]})
        config, invalid = _load_contract(self.repo_dir)
        self.assertIsNone(config)
        self.assertIsNotNone(invalid)

    def test_the_legacy_loader_returns_none_for_an_invalid_v2_contract(self):
        self._write_config({"framework": "pytest", "journeys": [{"id": "a", "tier": "nope"}]})
        self.assertIsNone(load_functional_verification_config(self.repo_dir))

    def test_the_legacy_loader_still_returns_the_config_for_a_valid_contract(self):
        self._write_config(_MIXED_CONTRACT)
        self.assertEqual(load_functional_verification_config(self.repo_dir).declared_journeys, ["a", "b", "c"])

    def test_missing_unreadable_malformed_and_non_object_files_are_not_configured_not_invalid(self):
        self.assertEqual(_load_contract(self.repo_dir), (None, None))
        lucid = Path(self.repo_dir) / ".lucid"
        lucid.mkdir()
        (lucid / "functional-verification.json").write_text("{not json", encoding="utf-8")
        self.assertEqual(_load_contract(self.repo_dir), (None, None))
        (lucid / "functional-verification.json").write_text("[1, 2]", encoding="utf-8")
        self.assertEqual(_load_contract(self.repo_dir), (None, None))

    def test_name_and_description_are_stripped_and_capped_but_never_invalidate_the_contract(self):
        self._write_config({"framework": "pytest", "journeys": [
            {"id": "a", "tier": "ci", "name": "  " + "n" * 200 + "  ", "description": "d" * 900},
            {"id": "b", "tier": "ci", "name": 5, "description": ["x"]},
            {"id": "c", "tier": "ci", "name": "   ", "description": ""},
        ]})
        config, invalid = _load_contract(self.repo_dir)
        self.assertIsNone(invalid)
        self.assertEqual(config.journeys[0].name, "n" * _JOURNEY_NAME_MAX_LEN)
        self.assertEqual(config.journeys[0].description, "d" * _JOURNEY_DESCRIPTION_MAX_LEN)
        self.assertEqual((config.journeys[1].name, config.journeys[1].description), (None, None))
        self.assertEqual((config.journeys[2].name, config.journeys[2].description), (None, None))

    def test_optional_text_boundaries(self):
        self.assertEqual(_JOURNEY_NAME_MAX_LEN, 120)
        self.assertEqual(_JOURNEY_DESCRIPTION_MAX_LEN, 500)
        self.assertEqual(_optional_text("abc", 3), "abc")
        self.assertEqual(_optional_text("abcd", 3), "abc")
        self.assertEqual(_optional_text("  ab ", 10), "ab")
        self.assertIsNone(_optional_text("", 3))
        self.assertIsNone(_optional_text(None, 3))
        self.assertIsNone(_optional_text(1, 3))

    def test_min_adequacy_pct_defaults_and_ignores_bools_in_the_v2_form_too(self):
        for raw, expected in ((None, 100.0), (True, 100.0), ("80", 100.0), (60, 60.0), (72.5, 72.5)):
            with self.subTest(raw=raw):
                doc = {"framework": "pytest", "journeys": [{"id": "a", "tier": "ci"}]}
                if raw is not None:
                    doc["min_adequacy_pct"] = raw
                self._write_config(doc)
                self.assertEqual(_load_contract(self.repo_dir)[0].min_adequacy_pct, expected)


class TierEvaluationTests(TempRepoTestCase):
    def test_ci_tier_scores_ci_and_both_and_defers_cd(self):
        self._write_config(_MIXED_CONTRACT)
        report = self._write_report("r.xml", _junit_xml([("t1", "passed", ["a"]), ("t2", "passed", ["c"]), ("t3", "passed", ["b"])]))
        result = evaluate_functional_adequacy(self.repo_dir, report, target_env="ci", tier="ci")
        self.assertEqual(
            result.as_dict(),
            {
                "available": True,
                "met": True,
                "framework": "pytest",
                "target_env": "ci",
                "metrics": {"total": 3, "passed": 3, "failed": 0, "skipped": 0},
                "adequacy": {
                    "status": "evaluated",
                    "metric_type": "cuj_coverage",
                    "score_pct": 100.0,
                    "declared": ["a", "c"],
                    "covered": ["a", "c"],
                    "missing": [],
                    "tier": "ci",
                    "deferred": ["b"],
                    "journeys": [
                        {"id": "a", "tier": "ci", "status": "covered", "name": "Alpha", "description": "the a journey"},
                        {"id": "b", "tier": "cd", "status": "deferred"},
                        {"id": "c", "tier": "both", "status": "covered", "name": "Cee"},
                    ],
                },
                "report_uri": None,
                "reason": "2/2 declared journey(s) covered (100.0% >= 100.0% required), 0 failed test(s)",
                "reason_code": None,
                "tests": [
                    {"name": "t1", "classname": "t", "status": "passed", "journeys": ["a"]},
                    {"name": "t2", "classname": "t", "status": "passed", "journeys": ["c"]},
                    {"name": "t3", "classname": "t", "status": "passed", "journeys": ["b"]},
                ],
                "tests_truncated": False,
            },
        )

    def test_cd_tier_scores_cd_and_both_and_defers_ci(self):
        self._write_config(_MIXED_CONTRACT)
        report = self._write_report("r.xml", _junit_xml([("t1", "passed", ["b"]), ("t2", "passed", ["a"])]))
        result = evaluate_functional_adequacy(self.repo_dir, report, tier="cd")
        adequacy = result.as_dict()["adequacy"]
        self.assertEqual((adequacy["declared"], adequacy["covered"], adequacy["missing"]), (["b", "c"], ["b"], ["c"]))
        self.assertEqual(adequacy["score_pct"], 50.0)
        self.assertEqual((adequacy["tier"], adequacy["deferred"]), ("cd", ["a"]))
        self.assertEqual([(j["id"], j["status"]) for j in adequacy["journeys"]], [("a", "deferred"), ("b", "covered"), ("c", "missing")])
        self.assertFalse(result.met)
        self.assertEqual(result.reason_code, REASON_CODE_PARTIAL_ADEQUACY)
        self.assertEqual(result.reason, "only 1/2 declared journey(s) covered (50.0% < 100.0% required); missing: ['c']")

    def test_a_both_journey_must_be_proven_at_each_tier_separately(self):
        self._write_config({"framework": "pytest", "journeys": [{"id": "x", "tier": "both"}]})
        good = self._write_report("good.xml", _junit_xml([("t", "passed", ["x"])]))
        empty = self._write_report("empty.xml", _junit_xml([("t", "passed", [])]))
        self.assertTrue(evaluate_functional_adequacy(self.repo_dir, good, tier="ci").met)
        self.assertTrue(evaluate_functional_adequacy(self.repo_dir, good, tier="cd").met)
        self.assertFalse(evaluate_functional_adequacy(self.repo_dir, empty, tier="ci").met)
        self.assertFalse(evaluate_functional_adequacy(self.repo_dir, empty, tier="cd").met)

    def test_a_legacy_contract_at_ci_emits_none_of_the_new_fields(self):
        self._write_config({"framework": "pytest", "declared_journeys": ["a", "b"]})
        report = self._write_report("r.xml", _junit_xml([("t1", "passed", ["a"]), ("t2", "passed", ["b"])]))
        adequacy = evaluate_functional_adequacy(self.repo_dir, report).as_dict()["adequacy"]
        self.assertEqual(set(adequacy), {"status", "metric_type", "score_pct", "declared", "covered", "missing"})

    def test_a_legacy_contract_at_cd_is_not_configured_for_that_tier_never_100_percent_of_zero(self):
        self._write_config({"framework": "pytest", "declared_journeys": ["a", "b"]})
        report = self._write_report("r.xml", _junit_xml([("t1", "passed", ["a"])]))
        result = evaluate_functional_adequacy(self.repo_dir, report, tier="cd")
        d = result.as_dict()
        self.assertFalse(result.available)
        self.assertFalse(result.met)
        self.assertEqual(d["adequacy"]["status"], "not_configured")
        self.assertEqual(result.reason_code, REASON_CODE_NOT_CONFIGURED)
        self.assertEqual(d["adequacy"]["declared"], [])
        self.assertEqual(d["adequacy"]["score_pct"], 0.0)
        self.assertEqual(d["adequacy"]["tier"], "cd")
        self.assertEqual(d["adequacy"]["deferred"], ["a", "b"])
        self.assertEqual([j["status"] for j in d["adequacy"]["journeys"]], ["deferred", "deferred"])
        self.assertEqual(
            result.reason,
            f"{_CONFIG_PATH} declares no journeys for tier 'cd' -- functional test adequacy is not evaluated at this tier (reported as unmet, not a silent pass)",
        )
        self.assertEqual(d["framework"], "pytest")

    def test_a_v2_contract_with_no_journeys_for_the_tier_is_not_configured_for_it(self):
        self._write_config({"framework": "pytest", "journeys": [{"id": "only-cd", "tier": "cd"}]})
        result = evaluate_functional_adequacy(self.repo_dir, None, tier="ci")
        self.assertEqual(result.adequacy_status, ADEQUACY_STATUS_NOT_CONFIGURED)
        self.assertEqual(result.deferred, ["only-cd"])

    def test_min_adequacy_pct_applies_to_the_tiers_own_denominator(self):
        self._write_config({"framework": "pytest", "min_adequacy_pct": 50, "journeys": [
            {"id": "a", "tier": "ci"}, {"id": "b", "tier": "ci"}, {"id": "z", "tier": "cd"}]})
        report = self._write_report("r.xml", _junit_xml([("t", "passed", ["a"])]))
        result = evaluate_functional_adequacy(self.repo_dir, report, tier="ci")
        self.assertEqual(result.score_pct, 50.0)
        self.assertTrue(result.met)
        self.assertEqual(result.reason, "1/2 declared journey(s) covered (50.0% >= 50.0% required), 0 failed test(s)")

    def test_a_failing_test_blocks_met_even_at_full_coverage(self):
        self._write_config({"framework": "pytest", "journeys": [{"id": "a", "tier": "ci"}]})
        report = self._write_report("r.xml", _junit_xml([("t1", "passed", ["a"]), ("t2", "failed", [])]))
        result = evaluate_functional_adequacy(self.repo_dir, report, tier="ci")
        self.assertFalse(result.met)
        self.assertEqual(result.reason_code, REASON_CODE_TEST_FAILURES)

    def test_an_unknown_tier_is_a_caller_bug_and_raises(self):
        for bad in ("both", "staging", "", None, "CI"):
            with self.subTest(bad=bad), self.assertRaises(ValueError) as ctx:
                evaluate_functional_adequacy(self.repo_dir, None, tier=bad)
            self.assertEqual(str(ctx.exception), f"tier must be one of ['ci', 'cd'], got {bad!r}")

    def test_an_invalid_contract_is_config_invalid_amber_never_not_configured(self):
        self._write_config({"framework": "pytest", "journeys": [{"id": "a", "tier": "staging"}]})
        result = evaluate_functional_adequacy(self.repo_dir, None, target_env="ci", report_uri="https://x")
        self.assertEqual(
            result.as_dict(),
            {
                "available": False,
                "met": False,
                "framework": None,
                "target_env": "ci",
                "metrics": {"total": 0, "passed": 0, "failed": 0, "skipped": 0},
                "adequacy": {
                    "status": "unavailable",
                    "metric_type": "cuj_coverage",
                    "score_pct": 0.0,
                    "declared": [],
                    "covered": [],
                    "missing": [],
                },
                "report_uri": "https://x",
                "reason": f"{_CONFIG_PATH} is invalid and was not evaluated: journeys[0].tier must be one of ['ci', 'cd', 'both'], got 'staging'",
                "reason_code": "config_invalid",
            },
        )

    def test_an_invalid_contract_reports_config_invalid_at_either_tier(self):
        self._write_config({"framework": "pytest", "journeys": [{"id": "a"}]})
        for tier in ("ci", "cd"):
            with self.subTest(tier=tier):
                self.assertEqual(evaluate_functional_adequacy(self.repo_dir, None, tier=tier).reason_code, REASON_CODE_CONFIG_INVALID)

    def test_report_missing_and_unsupported_framework_carry_the_tier_fields_for_a_v2_contract(self):
        self._write_config({"framework": "pytest", "journeys": [{"id": "a", "tier": "ci"}, {"id": "b", "tier": "cd"}]})
        no_report = evaluate_functional_adequacy(self.repo_dir, None, tier="ci")
        self.assertEqual(no_report.reason_code, REASON_CODE_REPORT_MISSING)
        self.assertEqual((no_report.tier, no_report.deferred), ("ci", ["b"]))
        self.assertEqual(no_report.declared, ["a"])
        self._write_config({"framework": "cypress", "journeys": [{"id": "a", "tier": "ci"}]})
        unsupported = evaluate_functional_adequacy(self.repo_dir, "x.xml", tier="ci")
        self.assertEqual(unsupported.reason_code, REASON_CODE_UNSUPPORTED_FRAMEWORK)
        self.assertEqual(unsupported.tier, "ci")


class TierFieldsDirectTests(unittest.TestCase):
    def _config(self, journeys, tiered=True):
        return FunctionalVerificationConfig(framework="pytest", min_adequacy_pct=100.0, journeys=journeys, tiered=tiered)

    def test_legacy_config_at_ci_yields_no_fields(self):
        self.assertEqual(_tier_fields(self._config([JourneyDeclaration("a", "ci")], tiered=False), "ci", []), {})

    def test_legacy_config_at_cd_still_yields_fields(self):
        fields = _tier_fields(self._config([JourneyDeclaration("a", "ci")], tiered=False), "cd", [])
        self.assertEqual(fields["tier"], "cd")

    def test_name_and_description_are_only_present_when_declared(self):
        fields = _tier_fields(self._config([JourneyDeclaration("a", "ci"), JourneyDeclaration("b", "cd", "B", "desc")]), "ci", ["a"])
        self.assertEqual(fields["journeys"][0], {"id": "a", "tier": "ci", "status": "covered"})
        self.assertEqual(fields["journeys"][1], {"id": "b", "tier": "cd", "status": "deferred", "name": "B", "description": "desc"})

    def test_a_declared_but_uncovered_in_tier_journey_is_missing_not_deferred(self):
        fields = _tier_fields(self._config([JourneyDeclaration("a", "both")]), "cd", [])
        self.assertEqual(fields["journeys"][0]["status"], "missing")
        self.assertEqual(fields["deferred"], [])


class _MultiReportFixture(TempRepoTestCase):
    """Shared setup: a cd-tier contract with journeys a/b, two good reports, and
    files that don't exist / can't be parsed. Holds no tests itself."""

    def setUp(self):
        super().setUp()
        self._write_config({"framework": "pytest", "journeys": [{"id": "a", "tier": "cd"}, {"id": "b", "tier": "cd"}]})
        self.good_a = self._write_report("a.xml", _junit_xml([("t1", "passed", ["a"])]))
        self.good_b = self._write_report("b.xml", _junit_xml([("t2", "passed", ["b"])]))
        self.missing = os.path.join(self.repo_dir, "never-written.xml")
        self.missing2 = os.path.join(self.repo_dir, "never-written-2.xml")
        self.bad_xml = self._write_report("bad.xml", "<not-closed")


class MultiReportAndExecutionAbortedTests(_MultiReportFixture):
    def test_normalize_report_paths_shapes(self):
        self.assertEqual(_normalize_report_paths(None), [])
        self.assertEqual(_normalize_report_paths(""), [])
        self.assertEqual(_normalize_report_paths([]), [])
        self.assertEqual(_normalize_report_paths("a.xml"), ["a.xml"])
        self.assertEqual(_normalize_report_paths(["a.xml", "", "b.xml"]), ["a.xml", "b.xml"])
        self.assertEqual(_normalize_report_paths(Path("a.xml")), ["a.xml"])
        self.assertEqual(_normalize_report_paths(("a.xml", "b.xml")), ["a.xml", "b.xml"])

    def test_several_reports_are_aggregated_into_one_evaluation(self):
        result = evaluate_functional_adequacy(self.repo_dir, [self.good_a, self.good_b], tier="cd")
        self.assertTrue(result.met)
        self.assertEqual((result.total, result.passed), (2, 2))
        self.assertEqual(result.covered, ["a", "b"])

    def test_a_single_string_path_still_works_exactly_as_a_one_element_list(self):
        one = evaluate_functional_adequacy(self.repo_dir, self.good_a, tier="cd")
        listed = evaluate_functional_adequacy(self.repo_dir, [self.good_a], tier="cd")
        self.assertEqual(one.as_dict(), listed.as_dict())

    def test_cd_with_no_report_at_all_is_report_missing_not_aborted(self):
        result = evaluate_functional_adequacy(self.repo_dir, [], tier="cd")
        self.assertEqual(result.reason_code, REASON_CODE_REPORT_MISSING)

    def test_cd_with_every_report_file_missing_is_execution_aborted(self):
        result = evaluate_functional_adequacy(self.repo_dir, [self.missing, self.missing2], target_env="staging", tier="cd")
        self.assertFalse(result.available)
        self.assertFalse(result.met)
        self.assertEqual(result.adequacy_status, ADEQUACY_STATUS_UNAVAILABLE)
        self.assertEqual(result.reason_code, REASON_CODE_EXECUTION_ABORTED)
        self.assertEqual(
            result.reason,
            f"execution aborted: none of the 2 --functional-report file(s) exist ({self.missing!r}, {self.missing2!r}) "
            "-- the suite did not run far enough to write a report",
        )
        self.assertEqual(result.missing, ["a", "b"])
        self.assertEqual(result.covered, [])
        self.assertEqual(result.target_env, "staging")

    def test_cd_with_some_files_missing_evaluates_the_rest_but_can_never_be_met(self):
        result = evaluate_functional_adequacy(self.repo_dir, [self.good_a, self.missing, self.good_b], tier="cd")
        self.assertIs(result.available, True)
        self.assertIs(result.met, False)
        self.assertEqual(result.adequacy_status, ADEQUACY_STATUS_EVALUATED)
        self.assertEqual(result.reason_code, REASON_CODE_EXECUTION_ABORTED)
        self.assertEqual(result.covered, ["a", "b"])
        self.assertEqual(result.score_pct, 100.0)
        self.assertTrue(result.reason.startswith("execution aborted: 1 of 3 --functional-report file(s) could not be read ("))
        self.assertIn(repr(self.missing), result.reason)
        self.assertTrue(result.reason.endswith("coverage reflects only the readable report(s): 2/2 declared journey(s) covered, 0 failed test(s)"))

    def test_the_readable_partial_run_reports_real_missing_journeys(self):
        result = evaluate_functional_adequacy(self.repo_dir, [self.good_a, self.missing], tier="cd")
        self.assertEqual((result.covered, result.missing, result.score_pct), (["a"], ["b"], 50.0))
        self.assertEqual(result.reason_code, REASON_CODE_EXECUTION_ABORTED)

    def test_cd_with_a_malformed_file_is_report_malformed_not_aborted(self):
        result = evaluate_functional_adequacy(self.repo_dir, [self.good_a, self.bad_xml], tier="cd")
        self.assertEqual(result.reason_code, REASON_CODE_REPORT_MALFORMED)
        self.assertIs(result.met, False)
        self.assertFalse(result.reason.startswith("execution aborted"))

    def test_cd_where_every_file_is_malformed_is_report_malformed(self):
        result = evaluate_functional_adequacy(self.repo_dir, [self.bad_xml, self.bad_xml], tier="cd")
        self.assertEqual(result.reason_code, REASON_CODE_REPORT_MALFORMED)
        self.assertFalse(result.available)
        self.assertTrue(result.reason.startswith(f"none of the 2 --functional-report files could be read as a 'pytest' report: {self.bad_xml!r}: "))

    def test_cd_with_a_missing_and_a_malformed_file_is_report_malformed_because_not_all_are_missing(self):
        result = evaluate_functional_adequacy(self.repo_dir, [self.missing, self.bad_xml], tier="cd")
        self.assertEqual(result.reason_code, REASON_CODE_REPORT_MALFORMED)

    def test_cd_missing_plus_malformed_plus_good_is_still_aborted_because_a_file_is_missing(self):
        result = evaluate_functional_adequacy(self.repo_dir, [self.good_a, self.missing, self.bad_xml], tier="cd")
        self.assertEqual(result.reason_code, REASON_CODE_EXECUTION_ABORTED)

    def test_ci_with_a_missing_report_keeps_the_pre_tier_report_malformed_behavior(self):
        self._write_config({"framework": "pytest", "declared_journeys": ["a"]})
        result = evaluate_functional_adequacy(self.repo_dir, self.missing)
        self.assertEqual(result.reason_code, REASON_CODE_REPORT_MALFORMED)
        self.assertTrue(result.reason.startswith(f"--functional-report {self.missing!r} could not be read as a 'pytest' report: "))

    def test_ci_partial_failure_is_report_malformed_never_execution_aborted(self):
        self._write_config({"framework": "pytest", "journeys": [{"id": "a", "tier": "ci"}]})
        result = evaluate_functional_adequacy(self.repo_dir, [self.good_a, self.missing], tier="ci")
        self.assertEqual(result.reason_code, REASON_CODE_REPORT_MALFORMED)
        self.assertIs(result.met, False)
        self.assertFalse(result.reason.startswith("execution aborted"))

    def test_test_failures_in_a_readable_report_still_surface_alongside_an_abort(self):
        failing = self._write_report("f.xml", _junit_xml([("t", "failed", ["a"])]))
        result = evaluate_functional_adequacy(self.repo_dir, [failing, self.missing], tier="cd")
        self.assertEqual(result.reason_code, REASON_CODE_EXECUTION_ABORTED)
        self.assertEqual(result.failed, 1)
        self.assertIn("1 failed test(s)", result.reason)

    def test_zero_executed_tests_message_names_the_first_report(self):
        empty = self._write_report("empty.xml", "<testsuites></testsuites>")
        result = evaluate_functional_adequacy(self.repo_dir, [empty], tier="cd")
        self.assertEqual(result.reason_code, REASON_CODE_NO_TESTS_EXECUTED)
        self.assertEqual(result.reason, f"'pytest' report at {empty!r} parsed but contained zero executed tests")


class ReportFailureDetailTests(_MultiReportFixture):
    """Direct-field pins for the failure records and the exact joined reason
    strings -- the parts an aggregate assertion like startswith() lets drift."""

    def _expected_message(self, path):
        try:
            _parse_junit_functional_report(path)
        except Exception as e:  # noqa: BLE001 -- reproducing exactly what _parse_reports catches
            return str(e)
        raise AssertionError("expected the parse to fail")

    def test_parse_reports_records_a_missing_file_exactly(self):
        cases, failures = _parse_reports(_parse_junit_functional_report, [self.missing])
        self.assertEqual(cases, [])
        self.assertEqual(failures, [_ReportFailure(path=self.missing, missing=True, message=self._expected_message(self.missing))])
        self.assertIn("No such file", failures[0].message)

    def test_parse_reports_records_a_malformed_file_exactly(self):
        _, failures = _parse_reports(_parse_junit_functional_report, [self.bad_xml])
        self.assertEqual(len(failures), 1)
        self.assertIs(failures[0].missing, False)
        self.assertEqual(failures[0].path, self.bad_xml)
        self.assertEqual(failures[0].message, self._expected_message(self.bad_xml))
        self.assertNotEqual(failures[0].message, "None")

    def test_parse_reports_keeps_good_cases_and_only_the_failures(self):
        cases, failures = _parse_reports(_parse_junit_functional_report, [self.good_a, self.missing, self.good_b])
        self.assertEqual(len(cases), 2)
        self.assertEqual([f.path for f in failures], [self.missing])

    def test_all_malformed_reason_joins_each_failure_with_a_semicolon_and_space(self):
        second_bad = self._write_report("bad2.xml", "<also-not-closed")
        result = evaluate_functional_adequacy(self.repo_dir, [self.bad_xml, second_bad], tier="cd")
        self.assertEqual(
            result.reason,
            "none of the 2 --functional-report files could be read as a 'pytest' report: "
            f"{self.bad_xml!r}: {self._expected_message(self.bad_xml)}; "
            f"{second_bad!r}: {self._expected_message(second_bad)}",
        )

    def test_partial_failure_reason_lists_every_unreadable_file_joined_by_semicolon_space(self):
        result = evaluate_functional_adequacy(self.repo_dir, [self.good_a, self.missing, self.missing2], tier="cd")
        self.assertIn(
            f"({self.missing!r}: {self._expected_message(self.missing)}; {self.missing2!r}: {self._expected_message(self.missing2)})",
            result.reason,
        )
        self.assertTrue(result.reason.startswith("execution aborted: 2 of 3 --functional-report file(s) could not be read ("))

    def test_a_partial_failure_is_forced_unmet_even_at_full_coverage(self):
        result = evaluate_functional_adequacy(self.repo_dir, [self.good_a, self.good_b, self.missing], tier="cd")
        self.assertEqual(result.score_pct, 100.0)
        self.assertIs(result.met, False)

    def test_an_all_failed_result_still_carries_the_tier_fields_for_a_v2_contract(self):
        result = evaluate_functional_adequacy(self.repo_dir, [self.missing, self.missing2], tier="cd")
        self.assertEqual(result.tier, "cd")
        self.assertEqual(result.deferred, [])
        self.assertEqual(
            result.journeys,
            [{"id": "a", "tier": "cd", "status": "missing"}, {"id": "b", "tier": "cd", "status": "missing"}],
        )
        self.assertEqual(result.as_dict()["adequacy"]["tier"], "cd")


class PassThroughFieldTests(TempRepoTestCase):
    def test_no_contract_passes_target_env_and_report_uri_through(self):
        result = evaluate_functional_adequacy(self.repo_dir, None, target_env="staging", report_uri="https://ci/1")
        self.assertEqual((result.target_env, result.report_uri), ("staging", "https://ci/1"))

    def test_no_journeys_for_the_tier_passes_target_env_and_report_uri_through(self):
        self._write_config({"framework": "pytest", "journeys": [{"id": "x", "tier": "cd"}]})
        result = evaluate_functional_adequacy(self.repo_dir, None, target_env="staging", report_uri="https://ci/1", tier="ci")
        self.assertEqual((result.target_env, result.report_uri, result.framework), ("staging", "https://ci/1", "pytest"))

    def test_no_journeys_for_the_tier_carries_the_tier_fields(self):
        self._write_config({"framework": "pytest", "journeys": [{"id": "x", "tier": "cd"}]})
        result = evaluate_functional_adequacy(self.repo_dir, None, tier="ci")
        self.assertEqual(result.tier, "ci")
        self.assertEqual(result.journeys, [{"id": "x", "tier": "cd", "status": "deferred"}])


class CleanTestTextTests(unittest.TestCase):
    def test_non_strings_and_blank_values_are_none(self):
        for value in (None, 5, b"x", ["a"], "", "   ", "\n\t "):
            with self.subTest(value=value):
                self.assertIsNone(_clean_test_text(value, 50))

    def test_whitespace_and_newlines_collapse_to_single_spaces(self):
        self.assertEqual(_clean_test_text("  assert 1 ==\n\t2   here ", 50), "assert 1 == 2 here")

    def test_control_characters_become_spaces_not_part_of_the_text(self):
        self.assertEqual(_clean_test_text("a\x00b\x1bc\x7fd\x9fe", 50), "a b c d e")

    def test_a_value_at_the_limit_is_kept_whole(self):
        self.assertEqual(_clean_test_text("x" * 10, 10), "x" * 10)

    def test_an_over_long_value_is_cut_to_exactly_the_limit_and_marked(self):
        out = _clean_test_text("x" * 11, 10)
        self.assertEqual(out, "x" * 7 + "...")
        self.assertEqual(len(out), 10)

    def test_the_cut_does_not_leave_trailing_space_before_the_mark(self):
        self.assertEqual(_clean_test_text("abcdef gh ijkl", 10), "abcdef...")


class CleanDurationTests(unittest.TestCase):
    def test_valid_values_round_to_milliseconds(self):
        self.assertEqual(_clean_duration("0.123456"), 0.123)
        self.assertEqual(_clean_duration(2), 2.0)
        self.assertEqual(_clean_duration("0"), 0.0)

    def test_invalid_values_are_none(self):
        for value in (None, "", "abc", "-0.1", "nan", "inf", "-inf", [1]):
            with self.subTest(value=value):
                self.assertIsNone(_clean_duration(value))


class TestRowsTests(unittest.TestCase):
    def _case(self, name, status, **kw):
        return _NormalizedCase(status=status, journeys=kw.pop("journeys", ()), name=name, **kw)

    def test_a_row_carries_every_field_present_and_omits_the_absent_ones(self):
        rows, truncated = _test_rows([
            self._case("t", "failed", classname="mod.Cls", duration_s=1.25, message="boom", journeys=("a", "b")),
            self._case("bare", "passed"),
        ])
        self.assertFalse(truncated)
        self.assertEqual(rows, [
            {"name": "t", "classname": "mod.Cls", "status": "failed", "duration_s": 1.25, "message": "boom",
             "journeys": ["a", "b"]},
            {"name": "bare", "status": "passed", "journeys": []},
        ])

    def test_failed_come_first_then_skipped_then_passed_preserving_report_order(self):
        rows, _ = _test_rows([
            self._case("p1", "passed"), self._case("s1", "skipped"), self._case("f1", "failed"),
            self._case("p2", "passed"), self._case("f2", "failed"),
        ])
        self.assertEqual([r["name"] for r in rows], ["f1", "f2", "s1", "p1", "p2"])

    def test_an_empty_or_unnameable_test_gets_a_placeholder_name(self):
        rows, _ = _test_rows([self._case("", "passed"), self._case("\x00\n", "passed")])
        self.assertEqual([r["name"] for r in rows], ["(unnamed test)", "(unnamed test)"])

    def test_long_names_and_messages_are_bounded(self):
        rows, _ = _test_rows([self._case("n" * 999, "failed", message="m" * 999, classname="c" * 999)])
        self.assertEqual(len(rows[0]["name"]), _TEST_NAME_MAX_LEN)
        self.assertEqual(len(rows[0]["message"]), _TEST_MESSAGE_MAX_LEN)
        self.assertEqual(len(rows[0]["classname"]), 200)

    def test_the_list_is_capped_and_only_ever_drops_passing_tests(self):
        cases = [self._case(f"p{i}", "passed") for i in range(MAX_REPORTED_TESTS)]
        cases.append(self._case("late-failure", "failed"))
        rows, truncated = _test_rows(cases)
        self.assertTrue(truncated)
        self.assertEqual(len(rows), MAX_REPORTED_TESTS)
        self.assertEqual(rows[0]["name"], "late-failure")
        self.assertNotIn(f"p{MAX_REPORTED_TESTS - 1}", [r["name"] for r in rows])

    def test_exactly_at_the_cap_is_not_truncated(self):
        rows, truncated = _test_rows([self._case(f"p{i}", "passed") for i in range(MAX_REPORTED_TESTS)])
        self.assertEqual(len(rows), MAX_REPORTED_TESTS)
        self.assertFalse(truncated)


class JunitCaseMessageTests(unittest.TestCase):
    def _elem(self, inner):
        import xml.etree.ElementTree as ET
        return ET.fromstring(f"<testcase>{inner}</testcase>")

    def test_the_message_attribute_wins_then_type_then_none(self):
        self.assertEqual(_junit_case_message(self._elem('<failure message="m" type="T">body</failure>')), "m")
        self.assertEqual(_junit_case_message(self._elem('<error type="ValueError"/>')), "ValueError")
        self.assertEqual(_junit_case_message(self._elem("<skipped/>")), None)
        self.assertEqual(_junit_case_message(self._elem("")), None)

    def test_failure_is_preferred_over_error_over_skipped(self):
        self.assertEqual(_junit_case_message(self._elem('<skipped message="s"/><error message="e"/><failure message="f"/>')), "f")
        self.assertEqual(_junit_case_message(self._elem('<skipped message="s"/><error message="e"/>')), "e")

    def test_element_text_is_never_used(self):
        self.assertIsNone(_junit_case_message(self._elem("<failure>Traceback: SECRET_TOKEN=abc</failure>")))


class PerTestResultsEvaluationTests(TempRepoTestCase):
    def _evaluate(self, xml, tier="ci", contract=None):
        self._write_config(contract or _MIXED_CONTRACT)
        return evaluate_functional_adequacy(self.repo_dir, self._write_report("r.xml", xml), tier=tier).as_dict()

    def test_rows_carry_name_class_status_duration_message_and_journeys_from_junit(self):
        xml = (
            '<testsuites><testsuite>'
            '<testcase classname="tests.test_a" name="test_ok" time="0.0125"><properties>'
            '<property name="cuj" value="@cuj:a"/></properties></testcase>'
            '<testcase classname="tests.test_a" name="test_bad" time="2"><failure message="assert 1 == 2"/></testcase>'
            '<testcase classname="tests.test_b" name="test_skip"><skipped message="needs a db"/></testcase>'
            '</testsuite></testsuites>'
        )
        out = self._evaluate(xml)
        self.assertEqual(out["tests"], [
            {"name": "test_bad", "classname": "tests.test_a", "status": "failed", "duration_s": 2.0,
             "message": "assert 1 == 2", "journeys": []},
            {"name": "test_skip", "classname": "tests.test_b", "status": "skipped", "message": "needs a db",
             "journeys": []},
            {"name": "test_ok", "classname": "tests.test_a", "status": "passed", "duration_s": 0.013,
             "journeys": ["a"]},
        ])
        self.assertIs(out["tests_truncated"], False)
        self.assertEqual(out["metrics"], {"total": 3, "passed": 1, "failed": 1, "skipped": 1})

    def test_tracebacks_and_captured_output_never_reach_the_predicate(self):
        xml = (
            '<testsuites><testsuite><testcase classname="c" name="t">'
            '<failure message="assert False">Traceback (most recent call last): TOKEN=hunter2</failure>'
            '<system-out>API_KEY=abc123</system-out><system-err>PASSWORD=xyz</system-err>'
            '</testcase></testsuite></testsuites>'
        )
        blob = json.dumps(self._evaluate(xml))
        for secret in ("hunter2", "abc123", "xyz", "Traceback"):
            self.assertNotIn(secret, blob)
        self.assertIn("assert False", blob)

    def test_the_cd_tier_carries_rows_too(self):
        out = self._evaluate(_junit_xml([("live1", "passed", ["b"])]), tier="cd")
        self.assertEqual([r["name"] for r in out["tests"]], ["live1"])

    def test_a_legacy_flat_contract_at_the_default_tier_stays_byte_identical(self):
        out = self._evaluate(
            _junit_xml([("t", "passed", ["a"])]),
            contract={"framework": "pytest", "declared_journeys": ["a"]},
        )
        self.assertNotIn("tests", out)
        self.assertNotIn("tests_truncated", out)
        self.assertNotIn("tier", out["adequacy"])

    def test_a_legacy_contract_evaluated_at_cd_is_not_a_result_with_rows(self):
        out = self._evaluate(
            _junit_xml([("t", "passed", ["a"])]),
            contract={"framework": "pytest", "declared_journeys": ["a"]},
            tier="cd",
        )
        self.assertNotIn("tests", out)

    def test_an_unavailable_result_has_no_rows(self):
        self._write_config(_MIXED_CONTRACT)
        out = evaluate_functional_adequacy(self.repo_dir, str(Path(self.repo_dir) / "missing.xml"), tier="ci").as_dict()
        self.assertNotIn("tests", out)

    def test_an_aborted_cd_run_still_reports_the_tests_that_did_run(self):
        self._write_config(_MIXED_CONTRACT)
        good = self._write_report("g.xml", _junit_xml([("ran", "passed", ["b"])]))
        missing = str(Path(self.repo_dir) / "never-written.xml")
        out = evaluate_functional_adequacy(self.repo_dir, [good, missing], tier="cd").as_dict()
        self.assertEqual(out["reason_code"], REASON_CODE_EXECUTION_ABORTED)
        self.assertFalse(out["met"])
        self.assertEqual([r["name"] for r in out["tests"]], ["ran"])

    def test_generic_json_and_playwright_supply_names(self):
        generic = _parse_generic_json_report(
            self._write_json_report("g.json", {"tests": [{"name": "gen", "status": "failed", "message": "why"}]})
        )
        self.assertEqual((generic[0].name, generic[0].message), ("gen", "why"))
        pw = _parse_playwright_report(
            self._write_json_report("p.json", _playwright_doc(("a spec", "passed")))
        )
        self.assertEqual(pw[0].name, "e2e a spec")


class FunctionalVerificationSchemaTests(unittest.TestCase):
    def setUp(self):
        try:
            import jsonschema  # noqa: F401
        except ImportError:  # pragma: no cover
            self.skipTest("jsonschema not installed")
        schema_path = Path(__file__).resolve().parent.parent / "schema" / "lucid-attestation-v1.schema.json"
        self.schema = json.loads(schema_path.read_text(encoding="utf-8"))["properties"]["functional_verification"]

    def _validate(self, doc):
        import jsonschema
        jsonschema.validate(doc, self.schema)

    def test_a_legacy_shaped_result_still_validates(self):
        self._validate(_unavailable_report(
            framework="pytest", target_env=None, declared_journeys=["a"], report_uri=None,
            reason="x", reason_code="report_missing").as_dict())

    def test_a_v2_result_with_tier_deferred_and_journeys_validates(self):
        with tempfile.TemporaryDirectory() as d:
            lucid = Path(d) / ".lucid"
            lucid.mkdir()
            (lucid / "functional-verification.json").write_text(json.dumps(_MIXED_CONTRACT), encoding="utf-8")
            report = Path(d) / "r.xml"
            report.write_text(_junit_xml([("t", "passed", ["a"])]), encoding="utf-8")
            self._validate(evaluate_functional_adequacy(d, str(report), tier="ci").as_dict())
            self._validate(evaluate_functional_adequacy(d, str(report), tier="cd").as_dict())

    def test_a_result_carrying_per_test_rows_validates_and_a_malformed_row_does_not(self):
        import jsonschema
        with tempfile.TemporaryDirectory() as d:
            lucid = Path(d) / ".lucid"
            lucid.mkdir()
            (lucid / "functional-verification.json").write_text(json.dumps(_MIXED_CONTRACT), encoding="utf-8")
            report = Path(d) / "r.xml"
            report.write_text(
                '<testsuites><testsuite><testcase classname="c" name="n" time="0.5">'
                '<failure message="boom"/></testcase></testsuite></testsuites>',
                encoding="utf-8",
            )
            doc = evaluate_functional_adequacy(d, str(report), tier="ci").as_dict()
        self.assertEqual(doc["tests"][0]["duration_s"], 0.5)
        self._validate(doc)
        for bad in (
            {"name": "n", "status": "bogus", "journeys": []},        # unknown status
            {"name": "n", "status": "passed"},                        # journeys required
            {"name": "n", "status": "passed", "journeys": [], "x": 1},  # no extra properties
            {"name": "n" * (_TEST_NAME_MAX_LEN + 1), "status": "passed", "journeys": []},
            {"name": "n", "status": "passed", "journeys": [], "message": "m" * (_TEST_MESSAGE_MAX_LEN + 1)},
        ):
            with self.subTest(bad=bad):
                broken = dict(doc, tests=[bad])
                with self.assertRaises(jsonschema.ValidationError):
                    self._validate(broken)

    def test_the_new_reason_codes_validate(self):
        for code in ("config_invalid", "execution_aborted"):
            with self.subTest(code=code):
                self._validate(_unavailable_report(
                    framework=None, target_env=None, declared_journeys=[], report_uri=None,
                    reason="x", reason_code=code).as_dict())

    def test_an_unknown_journey_status_or_tier_is_rejected(self):
        import jsonschema
        doc = _unavailable_report(framework="pytest", target_env=None, declared_journeys=["a"], report_uri=None,
                                  reason="x", reason_code="report_missing").as_dict()
        doc["adequacy"].update({"tier": "ci", "deferred": [], "journeys": [{"id": "a", "tier": "ci", "status": "bogus"}]})
        with self.assertRaises(jsonschema.ValidationError):
            self._validate(doc)
        doc["adequacy"].update({"tier": "staging", "journeys": []})
        with self.assertRaises(jsonschema.ValidationError):
            self._validate(doc)

