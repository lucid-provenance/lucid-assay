import json
import os
import sys
import unittest

from jsonschema import Draft202012Validator

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.builder import DEFAULT_PREDICATE_TYPE, build_statement

_SCHEMA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "schema", "lucid-attestation-v1.schema.json"
)
from cli.parsers.coverage import CoverageReport
from cli.parsers.github_rules import BranchGovernanceReport
from cli.parsers.junit import TestTotals
from cli.patch_coverage import PatchCoverageResult, REASON_CODE_NO_COVERABLE_LINES
from cli.real_coverage import CoverageTrackResult, RealCoverageResult
from cli.parsers.sarif import SarifSummaryReport
from cli.scorer import score_pipeline


def _default_branch_governance() -> BranchGovernanceReport:
    return BranchGovernanceReport(
        available=True,
        branch="main",
        pull_request_required=True,
        approvals_required=2,
        direct_push_prevented=True,
        bypass_actors_count=0,
        admin_enforced=True,
        warnings=[],
        reason="queried GitHub rules for example/app@main: 1 applicable rule(s), 0 bypass actor(s)",
    )


def _base_kwargs(**overrides):
    test_totals = overrides.pop(
        "test_totals",
        TestTotals(tests=100, passed=100, failed=0, errored=0, skipped=0, duration_ms=1000, flaky_retries=0),
    )
    patch_coverage = overrides.pop(
        "patch_coverage",
        PatchCoverageResult(available=True, line_rate=0.95, lines_changed=40, lines_covered=38, reason="ok"),
    )
    coverage = overrides.pop(
        "coverage",
        CoverageReport(overall_line_rate=0.85, overall_branch_rate=0.75, files={}),
    )
    patch_coverage_min = overrides.pop("patch_coverage_min", 0.80)
    overall_coverage_min = overrides.pop("overall_coverage_min", 0.60)
    total_assertions = overrides.pop("total_assertions", 200)
    total_test_functions = overrides.pop("total_test_functions", 100)
    pr_number = overrides.pop("pr_number", None)
    pr_approvers = overrides.pop("pr_approvers", [])
    pr_required_approvals = overrides.pop("pr_required_approvals", 0)
    pr_review_state = overrides.pop("pr_review_state", "not_applicable")
    branch_governance = overrides.pop("branch_governance", _default_branch_governance())

    rcs = overrides.pop(
        "rcs",
        score_pipeline(
            test_totals=test_totals,
            patch_coverage=patch_coverage,
            overall_line_rate=coverage.overall_line_rate,
            total_assertions=total_assertions,
            total_test_functions=total_test_functions,
            pr_present=pr_number is not None,
            approvers_count=len(pr_approvers),
            required_approvals=pr_required_approvals,
            review_state=pr_review_state,
            patch_coverage_min=patch_coverage_min,
            overall_coverage_min=overall_coverage_min,
            branch_governance=branch_governance,
        ),
    )

    kwargs = dict(
        subject_name="ghcr.io/example/app",
        subject_sha256="a" * 64,
        vcs_provider="github",
        repository="example/app",
        branch="main",
        commit_sha="b" * 40,
        base_commit_sha="c" * 40,
        pr_number=pr_number,
        pr_target_branch=None,
        pr_approvers=pr_approvers,
        pr_required_approvals=pr_required_approvals,
        pr_review_state=pr_review_state,
        branch_governance=branch_governance,
        test_framework="junit",
        test_report_sha256="d" * 64,
        test_report_uri="worm://evidence/d" * 1,
        test_totals=test_totals,
        coverage_format="cobertura-xml",
        coverage_report_sha256="e" * 64,
        coverage_report_uri="worm://evidence/e",
        coverage=coverage,
        patch_coverage=patch_coverage,
        patch_coverage_min=patch_coverage_min,
        overall_coverage_min=overall_coverage_min,
        total_assertions=total_assertions,
        total_test_functions=total_test_functions,
        empty_test_bodies=0,
        assertion_only_true=0,
        rcs=rcs,
    )
    kwargs.update(overrides)
    return kwargs


class BuilderStatementTests(unittest.TestCase):

    def test_predicate_type_matches_lucid_v1(self):
        statement = build_statement(**_base_kwargs())
        self.assertEqual(statement["predicateType"], "https://lucidprovenance.io/attestations/assay/v1")

    def test_predicate_type_uses_default_predicate_type_constant(self):
        statement = build_statement(**_base_kwargs())
        self.assertEqual(statement["predicateType"], DEFAULT_PREDICATE_TYPE)
        self.assertEqual(DEFAULT_PREDICATE_TYPE, "https://lucidprovenance.io/attestations/assay/v1")

    def test_statement_type_is_in_toto_v1(self):
        statement = build_statement(**_base_kwargs())
        self.assertEqual(statement["_type"], "https://in-toto.io/Statement/v1")

    def test_subject_sha256_is_normalized_lowercase_no_prefix(self):
        statement = build_statement(**_base_kwargs(subject_sha256="SHA256:" + "A" * 64))
        self.assertEqual(statement["subject"][0]["digest"]["sha256"], "a" * 64)
        self.assertEqual(
            statement["predicate"]["artifact"]["subject"]["digest"]["sha256"], "a" * 64
        )

    def test_test_report_sha256_is_normalized(self):
        statement = build_statement(**_base_kwargs(test_report_sha256="SHA256:" + "D" * 64))
        self.assertEqual(
            statement["predicate"]["test_verification"]["report_sha256"], "d" * 64
        )

    def test_commit_shas_are_lowercased(self):
        statement = build_statement(
            **_base_kwargs(commit_sha="B" * 40, base_commit_sha="C" * 40)
        )
        self.assertEqual(statement["predicate"]["vcs"]["commit_sha"], "b" * 40)
        self.assertEqual(statement["predicate"]["vcs"]["base_commit_sha"], "c" * 40)

    def test_base_commit_sha_none_is_preserved(self):
        statement = build_statement(**_base_kwargs(base_commit_sha=None))
        self.assertIsNone(statement["predicate"]["vcs"]["base_commit_sha"])

    def test_no_pr_number_yields_null_pull_request(self):
        statement = build_statement(**_base_kwargs(pr_number=None))
        self.assertIsNone(statement["predicate"]["vcs"]["pull_request"])

    def test_pr_number_present_populates_pull_request_block(self):
        statement = build_statement(
            **_base_kwargs(
                pr_number=42,
                pr_target_branch="release",
                pr_approvers=["bob", "alice"],
                pr_required_approvals=2,
                pr_review_state="approved",
            )
        )
        pull_request = statement["predicate"]["vcs"]["pull_request"]
        self.assertEqual(pull_request["number"], 42)
        self.assertEqual(pull_request["target_branch"], "release")
        self.assertEqual(pull_request["required_approvals"], 2)
        self.assertEqual(pull_request["review_state"], "approved")

    def test_pr_approvers_are_sorted_and_deduplicated(self):
        statement = build_statement(
            **_base_kwargs(pr_number=1, pr_approvers=["bob", "alice", "bob"])
        )
        pull_request = statement["predicate"]["vcs"]["pull_request"]
        self.assertEqual(pull_request["approvers"], ["alice", "bob"])

    def test_pr_target_branch_falls_back_to_branch(self):
        statement = build_statement(
            **_base_kwargs(pr_number=1, branch="main", pr_target_branch=None)
        )
        pull_request = statement["predicate"]["vcs"]["pull_request"]
        self.assertEqual(pull_request["target_branch"], "main")

    def test_density_ratio_is_none_when_no_test_functions(self):
        statement = build_statement(
            **_base_kwargs(total_assertions=0, total_test_functions=0)
        )
        self.assertIsNone(statement["predicate"]["assertion_density"]["density_ratio"])

    def test_density_ratio_is_computed_and_rounded(self):
        statement = build_statement(
            **_base_kwargs(total_assertions=150, total_test_functions=100)
        )
        self.assertEqual(
            statement["predicate"]["assertion_density"]["density_ratio"], 1.5
        )

    def test_valid_test_ratio_is_none_when_no_test_functions(self):
        statement = build_statement(
            **_base_kwargs(total_assertions=0, total_test_functions=0, valid_test_functions=0)
        )
        self.assertIsNone(statement["predicate"]["assertion_density"]["valid_test_ratio"])
        self.assertEqual(statement["predicate"]["assertion_density"]["valid_test_functions"], 0)

    def test_valid_test_ratio_is_computed_and_rounded(self):
        statement = build_statement(
            **_base_kwargs(total_assertions=200, total_test_functions=156, valid_test_functions=142)
        )
        assertion_density = statement["predicate"]["assertion_density"]
        self.assertEqual(assertion_density["valid_test_functions"], 142)
        self.assertEqual(assertion_density["valid_test_ratio"], round(142 / 156, 3))

    def test_valid_test_functions_defaults_to_zero_when_not_passed(self):
        # _base_kwargs() never sets valid_test_functions -- confirms the
        # parameter's own default keeps every pre-existing build_statement()
        # caller/test in this file working unchanged.
        statement = build_statement(**_base_kwargs(total_test_functions=100))
        assertion_density = statement["predicate"]["assertion_density"]
        self.assertEqual(assertion_density["valid_test_functions"], 0)
        self.assertEqual(assertion_density["valid_test_ratio"], 0.0)

    def test_skipped_ratio_avoids_zero_division_when_no_tests(self):
        statement = build_statement(
            **_base_kwargs(
                test_totals=TestTotals(tests=0, passed=0, failed=0, errored=0, skipped=0, duration_ms=0)
            )
        )
        heuristics = statement["predicate"]["assertion_density"]["heuristics"]
        self.assertEqual(heuristics["skipped_or_disabled_ratio"], 0.0)

    def test_skipped_ratio_reflects_skip_count(self):
        statement = build_statement(
            **_base_kwargs(
                test_totals=TestTotals(tests=10, passed=8, failed=0, errored=0, skipped=2, duration_ms=100)
            )
        )
        heuristics = statement["predicate"]["assertion_density"]["heuristics"]
        self.assertEqual(heuristics["skipped_or_disabled_ratio"], 0.2)

    def test_patch_met_true_when_line_rate_meets_threshold(self):
        statement = build_statement(
            **_base_kwargs(
                patch_coverage=PatchCoverageResult(
                    available=True, line_rate=0.90, lines_changed=40, lines_covered=36, reason="ok"
                ),
                patch_coverage_min=0.80,
            )
        )
        self.assertTrue(statement["predicate"]["coverage"]["thresholds"]["patch_met"])

    def test_patch_met_false_when_unavailable(self):
        statement = build_statement(
            **_base_kwargs(
                patch_coverage=PatchCoverageResult(
                    available=False, line_rate=None, lines_changed=0, lines_covered=0, reason="no base sha"
                ),
            )
        )
        self.assertFalse(statement["predicate"]["coverage"]["thresholds"]["patch_met"])

    def test_patch_coverage_reason_and_reason_code_are_embedded(self):
        statement = build_statement(
            **_base_kwargs(
                patch_coverage=PatchCoverageResult(
                    available=False, line_rate=None, lines_changed=0, lines_covered=0,
                    reason="diff contained no coverable changed lines (docs/config-only change)",
                    reason_code=REASON_CODE_NO_COVERABLE_LINES,
                ),
            )
        )
        patch_block = statement["predicate"]["coverage"]["patch"]
        self.assertIn("docs/config-only change", patch_block["reason"])
        self.assertEqual(patch_block["reason_code"], "no_coverable_lines")

    def test_patch_coverage_reason_code_defaults_to_none(self):
        statement = build_statement(**_base_kwargs())
        patch_block = statement["predicate"]["coverage"]["patch"]
        self.assertIn("reason_code", patch_block)
        self.assertIsNone(patch_block["reason_code"])

    def test_overall_met_reflects_threshold_comparison(self):
        statement = build_statement(
            **_base_kwargs(
                coverage=CoverageReport(overall_line_rate=0.50, overall_branch_rate=None, files={}),
                overall_coverage_min=0.60,
            )
        )
        self.assertFalse(statement["predicate"]["coverage"]["thresholds"]["overall_met"])

    def test_test_verification_totals_match_input(self):
        totals = TestTotals(tests=12, passed=10, failed=1, errored=1, skipped=0, duration_ms=555, flaky_retries=2)
        statement = build_statement(**_base_kwargs(test_totals=totals))
        recorded = statement["predicate"]["test_verification"]["totals"]
        self.assertEqual(recorded["tests"], 12)
        self.assertEqual(recorded["passed"], 10)
        self.assertEqual(recorded["failed"], 1)
        self.assertEqual(recorded["errored"], 1)
        self.assertEqual(recorded["skipped"], 0)
        self.assertEqual(statement["predicate"]["test_verification"]["flaky_retries"], 2)
        self.assertEqual(statement["predicate"]["test_verification"]["duration_ms"], 555)

    def test_test_verification_met_true_only_when_everything_ran_and_passed(self):
        totals = TestTotals(tests=12, passed=12, failed=0, errored=0, skipped=0, duration_ms=555)
        statement = build_statement(**_base_kwargs(test_totals=totals))
        self.assertTrue(statement["predicate"]["test_verification"]["met"])

    def test_test_verification_met_false_on_any_failure(self):
        totals = TestTotals(tests=12, passed=11, failed=1, errored=0, skipped=0, duration_ms=555)
        statement = build_statement(**_base_kwargs(test_totals=totals))
        self.assertFalse(statement["predicate"]["test_verification"]["met"])

    def test_test_verification_met_false_on_any_error(self):
        totals = TestTotals(tests=12, passed=11, failed=0, errored=1, skipped=0, duration_ms=555)
        statement = build_statement(**_base_kwargs(test_totals=totals))
        self.assertFalse(statement["predicate"]["test_verification"]["met"])

    def test_test_verification_met_false_on_any_skip_even_with_otherwise_perfect_pass_rate(self):
        # A skipped test is still a "no-no" -- a 100% pass rate on only
        # the tests that actually ran must not read as a clean gate.
        totals = TestTotals(tests=12, passed=11, failed=0, errored=0, skipped=1, duration_ms=555)
        statement = build_statement(**_base_kwargs(test_totals=totals))
        self.assertFalse(statement["predicate"]["test_verification"]["met"])

    def test_test_verification_met_false_when_zero_tests_executed(self):
        totals = TestTotals(tests=0, passed=0, failed=0, errored=0, skipped=0, duration_ms=0)
        statement = build_statement(**_base_kwargs(test_totals=totals))
        self.assertFalse(statement["predicate"]["test_verification"]["met"])

    def test_assertion_density_met_true_when_density_clears_the_real_target(self):
        # default fixture: 200 assertions / 100 test functions = 2.0, above 1.5.
        statement = build_statement(**_base_kwargs())
        density = statement["predicate"]["assertion_density"]
        self.assertEqual(density["target"], 1.5)
        self.assertTrue(density["met"])

    def test_assertion_density_met_false_when_density_falls_short_of_the_real_target(self):
        statement = build_statement(**_base_kwargs(total_assertions=50, total_test_functions=100))
        self.assertFalse(statement["predicate"]["assertion_density"]["met"])

    def test_assertion_density_met_false_never_fabricated_true_when_there_are_no_test_functions(self):
        statement = build_statement(**_base_kwargs(total_assertions=0, total_test_functions=0))
        density = statement["predicate"]["assertion_density"]
        self.assertIsNone(density["density_ratio"])
        self.assertFalse(density["met"])

    def test_static_analysis_configured_false_and_unavailable_when_no_sarif_was_given_at_all(self):
        statement = build_statement(**_base_kwargs())
        static_analysis = statement["predicate"]["static_analysis"]
        self.assertFalse(static_analysis["configured"])
        self.assertFalse(static_analysis["available"])
        self.assertEqual(static_analysis["reasons"], ["no --sarif reports configured for this run"])

    def test_static_analysis_configured_true_and_available_true_on_a_real_clean_scan(self):
        sarif_report = SarifSummaryReport(available=True, total_findings=0, tools_scanned=["semgrep"])
        statement = build_statement(**_base_kwargs(sarif_report=sarif_report))
        static_analysis = statement["predicate"]["static_analysis"]
        self.assertTrue(static_analysis["configured"])
        self.assertTrue(static_analysis["available"])

    def test_static_analysis_configured_true_but_unavailable_when_the_report_was_broken(self):
        sarif_report = SarifSummaryReport(available=False, reasons=["SARIF file not found: x.json"])
        statement = build_statement(**_base_kwargs(sarif_report=sarif_report))
        static_analysis = statement["predicate"]["static_analysis"]
        self.assertTrue(static_analysis["configured"])
        self.assertFalse(static_analysis["available"])
        self.assertEqual(static_analysis["reasons"], ["SARIF file not found: x.json"])

    def test_sbom_defaults_to_none(self):
        statement = build_statement(**_base_kwargs())
        self.assertIsNone(statement["predicate"]["artifact"]["sbom"])

    def test_sbom_is_passed_through_when_provided(self):
        sbom = {"bomFormat": "CycloneDX", "components": []}
        statement = build_statement(**_base_kwargs(sbom=sbom))
        self.assertEqual(statement["predicate"]["artifact"]["sbom"], sbom)

    def test_real_coverage_defaults_to_unavailable_when_not_passed(self):
        statement = build_statement(**_base_kwargs())
        real = statement["predicate"]["coverage"]["real"]

        self.assertFalse(real["overall"]["available"])
        self.assertFalse(real["patch"]["available"])
        self.assertIn("--coverage-contexts", real["overall"]["reason"])

    def test_real_coverage_is_embedded_when_provided(self):
        real_coverage = RealCoverageResult(
            overall=CoverageTrackResult(
                available=True,
                measured_line_rate=0.90,
                real_line_rate=0.85,
                total_lines=200,
                measured_covered_lines=180,
                vanity_only_lines=10,
            ),
            patch=CoverageTrackResult(available=False, reason="no patch-modified-lines data available"),
        )
        statement = build_statement(**_base_kwargs(real_coverage=real_coverage))
        real = statement["predicate"]["coverage"]["real"]

        self.assertTrue(real["overall"]["available"])
        self.assertEqual(real["overall"]["real_line_rate"], 0.85)
        self.assertEqual(real["overall"]["vanity_only_lines"], 10)
        self.assertFalse(real["patch"]["available"])

    def test_real_coverage_validates_against_schema(self):
        real_coverage = RealCoverageResult(
            overall=CoverageTrackResult(
                available=True, measured_line_rate=1.0, real_line_rate=0.75,
                total_lines=4, measured_covered_lines=4, vanity_only_lines=1,
            ),
            patch=CoverageTrackResult(
                available=True, measured_line_rate=1.0, real_line_rate=1.0,
                total_lines=2, measured_covered_lines=2, vanity_only_lines=0,
            ),
        )
        statement = build_statement(**_base_kwargs(real_coverage=real_coverage))

        with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema = json.load(f)
        errors = list(Draft202012Validator(schema).iter_errors(statement["predicate"]))
        self.assertEqual(errors, [], msg=[e.message for e in errors])

    def test_resolved_dependencies_defaults_to_empty_list(self):
        statement = build_statement(**_base_kwargs())
        self.assertEqual(statement["predicate"]["resolved_dependencies"], [])

    def test_resolved_dependencies_none_also_defaults_to_empty_list(self):
        # detect_and_parse_dependencies() never returns None (it fails
        # closed to [] itself), but build_statement's own default must be
        # equally defensive if ever called with resolved_dependencies=None
        # explicitly, rather than embedding a null into the predicate.
        statement = build_statement(**_base_kwargs(resolved_dependencies=None))
        self.assertEqual(statement["predicate"]["resolved_dependencies"], [])

    def test_resolved_dependencies_is_passed_through_when_provided(self):
        deps = [
            {"uri": "pkg:pypi/requests@2.31.0", "digest": {"sha256": "f" * 64}},
            {"uri": "pkg:npm/lodash@4.17.21", "digest": {}},
        ]
        statement = build_statement(**_base_kwargs(resolved_dependencies=deps))
        self.assertEqual(statement["predicate"]["resolved_dependencies"], deps)

    def test_resolved_dependencies_validates_against_schema(self):
        deps = [
            {"uri": "pkg:pypi/requests@2.31.0", "digest": {"sha256": "f" * 64}},
            {"uri": "pkg:golang/example.com/mod@v1.2.3", "digest": {}},
        ]
        statement = build_statement(**_base_kwargs(resolved_dependencies=deps))

        with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema = json.load(f)
        validator = Draft202012Validator(schema)
        errors = list(validator.iter_errors(statement["predicate"]))
        self.assertEqual(errors, [], msg=[e.message for e in errors])

    def test_valid_test_functions_validates_against_schema(self):
        statement = build_statement(
            **_base_kwargs(total_assertions=200, total_test_functions=156, valid_test_functions=142)
        )

        with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema = json.load(f)
        validator = Draft202012Validator(schema)
        errors = list(validator.iter_errors(statement["predicate"]))
        self.assertEqual(errors, [], msg=[e.message for e in errors])

    def test_release_confidence_score_is_embedded(self):
        statement = build_statement(**_base_kwargs())
        rcs_block = statement["predicate"]["release_confidence_score"]
        self.assertIn("value", rcs_block)
        self.assertIn("algorithm_version", rcs_block)
        self.assertIn("components", rcs_block)
        self.assertIn("degraded", rcs_block)

    def test_branch_governance_is_embedded(self):
        statement = build_statement(**_base_kwargs())
        bg_block = statement["predicate"]["branch_governance"]
        self.assertTrue(bg_block["available"])
        self.assertEqual(bg_block["branch"], "main")
        self.assertTrue(bg_block["pull_request_required"])
        self.assertEqual(bg_block["approvals_required"], 2)
        self.assertTrue(bg_block["direct_push_prevented"])
        self.assertEqual(bg_block["bypass_actors_count"], 0)
        self.assertTrue(bg_block["admin_enforced"])
        self.assertEqual(bg_block["warnings"], [])

    def test_branch_governance_warnings_are_passed_through(self):
        bg = _default_branch_governance()
        bg.available = True
        bg.bypass_actors_count = 1
        bg.admin_enforced = False
        bg.warnings = ["1 bypass actor(s) can bypass branch rules entirely (bypass_mode=always)"]
        statement = build_statement(**_base_kwargs(branch_governance=bg))
        bg_block = statement["predicate"]["branch_governance"]
        self.assertEqual(bg_block["bypass_actors_count"], 1)
        self.assertFalse(bg_block["admin_enforced"])
        self.assertIn("bypass_mode=always", bg_block["warnings"][0])

    def test_branch_governance_reason_code_defaults_to_none(self):
        statement = build_statement(**_base_kwargs())
        bg_block = statement["predicate"]["branch_governance"]
        self.assertIn("reason_code", bg_block)
        self.assertIsNone(bg_block["reason_code"])

    def test_branch_governance_reason_code_is_passed_through(self):
        from cli.parsers.github_rules import REASON_CODE_PLATFORM_UNSUPPORTED_TIER

        bg = _default_branch_governance()
        bg.available = False
        bg.reason = "GitHub API authentication/authorization failed ... Upgrade to GitHub Pro ..."
        bg.reason_code = REASON_CODE_PLATFORM_UNSUPPORTED_TIER
        statement = build_statement(**_base_kwargs(branch_governance=bg))
        bg_block = statement["predicate"]["branch_governance"]
        self.assertEqual(bg_block["reason_code"], "platform_unsupported_tier")

    def test_commit_author_defaults_to_none(self):
        """No caller-supplied CommitAuthorReport (most existing callers) --
        vcs.commit_author is None, never fabricated, and the key is still
        present so schema validation's additionalProperties=false holds."""
        statement = build_statement(**_base_kwargs())
        vcs = statement["predicate"]["vcs"]
        self.assertIn("commit_author", vcs)
        self.assertIsNone(vcs["commit_author"])

    def test_commit_author_is_embedded_when_supplied(self):
        from cli.parsers.commit_author import CommitAuthorReport

        report = CommitAuthorReport(
            available=True,
            commit_sha="b" * 40,
            name="Bill Wonch",
            email="bill.wonch@gmail.com",
            github_login="billwonch",
            verified_github_account=True,
            reason="commit author email resolved to verified GitHub account 'billwonch'",
        )
        statement = build_statement(**_base_kwargs(commit_author=report))
        commit_author_block = statement["predicate"]["vcs"]["commit_author"]
        self.assertEqual(commit_author_block["github_login"], "billwonch")
        self.assertTrue(commit_author_block["verified_github_account"])


class PipelineBlockTests(unittest.TestCase):
    """predicate.pipeline (schema-required: run_id/workflow_ref/ci_provider/
    run_attempt/started_at/finished_at all non-empty) used to hardcode
    literal "PLACEHOLDER_RUN_ID"/"PLACEHOLDER_WORKFLOW_REF" strings
    unconditionally, on every run -- including real, signed, production
    attestations. Now sourced from the same ambient GitHub Actions env vars
    cli/slsa_provenance.py already reads correctly for the separate SLSA
    statement (see _ambient_run_id/_ambient_run_attempt/
    _ambient_workflow_ref/_ambient_runner_environment's own docstrings)."""

    _ENV_KEYS = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW_REF", "RUNNER_ENVIRONMENT")

    def setUp(self):
        # This suite runs inside real GitHub Actions jobs too, where these
        # would genuinely be set ambiently -- clear them for test isolation
        # (see tests/conftest.py's GITHUB_STEP_SUMMARY fixture for the same
        # concern applied elsewhere) and restore whatever was really there
        # afterward.
        self._env_backup = {k: os.environ.get(k) for k in self._ENV_KEYS}
        for k in self._ENV_KEYS:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._env_backup.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_off_ci_uses_explicit_sentinel_not_a_fake_looking_placeholder(self):
        statement = build_statement(**_base_kwargs())
        pipeline = statement["predicate"]["pipeline"]

        self.assertEqual(pipeline["run_id"], "not-run-in-ci")
        self.assertEqual(pipeline["workflow_ref"], "not-run-in-ci")
        self.assertEqual(pipeline["run_attempt"], 1)
        self.assertEqual(pipeline["runner_environment"], "unknown")
        self.assertNotIn("PLACEHOLDER", pipeline["run_id"])
        self.assertNotIn("PLACEHOLDER", pipeline["workflow_ref"])

    def test_ambient_github_actions_context_is_used_when_present(self):
        os.environ["GITHUB_RUN_ID"] = "123456789"
        os.environ["GITHUB_RUN_ATTEMPT"] = "2"
        os.environ["GITHUB_WORKFLOW_REF"] = "lucid-provenance/lucid-assay/.github/workflows/assay.yml@refs/heads/main"
        os.environ["RUNNER_ENVIRONMENT"] = "github-hosted"

        statement = build_statement(**_base_kwargs())
        pipeline = statement["predicate"]["pipeline"]

        self.assertEqual(pipeline["run_id"], "123456789")
        self.assertEqual(pipeline["run_attempt"], 2)
        self.assertEqual(
            pipeline["workflow_ref"], "lucid-provenance/lucid-assay/.github/workflows/assay.yml@refs/heads/main"
        )
        self.assertEqual(pipeline["runner_environment"], "github-hosted")

    def test_run_attempt_defaults_to_one_when_env_var_genuinely_unset(self):
        os.environ["GITHUB_RUN_ID"] = "123456789"
        # GITHUB_RUN_ATTEMPT deliberately left unset -- genuinely absent on
        # a workflow's first attempt, not a guess (matches
        # slsa_provenance.py's own documented convention for this).
        statement = build_statement(**_base_kwargs())
        self.assertEqual(statement["predicate"]["pipeline"]["run_attempt"], 1)

    def test_run_attempt_falls_back_to_one_on_unparseable_value(self):
        os.environ["GITHUB_RUN_ATTEMPT"] = "not-a-number"
        statement = build_statement(**_base_kwargs())  # must not raise
        self.assertEqual(statement["predicate"]["pipeline"]["run_attempt"], 1)

    def test_pipeline_block_validates_against_schema_off_ci(self):
        statement = build_statement(**_base_kwargs())

        with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema = json.load(f)
        errors = list(Draft202012Validator(schema).iter_errors(statement["predicate"]))
        self.assertEqual(errors, [], msg=[e.message for e in errors])

    def test_pipeline_block_validates_against_schema_on_ci(self):
        os.environ["GITHUB_RUN_ID"] = "123456789"
        os.environ["GITHUB_RUN_ATTEMPT"] = "1"
        os.environ["GITHUB_WORKFLOW_REF"] = "lucid-provenance/lucid-assay/.github/workflows/assay.yml@refs/heads/main"
        os.environ["RUNNER_ENVIRONMENT"] = "github-hosted"

        statement = build_statement(**_base_kwargs())

        with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema = json.load(f)
        errors = list(Draft202012Validator(schema).iter_errors(statement["predicate"]))
        self.assertEqual(errors, [], msg=[e.message for e in errors])


if __name__ == "__main__":
    unittest.main()
