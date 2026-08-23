import json
import os
import sys
import unittest

from jsonschema import Draft202012Validator

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.builder import DEFAULT_PREDICATE_TYPE, build_statement

_SCHEMA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "schema", "tenax-attestation-v1.schema.json"
)
from cli.parsers.coverage import CoverageReport
from cli.parsers.github_rules import BranchGovernanceReport
from cli.parsers.junit import TestTotals
from cli.patch_coverage import PatchCoverageResult, REASON_CODE_NO_COVERABLE_LINES
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

    def test_predicate_type_matches_tenax_v1(self):
        statement = build_statement(**_base_kwargs())
        self.assertEqual(statement["predicateType"], "https://tenax.io/attestations/assay/v1")

    def test_predicate_type_uses_default_predicate_type_constant(self):
        statement = build_statement(**_base_kwargs())
        self.assertEqual(statement["predicateType"], DEFAULT_PREDICATE_TYPE)
        self.assertEqual(DEFAULT_PREDICATE_TYPE, "https://tenax.io/attestations/assay/v1")

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

    def test_sbom_defaults_to_none(self):
        statement = build_statement(**_base_kwargs())
        self.assertIsNone(statement["predicate"]["artifact"]["sbom"])

    def test_sbom_is_passed_through_when_provided(self):
        sbom = {"bomFormat": "CycloneDX", "components": []}
        statement = build_statement(**_base_kwargs(sbom=sbom))
        self.assertEqual(statement["predicate"]["artifact"]["sbom"], sbom)

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


if __name__ == "__main__":
    unittest.main()
