import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.parsers.github_rules import BranchGovernanceReport, GitHubAPIError
from cli.parsers.s2c2f import (
    STATUS_MET,
    STATUS_NOT_YET_REPORTED,
    STATUS_UNMET,
    evaluate_s2c2f,
)
from cli.parsers.sarif import SarifRuleGroup, SarifSummaryReport, SarifToolSummary
from cli.parsers.sbom import SbomComponent, build_sbom_sarif_report, sbom_components_to_resolved_dependencies


def _governance(**overrides):
    defaults = dict(
        available=True,
        branch="main",
        pull_request_required=True,
        approvals_required=1,
        direct_push_prevented=True,
        bypass_actors_count=0,
        admin_enforced=True,
        warnings=[],
        reason="ok",
        required_status_check_contexts=[],
    )
    defaults.update(overrides)
    return BranchGovernanceReport(**defaults)


def _controls_by_id(report):
    return {c.id: c for c in report.controls}


class EvaluateS2C2FTests(unittest.TestCase):
    """No-token path: every network-backed control must degrade to
    not_yet_reported (never raise, never silently report met/unmet)."""

    def test_no_token_degrades_network_controls_without_raising(self):
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token=None,
        )
        controls = _controls_by_id(report)
        self.assertEqual(controls["SCA-1"].status, STATUS_NOT_YET_REPORTED)
        self.assertEqual(controls["SCA-3"].status, STATUS_NOT_YET_REPORTED)
        self.assertEqual(controls["INV-2"].status, STATUS_NOT_YET_REPORTED)

    def test_invalid_repository_shape_degrades_network_controls(self):
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="not-a-valid-repo-identifier",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token="tok",
        )
        self.assertEqual(_controls_by_id(report)["SCA-3"].status, STATUS_NOT_YET_REPORTED)

    def test_empty_resolved_dependencies_reports_ing1_inv1_aud2_aud3_unmet(self):
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token=None,
        )
        controls = _controls_by_id(report)
        for control_id in ("ING-1", "INV-1", "AUD-2", "AUD-3"):
            self.assertEqual(controls[control_id].status, STATUS_UNMET, control_id)

    def test_pkg_purl_with_digest_reports_ing1_inv1_aud2_aud3_met(self):
        deps = [{"uri": "pkg:pypi/requests@2.31.0", "digest": {"sha256": "a" * 64}}]
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=deps,
            sarif_report=None,
            branch_governance=_governance(),
            token=None,
        )
        controls = _controls_by_id(report)
        for control_id in ("ING-1", "INV-1", "AUD-2", "AUD-3"):
            self.assertEqual(controls[control_id].status, STATUS_MET, control_id)

    def test_pkg_purl_without_digest_still_fails_aud3(self):
        deps = [{"uri": "pkg:maven/com.acme/widget@1.0", "digest": {}}]
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=deps,
            sarif_report=None,
            branch_governance=_governance(),
            token=None,
        )
        controls = _controls_by_id(report)
        self.assertEqual(controls["ING-1"].status, STATUS_MET)
        self.assertEqual(controls["AUD-3"].status, STATUS_UNMET)

    def test_sca_tool_sarif_report_satisfies_sca1(self):
        sarif = SarifSummaryReport(available=True, tools_scanned=["Trivy"])
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=sarif,
            branch_governance=_governance(),
            token=None,
        )
        control = _controls_by_id(report)["SCA-1"]
        self.assertEqual(control.status, STATUS_MET)
        self.assertIn("Trivy", control.detail)

    def test_license_tool_sarif_report_satisfies_sca2(self):
        sarif = SarifSummaryReport(available=True, tools_scanned=["FOSSA"])
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=sarif,
            branch_governance=_governance(),
            token=None,
        )
        self.assertEqual(_controls_by_id(report)["SCA-2"].status, STATUS_MET)

    def test_unrelated_sarif_tool_does_not_satisfy_sca1_or_sca2(self):
        sarif = SarifSummaryReport(available=True, tools_scanned=["eslint"])
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=sarif,
            branch_governance=_governance(),
            token=None,
        )
        controls = _controls_by_id(report)
        self.assertEqual(controls["SCA-1"].status, STATUS_NOT_YET_REPORTED)
        self.assertEqual(controls["SCA-2"].status, STATUS_NOT_YET_REPORTED)

    def test_clean_grype_sarif_satisfies_sca1(self):
        # Grype ran (driver present, tools_scanned=["grype"]), found
        # nothing -- SCA-1 is a process-existence control ("is
        # vulnerability scanning in place"), so a clean scan still counts.
        sarif = SarifSummaryReport(available=True, tools_scanned=["grype"], tools=[SarifToolSummary(name="grype")])
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=sarif,
            branch_governance=_governance(),
            token=None,
        )
        control = _controls_by_id(report)["SCA-1"]
        self.assertEqual(control.status, STATUS_MET)
        self.assertIn("grype", control.detail)

    def test_finding_heavy_grype_sarif_still_satisfies_sca1_not_unmet(self):
        # A Grype run that found real CVEs still has the scanning control
        # in place -- SCA-1 must not flip to unmet because vulnerabilities
        # were found. The findings themselves are a separate signal,
        # surfaced in predicate.static_analysis, not in this control's
        # met/unmet status (same precedent as SCA-2 and a forbidden
        # license: the check having run is what's credited).
        tool = SarifToolSummary(
            name="grype", errors_count=2, critical_count=1, high_count=1, total_findings=2,
            rules=[
                SarifRuleGroup(rule_id="CVE-2024-0001-openssl", count=1, security_severity="critical"),
                SarifRuleGroup(rule_id="CVE-2024-0002-curl", count=1, security_severity="high"),
            ],
        )
        sarif = SarifSummaryReport(
            available=True, tools_scanned=["grype"], tools=[tool],
            total_findings=2, errors_count=2, critical_count=1, high_count=1,
        )
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=sarif,
            branch_governance=_governance(),
            token=None,
        )
        self.assertEqual(_controls_by_id(report)["SCA-1"].status, STATUS_MET)

    def test_grype_sarif_alone_does_not_satisfy_sca3(self):
        # Regression guard: Grype's SARIF output carries zero EOL/
        # unmaintained-package signal (confirmed against its own SARIF
        # presenter source -- AlertsByPackage/distro-EOL data is a
        # separate structure the SARIF presenter never reads). A Grype
        # SARIF report -- clean or finding-heavy -- must never credit
        # SCA-3 on its own; that control stays scoped to the GitHub
        # Dependabot alerts API, its only honest signal.
        sarif = SarifSummaryReport(available=True, tools_scanned=["grype"], tools=[SarifToolSummary(name="grype")])
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=sarif,
            branch_governance=_governance(),
            token=None,
        )
        self.assertEqual(_controls_by_id(report)["SCA-3"].status, STATUS_NOT_YET_REPORTED)

    def test_sbom_license_findings_satisfy_sca2_end_to_end(self):
        # The real integration this module exists to close: a --sbom's
        # forbidden-license findings, converted to a SARIF report by
        # cli.parsers.sbom.build_sbom_sarif_report exactly the way
        # cli.main wires it, flip SCA-2 from not_yet_reported to met with
        # no dedicated SBOM-awareness inside s2c2f.py itself -- it's just
        # another recognized SARIF tool name.
        components = [SbomComponent(name="bad", purl="pkg:pypi/bad@1.0", license_expression="AGPL-3.0")]
        sarif = build_sbom_sarif_report(components)
        deps = sbom_components_to_resolved_dependencies(components)

        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=deps,
            sarif_report=sarif,
            branch_governance=_governance(),
            token=None,
        )
        controls = _controls_by_id(report)
        self.assertEqual(controls["SCA-2"].status, STATUS_MET)
        self.assertIn("lucid-assay-sbom-license-policy", controls["SCA-2"].detail)
        # INV-1/ING-1 come along for free -- the SBOM's PURLs feed
        # resolved_dependencies exactly like a lockfile's would.
        self.assertEqual(controls["INV-1"].status, STATUS_MET)
        self.assertEqual(controls["ING-1"].status, STATUS_MET)

    def test_sbom_with_only_clean_components_still_satisfies_sca2(self):
        # SCA-2 means "was a license check performed", not "did it find a
        # violation" -- a clean scan (the tool ran, found nothing bad)
        # still counts, same as SCA-1 crediting a vulnerability scanner
        # that happened to find zero CVEs.
        components = [SbomComponent(name="ok", purl="pkg:pypi/ok@1.0", license_expression="MIT")]
        sarif = build_sbom_sarif_report(components)  # available=True, but zero findings

        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=sbom_components_to_resolved_dependencies(components),
            sarif_report=sarif,
            branch_governance=_governance(),
            token=None,
        )
        self.assertEqual(_controls_by_id(report)["SCA-2"].status, STATUS_MET)

    def test_dependabot_config_file_satisfies_upd3(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            os.makedirs(os.path.join(repo_dir, ".github"))
            with open(os.path.join(repo_dir, ".github", "dependabot.yml"), "w") as f:
                f.write("version: 2\n")
            report = evaluate_s2c2f(
                repo_dir=repo_dir,
                repository="acme/widgets",
                resolved_dependencies=[],
                sarif_report=None,
                branch_governance=_governance(),
                token=None,
            )
        self.assertEqual(_controls_by_id(report)["UPD-3"].status, STATUS_MET)

    def test_private_registry_npmrc_satisfies_ing2(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, ".npmrc"), "w") as f:
                f.write("registry=https://npm.internal.acme.com/\n")
            report = evaluate_s2c2f(
                repo_dir=repo_dir,
                repository="acme/widgets",
                resolved_dependencies=[],
                sarif_report=None,
                branch_governance=_governance(),
                token=None,
            )
        self.assertEqual(_controls_by_id(report)["ING-2"].status, STATUS_MET)

    def test_public_registry_npmrc_does_not_satisfy_ing2(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, ".npmrc"), "w") as f:
                f.write("registry=https://registry.npmjs.org/\n")
            report = evaluate_s2c2f(
                repo_dir=repo_dir,
                repository="acme/widgets",
                resolved_dependencies=[],
                sarif_report=None,
                branch_governance=_governance(),
                token=None,
            )
        self.assertEqual(_controls_by_id(report)["ING-2"].status, STATUS_UNMET)

    def test_upd1_manual_updates_always_not_yet_reported(self):
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token=None,
        )
        self.assertEqual(_controls_by_id(report)["UPD-1"].status, STATUS_NOT_YET_REPORTED)

    def test_enf1_met_when_pr_required_and_direct_push_prevented(self):
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(pull_request_required=True, direct_push_prevented=True),
            token=None,
        )
        self.assertEqual(_controls_by_id(report)["ENF-1"].status, STATUS_MET)

    def test_enf1_unmet_when_direct_push_not_prevented(self):
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(pull_request_required=False, direct_push_prevented=False),
            token=None,
        )
        self.assertEqual(_controls_by_id(report)["ENF-1"].status, STATUS_UNMET)

    def test_enf1_and_aud1_not_yet_reported_when_governance_unavailable(self):
        unavailable = _governance(available=False, reason="no token")
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=unavailable,
            token=None,
        )
        controls = _controls_by_id(report)
        self.assertEqual(controls["ENF-1"].status, STATUS_NOT_YET_REPORTED)
        self.assertEqual(controls["AUD-1"].status, STATUS_NOT_YET_REPORTED)

    def test_aud1_met_when_a_required_status_check_names_provenance(self):
        governance = _governance(required_status_check_contexts=["ci/build", "lucid-assay/verify"])
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=governance,
            token=None,
        )
        control = _controls_by_id(report)["AUD-1"]
        self.assertEqual(control.status, STATUS_MET)
        self.assertIn("lucid-assay/verify", control.detail)

    def test_aud1_unmet_when_no_required_status_check_names_provenance(self):
        governance = _governance(required_status_check_contexts=["ci/lint", "ci/unit-tests"])
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=governance,
            token=None,
        )
        self.assertEqual(_controls_by_id(report)["AUD-1"].status, STATUS_UNMET)

    @patch("cli.parsers.s2c2f._github_api_status")
    @patch("cli.parsers.s2c2f._github_api_get")
    def test_vulnerability_alerts_204_satisfies_sca1(self, mock_get, mock_status):
        mock_get.return_value = None
        mock_status.side_effect = lambda path, token, timeout=10: 204 if "vulnerability-alerts" in path else 404

        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token="tok",
        )
        self.assertEqual(_controls_by_id(report)["SCA-1"].status, STATUS_MET)

    @patch("cli.parsers.s2c2f._github_api_status")
    @patch("cli.parsers.s2c2f._github_api_get")
    def test_dependabot_alerts_200_satisfies_sca3(self, mock_get, mock_status):
        mock_get.return_value = None
        mock_status.side_effect = lambda path, token, timeout=10: 200 if "dependabot/alerts" in path else 404

        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token="tok",
        )
        self.assertEqual(_controls_by_id(report)["SCA-3"].status, STATUS_MET)

    @patch("cli.parsers.s2c2f._github_api_status")
    @patch("cli.parsers.s2c2f._github_api_get")
    def test_dependabot_alerts_403_is_not_yet_reported_not_unmet(self, mock_get, mock_status):
        mock_get.return_value = None
        mock_status.side_effect = lambda path, token, timeout=10: 403 if "dependabot/alerts" in path else 404

        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token="tok",
        )
        self.assertEqual(_controls_by_id(report)["SCA-3"].status, STATUS_NOT_YET_REPORTED)

    @patch("cli.parsers.s2c2f._github_api_status")
    @patch("cli.parsers.s2c2f._github_api_get")
    def test_community_profile_security_md_satisfies_inv2(self, mock_get, mock_status):
        mock_status.return_value = 404
        mock_get.return_value = {"files": {"security": {"href": "https://example/SECURITY.md"}}}

        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token="tok",
        )
        self.assertEqual(_controls_by_id(report)["INV-2"].status, STATUS_MET)

    @patch("cli.parsers.s2c2f._github_api_status")
    @patch("cli.parsers.s2c2f._github_api_get")
    def test_community_profile_api_failure_is_not_yet_reported(self, mock_get, mock_status):
        mock_status.return_value = 404
        mock_get.side_effect = GitHubAPIError("boom", status_code=403)

        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token="tok",
        )
        self.assertEqual(_controls_by_id(report)["INV-2"].status, STATUS_NOT_YET_REPORTED)

    def test_evaluated_controls_count_matches_controls_length(self):
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token=None,
        )
        as_dict = report.as_dict()
        self.assertEqual(as_dict["evaluated_controls"], len(as_dict["controls"]))
        self.assertEqual(as_dict["framework"], "S2C2F")


if __name__ == "__main__":
    unittest.main()
