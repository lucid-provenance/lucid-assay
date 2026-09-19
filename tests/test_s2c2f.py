import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.parsers.github_rules import BranchGovernanceReport, GitHubAPIError
from cli.parsers.s2c2f import (
    DENYLIST_SCHEMA_VERSION,
    MANUAL_UPDATES_SCHEMA_VERSION,
    STATUS_MET,
    STATUS_NOT_YET_REPORTED,
    STATUS_UNMET,
    _FeedProvenanceResult,
    _canonical_entries_bytes,
    _codeowners_pattern_covers_manifest,
    _eval_enf2_curated_feeds,
    _eval_ing2_local_copies,
    _eval_ing3_denylists,
    _eval_ing4_source_cloning,
    _eval_sca1_vulnerability_scans,
    _eval_sca2_license_checks,
    _eval_sca3_eol_scans,
    _eval_sca4_malware_scans,
    _eval_sca5_proactive_reviews,
    _eval_upd1_manual_updates,
    _eval_upd2_auto_updates,
    _evaluate_maven_feed,
    _evaluate_npm_feed,
    _evaluate_pip_feed,
    _find_codeowners_manifest_coverage,
    _find_dependabot_automerge_workflow,
    _iter_npm_resolved_urls,
    _load_manual_updates_process_ref,
    _process_ref_is_url,
    compute_denylist_digest,
    evaluate_s2c2f,
    load_denylist,
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
        # SCA-1 still has a real API fallback path that a missing token
        # genuinely can't complete -- stays not_yet_reported. SCA-2 has
        # no such fallback at all: a real check ran against real SARIF
        # input and found no matching tool, a confirmed absence (fixed
        # 2026-09-18, same reasoning as ING-3/UPD-1's checked-absent unmet).
        self.assertEqual(controls["SCA-1"].status, STATUS_NOT_YET_REPORTED)
        self.assertEqual(controls["SCA-2"].status, STATUS_UNMET)

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
        # ING-2's real signal is per-dependency (which host each resolved
        # package-lock.json entry actually came from) -- a bare .npmrc with
        # no lockfile to check against can no longer satisfy it (promoted
        # 2026-09-18; see cli.parsers.s2c2f's own module docstring).
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, ".npmrc"), "w") as f:
                f.write("registry=https://npm.internal.acme.com/\n")
            with open(os.path.join(repo_dir, "package-lock.json"), "w") as f:
                json.dump({"packages": {"": {}, "node_modules/left-pad": {
                    "resolved": "https://npm.internal.acme.com/left-pad/-/left-pad-1.3.0.tgz"
                }}}, f)
            report = evaluate_s2c2f(
                repo_dir=repo_dir,
                repository="acme/widgets",
                resolved_dependencies=[],
                sarif_report=None,
                branch_governance=_governance(),
                token=None,
                internal_registry_hosts=["npm.internal.acme.com"],
            )
        self.assertEqual(_controls_by_id(report)["ING-2"].status, STATUS_MET)

    def test_public_registry_npmrc_does_not_satisfy_ing2(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, ".npmrc"), "w") as f:
                f.write("registry=https://registry.npmjs.org/\n")
            with open(os.path.join(repo_dir, "package-lock.json"), "w") as f:
                json.dump({"packages": {"": {}, "node_modules/left-pad": {
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
                }}}, f)
            report = evaluate_s2c2f(
                repo_dir=repo_dir,
                repository="acme/widgets",
                resolved_dependencies=[],
                sarif_report=None,
                branch_governance=_governance(),
                token=None,
                internal_registry_hosts=["npm.internal.acme.com"],
            )
        self.assertEqual(_controls_by_id(report)["ING-2"].status, STATUS_UNMET)

    def test_no_manifest_at_all_yields_not_yet_reported_ing2(self):
        # No package-lock.json/requirements.txt/pyproject.toml/Pipfile/
        # pom.xml at all -- nothing to evaluate feed provenance against,
        # never a fabricated met/unmet.
        with tempfile.TemporaryDirectory() as repo_dir:
            report = evaluate_s2c2f(
                repo_dir=repo_dir,
                repository="acme/widgets",
                resolved_dependencies=[],
                sarif_report=None,
                branch_governance=_governance(),
                token=None,
            )
        self.assertEqual(_controls_by_id(report)["ING-2"].status, STATUS_NOT_YET_REPORTED)
        self.assertEqual(_controls_by_id(report)["ENF-2"].status, STATUS_NOT_YET_REPORTED)

    def test_upd1_manual_updates_unmet_with_no_assertion_at_all(self):
        # 2026-09-18: UPD-1 stopped being a permanent not_yet_reported --
        # it's now a real, checked assertion (see Upd1ManualUpdatesTests).
        # No config, no runbook: checked and confirmed absent, unmet.
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token=None,
        )
        self.assertEqual(_controls_by_id(report)["UPD-1"].status, STATUS_UNMET)

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
        mock_status.side_effect = lambda path, token, timeout=10: (204, None) if "vulnerability-alerts" in path else (404, None)

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
        mock_status.side_effect = lambda path, token, timeout=10: (200, None) if "dependabot/alerts" in path else (404, None)

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
    def test_dependabot_alerts_403_is_unmet_a_confirmed_answer_not_an_unknown(self, mock_get, mock_status):
        # Fixed 2026-09-18: a real, confirmed case showed 403 here can
        # mean "the repository feature itself is disabled" (GitHub's own
        # body message), a definitively knowable state -- not just "the
        # token lacks permission". Either way the practical answer is
        # the same and real: this control isn't satisfied today.
        mock_get.return_value = None
        mock_status.side_effect = lambda path, token, timeout=10: (403, "Dependabot alerts are disabled for this repository.") if "dependabot/alerts" in path else (404, None)

        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token="tok",
        )
        result = _controls_by_id(report)["SCA-3"]
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertIn("Dependabot alerts are disabled for this repository.", result.detail)

    @patch("cli.parsers.s2c2f._github_api_status")
    @patch("cli.parsers.s2c2f._github_api_get")
    def test_dependabot_alerts_403_without_a_body_message_falls_back_honestly(self, mock_get, mock_status):
        mock_get.return_value = None
        mock_status.side_effect = lambda path, token, timeout=10: (403, None) if "dependabot/alerts" in path else (404, None)

        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token="tok",
        )
        result = _controls_by_id(report)["SCA-3"]
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertIn("likely lacks", result.detail)

    @patch("cli.parsers.s2c2f._github_api_status")
    @patch("cli.parsers.s2c2f._github_api_get")
    def test_own_repo_security_md_satisfies_inv2(self, mock_get, mock_status):
        # GitHub's community/profile response has never had a `security`
        # key at all (confirmed against GitHub's own REST API docs) --
        # INV-2 is checked directly via the Contents API instead. Only
        # the repo's own root SECURITY.md exists here; the other two
        # candidate paths (and the org .github fallback) must never be
        # reached once the first one is found.
        mock_status.return_value = (404, None)
        mock_get.side_effect = lambda path, token, timeout=10: (
            {"name": "SECURITY.md"} if path == "/repos/acme/widgets/contents/SECURITY.md" else None
        )

        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token="tok",
        )
        self.assertEqual(_controls_by_id(report)["INV-2"].status, STATUS_MET)
        mock_get.assert_any_call("/repos/acme/widgets/contents/SECURITY.md", "tok", 10)
        # The org .github fallback must never be queried once the repo's
        # own file was already found.
        called_paths = [c.args[0] for c in mock_get.call_args_list]
        self.assertFalse(any("acme/.github" in p for p in called_paths))

    @patch("cli.parsers.s2c2f._github_api_status")
    @patch("cli.parsers.s2c2f._github_api_get")
    def test_org_default_security_md_satisfies_inv2_when_repo_has_none(self, mock_get, mock_status):
        # Replicates GitHub's own org-wide default community health file
        # fallback: acme/widgets has none of its own, but acme/.github
        # does -- this must still report MET, the same way GitHub's own
        # UI credits the inherited default.
        mock_status.return_value = (404, None)
        mock_get.side_effect = lambda path, token, timeout=10: (
            {"name": "SECURITY.md"} if path == "/repos/acme/.github/contents/SECURITY.md" else None
        )

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
    def test_no_security_md_anywhere_is_unmet(self, mock_get, mock_status):
        mock_status.return_value = (404, None)
        mock_get.return_value = None  # every candidate path, repo and org alike, 404s

        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(),
            repository="acme/widgets",
            resolved_dependencies=[],
            sarif_report=None,
            branch_governance=_governance(),
            token="tok",
        )
        self.assertEqual(_controls_by_id(report)["INV-2"].status, STATUS_UNMET)

    @patch("cli.parsers.s2c2f._github_api_status")
    @patch("cli.parsers.s2c2f._github_api_get")
    def test_contents_api_failure_is_not_yet_reported(self, mock_get, mock_status):
        mock_status.return_value = (404, None)
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


def _write_denylist(path, entries):
    with open(path, "w") as f:
        json.dump({
            "schema_version": DENYLIST_SCHEMA_VERSION,
            "entries": entries,
            "digest_sha256": compute_denylist_digest(entries),
        }, f)


class Ing3DenylistsTests(unittest.TestCase):
    """Promoted 2026-09-18 from scripts/_ingestion_lib.py -- see
    cli.parsers.s2c2f's own module docstring."""

    def test_missing_denylist_is_unmet_not_not_yet_reported(self):
        # A repo that never set one up genuinely hasn't implemented ING-3
        # -- a definitive, confirmed absence, not "couldn't check".
        with tempfile.TemporaryDirectory() as repo_dir:
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
            )
        result = _controls_by_id(report)["ING-3"]
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertIn("no denylist policy artifact found", result.detail)

    def test_empty_denylist_with_dependencies_is_met(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            denylist_path = os.path.join(repo_dir, "denylist.json")
            _write_denylist(denylist_path, [])
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets",
                resolved_dependencies=[{"uri": "pkg:pypi/requests@2.31.0"}],
                sarif_report=None, branch_governance=_governance(), token=None,
                denylist_path=denylist_path,
            )
        self.assertEqual(_controls_by_id(report)["ING-3"].status, STATUS_MET)

    def test_matching_dependency_is_unmet(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            denylist_path = os.path.join(repo_dir, "denylist.json")
            _write_denylist(denylist_path, [{"ecosystem": "pypi", "name": "evil-pkg", "reason": "known backdoor"}])
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets",
                resolved_dependencies=[{"uri": "pkg:pypi/evil-pkg@1.0.0"}],
                sarif_report=None, branch_governance=_governance(), token=None,
                denylist_path=denylist_path,
            )
        result = _controls_by_id(report)["ING-3"]
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertIn("evil-pkg", result.detail)

    def test_tampered_digest_is_unmet_not_a_silent_pass(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            denylist_path = os.path.join(repo_dir, "denylist.json")
            with open(denylist_path, "w") as f:
                json.dump({"schema_version": DENYLIST_SCHEMA_VERSION, "entries": [], "digest_sha256": "not-the-real-digest"}, f)
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
                denylist_path=denylist_path,
            )
        result = _controls_by_id(report)["ING-3"]
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertIn("possible tampering", result.detail)

    def test_default_denylist_path_is_lucid_denylist_json_under_repo_dir(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            os.makedirs(os.path.join(repo_dir, ".lucid"))
            _write_denylist(os.path.join(repo_dir, ".lucid", "denylist.json"), [])
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
            )
        self.assertEqual(_controls_by_id(report)["ING-3"].status, STATUS_MET)

    def test_unsafe_denylist_path_degrades_closed_never_raises(self):
        # SonarQube flagged this: --denylist is CLI-operator-supplied,
        # same class of input as --junit-xml/--coverage-report/--sarif,
        # and load_denylist() previously read it without routing through
        # cli.common.safe_resolve_path() first -- the "sanitize right
        # before the read" pattern every other file-input path in this
        # package already follows (cli.parsers.sarif/coverage). A null
        # byte is the concrete case safe_resolve_path itself rejects.
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(), repository="acme/widgets", resolved_dependencies=[],
            sarif_report=None, branch_governance=_governance(), token=None,
            denylist_path="denylist.json\x00.txt",
        )
        result = _controls_by_id(report)["ING-3"]
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertIn("unsafe denylist path", result.detail)


def _write_manual_updates_config(repo_dir, process_ref):
    os.makedirs(os.path.join(repo_dir, ".lucid"), exist_ok=True)
    with open(os.path.join(repo_dir, ".lucid", "manual-updates.json"), "w") as f:
        json.dump({"schema_version": MANUAL_UPDATES_SCHEMA_VERSION, "process_ref": process_ref}, f)


class Upd1ManualUpdatesTests(unittest.TestCase):
    """Rewritten 2026-09-18 from a permanent not_yet_reported to a real,
    checked assertion -- see cli.parsers.s2c2f's own comment on why a
    markdown-content heuristic was deliberately rejected in favor of this."""

    def test_process_ref_pointing_at_a_real_local_file_is_met(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            os.makedirs(os.path.join(repo_dir, "docs"))
            with open(os.path.join(repo_dir, "docs", "manual-updates.md"), "w") as f:
                f.write("# Manual update process\n")
            _write_manual_updates_config(repo_dir, "docs/manual-updates.md")
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
            )
        result = _controls_by_id(report)["UPD-1"]
        self.assertEqual(result.status, STATUS_MET)
        self.assertIn("docs/manual-updates.md", result.detail)

    def test_process_ref_pointing_at_a_missing_local_file_is_unmet(self):
        # A dangling pointer is a real, reportable problem -- never
        # silently trusted just because the config file itself is valid.
        with tempfile.TemporaryDirectory() as repo_dir:
            _write_manual_updates_config(repo_dir, "docs/manual-updates.md")
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
            )
        result = _controls_by_id(report)["UPD-1"]
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertIn("stale or broken", result.detail)

    def test_process_ref_pointing_at_a_url_is_met_without_fetching_it(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            _write_manual_updates_config(repo_dir, "https://wiki.acme.internal/ops/manual-dependency-updates")
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
            )
        result = _controls_by_id(report)["UPD-1"]
        self.assertEqual(result.status, STATUS_MET)
        self.assertIn("wiki.acme.internal", result.detail)

    def test_updating_md_fallback_is_met(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, "UPDATING.md"), "w") as f:
                f.write("# Updating\n")
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
            )
        self.assertEqual(_controls_by_id(report)["UPD-1"].status, STATUS_MET)

    def test_no_config_and_no_runbook_is_unmet(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
            )
        result = _controls_by_id(report)["UPD-1"]
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertIn("no documented manual-update process asserted", result.detail)

    def test_malformed_config_is_treated_as_absent_falls_back_to_runbook_check(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            os.makedirs(os.path.join(repo_dir, ".lucid"))
            with open(os.path.join(repo_dir, ".lucid", "manual-updates.json"), "w") as f:
                f.write("{not valid json")
            with open(os.path.join(repo_dir, "UPDATING.md"), "w") as f:
                f.write("# Updating\n")
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
            )
        self.assertEqual(_controls_by_id(report)["UPD-1"].status, STATUS_MET)


class Upd2AutoUpdatesTests(unittest.TestCase):
    """Rewritten 2026-09-18, same day as it was first built: the original
    design (GET /repos/{owner}/{repo}'s allow_auto_merge field) was
    confirmed -- against a real CI run, then independently against a real
    unauthenticated API call -- to be structurally unreachable with any
    read-only token, since GitHub omits that field unless the caller has
    push access. Replaced with a real, local, no-API signal: a workflow
    under .github/workflows/ that wires up Dependabot-PR auto-merge via
    dependabot/fetch-metadata."""

    def _write_dependabot_config(self, repo_dir):
        os.makedirs(os.path.join(repo_dir, ".github"))
        with open(os.path.join(repo_dir, ".github", "dependabot.yml"), "w") as f:
            f.write("version: 2\n")

    def _write_automerge_workflow(self, repo_dir, name="dependabot-automerge.yml"):
        workflows_dir = os.path.join(repo_dir, ".github", "workflows")
        os.makedirs(workflows_dir, exist_ok=True)
        with open(os.path.join(workflows_dir, name), "w") as f:
            f.write("on: pull_request\njobs:\n  auto-merge:\n    steps:\n      - uses: dependabot/fetch-metadata@v2\n")

    def test_dependabot_config_plus_automerge_workflow_is_met(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            self._write_dependabot_config(repo_dir)
            self._write_automerge_workflow(repo_dir)
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
            )
        result = _controls_by_id(report)["UPD-2"]
        self.assertEqual(result.status, STATUS_MET)
        self.assertIn("dependabot-automerge.yml", result.detail)

    def test_dependabot_config_without_automerge_workflow_is_unmet(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            self._write_dependabot_config(repo_dir)
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
            )
        result = _controls_by_id(report)["UPD-2"]
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertIn("no dependabot/fetch-metadata usage found", result.detail)

    def test_a_workflow_that_merely_skips_steps_for_dependabot_actors_does_not_satisfy_it(self):
        # A workflow with an `if: github.actor != 'dependabot[bot]'` guard
        # (this repo's own real assay.yml pattern) is not auto-merge
        # automation -- it's the opposite, a secrets-withholding
        # workaround. Must not be mistaken for the real signal.
        with tempfile.TemporaryDirectory() as repo_dir:
            self._write_dependabot_config(repo_dir)
            workflows_dir = os.path.join(repo_dir, ".github", "workflows")
            os.makedirs(workflows_dir)
            with open(os.path.join(workflows_dir, "ci.yml"), "w") as f:
                f.write("on: push\njobs:\n  build:\n    steps:\n      - if: github.actor != 'dependabot[bot]'\n        run: echo ok\n")
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
            )
        self.assertEqual(_controls_by_id(report)["UPD-2"].status, STATUS_UNMET)

    def test_no_update_automation_config_is_unmet_even_with_an_automerge_workflow(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            self._write_automerge_workflow(repo_dir)
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
            )
        self.assertEqual(_controls_by_id(report)["UPD-2"].status, STATUS_UNMET)

    def test_no_token_needed_at_all_this_is_a_local_check(self):
        # Unlike the original design, this control needs no GitHub API
        # access whatsoever -- confirms it evaluates identically with or
        # without a token.
        with tempfile.TemporaryDirectory() as repo_dir:
            self._write_dependabot_config(repo_dir)
            self._write_automerge_workflow(repo_dir)
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
            )
        self.assertEqual(_controls_by_id(report)["UPD-2"].status, STATUS_MET)


class Ing4SourceCloningTests(unittest.TestCase):
    def test_always_unmet_a_confirmed_gap_not_an_unknown(self):
        # Fixed 2026-09-18: this check never branches on anything -- it's
        # not that we couldn't determine the answer, it's that we know
        # it for certain. A confirmed absence is unmet, not
        # not_yet_reported (same fix UPD-1 got the same day).
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(), repository="acme/widgets", resolved_dependencies=[],
            sarif_report=None, branch_governance=_governance(), token=None,
        )
        result = _controls_by_id(report)["ING-4"]
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertIn("no such infrastructure is operated today", result.detail)


class Sca4MalwareScansTests(unittest.TestCase):
    def _sarif(self, tools_scanned):
        return SarifSummaryReport(available=True, tools_scanned=tools_scanned)

    def test_osv_scanner_sarif_satisfies_sca4(self):
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(), repository="acme/widgets", resolved_dependencies=[],
            sarif_report=self._sarif(["osv-scanner"]), branch_governance=_governance(), token=None,
        )
        self.assertEqual(_controls_by_id(report)["SCA-4"].status, STATUS_MET)

    def test_a_pure_cve_tool_does_not_satisfy_sca4_even_though_it_satisfies_sca1(self):
        # trivy is a recognized SCA-1 (Vulnerability Scans) tool but has no
        # dedicated malicious-package feed -- SCA-4 is a genuinely
        # different question ("did a malware-capable scan run"), and the
        # two must be able to disagree.
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(), repository="acme/widgets", resolved_dependencies=[],
            sarif_report=self._sarif(["trivy"]), branch_governance=_governance(), token=None,
        )
        controls = _controls_by_id(report)
        self.assertEqual(controls["SCA-1"].status, STATUS_MET)
        self.assertEqual(controls["SCA-4"].status, STATUS_UNMET)

    def test_no_sarif_at_all_is_unmet(self):
        # Fixed 2026-09-18: a real check ran against whatever --sarif
        # input this run actually provided (none) and found no matching
        # tool -- a confirmed absence for this run, not an unknown.
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(), repository="acme/widgets", resolved_dependencies=[],
            sarif_report=None, branch_governance=_governance(), token=None,
        )
        self.assertEqual(_controls_by_id(report)["SCA-4"].status, STATUS_UNMET)


class Sca5ProactiveReviewsTests(unittest.TestCase):
    def test_branch_governance_unavailable_is_not_yet_reported(self):
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(), repository="acme/widgets", resolved_dependencies=[],
            sarif_report=None, branch_governance=_governance(available=False), token=None,
        )
        self.assertEqual(_controls_by_id(report)["SCA-5"].status, STATUS_NOT_YET_REPORTED)

    def test_no_codeowners_is_unmet(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(require_code_owner_review=True), token=None,
            )
        self.assertEqual(_controls_by_id(report)["SCA-5"].status, STATUS_UNMET)

    def test_codeowners_covers_manifest_but_review_not_required_is_unmet(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, "CODEOWNERS"), "w") as f:
                f.write("package.json @acme/platform-team\n")
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(require_code_owner_review=False), token=None,
            )
        result = _controls_by_id(report)["SCA-5"]
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertIn("does not require code-owner review", result.detail)

    def test_codeowners_covers_manifest_and_review_required_is_met(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            os.makedirs(os.path.join(repo_dir, ".github"))
            with open(os.path.join(repo_dir, ".github", "CODEOWNERS"), "w") as f:
                f.write("*.md @acme/docs-team\nrequirements.txt @acme/platform-team\n")
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(require_code_owner_review=True), token=None,
            )
        result = _controls_by_id(report)["SCA-5"]
        self.assertEqual(result.status, STATUS_MET)
        self.assertIn("requirements.txt", result.detail)

    def test_codeowners_present_but_covers_no_manifest_is_unmet(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, "CODEOWNERS"), "w") as f:
                f.write("*.md @acme/docs-team\n")
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(require_code_owner_review=True), token=None,
            )
        self.assertEqual(_controls_by_id(report)["SCA-5"].status, STATUS_UNMET)

    def test_wildcard_codeowners_entry_covers_every_manifest(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, "CODEOWNERS"), "w") as f:
                f.write("* @acme/platform-team\n")
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(require_code_owner_review=True), token=None,
            )
        self.assertEqual(_controls_by_id(report)["SCA-5"].status, STATUS_MET)


class Enf2CuratedFeedsTests(unittest.TestCase):
    def test_all_internal_is_met(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, "package-lock.json"), "w") as f:
                json.dump({"packages": {"": {}, "node_modules/left-pad": {
                    "resolved": "https://npm.internal.acme.com/left-pad/-/left-pad-1.3.0.tgz"
                }}}, f)
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
                internal_registry_hosts=["npm.internal.acme.com"],
            )
        result = _controls_by_id(report)["ENF-2"]
        self.assertEqual(result.status, STATUS_MET)
        self.assertIn("enforcement would not break this build", result.detail)

    def test_a_public_resolution_is_unmet_a_real_enforcement_gate_would_break(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, "package-lock.json"), "w") as f:
                json.dump({"packages": {"": {}, "node_modules/left-pad": {
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
                }}}, f)
            report = evaluate_s2c2f(
                repo_dir=repo_dir, repository="acme/widgets", resolved_dependencies=[],
                sarif_report=None, branch_governance=_governance(), token=None,
                internal_registry_hosts=["npm.internal.acme.com"],
            )
        result = _controls_by_id(report)["ENF-2"]
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertIn("a build enforcing curated-feed consumption would break here", result.detail)


class NewControlCatalogTests(unittest.TestCase):
    """Locks in label/level for every control promoted/added 2026-09-18 --
    a typo here would silently mismatch lucid-console's lib/s2c2f.ts
    catalog (checked by hand against that file, not duplicated here)."""

    def test_labels_and_levels(self):
        report = evaluate_s2c2f(
            repo_dir=tempfile.mkdtemp(), repository="acme/widgets", resolved_dependencies=[],
            sarif_report=None, branch_governance=_governance(), token=None,
        )
        controls = _controls_by_id(report)
        expected = {
            "ING-3": ("Denylists", 3),
            "ING-4": ("Source Cloning", 3),
            "SCA-4": ("Malware Scans", 3),
            "SCA-5": ("Proactive Reviews", 3),
            "ENF-2": ("Curated Feeds", 3),
            "UPD-2": ("Auto-Updates", 2),
        }
        for control_id, (label, level) in expected.items():
            self.assertEqual(controls[control_id].label, label, control_id)
            self.assertEqual(controls[control_id].level, level, control_id)


# ---------------------------------------------------------------------------
# Direct-field tests on private helpers, 2026-09-19: mutation testing on
# PR #104's real diff (cli/main.py, cli/parsers/github_rules.py,
# cli/parsers/s2c2f.py) scored 68.4% -- weak tier, blocked by
# --disallow-degraded. Every survivor traced to the same root cause: the
# integration-level tests above call evaluate_s2c2f() and check only
# `.status` (or a substring of `.detail`), so a mutation swapping an
# unobserved field (a wrong ecosystem string, an off-by-one counter never
# referenced in the asserted substring, singular/plural grammar, a status
# constant one branch over) went undetected. Same fix this project's own
# PythonRunnerRunDirectFieldTests already established for exactly this
# class of gap: call the private helper directly, assert every field
# exactly, not through the lossy public-API substring lens.
# ---------------------------------------------------------------------------


class IterNpmResolvedUrlsTests(unittest.TestCase):
    def test_packages_format_skips_root_entry(self):
        data = {"packages": {"": {"resolved": "should-never-be-yielded"}, "node_modules/left-pad": {"resolved": "https://registry.npmjs.org/left-pad"}}}
        self.assertEqual(list(_iter_npm_resolved_urls(data)), ["https://registry.npmjs.org/left-pad"])

    def test_packages_format_skips_entries_with_no_resolved_field(self):
        data = {"packages": {"": {}, "node_modules/left-pad": {"version": "1.3.0"}}}
        self.assertEqual(list(_iter_npm_resolved_urls(data)), [])

    def test_packages_format_skips_non_dict_meta(self):
        data = {"packages": {"": {}, "node_modules/left-pad": "not-a-dict"}}
        self.assertEqual(list(_iter_npm_resolved_urls(data)), [])

    def test_dependencies_v1_format_recurses_into_nested_dependencies(self):
        data = {"dependencies": {
            "left-pad": {"resolved": "https://registry.npmjs.org/left-pad", "dependencies": {
                "nested-dep": {"resolved": "https://registry.npmjs.org/nested-dep"},
            }},
        }}
        self.assertEqual(
            sorted(_iter_npm_resolved_urls(data)),
            sorted(["https://registry.npmjs.org/left-pad", "https://registry.npmjs.org/nested-dep"]),
        )

    def test_dependencies_v1_format_skips_non_dict_meta(self):
        data = {"dependencies": {"left-pad": "not-a-dict"}}
        self.assertEqual(list(_iter_npm_resolved_urls(data)), [])

    def test_neither_packages_nor_dependencies_yields_nothing(self):
        self.assertEqual(list(_iter_npm_resolved_urls({})), [])


def _write_package_lock(repo_dir, resolved_urls):
    """resolved_urls: list of URL strings, written as distinct packages
    entries (npm v7+ "packages" format)."""
    packages = {"": {}}
    for i, url in enumerate(resolved_urls):
        packages[f"node_modules/dep{i}"] = {"resolved": url}
    with open(os.path.join(repo_dir, "package-lock.json"), "w") as f:
        json.dump({"packages": packages}, f)


class EvaluateNpmFeedDirectFieldTests(unittest.TestCase):
    def test_no_lockfile_returns_none(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            self.assertIsNone(_evaluate_npm_feed(Path(repo_dir), []))

    def test_malformed_json_exact_result(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            with open(os.path.join(repo_dir, "package-lock.json"), "w") as f:
                f.write("{not valid json")
            result = _evaluate_npm_feed(Path(repo_dir), [])
        self.assertEqual(result, _FeedProvenanceResult("npm", False, "package-lock.json is present but unreadable/malformed JSON"))

    def test_no_resolved_urls_exact_result(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            _write_package_lock(repo_dir, [])
            result = _evaluate_npm_feed(Path(repo_dir), [])
        self.assertEqual(result, _FeedProvenanceResult("npm", False, "package-lock.json carries no resolved dependency URLs to evaluate"))

    def test_single_public_dependency_exact_result_singular_grammar(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            _write_package_lock(repo_dir, ["https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"])
            result = _evaluate_npm_feed(Path(repo_dir), ["internal.example"])
        self.assertEqual(result, _FeedProvenanceResult(
            "npm", False,
            "1 resolved dependency: 0 via a configured internal host, 1 direct from registry.npmjs.org, 0 from another unclassified host",
        ))

    def test_mixed_internal_public_other_exact_result_plural_grammar(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            _write_package_lock(repo_dir, [
                "https://internal.example/left-pad",
                "https://registry.npmjs.org/right-pad",
                "https://some-other-registry.example/other-pad",
            ])
            result = _evaluate_npm_feed(Path(repo_dir), ["internal.example"])
        self.assertEqual(result, _FeedProvenanceResult(
            "npm", False,
            "3 resolved dependencies: 1 via a configured internal host, 1 direct from registry.npmjs.org, 1 from another unclassified host",
        ))

    def test_all_internal_single_dependency_exact_result_singular_grammar(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            _write_package_lock(repo_dir, ["https://internal.example/left-pad"])
            result = _evaluate_npm_feed(Path(repo_dir), ["internal.example"])
        self.assertEqual(result, _FeedProvenanceResult("npm", True, "all 1 resolved dependency came from a configured internal host"))

    def test_all_internal_multiple_dependencies_exact_result_plural_grammar(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            _write_package_lock(repo_dir, ["https://internal.example/left-pad", "https://internal.example/right-pad"])
            result = _evaluate_npm_feed(Path(repo_dir), ["internal.example"])
        self.assertEqual(result, _FeedProvenanceResult("npm", True, "all 2 resolved dependencies came from a configured internal host"))


class EvaluatePipFeedDirectFieldTests(unittest.TestCase):
    def test_no_pip_manifest_returns_none(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            self.assertIsNone(_evaluate_pip_feed(Path(repo_dir)))

    def test_manifest_without_proxy_config_exact_result(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            with open(os.path.join(repo_dir, "requirements.txt"), "w") as f:
                f.write("requests==2.31.0\n")
            result = _evaluate_pip_feed(Path(repo_dir))
        self.assertEqual(result, _FeedProvenanceResult(
            "pip", False,
            "a pip manifest is present but no pip.conf/pip.ini at the repo root names a private index-url; "
            "an org-wide proxy configured outside the repo would not be visible here",
        ))

    def test_manifest_with_proxy_config_exact_result(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            with open(os.path.join(repo_dir, "pyproject.toml"), "w") as f:
                f.write("[project]\nname = 'widgets'\n")
            with open(os.path.join(repo_dir, "pip.conf"), "w") as f:
                f.write("[global]\nindex-url = https://pip.internal.example/simple\n")
            result = _evaluate_pip_feed(Path(repo_dir))
        self.assertEqual(result, _FeedProvenanceResult("pip", True, "pip.conf names a non-default index-url, consistent with an internal package proxy"))


class EvaluateMavenFeedDirectFieldTests(unittest.TestCase):
    def test_no_pom_returns_none(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            self.assertIsNone(_evaluate_maven_feed(Path(repo_dir)))

    def test_no_repository_block_exact_result(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            with open(os.path.join(repo_dir, "pom.xml"), "w") as f:
                f.write("<project></project>")
            result = _evaluate_maven_feed(Path(repo_dir))
        self.assertEqual(result, _FeedProvenanceResult(
            "maven", False,
            "pom.xml declares no <repository> outside Maven Central; settings.xml-level mirrors (outside this repo) would not be visible here",
        ))

    def test_repository_pointing_at_maven_central_exact_result(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            with open(os.path.join(repo_dir, "pom.xml"), "w") as f:
                f.write("<project><repositories><repository><url>https://repo.maven.apache.org/maven2</url></repository></repositories></project>")
            result = _evaluate_maven_feed(Path(repo_dir))
        self.assertEqual(result, _FeedProvenanceResult(
            "maven", False,
            "pom.xml declares no <repository> outside Maven Central; settings.xml-level mirrors (outside this repo) would not be visible here",
        ))

    def test_repository_pointing_outside_maven_central_exact_result(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            with open(os.path.join(repo_dir, "pom.xml"), "w") as f:
                f.write("<project><repositories><repository><url>https://maven.internal.example/repo</url></repository></repositories></project>")
            result = _evaluate_maven_feed(Path(repo_dir))
        self.assertEqual(result, _FeedProvenanceResult("maven", True, "pom.xml declares a <repository> outside Maven Central (https://maven.internal.example/repo)"))


class Ing2Enf2DirectFieldTests(unittest.TestCase):
    """Constructs _FeedProvenanceResult lists directly, bypassing the
    filesystem entirely -- isolates ING-2/ENF-2's own join/filter logic
    from the feed-provenance helpers already covered above."""

    def test_empty_feed_results_exact_not_yet_reported(self):
        ing2 = _eval_ing2_local_copies([])
        enf2 = _eval_enf2_curated_feeds([])
        self.assertEqual(ing2.status, STATUS_NOT_YET_REPORTED)
        self.assertEqual(ing2.detail, "no npm/pip/maven manifest was found under the repo to evaluate feed provenance against")
        self.assertEqual(enf2.status, STATUS_NOT_YET_REPORTED)
        self.assertEqual(enf2.detail, "no npm/pip/maven manifest was found under the repo to evaluate curated-feed enforcement against")

    def test_all_met_exact_joined_detail(self):
        results = [_FeedProvenanceResult("npm", True, "all good"), _FeedProvenanceResult("pip", True, "also good")]
        ing2 = _eval_ing2_local_copies(results)
        enf2 = _eval_enf2_curated_feeds(results)
        self.assertEqual(ing2.status, STATUS_MET)
        self.assertEqual(ing2.detail, "npm: all good; pip: also good")
        self.assertEqual(enf2.status, STATUS_MET)
        self.assertEqual(enf2.detail, "no dependency resolution bypassed the required curated feed(s); enforcement would not break this build: npm: all good; pip: also good")

    def test_one_failing_ing2_lists_every_result_enf2_lists_only_failing(self):
        results = [_FeedProvenanceResult("npm", False, "npm bad"), _FeedProvenanceResult("pip", True, "pip good")]
        ing2 = _eval_ing2_local_copies(results)
        enf2 = _eval_enf2_curated_feeds(results)
        self.assertEqual(ing2.status, STATUS_UNMET)
        self.assertEqual(ing2.detail, "npm: npm bad; pip: pip good")
        self.assertEqual(enf2.status, STATUS_UNMET)
        self.assertEqual(enf2.detail, "a build enforcing curated-feed consumption would break here: npm: npm bad")


class Sca1DirectFieldTests(unittest.TestCase):
    def test_tool_match_exact_detail(self):
        result = _eval_sca1_vulnerability_scans(["grype"], None)
        self.assertEqual(result.status, STATUS_MET)
        self.assertEqual(result.detail, "SARIF findings from a recognized SCA tool (grype)")

    def test_204_exact_detail(self):
        result = _eval_sca1_vulnerability_scans([], 204)
        self.assertEqual(result.status, STATUS_MET)
        self.assertEqual(result.detail, "GitHub Dependabot vulnerability alerts are enabled for this repository")

    def test_404_exact_detail(self):
        result = _eval_sca1_vulnerability_scans([], 404)
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertEqual(result.detail, "GitHub Dependabot vulnerability alerts are not enabled, and no SARIF input came from a recognized SCA tool")

    def test_none_status_exact_detail_not_yet_reported(self):
        result = _eval_sca1_vulnerability_scans([], None)
        self.assertEqual(result.status, STATUS_NOT_YET_REPORTED)
        self.assertEqual(result.detail, "no SARIF input from a recognized SCA tool, and the GitHub vulnerability-alerts API could not be reached (missing token or network failure)")

    def test_inconclusive_status_exact_detail_unmet(self):
        result = _eval_sca1_vulnerability_scans([], 403)
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertEqual(result.detail, "no SARIF input from a recognized SCA tool, and GitHub's vulnerability-alerts API returned an inconclusive status (403)")


class Sca2DirectFieldTests(unittest.TestCase):
    def test_tool_match_exact_detail(self):
        result = _eval_sca2_license_checks(["fossa"])
        self.assertEqual(result.status, STATUS_MET)
        self.assertEqual(result.detail, "SARIF findings from a recognized license-scanning tool (fossa)")

    def test_no_match_exact_detail_unmet(self):
        result = _eval_sca2_license_checks([])
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertEqual(result.detail, "no --sarif input came from a recognized license-scanning tool; no other generic signal is available")


class Sca3DirectFieldTests(unittest.TestCase):
    def test_200_exact_detail(self):
        result = _eval_sca3_eol_scans(200, None)
        self.assertEqual(result.status, STATUS_MET)
        self.assertEqual(result.detail, "GitHub Dependabot alerts API is enabled and reachable for this repository (closest available signal for automated deprecated/EOL package flagging)")

    def test_404_exact_detail(self):
        result = _eval_sca3_eol_scans(404, None)
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertEqual(result.detail, "GitHub Dependabot alerts are not enabled for this repository")

    def test_403_with_real_body_message_exact_detail(self):
        result = _eval_sca3_eol_scans(403, "Dependabot alerts are disabled for this repository.")
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertEqual(result.detail, "GitHub Dependabot alerts API returned 403: Dependabot alerts are disabled for this repository.")

    def test_403_without_body_message_exact_fallback_detail(self):
        result = _eval_sca3_eol_scans(403, None)
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertEqual(result.detail, "GitHub Dependabot alerts API returned 403: the token likely lacks 'Dependabot alerts: Read' permission")

    def test_unreachable_exact_detail_not_yet_reported(self):
        result = _eval_sca3_eol_scans(None, None)
        self.assertEqual(result.status, STATUS_NOT_YET_REPORTED)
        self.assertEqual(result.detail, "GitHub Dependabot alerts API could not be reached (missing token or network failure)")


class Sca4DirectFieldTests(unittest.TestCase):
    def test_tool_match_exact_detail(self):
        result = _eval_sca4_malware_scans(["osv-scanner"])
        self.assertEqual(result.status, STATUS_MET)
        self.assertEqual(result.detail, "SARIF findings from a recognized malware/malicious-package-scanning tool (osv-scanner)")

    def test_no_match_exact_detail_unmet(self):
        result = _eval_sca4_malware_scans([])
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertEqual(result.detail, "no --sarif input came from a recognized malware-scanning tool (default: OSV-Scanner); no other generic signal is available")


class CodeownersPatternCoversManifestDirectTests(unittest.TestCase):
    def test_exact_filename_match(self):
        self.assertEqual(_codeowners_pattern_covers_manifest("package.json"), "package.json")

    def test_leading_slash_stripped(self):
        self.assertEqual(_codeowners_pattern_covers_manifest("/requirements.txt"), "requirements.txt")

    def test_trailing_double_star_stripped(self):
        self.assertEqual(_codeowners_pattern_covers_manifest("/pom.xml/**"), "pom.xml")

    def test_bare_wildcard_matches_first_catalog_entry(self):
        self.assertEqual(_codeowners_pattern_covers_manifest("*"), "package.json")

    def test_double_star_matches_first_catalog_entry(self):
        self.assertEqual(_codeowners_pattern_covers_manifest("**"), "package.json")

    def test_unrelated_pattern_returns_none(self):
        self.assertIsNone(_codeowners_pattern_covers_manifest("*.md"))


class FindCodeownersManifestCoverageDirectTests(unittest.TestCase):
    def test_no_codeowners_file_at_any_location_returns_none(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            self.assertIsNone(_find_codeowners_manifest_coverage(repo_dir))

    def test_comment_and_blank_lines_skipped(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, "CODEOWNERS"), "w") as f:
                f.write("# a comment\n\npackage.json @acme/team\n")
            self.assertEqual(_find_codeowners_manifest_coverage(repo_dir), ("CODEOWNERS", "package.json"))

    def test_root_codeowners_checked_before_github_subdirectory(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            os.makedirs(os.path.join(repo_dir, ".github"))
            with open(os.path.join(repo_dir, "CODEOWNERS"), "w") as f:
                f.write("package.json @acme/team\n")
            with open(os.path.join(repo_dir, ".github", "CODEOWNERS"), "w") as f:
                f.write("requirements.txt @acme/other-team\n")
            self.assertEqual(_find_codeowners_manifest_coverage(repo_dir), ("CODEOWNERS", "package.json"))


class Sca5DirectFieldTests(unittest.TestCase):
    def test_branch_governance_unavailable_exact_detail(self):
        result = _eval_sca5_proactive_reviews(tempfile.mkdtemp(), _governance(available=False))
        self.assertEqual(result.status, STATUS_NOT_YET_REPORTED)
        self.assertEqual(result.detail, "branch governance could not be verified (see predicate.branch_governance.reason)")

    def test_no_coverage_exact_detail(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            result = _eval_sca5_proactive_reviews(repo_dir, _governance())
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertEqual(result.detail, "no CODEOWNERS entry (checked CODEOWNERS/.github/CODEOWNERS/docs/CODEOWNERS) covers a recognized dependency-manifest file")

    def test_coverage_without_required_review_exact_detail(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, "CODEOWNERS"), "w") as f:
                f.write("requirements.txt @acme/team\n")
            result = _eval_sca5_proactive_reviews(repo_dir, _governance(require_code_owner_review=False))
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertEqual(result.detail, "CODEOWNERS covers requirements.txt, but the branch does not require code-owner review (require_code_owner_review is false)")

    def test_coverage_with_required_review_exact_detail_met(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, "CODEOWNERS"), "w") as f:
                f.write("requirements.txt @acme/team\n")
            result = _eval_sca5_proactive_reviews(repo_dir, _governance(require_code_owner_review=True))
        self.assertEqual(result.status, STATUS_MET)
        self.assertEqual(result.detail, "CODEOWNERS covers requirements.txt, and the branch requires code-owner review before merge")


class LoadManualUpdatesProcessRefDirectTests(unittest.TestCase):
    def test_missing_file_returns_none(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as repo_dir:
            self.assertIsNone(_load_manual_updates_process_ref(Path(repo_dir)))

    def test_malformed_json_returns_none(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as repo_dir:
            os.makedirs(os.path.join(repo_dir, ".lucid"))
            with open(os.path.join(repo_dir, ".lucid", "manual-updates.json"), "w") as f:
                f.write("{not valid json")
            self.assertIsNone(_load_manual_updates_process_ref(Path(repo_dir)))

    def test_wrong_schema_version_returns_none(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as repo_dir:
            _write_manual_updates_config(repo_dir, "docs/x.md")
            with open(os.path.join(repo_dir, ".lucid", "manual-updates.json"), "w") as f:
                json.dump({"schema_version": "wrong/v0", "process_ref": "docs/x.md"}, f)
            self.assertIsNone(_load_manual_updates_process_ref(Path(repo_dir)))

    def test_empty_process_ref_returns_none(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as repo_dir:
            _write_manual_updates_config(repo_dir, "   ")
            self.assertIsNone(_load_manual_updates_process_ref(Path(repo_dir)))

    def test_valid_process_ref_returned_verbatim(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as repo_dir:
            _write_manual_updates_config(repo_dir, "docs/manual-updates.md")
            self.assertEqual(_load_manual_updates_process_ref(Path(repo_dir)), "docs/manual-updates.md")


class ProcessRefIsUrlDirectTests(unittest.TestCase):
    def test_https_url_is_true(self):
        self.assertTrue(_process_ref_is_url("https://wiki.example.com/docs"))

    def test_http_url_is_true(self):
        self.assertTrue(_process_ref_is_url("http://wiki.example.com/docs"))

    def test_relative_path_is_false(self):
        self.assertFalse(_process_ref_is_url("docs/manual-updates.md"))

    def test_unsupported_scheme_is_false(self):
        self.assertFalse(_process_ref_is_url("ftp://example.com/docs"))

    def test_scheme_with_no_netloc_is_false(self):
        self.assertFalse(_process_ref_is_url("https://"))


class Upd1DirectFieldTests(unittest.TestCase):
    def test_unresolvable_repo_dir_exact_detail(self):
        result = _eval_upd1_manual_updates("bad\x00path")
        self.assertEqual(result.status, STATUS_NOT_YET_REPORTED)
        self.assertEqual(result.detail, "repo_dir 'bad\\x00path' could not be resolved")


class FindDependabotAutomergeWorkflowDirectTests(unittest.TestCase):
    def test_no_github_directory_returns_none(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            self.assertIsNone(_find_dependabot_automerge_workflow(repo_dir))

    def test_workflows_directory_with_no_yaml_files_returns_none(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            workflows_dir = os.path.join(repo_dir, ".github", "workflows")
            os.makedirs(workflows_dir)
            with open(os.path.join(workflows_dir, "readme.txt"), "w") as f:
                f.write("dependabot/fetch-metadata mentioned but wrong extension\n")
            self.assertIsNone(_find_dependabot_automerge_workflow(repo_dir))

    def test_yaml_workflow_without_marker_returns_none(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            workflows_dir = os.path.join(repo_dir, ".github", "workflows")
            os.makedirs(workflows_dir)
            with open(os.path.join(workflows_dir, "ci.yml"), "w") as f:
                f.write("on: push\njobs:\n  build:\n    steps:\n      - run: echo hi\n")
            self.assertIsNone(_find_dependabot_automerge_workflow(repo_dir))

    def test_yaml_workflow_with_marker_returns_real_path(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            workflows_dir = os.path.join(repo_dir, ".github", "workflows")
            os.makedirs(workflows_dir)
            with open(os.path.join(workflows_dir, "automerge.yml"), "w") as f:
                f.write("uses: dependabot/fetch-metadata@v2\n")
            self.assertEqual(_find_dependabot_automerge_workflow(repo_dir), ".github/workflows/automerge.yml")

    def test_yml_and_yaml_extensions_both_recognized(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            workflows_dir = os.path.join(repo_dir, ".github", "workflows")
            os.makedirs(workflows_dir)
            with open(os.path.join(workflows_dir, "automerge.yaml"), "w") as f:
                f.write("uses: dependabot/fetch-metadata@v2\n")
            self.assertEqual(_find_dependabot_automerge_workflow(repo_dir), ".github/workflows/automerge.yaml")


class CanonicalEntriesBytesAndDigestDirectTests(unittest.TestCase):
    def test_canonical_bytes_are_sorted_keys_compact_separators(self):
        entries = [{"name": "evil", "ecosystem": "pypi", "reason": "bad"}]
        result = _canonical_entries_bytes(entries)
        self.assertEqual(result, b'[{"ecosystem":"pypi","name":"evil","reason":"bad"}]')

    def test_key_order_does_not_affect_the_digest(self):
        entries_a = [{"name": "evil", "ecosystem": "pypi", "reason": "bad"}]
        entries_b = [{"reason": "bad", "ecosystem": "pypi", "name": "evil"}]
        self.assertEqual(compute_denylist_digest(entries_a), compute_denylist_digest(entries_b))

    def test_digest_changes_when_entries_change(self):
        digest_empty = compute_denylist_digest([])
        digest_one = compute_denylist_digest([{"name": "evil", "ecosystem": "pypi", "reason": "bad"}])
        self.assertNotEqual(digest_empty, digest_one)


class LoadDenylistDirectFieldTests(unittest.TestCase):
    def test_missing_file_exact_reason(self):
        from pathlib import Path
        path = Path(tempfile.mkdtemp()) / "denylist.json"
        doc, reason = load_denylist(path)
        self.assertIsNone(doc)
        self.assertEqual(reason, f"no denylist policy artifact found at {path}")

    def test_malformed_json_reason_names_the_resolved_path(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as repo_dir:
            path = Path(repo_dir) / "denylist.json"
            path.write_text("{not valid json")
            doc, reason = load_denylist(path)
        self.assertIsNone(doc)
        self.assertIn(str(path), reason)
        self.assertIn("is not valid JSON", reason)

    def test_missing_digest_exact_reason(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as repo_dir:
            path = Path(repo_dir) / "denylist.json"
            path.write_text(json.dumps({"schema_version": DENYLIST_SCHEMA_VERSION, "entries": []}))
            doc, reason = load_denylist(path)
        self.assertIsNone(doc)
        self.assertEqual(reason, f"{path} is missing 'digest_sha256'")


class Ing3SingularPluralDirectTests(unittest.TestCase):
    def test_single_resolved_dependency_singular_grammar(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            denylist_path = Path(repo_dir) / "denylist.json"
            _write_denylist(str(denylist_path), [])
            result = _eval_ing3_denylists(denylist_path, [{"uri": "pkg:pypi/requests@2.31.0"}])
        self.assertEqual(result.status, STATUS_MET)
        self.assertEqual(result.detail, "denylist artifact present, schema-valid, digest-verified (0 entries); none matched the 1 resolved dependency checked")

    def test_two_resolved_dependencies_plural_grammar(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            from pathlib import Path
            denylist_path = Path(repo_dir) / "denylist.json"
            _write_denylist(str(denylist_path), [])
            result = _eval_ing3_denylists(denylist_path, [{"uri": "pkg:pypi/requests@2.31.0"}, {"uri": "pkg:pypi/flask@3.0.0"}])
        self.assertEqual(result.status, STATUS_MET)
        self.assertEqual(result.detail, "denylist artifact present, schema-valid, digest-verified (0 entries); none matched the 2 resolved dependencies checked")


class Ing4DirectFieldTests(unittest.TestCase):
    def test_exact_detail(self):
        result = _eval_ing4_source_cloning()
        self.assertEqual(result.status, STATUS_UNMET)
        self.assertEqual(result.detail, "no generic, repo-observable signal exists for upstream-source mirroring; no such infrastructure is operated today")


if __name__ == "__main__":
    unittest.main()
