"""
Tests for the Repository & Workstation Governance section
(predicate.repository_governance -- cli/verify.py's
_extract_repository_governance / _repo_gov_check_* /
_format_repository_governance_report, plus the --require-commit-signing
opt-in gate). Compensating controls for a solo-maintained repo that
structurally can't satisfy SLSA Source Level 4 -- see cli/verify.py's own
module docstring and cli/parsers/github_rules.py /
cli/parsers/commit_author.py for where the underlying signals come from.
Mirrors tests/test_source_track_and_build_l3.py's style for the
RequireSlsaBuildL3Tests-shaped gating tests.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import unittest
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.verify import (
    _build_verify_json_payload,
    _extract_repository_governance,
    _format_repository_governance_report,
    _render_step_summary_markdown,
    _repo_gov_check_commit_signing,
    _repo_gov_check_deletions_blocked,
    _repo_gov_check_force_pushes_blocked,
    _repo_gov_check_linear_history,
    verify_dsse_attestation,
)

SUBJECT_DIGEST = "a" * 64


def _repo_gov(
    *,
    available=True,
    linear_history_required=True,
    force_pushes_blocked=True,
    deletions_blocked=True,
    commit_signature=None,
) -> Dict[str, Any]:
    return {
        "available": available,
        "linear_history_required": linear_history_required,
        "force_pushes_blocked": force_pushes_blocked,
        "deletions_blocked": deletions_blocked,
        "commit_signature": commit_signature,
    }


def _signed(sig_type="gpg", source_sha=None) -> Dict[str, Any]:
    return {"available": True, "verified": True, "reason": "valid", "signature_type": sig_type, "source_sha": source_sha}


def _unsigned(reason="unsigned", source_sha=None) -> Dict[str, Any]:
    return {"available": True, "verified": False, "reason": reason, "signature_type": None, "source_sha": source_sha}


def _statement(*, repository_governance=None, rcs_value=85) -> Dict[str, Any]:
    predicate: Dict[str, Any] = {
        "release_confidence_score": {
            "value": rcs_value,
            "algorithm_version": "rcs-v0.1",
            "components": {},
            "degraded": False,
        },
        "test_verification": {
            "totals": {"tests": 4, "passed": 4, "failed": 0, "errored": 0, "skipped": 0},
        },
        "coverage": {"overall": {"line_rate": 0.9, "branch_rate": 0.8}},
    }
    if repository_governance is not None:
        predicate["repository_governance"] = repository_governance
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "registry.example.com/org/svc", "digest": {"sha256": SUBJECT_DIGEST}}],
        "predicateType": "https://lucidprovenance.io/attestations/assay/v1",
        "predicate": predicate,
    }


def _envelope(statement: Dict[str, Any]) -> Dict[str, Any]:
    payload_b64 = base64.b64encode(json.dumps(statement).encode("utf-8")).decode("ascii")
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": payload_b64,
        "signatures": [{"sig": "DRY_RUN_UNSIGNED", "certificate": "DRY_RUN_NO_CERT"}],
    }


class ExtractRepositoryGovernanceTests(unittest.TestCase):
    def test_absent_block_returns_empty(self):
        self.assertEqual(_extract_repository_governance({}), [])

    def test_non_dict_block_treated_as_absent(self):
        self.assertEqual(_extract_repository_governance({"repository_governance": "nope"}), [])

    def test_present_block_yields_all_four_items_in_order(self):
        items = _extract_repository_governance({"repository_governance": _repo_gov(commit_signature=_signed())})
        labels = [i["label"] for i in items]
        self.assertEqual(len(items), 4)
        self.assertTrue(labels[0].startswith("Cryptographic Commit Signing"))
        self.assertTrue(labels[1].startswith("Linear History Enforced"))
        self.assertTrue(labels[2].startswith("Force Pushes Blocked"))
        self.assertTrue(labels[3].startswith("Branch Deletion Blocked"))

    def test_all_passing_when_fully_compliant(self):
        items = _extract_repository_governance({"repository_governance": _repo_gov(commit_signature=_signed())})
        self.assertTrue(all(i["passed"] for i in items))


class RepoGovCheckCommitSigningTests(unittest.TestCase):
    def test_missing_commit_signature_block_fails_closed(self):
        result = _repo_gov_check_commit_signing(_repo_gov(commit_signature=None))
        self.assertFalse(result["passed"])
        self.assertIn("not captured", result["detail"])

    def test_non_dict_commit_signature_treated_same_as_missing(self):
        repo_gov = _repo_gov()
        repo_gov["commit_signature"] = "nope"
        result = _repo_gov_check_commit_signing(repo_gov)
        self.assertFalse(result["passed"])
        self.assertIn("not captured", result["detail"])

    def test_unavailable_commit_signature_fails_with_its_own_detail(self):
        result = _repo_gov_check_commit_signing(_repo_gov(commit_signature={"available": False}))
        self.assertFalse(result["passed"])
        self.assertIn("unavailable", result["detail"])

    def test_verified_gpg_passes_with_signature_type_in_label(self):
        result = _repo_gov_check_commit_signing(_repo_gov(commit_signature=_signed("gpg")))
        self.assertTrue(result["passed"])
        self.assertIn("verified via GPG", result["label"])

    def test_verified_ssh_passes_with_signature_type_in_label(self):
        result = _repo_gov_check_commit_signing(_repo_gov(commit_signature=_signed("ssh")))
        self.assertTrue(result["passed"])
        self.assertIn("verified via SSH", result["label"])

    def test_verified_true_without_signature_type_omits_via_clause(self):
        commit_sig = _signed("gpg")
        commit_sig["signature_type"] = None
        result = _repo_gov_check_commit_signing(_repo_gov(commit_signature=commit_sig))
        self.assertTrue(result["passed"])
        self.assertIn("(verified)", result["label"])
        self.assertNotIn("via", result["label"])

    def test_unsigned_fails_with_github_reason_quoted(self):
        result = _repo_gov_check_commit_signing(_repo_gov(commit_signature=_unsigned("unsigned")))
        self.assertFalse(result["passed"])
        self.assertIn("(unsigned)", result["detail"])

    def test_unsigned_with_no_reason_still_fails_without_crashing(self):
        commit_sig = _unsigned()
        commit_sig["reason"] = None
        result = _repo_gov_check_commit_signing(_repo_gov(commit_signature=commit_sig))
        self.assertFalse(result["passed"])
        self.assertIn("unsigned or unverified", result["detail"])

    def test_verified_with_source_sha_notes_the_walk_back_in_the_label(self):
        """source_sha set means commit_author.py walked back through a
        GitHub-web-flow merge commit -- the label must say so, so a
        reader isn't misled into thinking HEAD itself (often the merge
        commit) was what got cryptographically verified."""
        commit_sig = _signed("ssh", source_sha="a" * 40)
        result = _repo_gov_check_commit_signing(_repo_gov(commit_signature=commit_sig))
        self.assertTrue(result["passed"])
        self.assertIn("verified via SSH on the PR's own head commit", result["label"])
        self.assertIn("not the merge commit", result["label"])

    def test_verified_without_source_sha_omits_the_walk_back_clause(self):
        commit_sig = _signed("gpg", source_sha=None)
        result = _repo_gov_check_commit_signing(_repo_gov(commit_signature=commit_sig))
        self.assertTrue(result["passed"])
        self.assertNotIn("PR's own head commit", result["label"])

    def test_unsigned_with_source_sha_notes_the_walk_back_in_the_detail(self):
        commit_sig = _unsigned("unsigned", source_sha="a" * 40)
        result = _repo_gov_check_commit_signing(_repo_gov(commit_signature=commit_sig))
        self.assertFalse(result["passed"])
        self.assertIn("PR's own head commit", result["detail"])

    def test_walk_back_failure_reason_surfaced_as_a_normal_failure(self):
        """commit_author.py reports a failed walk-back as
        verified=None/reason=<explanation> -- this must render as an
        honest failure, not silently pass."""
        commit_sig = {
            "available": True, "verified": None,
            "reason": "gave up walking back through GitHub-generated merge commits after 5 hops "
                      "without reaching a non-merge commit",
            "signature_type": None, "source_sha": "b" * 40,
        }
        result = _repo_gov_check_commit_signing(_repo_gov(commit_signature=commit_sig))
        self.assertFalse(result["passed"])
        self.assertIn("gave up walking back", result["detail"])


class RepoGovCheckLinearHistoryTests(unittest.TestCase):
    def test_unavailable_fails_closed(self):
        result = _repo_gov_check_linear_history(_repo_gov(available=False))
        self.assertFalse(result["passed"])
        self.assertIn("branch governance unavailable", result["detail"])

    def test_rule_active_passes(self):
        result = _repo_gov_check_linear_history(_repo_gov(linear_history_required=True))
        self.assertTrue(result["passed"])
        self.assertIn("merge commits disallowed", result["label"])

    def test_rule_inactive_fails_naming_the_rule_type(self):
        result = _repo_gov_check_linear_history(_repo_gov(linear_history_required=False))
        self.assertFalse(result["passed"])
        self.assertIn("required_linear_history", result["detail"])


class RepoGovCheckForcePushesBlockedTests(unittest.TestCase):
    def test_unavailable_fails_closed(self):
        result = _repo_gov_check_force_pushes_blocked(_repo_gov(available=False))
        self.assertFalse(result["passed"])
        self.assertIn("branch governance unavailable", result["detail"])

    def test_rule_active_passes(self):
        result = _repo_gov_check_force_pushes_blocked(_repo_gov(force_pushes_blocked=True))
        self.assertTrue(result["passed"])
        self.assertIn("history rewrite disabled", result["label"])

    def test_rule_inactive_fails_naming_the_rule_type(self):
        result = _repo_gov_check_force_pushes_blocked(_repo_gov(force_pushes_blocked=False))
        self.assertFalse(result["passed"])
        self.assertIn("non_fast_forward", result["detail"])


class RepoGovCheckDeletionsBlockedTests(unittest.TestCase):
    def test_unavailable_fails_closed(self):
        result = _repo_gov_check_deletions_blocked(_repo_gov(available=False))
        self.assertFalse(result["passed"])
        self.assertIn("branch governance unavailable", result["detail"])

    def test_rule_active_passes(self):
        result = _repo_gov_check_deletions_blocked(_repo_gov(deletions_blocked=True))
        self.assertTrue(result["passed"])

    def test_rule_inactive_fails_naming_the_rule_type(self):
        result = _repo_gov_check_deletions_blocked(_repo_gov(deletions_blocked=False))
        self.assertFalse(result["passed"])
        self.assertIn("deletion", result["detail"])


class FormatRepositoryGovernanceReportTests(unittest.TestCase):
    def test_empty_items_renders_no_section_at_all(self):
        self.assertEqual(_format_repository_governance_report([]), [])

    def test_header_reports_met_count(self):
        items = _extract_repository_governance({"repository_governance": _repo_gov(commit_signature=_unsigned())})
        text = "\n".join(_format_repository_governance_report(items))
        self.assertIn("=== Repository & Workstation Governance (Policy Assessment) (3/4 controls met) ===", text)

    def test_no_status_line_rendered(self):
        # Deliberate deviation from a leveled SLSA track: four independent
        # controls, not a cumulative pass/fail -- matches this codebase's
        # own S2C2F / Dependency Materialization Evidence convention.
        items = _extract_repository_governance({"repository_governance": _repo_gov(commit_signature=_signed())})
        text = "\n".join(_format_repository_governance_report(items))
        self.assertNotIn("Status:", text)
        self.assertTrue(text.rstrip("\n").endswith("====================================="))

    def test_failing_item_renders_cross_mark_and_detail(self):
        items = [_repo_gov_check_deletions_blocked(_repo_gov(deletions_blocked=False))]
        text = "\n".join(_format_repository_governance_report(items))
        self.assertIn("[✗] Branch Deletion Blocked -- no 'deletion' rule is active on this branch", text)

    def test_passing_item_renders_check_mark_no_trailing_dash(self):
        items = [_repo_gov_check_deletions_blocked(_repo_gov(deletions_blocked=True))]
        text = "\n".join(_format_repository_governance_report(items))
        self.assertIn("[✓] Branch Deletion Blocked", text)
        self.assertNotIn(" -- ", text.splitlines()[1])


class RepositoryGovernanceIntegrationTests(unittest.TestCase):
    """End-to-end via verify_dsse_attestation(): confirms the section
    reaches the shared step-summary report and the --format json payload,
    the same way DependencyGovernanceIntegrationTests does for its
    section (tests/test_verify.py)."""

    def test_step_summary_includes_repository_governance_section(self):
        statement = _statement(repository_governance=_repo_gov(commit_signature=_signed("ssh")))
        envelope = _envelope(statement)

        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)
        summary = _render_step_summary_markdown(result)

        self.assertIn("Repository & Workstation Governance", summary)
        self.assertIn("[✓] Cryptographic Commit Signing (verified via SSH)", summary)
        self.assertIn("[✓] Linear History Enforced", summary)

    def test_no_repository_governance_data_omits_the_section_entirely(self):
        envelope = _envelope(_statement())
        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        summary = _render_step_summary_markdown(result)

        self.assertNotIn("Repository & Workstation Governance", summary)

    def test_json_payload_carries_repository_governance_items(self):
        statement = _statement(repository_governance=_repo_gov(commit_signature=_signed()))
        envelope = _envelope(statement)

        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)
        payload = _build_verify_json_payload(result)

        self.assertEqual(len(payload["repository_governance"]["items"]), 4)
        json.dumps(payload)  # must remain JSON-serializable end to end

    def test_purely_informational_by_default_even_when_all_controls_fail(self):
        statement = _statement(
            repository_governance=_repo_gov(
                linear_history_required=False,
                force_pushes_blocked=False,
                deletions_blocked=False,
                commit_signature=_unsigned(),
            )
        )
        envelope = _envelope(statement)

        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        self.assertTrue(result.passed, result.violations)
        self.assertEqual(sum(1 for i in result.repository_governance_items if i["passed"]), 0)


class RequireCommitSigningTests(unittest.TestCase):
    """Mirrors tests/test_source_track_and_build_l3.py's
    RequireSlsaBuildL3Tests -- the exact same off-by-default,
    opt-in-folds-into-the-gate shape, but scoped to only the commit-
    signing item (the other three repository-governance controls have no
    gate path -- see cli/verify.py's --require-commit-signing help text)."""

    def test_flag_off_by_default_does_not_affect_gate(self):
        statement = _statement(repository_governance=_repo_gov(commit_signature=_unsigned()))
        envelope = _envelope(statement)

        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True)

        self.assertTrue(result.passed, result.violations)

    def test_require_flag_fails_the_gate_on_unsigned_commit(self):
        statement = _statement(repository_governance=_repo_gov(commit_signature=_unsigned()))
        envelope = _envelope(statement)

        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True, require_commit_signing=True)

        self.assertFalse(result.passed)
        self.assertTrue(
            any("--require-commit-signing" in v for v in result.violations), result.violations
        )

    def test_require_flag_passes_the_gate_on_verified_commit(self):
        statement = _statement(repository_governance=_repo_gov(commit_signature=_signed()))
        envelope = _envelope(statement)

        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True, require_commit_signing=True)

        self.assertTrue(result.passed, result.violations)

    def test_require_flag_fails_closed_when_no_repository_governance_data_at_all(self):
        envelope = _envelope(_statement())

        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True, require_commit_signing=True)

        self.assertFalse(result.passed)
        self.assertTrue(
            any("--require-commit-signing" in v for v in result.violations), result.violations
        )

    def test_require_flag_does_not_care_about_the_other_three_controls(self):
        """Only the commit-signing item feeds the gate -- a signed commit
        on a branch with zero ruleset hygiene must still pass with the
        flag set, since those three controls have no opt-in gate path."""
        statement = _statement(
            repository_governance=_repo_gov(
                linear_history_required=False,
                force_pushes_blocked=False,
                deletions_blocked=False,
                commit_signature=_signed(),
            )
        )
        envelope = _envelope(statement)

        result = verify_dsse_attestation(envelope, min_rcs=0, dry_run=True, require_commit_signing=True)

        self.assertTrue(result.passed, result.violations)


if __name__ == "__main__":
    unittest.main()
