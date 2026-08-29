import json
import base64
import pytest
from pathlib import Path

from cli.verify import verify_dsse_attestation, VerificationResult
from cli.parsers.sarif import parse_sarif_file, aggregate_sarif_reports, SarifSummaryReport, SarifFinding


# --- Helper functions to create mock payloads ---

def _create_mock_dsse_envelope(
    payload: dict,
    sig: str = "DRY_RUN_UNSIGNED",
    cert: str = "DRY_RUN_NO_CERT"
) -> dict:
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8"),
        "signatures": [{"sig": sig, "certificate": cert}],
    }

def _get_valid_statement_base(rcs_value=100, degraded=False):
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://lucidprovenance.io/attestations/assay/v1",
        "subject": [{"name": "test", "digest": {"sha256": "abcdef"}}],
        "predicate": {
            "release_confidence_score": {
                "value": rcs_value,
                "degraded": degraded
            }
        }
    }


# --- 1. Identity & Certificate Claim Validation (cli/verify.py) Boundaries ---

class TestIdentityAndCertificateBoundaries:
    
    def test_repository_mismatch_strictly_rejected(self):
        # dry_run=True (used elsewhere in this file) skips identity
        # verification entirely, so it can't exercise a repository
        # mismatch at all -- unit test the composed policy object
        # directly instead (same approach as
        # tests/test_verify.py::CertificateIdentityClaimsTests), against
        # a synthetic Fulcio-shaped cert genuinely minted for a different
        # repository than --expected-repository asserts.
        from sigstore.errors import VerificationError

        from cli.verify import GITHUB_ACTIONS_OIDC_ISSUER, _build_identity_policy
        from tests._fulcio_cert_helpers import _make_fulcio_style_cert

        cert = _make_fulcio_style_cert(repository="acme/widgets", issuer=GITHUB_ACTIONS_OIDC_ISSUER)
        policy, _, _ = _build_identity_policy(
            cert_identity=None,
            cert_oidc_issuer=None,
            expected_issuer=None,
            expected_repository="attacker/evil-fork",
            expected_workflow=None,
            expected_ref=None,
        )

        with pytest.raises(VerificationError):
            policy.verify(cert)

    def test_malformed_envelope_payloads(self):
        # 1. Invalid JSON in base64 payload
        bad_base64 = base64.b64encode(b"not json").decode("utf-8")
        envelope = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": bad_base64,
            "signatures": [{"sig": "test", "certificate": "test"}]
        }
        res = verify_dsse_attestation(envelope, dry_run=True)
        assert res.passed is False
        assert any("failed to decode DSSE payload" in v for v in res.violations)
        
        # 2. Valid base64 but not a JSON object
        bad_json_b64 = base64.b64encode(b'["list", "instead", "of", "dict"]').decode("utf-8")
        envelope["payload"] = bad_json_b64
        res = verify_dsse_attestation(envelope, dry_run=True)
        assert res.passed is False
        assert any("decoded DSSE payload is not a JSON object" in v for v in res.violations)
        
        # 3. Missing signatures list
        envelope["payload"] = base64.b64encode(b'{}').decode("utf-8")
        envelope["signatures"] = []
        res = verify_dsse_attestation(envelope, dry_run=True)
        assert res.passed is False
        assert any("no signatures" in v for v in res.violations)
        
        # 4. Completely corrupt structure
        res = verify_dsse_attestation(["not", "dict"], dry_run=True) # type: ignore
        assert res.passed is False
        assert "DSSE envelope is not a JSON object" in res.violations

    def test_non_standard_rcs_values(self):
        statement = _get_valid_statement_base()
        
        # Test string value for RCS
        statement["predicate"]["release_confidence_score"]["value"] = "100"
        envelope = _create_mock_dsse_envelope(statement)
        res = verify_dsse_attestation(envelope, dry_run=True)
        assert res.passed is False
        assert any("invalid release_confidence_score.value" in v for v in res.violations)
        
        # Test boolean value
        statement["predicate"]["release_confidence_score"]["value"] = True
        envelope = _create_mock_dsse_envelope(statement)
        res = verify_dsse_attestation(envelope, dry_run=True)
        assert res.passed is False
        assert any("invalid release_confidence_score.value" in v for v in res.violations)

        # Test NaN
        statement["predicate"]["release_confidence_score"]["value"] = float("nan")
        envelope = _create_mock_dsse_envelope(statement)
        res = verify_dsse_attestation(envelope, dry_run=True)
        assert res.passed is False
        assert any("invalid release_confidence_score.value" in v for v in res.violations)


# --- 2. SARIF Parsing & Path Normalization Boundaries ---

class TestSarifParsingBoundaries:
    
    def test_relative_path_normalization(self, tmp_path):
        # We need to test if `cli/../cli/scorer.py` normalizes correctly
        # We can construct a dummy SARIF file and parse it.
        sarif_data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "test-tool"}},
                    "results": [
                        {
                            "ruleId": "TEST-1",
                            "level": "error",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "cli/../cli/scorer.py"
                                        },
                                        "region": {"startLine": 10}
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        sarif_file = tmp_path / "test.sarif"
        sarif_file.write_text(json.dumps(sarif_data))
        
        # We mock patch modified lines to see if it correctly correlates
        patch_modified = {"cli/scorer.py": {10}}
        
        report = parse_sarif_file(sarif_file, patch_modified_lines=patch_modified)
        assert report.available is True
        assert len(report.findings) == 1
        finding = report.findings[0]
        # Should normalize 'cli/../cli/scorer.py' to 'cli/scorer.py'
        assert finding.file_path == "cli/scorer.py"
        assert finding.is_new_in_patch is True
        
        # Try with file:// prefix and leading slashes
        sarif_data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "file:///absolute/path/../path/file.py"
        sarif_file.write_text(json.dumps(sarif_data))
        report = parse_sarif_file(sarif_file)
        assert report.findings[0].file_path == "absolute/path/file.py"

    def test_aggregation_precedence(self):
        # One tool reports 0 findings, another reports errors.
        # aggregate_sarif_reports should retain errors and fail closed if unavailable.
        good_report = SarifSummaryReport(available=True, total_findings=0)
        bad_report = SarifSummaryReport(
            available=True, 
            total_findings=1, 
            errors_count=1,
            findings=[SarifFinding("tool", "rule", "error", "msg", "file", 1)]
        )
        unavailable_report = SarifSummaryReport(available=False, reasons=["corrupt"])
        
        # Good + Bad = Aggregate has findings
        agg1 = aggregate_sarif_reports([good_report, bad_report])
        assert agg1.available is True
        assert agg1.total_findings == 1
        assert agg1.errors_count == 1
        
        # Good + Unavailable = Aggregate unavailable (fail closed)
        agg2 = aggregate_sarif_reports([good_report, unavailable_report])
        assert agg2.available is False
        assert "corrupt" in agg2.reasons

    def test_malformed_line_indices(self, tmp_path):
        sarif_data = {
            "runs": [
                {
                    "tool": {"driver": {"name": "test-tool"}},
                    "results": [
                        {
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "file.py"},
                                        "region": {"startLine": 0} # 0
                                    }
                                }
                            ]
                        },
                        {
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "file2.py"},
                                        "region": {"startLine": "invalid"} # String instead of int
                                    }
                                }
                            ]
                        },
                        {
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "file3.py"}
                                        # Missing region entirely
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        sarif_file = tmp_path / "test.sarif"
        sarif_file.write_text(json.dumps(sarif_data))
        
        report = parse_sarif_file(sarif_file)
        assert report.available is True
        assert len(report.findings) == 3
        # Should default to 0 for invalid/missing lines safely
        for finding in report.findings:
            assert finding.start_line == 0

    def test_empty_incomplete_runs(self, tmp_path):
        sarif_file = tmp_path / "empty.sarif"
        
        # Empty runs
        sarif_file.write_text(json.dumps({"runs": []}))
        report = parse_sarif_file(sarif_file)
        assert report.available is True
        assert report.total_findings == 0
        
        # Missing results
        sarif_file.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "test"}}}]}))
        report = parse_sarif_file(sarif_file)
        assert report.available is True
        assert report.total_findings == 0
        
        # Omitted driver name
        sarif_file.write_text(json.dumps({"runs": [{"tool": {}, "results": [{"ruleId": "r1", "level": "warning"}]}]}))
        report = parse_sarif_file(sarif_file)
        assert report.available is True
        assert report.findings[0].tool_name == "unknown"


# --- 3. Pipeline Telemetry & Telemetry Edge Cases ---

class TestPipelineTelemetryEdgeCases:
    
    def test_missing_base_sha(self):
        from cli.main import parse_args
        
        argv = [
            "--junit-xml", "report.xml",
            "--coverage-report", "coverage.xml",
            "--image-ref", "ghcr.io/test/test",
            "--image-digest", "sha256:abcd",
            "--head-sha", "1234",
            "--repository", "test/test",
            "--branch", "main",
            # Note: --base-sha is not provided
        ]
        
        args = parse_args(argv)
        assert args.base_sha is None
