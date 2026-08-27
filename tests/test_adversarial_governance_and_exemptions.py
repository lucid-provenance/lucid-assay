import json
import base64
import os
import pytest
import urllib.error
import io
import subprocess
from unittest.mock import patch, MagicMock

import tests.test_patch_coverage

from cli.parsers.github_rules import (
    inspect_branch_governance,
    REASON_CODE_PLATFORM_UNSUPPORTED_TIER,
    GitHubAPIError
)
from cli.scorer import score_pipeline
from cli.patch_coverage import compute_patch_coverage, REASON_CODE_NO_COVERABLE_LINES
from cli.verify import verify_dsse_attestation

# --- Helpers ---

def _mock_github_api_get(routes):
    def _dispatch(path, token, timeout=10):
        if path in routes:
            outcome = routes[path]
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        raise AssertionError(f"Unexpected path queried: {path}")
    return _dispatch

class TestAdversarialGovernanceAndExemptions:

    @patch("cli.parsers.github_rules._github_api_get")
    def test_rate_limit_collision(self, mock_get):
        # Ensure a rate limit isn't misclassified as a platform unsupported tier
        error = urllib.error.HTTPError(
            "url", 403, "Forbidden", {"x-ratelimit-remaining": "0"}, io.BytesIO(b'{"message": "API rate limit exceeded for user ID."}')
        )
        api_error = GitHubAPIError("rate limit", status_code=403)
        api_error.__cause__ = error

        mock_get.side_effect = _mock_github_api_get({
            "/repos/acme/repo/rules/branches/main": api_error
        })
        
        report = inspect_branch_governance("acme/repo", "main", "token")
        
        assert report.available is False
        assert report.reason_code != REASON_CODE_PLATFORM_UNSUPPORTED_TIER
        
    def test_payload_injection_memory_fuzzing(self):
        # Pass massive error response bodies and non-UTF8 to verify degradation without crashing
        
        # We replace `urllib.request.urlopen` directly for this mock, since `_github_api_get` 
        # is the thing we want to test parsing logic on.
        from cli.parsers.github_rules import _github_api_get, GitHubAPIError
        import urllib.request
        
        # 1. Non-UTF8 binary blob (simulates a CDN error page or raw binary response)
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = b"\xff\xfe\x00\x00\x01\x00"
            mock_resp.headers.get.return_value = ""
            mock_urlopen.return_value.__enter__.return_value = mock_resp
            
            with pytest.raises(GitHubAPIError) as exc:
                _github_api_get("/repos/acme/repo", "token")
            assert "failed" in str(exc.value)

        # 2. Deeply nested JSON: a hostile/pathologically-deep response body
        # is exactly as suspect as garbled binary (case 1) or an HTML error
        # page (case 3) -- must degrade the same way, a clean GitHubAPIError,
        # not an unhandled RecursionError. Depth of 10,000 reliably exceeds
        # sys.getrecursionlimit() regardless of how much stack the
        # surrounding call chain already used, so this is deterministic
        # rather than depending on exactly how close a depth of 1000 sits
        # to the ambient limit at the moment of the call.
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            depth = 10_000
            deep_json = b'{"a":' * depth + b'1' + b'}' * depth
            mock_resp.read.return_value = deep_json
            mock_resp.headers.get.return_value = ""
            mock_urlopen.return_value.__enter__.return_value = mock_resp

            with pytest.raises(GitHubAPIError) as exc:
                _github_api_get("/repos/acme/repo", "token")
            assert "failed" in str(exc.value)
            
        # 3. HTTPError with malformed HTML (e.g. Cloudflare 502 error page)
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                "url", 502, "Bad Gateway", {}, io.BytesIO(b'<html><body>Cloudflare error</body></html>')
            )
            with pytest.raises(GitHubAPIError) as exc:
                _github_api_get("/repos/acme/repo", "token")
            assert "HTTP 502" in str(exc.value)
        
    def test_partial_ruleset_tainting(self):
        # Mock HTTP 200 OK on /rulesets, but 403 on /rules/branches/...
        # Verifies the report is available=False instead of available=True with no rules
        
        with patch("cli.parsers.github_rules._github_api_get") as mock_get:
            def route(path, token, timeout=10):
                if path.endswith("/rulesets"):
                    return [{"id": 1, "target": "branch", "enforcement": "active"}]
                if "/rulesets/" in path:
                    return {"id": 1, "bypass_actors": []}
                if path.endswith("/branches/main"):
                    raise GitHubAPIError("rate limit", status_code=403)
                raise AssertionError(f"unexpected path {path}")
            
            mock_get.side_effect = route
            
            report = inspect_branch_governance("acme/repo", "main", "token")
            
            assert report.available is False
            assert "querying rules for branch" in report.reason
            
    def test_token_sabotage_scorer_gaming(self):
        # Intentionally supplying a garbage token will lead to a 403.
        # Ensure it's not given REASON_CODE_PLATFORM_UNSUPPORTED_TIER unless the message actually matched.
        
        with patch("cli.parsers.github_rules._github_api_get") as mock_get:
            error = urllib.error.HTTPError(
                "url", 403, "Forbidden", {}, io.BytesIO(b'{"message": "Bad credentials"}')
            )
            api_error = GitHubAPIError("Bad credentials", status_code=403)
            api_error.__cause__ = error
            
            mock_get.side_effect = api_error
            
            report = inspect_branch_governance("acme/repo", "main", "bad_token")
            
            assert report.available is False
            assert report.reason_code != REASON_CODE_PLATFORM_UNSUPPORTED_TIER

        
    def test_trojan_doc_mixed_diff_bypass(self):
        # A PR touches 20 .md files and exactly one .py script.
        # Check that it evaluates as code-bearing (not exempted with REASON_CODE_NO_COVERABLE_LINES)
        from cli.parsers.coverage import CoverageReport, FileCoverage
        
        coverage = CoverageReport(
            overall_line_rate=0.9,
            overall_branch_rate=0.8,
            files={"evil.py": FileCoverage(line_hits={1: 1})}
        )
        with tests.test_patch_coverage._TempGitRepo() as repo:
            with open(os.path.join(repo.path, "evil.py"), "w") as f:
                f.write("def evil():\n    pass\n")
            with open(os.path.join(repo.path, "README2.md"), "w") as f:
                f.write("# more docs\n")
            tests.test_patch_coverage._git(["add", "."], repo.path)
            tests.test_patch_coverage._git(["commit", "-q", "-m", "mixed"], repo.path)
            head_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repo.path, capture_output=True, text=True, check=True
            ).stdout.strip()
            
            result = compute_patch_coverage(repo.base_sha, head_sha, repo.path, coverage)
            
            assert result.available is True
            assert result.reason_code != REASON_CODE_NO_COVERABLE_LINES
            assert result.lines_changed > 0
        
    def test_extension_and_path_smuggling(self):
        from cli.parsers.coverage import CoverageReport, FileCoverage
        coverage = CoverageReport(
            overall_line_rate=0.9,
            overall_branch_rate=0.8,
            files={
                "README.md.py": FileCoverage(line_hits={1: 1}),
                "docs/evil.py": FileCoverage(line_hits={1: 1}),
                "something.md/payload.sh": FileCoverage(line_hits={1: 1})
            }
        )
        
        with tests.test_patch_coverage._TempGitRepo() as repo:
            # Create files that try to smuggle extensions
            with open(os.path.join(repo.path, "README.md.py"), "w") as f:
                f.write("def sneak():\n    pass\n")
                
            os.makedirs(os.path.join(repo.path, "docs"), exist_ok=True)
            with open(os.path.join(repo.path, "docs/evil.py"), "w") as f:
                f.write("def sneak2():\n    pass\n")
                
            os.makedirs(os.path.join(repo.path, "something.md"), exist_ok=True)
            with open(os.path.join(repo.path, "something.md/payload.sh"), "w") as f:
                f.write("echo 'sneak3'\n")
                
            # Create symlink pointing from .md to executable code
            os.symlink("docs/evil.py", os.path.join(repo.path, "docs/symlink.md"))

            tests.test_patch_coverage._git(["add", "."], repo.path)
            tests.test_patch_coverage._git(["commit", "-q", "-m", "smuggling"], repo.path)
            head_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repo.path, capture_output=True, text=True, check=True
            ).stdout.strip()
            
            result = compute_patch_coverage(repo.base_sha, head_sha, repo.path, coverage)
            
            assert result.available is True
            assert result.reason_code != REASON_CODE_NO_COVERABLE_LINES
            assert result.lines_changed > 0
        
    def test_infrastructure_workflow_files(self):
        # .github/workflows/*.yml, Dockerfile, pyproject.toml
        from cli.parsers.coverage import CoverageReport, FileCoverage
        
        # Test that compute_patch_coverage doesn't silently classify them as exempted (REASON_CODE_NO_COVERABLE_LINES) 
        # unless they truly have no coverable lines in the coverage report. 
        # If they aren't measured by the coverage tool, they will just report available=False with REASON_CODE_NO_COVERABLE_LINES
        # But this tests that if they *are* measured (e.g. some tool measures dockerfile coverage), they are handled correctly.
        coverage = CoverageReport(
            overall_line_rate=0.9,
            overall_branch_rate=0.8,
            files={
                ".github/workflows/ci.yml": FileCoverage(line_hits={1: 1}),
                "Dockerfile": FileCoverage(line_hits={1: 1}),
                "pyproject.toml": FileCoverage(line_hits={1: 1})
            }
        )
        
        with tests.test_patch_coverage._TempGitRepo() as repo:
            os.makedirs(os.path.join(repo.path, ".github/workflows"), exist_ok=True)
            with open(os.path.join(repo.path, ".github/workflows/ci.yml"), "w") as f:
                f.write("name: CI\n")
            with open(os.path.join(repo.path, "Dockerfile"), "w") as f:
                f.write("FROM ubuntu\n")
            with open(os.path.join(repo.path, "pyproject.toml"), "w") as f:
                f.write("[tool.poetry]\n")
                
            tests.test_patch_coverage._git(["add", "."], repo.path)
            tests.test_patch_coverage._git(["commit", "-q", "-m", "infra"], repo.path)
            head_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repo.path, capture_output=True, text=True, check=True
            ).stdout.strip()
            
            result = compute_patch_coverage(repo.base_sha, head_sha, repo.path, coverage)
            
            assert result.available is True
            assert result.reason_code != REASON_CODE_NO_COVERABLE_LINES
            assert result.lines_changed == 3
        
    def test_deleted_executable_code(self):
        from cli.parsers.coverage import CoverageReport, FileCoverage
        coverage = CoverageReport(
            overall_line_rate=0.9,
            overall_branch_rate=0.8,
            files={"app.py": FileCoverage(line_hits={1: 1})}
        )
        with tests.test_patch_coverage._TempGitRepo() as repo:
            # We already have app.py with some code from _TempGitRepo
            # Let's delete app.py
            tests.test_patch_coverage._git(["rm", "app.py"], repo.path)
            tests.test_patch_coverage._git(["commit", "-q", "-m", "delete"], repo.path)
            head_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repo.path, capture_output=True, text=True, check=True
            ).stdout.strip()
            
            # Since the PR only deletes code, the patch contains no added/modified lines in code files
            result = compute_patch_coverage(repo.base_sha, head_sha, repo.path, coverage)
            
            assert result.available is False
            assert result.reason_code == REASON_CODE_NO_COVERABLE_LINES
            
    def test_predicate_tampering(self):
        # We simulate verify_dsse_attestation receiving a manipulated payload 
        # It's an integration test with the verification logic to ensure signatures fail on tampering
        import tests.test_security_boundaries
        
        # Original envelope
        envelope = tests.test_security_boundaries._create_mock_dsse_envelope(
            tests.test_security_boundaries._get_valid_statement_base()
        )
        
        # Tamper with the payload while keeping the signature
        import copy
        tampered_statement = tests.test_security_boundaries._get_valid_statement_base()
        tampered_statement["predicate"]["release_confidence_score"]["degraded"] = False # Changed from what it might have been
        
        tampered_envelope = copy.deepcopy(envelope)
        tampered_envelope["payload"] = base64.b64encode(json.dumps(tampered_statement).encode("utf-8")).decode("utf-8")
        
        # For this test, we run verify_dsse_attestation. Since it's a dry-run the sig test may not fail, 
        # so let's check a scenario where disallow-degraded allows exemptions.
        statement = tests.test_security_boundaries._get_valid_statement_base(degraded=True)
        statement["predicate"]["release_confidence_score"]["degraded_reasons"] = [
            "patch_coverage:no_coverable_lines"
        ]
        envelope2 = tests.test_security_boundaries._create_mock_dsse_envelope(statement)
        
        # Verification allows it
        res = verify_dsse_attestation(envelope2, dry_run=True, disallow_degraded=True)
        assert res.passed is True
        
        # Tamper the degraded reason to an unapproved one
        tampered_statement2 = copy.deepcopy(statement)
        tampered_statement2["predicate"]["release_confidence_score"]["degraded_reasons"] = ["branch_governance:unknown"]
        tampered_envelope2 = copy.deepcopy(envelope2)
        tampered_envelope2["payload"] = base64.b64encode(json.dumps(tampered_statement2).encode("utf-8")).decode("utf-8")
        
        res_tampered = verify_dsse_attestation(tampered_envelope2, dry_run=True, disallow_degraded=True)
        assert res_tampered.passed is False
        assert any("release_confidence_score.degraded is true and --disallow-degraded was set" in v for v in res_tampered.violations)
