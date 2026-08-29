import base64
import json
import math
import pytest
from cli.verify import verify_dsse_attestation

def create_envelope(payload_override=None, envelope_override=None):
    payload = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://lucidprovenance.io/attestations/assay/v1",
        "subject": [{"name": "foo", "digest": {"sha256": "abcdef"}}],
        "predicate": {
            "release_confidence_score": {
                "value": 10,
                "degraded": False
            }
        }
    }
    if payload_override:
        payload.update(payload_override)
    
    envelope = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(payload).encode()).decode(),
        "signatures": [{"sig": "DRY_RUN_UNSIGNED", "certificate": "DRY_RUN_NO_CERT"}]
    }
    if envelope_override:
        envelope.update(envelope_override)
    return envelope

def test_exact_match_verification():
    # 1. Exact Match Verification
    env = create_envelope()
    res = verify_dsse_attestation(env, require_digest="sha256:abc")
    assert res.passed is False
    assert any("not found among attested digests" in v for v in res.violations)
    
    res2 = verify_dsse_attestation(env, require_digest="sha256:bcde")
    assert res2.passed is False
    
    res3 = verify_dsse_attestation(env, require_digest="sha256:abcdef")
    assert res3.passed is True

def test_non_standard_numeric_scores():
    # 2. Non-Standard Numeric Scores
    env = create_envelope({"predicate": {"release_confidence_score": {"value": "85.0", "degraded": False}}})
    res = verify_dsse_attestation(env, min_rcs=10)
    assert res.passed is False

    env = create_envelope({"predicate": {"release_confidence_score": {"value": math.nan, "degraded": False}}})
    res = verify_dsse_attestation(env, min_rcs=10)
    assert res.passed is False

    env = create_envelope({"predicate": {"release_confidence_score": {"value": math.inf, "degraded": False}}})
    res = verify_dsse_attestation(env, min_rcs=10)
    # The requirement says "Ensure the verifier returns valid=False or safely handles comparisons"
    # Wait, the prompt says "Ensure the verifier returns valid=False or safely handles comparisons."
    # Let's say valid=False for infinity
    assert res.passed is False

    env = create_envelope({"predicate": {"release_confidence_score": {"value": -5.5, "degraded": False}}})
    res = verify_dsse_attestation(env, min_rcs=0)
    assert res.passed is False

def test_predicate_schema_verification():
    # 3. Predicate Schema Verification
    env = create_envelope({"predicateType": "https://wrong.url"})
    res = verify_dsse_attestation(env)
    assert res.passed is False
    assert any("predicateType" in v for v in res.violations)

def test_malformed_subject_and_metrics_trees():
    # Empty subject
    env = create_envelope({"subject": []})
    res = verify_dsse_attestation(env, require_digest="sha256:abcdef")
    assert res.passed is False

    # Multiple subjects
    env = create_envelope({"subject": [
        {"name": "foo", "digest": {"sha256": "abcdef"}},
        {"name": "bar", "digest": {"sha256": "123456"}}
    ]})
    res = verify_dsse_attestation(env, require_digest="sha256:123456")
    assert res.passed is True

    # wrong data types in metrics/scoring
    env = create_envelope({"predicate": {
        "release_confidence_score": "this is a string, not a dict",
        "test_verification": "not a dict",
        "coverage": None,
        "assertion_density": []
    }})
    res = verify_dsse_attestation(env)
    assert res.passed is False
    
    # Degraded boolean truthiness: string "false"
    env = create_envelope({"predicate": {"release_confidence_score": {"value": 10, "degraded": "false"}}})
    res = verify_dsse_attestation(env, disallow_degraded=True)
    # If strictly checking `is True`, "false" should not trigger violation, but the type is wrong
    # Let's assert it gracefully handles it, maybe fails on validation
    assert res.passed is False
    
def test_envelope_structure_boundaries():
    env = create_envelope(envelope_override={"signatures": [{}]})
    res = verify_dsse_attestation(env)
    assert isinstance(res.passed, bool)

    env = {}
    res = verify_dsse_attestation(env)
    assert res.passed is False

    env = create_envelope(envelope_override={"payload": "aGVsbG8="})
    res = verify_dsse_attestation(env)
    assert res.passed is False
    
    env = create_envelope(envelope_override={"payloadType": "wrong"})
    res = verify_dsse_attestation(env)
    assert res.passed is False
