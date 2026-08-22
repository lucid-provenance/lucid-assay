import base64
import json
from cli.verify import verify_dsse_attestation

def generate_envelope(override):
    envelope = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://tenax.io/attestations/assay/v1",
            "subject": [{"name": "foo", "digest": {"sha256": "abcdef"}}],
            "predicate": {
                "release_confidence_score": {
                    "value": 10,
                    "degraded": False
                }
            }
        }).encode()).decode(),
        "signatures": [{"sig": "something", "certificate": "cert"}]
    }
    envelope.update(override)
    return envelope
