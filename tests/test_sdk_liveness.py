from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from iap_sdk.continuity.signing import build_liveness_response_to_sign
from iap_sdk.crypto.agent_identity import derive_agent_id
from iap_sdk.crypto.ed25519_verify import verify_ed25519
from iap_sdk.liveness import build_liveness_response, verify_liveness_attestation


def test_build_liveness_response_produces_valid_signature() -> None:
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    agent_id = derive_agent_id(public_bytes)

    payload = build_liveness_response(
        challenge_id="challenge-1",
        agent_id=agent_id,
        nonce="nonce-1",
        private_key_bytes=private_bytes,
    )

    canonical = build_liveness_response_to_sign(
        {
            "challenge_id": "challenge-1",
            "agent_id": agent_id,
            "nonce": "nonce-1",
            "issued_intent": payload["issued_intent"],
        }
    )
    signature = base64.b64decode(payload["agent_signature_b64"])
    assert verify_ed25519(signature, canonical, public_bytes) is True


def test_verify_liveness_attestation_status() -> None:
    assert verify_liveness_attestation({"status": "VERIFIED"}) is True
    assert verify_liveness_attestation({"status": "PENDING"}) is False
