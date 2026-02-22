"""SDK helpers for liveness challenge flow."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from iap_sdk.continuity.signing import LIVENESS_ISSUED_INTENT, build_liveness_response_to_sign
from iap_sdk.errors import RegistryUnavailableError


def request_liveness_challenge(*, base_url: str, agent_id: str, timeout: float = 10.0) -> dict:
    try:
        import requests

        response = requests.post(
            f"{base_url.rstrip('/')}/v1/liveness/challenges",
            json={"agent_id": agent_id},
            timeout=timeout,
        )
    except Exception as exc:  # pragma: no cover
        raise RegistryUnavailableError(str(exc)) from exc

    if response.status_code >= 400:
        raise RegistryUnavailableError(
            f"liveness challenge request failed: {response.status_code} {response.text}"
        )
    return response.json()


def build_liveness_response(
    *,
    challenge_id: str,
    agent_id: str,
    nonce: str,
    private_key_bytes: bytes,
) -> dict:
    payload = {
        "challenge_id": challenge_id,
        "agent_id": agent_id,
        "nonce": nonce,
        "issued_intent": LIVENESS_ISSUED_INTENT,
    }
    canonical = build_liveness_response_to_sign(payload)
    signature = Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(canonical)
    return {
        "agent_id": agent_id,
        "issued_intent": LIVENESS_ISSUED_INTENT,
        "agent_signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def respond_liveness_challenge(
    *,
    base_url: str,
    challenge_id: str,
    payload: dict,
    timeout: float = 10.0,
) -> dict:
    try:
        import requests

        response = requests.post(
            f"{base_url.rstrip('/')}/v1/liveness/challenges/{challenge_id}/respond",
            json=payload,
            timeout=timeout,
        )
    except Exception as exc:  # pragma: no cover
        raise RegistryUnavailableError(str(exc)) from exc

    if response.status_code >= 400:
        raise RegistryUnavailableError(
            f"liveness challenge response failed: {response.status_code} {response.text}"
        )
    return response.json()


def verify_liveness_attestation(challenge_status: dict) -> bool:
    return challenge_status.get("status") == "VERIFIED"
