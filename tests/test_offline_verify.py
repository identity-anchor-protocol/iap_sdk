from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from iap_sdk.certificates import IDENTITY_TYPE, KEY_ROTATION_TYPE, PROTOCOL_VERSION
from iap_sdk.crypto.agent_identity import derive_agent_id
from iap_sdk.offline_verify import verify_certificate_dict


def _identity_cert(private: Ed25519PrivateKey, public_key: bytes) -> dict:
    cert = {
        "certificate_version": PROTOCOL_VERSION,
        "certificate_type": IDENTITY_TYPE,
        "agent_id": derive_agent_id(public_key),
        "agent_public_key_b64": base64.b64encode(public_key).decode("ascii"),
        "issued_at": "2026-02-21T00:00:00Z",
        "registry_id": "iap-registry-test",
        "metadata": {"agent_name": "Atlas"},
    }
    canonical = json.dumps(cert, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    cert["registry_signature_b64"] = base64.b64encode(private.sign(canonical)).decode("ascii")
    return cert


def test_offline_verify_valid_identity_certificate() -> None:
    registry_private = Ed25519PrivateKey.generate()
    registry_public_b64 = base64.b64encode(
        registry_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")

    agent_private = Ed25519PrivateKey.generate()
    agent_public = agent_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    cert = _identity_cert(registry_private, agent_public)
    ok, reason = verify_certificate_dict(cert, registry_public_key_b64=registry_public_b64)

    assert ok is True
    assert reason == "ok"


def test_offline_verify_fails_for_tampered_certificate() -> None:
    registry_private = Ed25519PrivateKey.generate()
    registry_public_b64 = base64.b64encode(
        registry_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")

    agent_private = Ed25519PrivateKey.generate()
    agent_public = agent_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    cert = _identity_cert(registry_private, agent_public)
    cert["agent_id"] = "ed25519:tamperedtamperedtamperedtampered"

    ok, reason = verify_certificate_dict(cert, registry_public_key_b64=registry_public_b64)
    assert ok is False
    assert reason in {"agent_id derivation mismatch", "invalid registry signature"}


def test_offline_verify_key_rotation_certificate() -> None:
    registry_private = Ed25519PrivateKey.generate()
    registry_public_b64 = base64.b64encode(
        registry_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")

    old_agent_private = Ed25519PrivateKey.generate()
    old_agent_public = old_agent_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    new_agent_private = Ed25519PrivateKey.generate()
    new_agent_public = new_agent_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    cert = {
        "certificate_version": PROTOCOL_VERSION,
        "certificate_type": KEY_ROTATION_TYPE,
        "agent_id": derive_agent_id(new_agent_public),
        "old_agent_id": derive_agent_id(old_agent_public),
        "new_agent_id": derive_agent_id(new_agent_public),
        "old_agent_public_key_b64": base64.b64encode(old_agent_public).decode("ascii"),
        "new_agent_public_key_b64": base64.b64encode(new_agent_public).decode("ascii"),
        "issued_at": "2026-02-22T00:00:00Z",
        "registry_id": "iap-registry-test",
    }
    canonical = json.dumps(cert, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    cert["registry_signature_b64"] = base64.b64encode(registry_private.sign(canonical)).decode(
        "ascii"
    )

    ok, reason = verify_certificate_dict(cert, registry_public_key_b64=registry_public_b64)
    assert ok is True
    assert reason == "ok"
