"""Canonical request-to-sign builders for IAP requests."""

from __future__ import annotations

import json

CONTINUITY_ISSUED_INTENT = "IAP-Registry-Continuity-Request"
IDENTITY_ANCHOR_ISSUED_INTENT = "IAP-Registry-IdentityAnchor-Request"
LINEAGE_ISSUED_INTENT = "IAP-Registry-Lineage-Request"
LINEAGE_PARENT_CONSENT_ISSUED_INTENT = "IAP-Registry-Lineage-Parent-Consent"
KEY_ROTATION_ISSUED_INTENT = "IAP-Registry-KeyRotation-Request"
LIVENESS_ISSUED_INTENT = "IAP-Registry-Liveness-Challenge-Response"

_COMMON_REQUIRED_FIELDS = (
    "agent_id",
    "agent_public_key_b64",
    "nonce",
    "created_at",
    "agent_signature_b64",
)


def _reject_floats(value: object) -> None:
    if isinstance(value, float):
        raise ValueError("floats are not allowed")
    if isinstance(value, dict):
        for nested_value in value.values():
            _reject_floats(nested_value)
    elif isinstance(value, (list, tuple)):
        for nested_value in value:
            _reject_floats(nested_value)


def _assert_common(payload: dict) -> None:
    for field in _COMMON_REQUIRED_FIELDS:
        if field not in payload:
            raise ValueError(f"missing required field: {field}")

    if not isinstance(payload["agent_id"], str) or not payload["agent_id"]:
        raise ValueError("agent_id must be a non-empty string")
    if not isinstance(payload["agent_public_key_b64"], str) or not payload["agent_public_key_b64"]:
        raise ValueError("agent_public_key_b64 must be a non-empty string")
    if not isinstance(payload["nonce"], str) or not payload["nonce"]:
        raise ValueError("nonce must be a non-empty string")
    if not isinstance(payload["created_at"], str) or not payload["created_at"]:
        raise ValueError("created_at must be a non-empty string")


def _canonical_bytes(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def build_request_to_sign(payload: dict) -> bytes:
    """Build canonical bytes for continuity request signing."""
    _reject_floats(payload)
    _assert_common(payload)

    if (
        "memory_root" not in payload
        or not isinstance(payload["memory_root"], str)
        or not payload["memory_root"]
    ):
        raise ValueError("memory_root must be a non-empty string")
    if "sequence" not in payload:
        raise ValueError("missing required field: sequence")
    if not isinstance(payload["sequence"], int) or payload["sequence"] < 1:
        raise ValueError("sequence must be an int >= 1")
    if (
        "manifest_version" not in payload
        or not isinstance(payload["manifest_version"], str)
        or not payload["manifest_version"]
    ):
        raise ValueError("manifest_version must be a non-empty string")
    if (
        "manifest_hash" not in payload
        or not isinstance(payload["manifest_hash"], str)
        or not payload["manifest_hash"]
    ):
        raise ValueError("manifest_hash must be a non-empty string")

    issued_intent = payload.get("issued_intent", CONTINUITY_ISSUED_INTENT)
    if issued_intent != CONTINUITY_ISSUED_INTENT:
        raise ValueError("issued_intent must be IAP-Registry-Continuity-Request")

    canonical_payload = {
        "agent_id": payload["agent_id"],
        "agent_public_key_b64": payload["agent_public_key_b64"],
        "memory_root": payload["memory_root"],
        "sequence": payload["sequence"],
        "manifest_version": payload["manifest_version"],
        "manifest_hash": payload["manifest_hash"],
        "issued_intent": issued_intent,
        "nonce": payload["nonce"],
        "created_at": payload["created_at"],
    }
    if payload.get("agent_custody_class") is not None:
        canonical_payload["agent_custody_class"] = payload["agent_custody_class"]
    return _canonical_bytes(canonical_payload)


def build_identity_anchor_request_to_sign(payload: dict) -> bytes:
    """Build canonical bytes for identity-anchor request signing."""
    _reject_floats(payload)
    _assert_common(payload)

    issued_intent = payload.get("issued_intent", IDENTITY_ANCHOR_ISSUED_INTENT)
    if issued_intent != IDENTITY_ANCHOR_ISSUED_INTENT:
        raise ValueError("issued_intent must be IAP-Registry-IdentityAnchor-Request")

    canonical_payload = {
        "agent_id": payload["agent_id"],
        "agent_public_key_b64": payload["agent_public_key_b64"],
        "issued_intent": issued_intent,
        "nonce": payload["nonce"],
        "created_at": payload["created_at"],
    }
    return _canonical_bytes(canonical_payload)


def build_lineage_request_to_sign(payload: dict) -> bytes:
    """Build canonical bytes for lineage request signing."""
    _reject_floats(payload)
    _assert_common(payload)

    issued_intent = payload.get("issued_intent", LINEAGE_ISSUED_INTENT)
    if issued_intent != LINEAGE_ISSUED_INTENT:
        raise ValueError("issued_intent must be IAP-Registry-Lineage-Request")

    return _canonical_bytes(
        {
            "agent_id": payload["agent_id"],
            "agent_public_key_b64": payload["agent_public_key_b64"],
            "parent_agent_id": payload.get("parent_agent_id"),
            "fork_event_hash": payload.get("fork_event_hash"),
            "lineage_proof_policy": payload.get("lineage_proof_policy", "parent_anchor_exists"),
            "parent_consent_signature_b64": payload.get("parent_consent_signature_b64"),
            "issued_intent": issued_intent,
            "nonce": payload["nonce"],
            "created_at": payload["created_at"],
        }
    )


def build_lineage_parent_consent_to_sign(payload: dict) -> bytes:
    """Build canonical bytes for parent-consent signature in lineage requests."""
    _reject_floats(payload)
    required = (
        "parent_agent_id",
        "agent_id",
        "agent_public_key_b64",
        "nonce",
        "created_at",
    )
    for field in required:
        if field not in payload or not isinstance(payload[field], str) or not payload[field]:
            raise ValueError(f"{field} must be a non-empty string")

    issued_intent = payload.get("issued_intent", LINEAGE_PARENT_CONSENT_ISSUED_INTENT)
    if issued_intent != LINEAGE_PARENT_CONSENT_ISSUED_INTENT:
        raise ValueError("issued_intent must be IAP-Registry-Lineage-Parent-Consent")

    canonical_payload = {
        "parent_agent_id": payload["parent_agent_id"],
        "agent_id": payload["agent_id"],
        "agent_public_key_b64": payload["agent_public_key_b64"],
        "fork_event_hash": payload.get("fork_event_hash"),
        "issued_intent": issued_intent,
        "nonce": payload["nonce"],
        "created_at": payload["created_at"],
    }
    return _canonical_bytes(canonical_payload)


def build_key_rotation_request_to_sign(payload: dict) -> bytes:
    """Build canonical bytes for key rotation request signing."""
    _reject_floats(payload)

    required = (
        "old_agent_id",
        "new_agent_id",
        "old_agent_public_key_b64",
        "new_agent_public_key_b64",
        "nonce",
        "created_at",
    )
    for field in required:
        if field not in payload or not isinstance(payload[field], str) or not payload[field]:
            raise ValueError(f"{field} must be a non-empty string")

    issued_intent = payload.get("issued_intent", KEY_ROTATION_ISSUED_INTENT)
    if issued_intent != KEY_ROTATION_ISSUED_INTENT:
        raise ValueError("issued_intent must be IAP-Registry-KeyRotation-Request")

    return _canonical_bytes(
        {
            "old_agent_id": payload["old_agent_id"],
            "new_agent_id": payload["new_agent_id"],
            "old_agent_public_key_b64": payload["old_agent_public_key_b64"],
            "new_agent_public_key_b64": payload["new_agent_public_key_b64"],
            "issued_intent": issued_intent,
            "nonce": payload["nonce"],
            "created_at": payload["created_at"],
        }
    )


def build_liveness_response_to_sign(payload: dict) -> bytes:
    """Build canonical bytes for liveness challenge response signing."""
    _reject_floats(payload)
    required = ("challenge_id", "agent_id", "nonce")
    for field in required:
        if field not in payload or not isinstance(payload[field], str) or not payload[field]:
            raise ValueError(f"{field} must be a non-empty string")

    issued_intent = payload.get("issued_intent", LIVENESS_ISSUED_INTENT)
    if issued_intent != LIVENESS_ISSUED_INTENT:
        raise ValueError("issued_intent must be IAP-Registry-Liveness-Challenge-Response")

    return _canonical_bytes(
        {
            "challenge_id": payload["challenge_id"],
            "agent_id": payload["agent_id"],
            "nonce": payload["nonce"],
            "issued_intent": issued_intent,
        }
    )
