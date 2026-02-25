"""SDK request builders/signers."""

from __future__ import annotations

import base64
import warnings
from datetime import datetime, timezone
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from iap_sdk.continuity.signing import (
    CONTINUITY_ISSUED_INTENT,
    IDENTITY_ANCHOR_ISSUED_INTENT,
    KEY_ROTATION_ISSUED_INTENT,
    LINEAGE_PARENT_CONSENT_ISSUED_INTENT,
    LINEAGE_ISSUED_INTENT,
    build_identity_anchor_request_to_sign,
    build_key_rotation_request_to_sign,
    build_lineage_parent_consent_to_sign,
    build_lineage_request_to_sign,
    build_request_to_sign,
)
from iap_sdk.custody import normalize_custody_class
from iap_sdk.errors import SequenceViolationError


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def check_sequence_integrity(previous_sequence: int | None, next_sequence: int) -> None:
    if next_sequence < 1:
        raise SequenceViolationError("sequence must be >= 1")
    if previous_sequence is not None and next_sequence <= previous_sequence:
        raise SequenceViolationError("sequence must strictly increase")


def build_continuity_request(
    *,
    agent_public_key_b64: str,
    agent_id: str,
    memory_root: str,
    sequence: int,
    manifest_version: str,
    manifest_hash: str,
    agent_name: str | None = None,
    agent_custody_class: str | None = None,
    nonce: str | None = None,
    created_at: str | None = None,
) -> dict:
    normalized_custody = (
        normalize_custody_class(agent_custody_class) if agent_custody_class is not None else None
    )
    return {
        "agent_public_key_b64": agent_public_key_b64,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "agent_custody_class": normalized_custody,
        "memory_root": memory_root,
        "sequence": sequence,
        "manifest_version": manifest_version,
        "manifest_hash": manifest_hash,
        "nonce": nonce or str(uuid4()),
        "created_at": created_at or _utc_now_iso(),
        "issued_intent": CONTINUITY_ISSUED_INTENT,
        "agent_signature_b64": "",
    }


def sign_continuity_request(payload: dict, private_key_bytes: bytes) -> dict:
    payload_to_sign = dict(payload)
    canonical = build_request_to_sign(payload_to_sign)
    signature = Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(canonical)
    payload_to_sign["agent_signature_b64"] = base64.b64encode(signature).decode("ascii")
    return payload_to_sign


def build_identity_anchor_request(
    *,
    agent_public_key_b64: str,
    agent_id: str,
    metadata: dict[str, str] | None = None,
    nonce: str | None = None,
    created_at: str | None = None,
) -> dict:
    return {
        "agent_public_key_b64": agent_public_key_b64,
        "agent_id": agent_id,
        "metadata": metadata or {},
        "nonce": nonce or str(uuid4()),
        "created_at": created_at or _utc_now_iso(),
        "issued_intent": IDENTITY_ANCHOR_ISSUED_INTENT,
        "agent_signature_b64": "",
    }


def sign_identity_anchor_request(payload: dict, private_key_bytes: bytes) -> dict:
    payload_to_sign = dict(payload)
    canonical = build_identity_anchor_request_to_sign(payload_to_sign)
    signature = Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(canonical)
    payload_to_sign["agent_signature_b64"] = base64.b64encode(signature).decode("ascii")
    return payload_to_sign


def build_lineage_request(
    *,
    agent_public_key_b64: str,
    agent_id: str,
    parent_agent_id: str | None = None,
    fork_event_hash: str | None = None,
    lineage_proof_policy: str = "parent_anchor_exists",
    parent_consent_signature_b64: str | None = None,
    nonce: str | None = None,
    created_at: str | None = None,
) -> dict:
    return {
        "agent_public_key_b64": agent_public_key_b64,
        "agent_id": agent_id,
        "parent_agent_id": parent_agent_id,
        "fork_event_hash": fork_event_hash,
        "lineage_proof_policy": lineage_proof_policy,
        "parent_consent_signature_b64": parent_consent_signature_b64,
        "nonce": nonce or str(uuid4()),
        "created_at": created_at or _utc_now_iso(),
        "issued_intent": LINEAGE_ISSUED_INTENT,
        "agent_signature_b64": "",
    }


def sign_lineage_request(payload: dict, private_key_bytes: bytes) -> dict:
    payload_to_sign = dict(payload)
    canonical = build_lineage_request_to_sign(payload_to_sign)
    signature = Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(canonical)
    payload_to_sign["agent_signature_b64"] = base64.b64encode(signature).decode("ascii")
    return payload_to_sign


def build_lineage_parent_consent(
    *,
    parent_agent_id: str,
    agent_id: str,
    agent_public_key_b64: str,
    fork_event_hash: str | None = None,
    nonce: str,
    created_at: str,
) -> dict:
    return {
        "parent_agent_id": parent_agent_id,
        "agent_id": agent_id,
        "agent_public_key_b64": agent_public_key_b64,
        "fork_event_hash": fork_event_hash,
        "nonce": nonce,
        "created_at": created_at,
        "issued_intent": LINEAGE_PARENT_CONSENT_ISSUED_INTENT,
    }


def sign_lineage_parent_consent(payload: dict, parent_private_key_bytes: bytes) -> str:
    canonical = build_lineage_parent_consent_to_sign(dict(payload))
    signature = Ed25519PrivateKey.from_private_bytes(parent_private_key_bytes).sign(canonical)
    return base64.b64encode(signature).decode("ascii")


def build_key_rotation_request(
    *,
    old_agent_id: str,
    new_agent_id: str,
    old_agent_public_key_b64: str,
    new_agent_public_key_b64: str,
    nonce: str | None = None,
    created_at: str | None = None,
) -> dict:
    return {
        "old_agent_id": old_agent_id,
        "new_agent_id": new_agent_id,
        "old_agent_public_key_b64": old_agent_public_key_b64,
        "new_agent_public_key_b64": new_agent_public_key_b64,
        "nonce": nonce or str(uuid4()),
        "created_at": created_at or _utc_now_iso(),
        "issued_intent": KEY_ROTATION_ISSUED_INTENT,
        "old_signature_b64": "",
        "new_signature_b64": "",
    }


def sign_key_rotation_request(
    payload: dict,
    *,
    old_private_key_bytes: bytes,
    new_private_key_bytes: bytes,
) -> dict:
    payload_to_sign = dict(payload)
    canonical = build_key_rotation_request_to_sign(payload_to_sign)
    old_signature = Ed25519PrivateKey.from_private_bytes(old_private_key_bytes).sign(canonical)
    new_signature = Ed25519PrivateKey.from_private_bytes(new_private_key_bytes).sign(canonical)
    payload_to_sign["old_signature_b64"] = base64.b64encode(old_signature).decode("ascii")
    payload_to_sign["new_signature_b64"] = base64.b64encode(new_signature).decode("ascii")
    return payload_to_sign


def build_continuity_request_legacy(
    *,
    agent_public_key_b64: str,
    agent_id: str,
    memory_root: str,
    sequence: int,
    agent_name: str | None = None,
    nonce: str | None = None,
    created_at: str | None = None,
) -> dict:
    warnings.warn(
        "build_continuity_request_legacy() is deprecated: use build_continuity_request() "
        "with manifest_version and manifest_hash.",
        DeprecationWarning,
        stacklevel=2,
    )
    return {
        "agent_public_key_b64": agent_public_key_b64,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "memory_root": memory_root,
        "sequence": sequence,
        "nonce": nonce or str(uuid4()),
        "created_at": created_at or _utc_now_iso(),
        "issued_intent": CONTINUITY_ISSUED_INTENT,
        "agent_signature_b64": "",
    }
