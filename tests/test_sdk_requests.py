from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from iap_sdk.continuity.signing import (
    build_identity_anchor_request_to_sign,
    build_key_rotation_request_to_sign,
    build_lineage_request_to_sign,
    build_request_to_sign,
)
from iap_sdk.crypto.agent_identity import derive_agent_id
from iap_sdk.crypto.ed25519_verify import verify_ed25519
from iap_sdk.errors import SequenceViolationError
from iap_sdk.requests import (
    build_continuity_request,
    build_identity_anchor_request,
    build_key_rotation_request,
    build_lineage_request,
    check_sequence_integrity,
    sign_continuity_request,
    sign_identity_anchor_request,
    sign_key_rotation_request,
    sign_lineage_request,
)


def _identity() -> tuple[bytes, str, str]:
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_key_b64 = base64.b64encode(public_bytes).decode("ascii")
    return private_bytes, public_key_b64, derive_agent_id(public_bytes)


def test_check_sequence_integrity_rejects_non_increasing() -> None:
    check_sequence_integrity(None, 1)
    check_sequence_integrity(1, 2)
    with pytest.raises(SequenceViolationError):
        check_sequence_integrity(2, 2)
    with pytest.raises(SequenceViolationError):
        check_sequence_integrity(2, 1)


def test_sign_continuity_request_produces_valid_signature() -> None:
    private_bytes, public_key_b64, agent_id = _identity()
    payload = build_continuity_request(
        agent_public_key_b64=public_key_b64,
        agent_id=agent_id,
        memory_root="a" * 64,
        sequence=1,
        manifest_version="IAM-1",
        manifest_hash="b" * 64,
    )
    signed = sign_continuity_request(payload, private_bytes)
    signature = base64.b64decode(signed["agent_signature_b64"])
    canonical = build_request_to_sign(signed)
    public_key = base64.b64decode(public_key_b64)
    assert verify_ed25519(signature, canonical, public_key) is True


def test_sign_lineage_request_produces_valid_signature() -> None:
    private_bytes, public_key_b64, agent_id = _identity()
    payload = build_lineage_request(
        agent_public_key_b64=public_key_b64,
        agent_id=agent_id,
        parent_agent_id=agent_id,
        fork_event_hash="f" * 64,
    )
    signed = sign_lineage_request(payload, private_bytes)
    signature = base64.b64decode(signed["agent_signature_b64"])
    canonical = build_lineage_request_to_sign(signed)
    public_key = base64.b64decode(public_key_b64)
    assert verify_ed25519(signature, canonical, public_key) is True


def test_sign_identity_anchor_request_produces_valid_signature() -> None:
    private_bytes, public_key_b64, agent_id = _identity()
    payload = build_identity_anchor_request(
        agent_public_key_b64=public_key_b64,
        agent_id=agent_id,
        metadata={"agent_name": "Atlas"},
    )
    signed = sign_identity_anchor_request(payload, private_bytes)
    signature = base64.b64decode(signed["agent_signature_b64"])
    canonical = build_identity_anchor_request_to_sign(signed)
    public_key = base64.b64decode(public_key_b64)
    assert verify_ed25519(signature, canonical, public_key) is True


def test_sign_key_rotation_request_produces_valid_dual_signatures() -> None:
    old_private_bytes, old_public_key_b64, old_agent_id = _identity()
    new_private_bytes, new_public_key_b64, new_agent_id = _identity()
    payload = build_key_rotation_request(
        old_agent_id=old_agent_id,
        new_agent_id=new_agent_id,
        old_agent_public_key_b64=old_public_key_b64,
        new_agent_public_key_b64=new_public_key_b64,
    )
    signed = sign_key_rotation_request(
        payload,
        old_private_key_bytes=old_private_bytes,
        new_private_key_bytes=new_private_bytes,
    )
    canonical = build_key_rotation_request_to_sign(signed)
    old_signature = base64.b64decode(signed["old_signature_b64"])
    new_signature = base64.b64decode(signed["new_signature_b64"])
    assert verify_ed25519(old_signature, canonical, base64.b64decode(old_public_key_b64)) is True
    assert verify_ed25519(new_signature, canonical, base64.b64decode(new_public_key_b64)) is True
